//! Links to other relays, and the circuits that run over them.
//!
//! A chained circuit needs the first relay to be a client of the second. This
//! is that: one connection per relay pair, shared by every circuit going that
//! way.
//!
//! # Why one link per pair and not one per circuit
//!
//! The link is authenticated by the relays' own keys, deliberately, so that the
//! exit relay knows which relay a circuit came from and is not open transit.
//! Once that is true the exit relay can count the circuits arriving from one
//! relay however they are carried, and separate connections would give away
//! exactly as much as one connection does while costing a connection per call.
//!
//! # Why the dialling arrives as a trait
//!
//! The same reason the opening does. Dialling needs a key, a resolver and a TLS
//! configuration, and none of those are this crate's to choose on behalf of an
//! operator. A relay given no dialler chains nothing, which is what a relay did
//! before chaining and remains the default.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};

/// What a dial produces, or why it did not.
#[derive(Debug)]
pub struct DialError(pub String);

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A dial in progress.
pub type DialFuture =
    Pin<Box<dyn Future<Output = Result<crate::client::Client, DialError>> + Send>>;

/// Opens a connection to another relay.
///
/// Implemented outside this crate, by whatever holds the relay's own key and
/// knows how it is meant to reach the network.
pub trait RelayDialer: fmt::Debug + Send + Sync + 'static {
    /// `url` arrived inside a sealed descriptor and has been read by nobody
    /// else. It has not been checked: an implementation must decide for itself
    /// whether this relay is willing to dial it.
    fn dial(&self, url: String) -> DialFuture;

    /// Fetches another relay's published circuit key, for a caller who must not
    /// ask that relay directly.
    ///
    /// `None` for anything that did not produce a key: a relay that terminates
    /// no circuits, one that cannot be reached, and one this relay will not
    /// talk to. The caller cannot tell those apart, and telling it would say
    /// which relays this one is willing to reach.
    ///
    /// The same permission as `dial` governs this: it is the same outward
    /// connection to the same stranger-chosen address.
    fn fetch_circuit_key(&self, url: String) -> KeyFuture;
}

/// A key fetch in progress.
pub type KeyFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// A shared dialler, or none.
pub type MaybeDialer = Option<Arc<dyn RelayDialer>>;

/// What one link is asked to do.
enum Request {
    /// Open a circuit at the far relay, carrying a descriptor this relay cannot
    /// read.
    Open {
        circuit: u32,
        sealed: Bytes,
        /// Told whether it opened. The requester is waiting on this and nothing
        /// else, so a link that dies must drop it rather than leave it hanging.
        answer: oneshot::Sender<bool>,
        /// Where a reply on this circuit goes back to: the queue the waiting
        /// connection's own writer reads.
        ///
        /// A queue rather than a name in the client table. A link that held the
        /// client table would keep it alive for as long as the link lived, and
        /// the table holds the links, so the two would keep each other alive
        /// for ever. A sender keeps alive only the connection it belongs to,
        /// which is exactly the thing that should outlive nothing.
        back: mpsc::Sender<RelayToClientMsg>,
        /// The id that connection knows this circuit by, which is not the id
        /// this link knows it by.
        owner_circuit: u32,
    },
    /// Carry datagrams along a circuit that is already open.
    Carry { circuit: u32, datagrams: Datagrams },
}

/// One connection to one relay.
struct Link {
    to: mpsc::Sender<Request>,
}

/// Every link this relay holds.
#[derive(Clone)]
pub struct Links(Arc<Inner>);

impl Default for Links {
    /// A relay that chains nothing.
    fn default() -> Self {
        Self::new(None)
    }
}

struct Inner {
    dialer: MaybeDialer,
    links: DashMap<String, Link>,
}

impl fmt::Debug for Links {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Links({} open)", self.0.links.len())
    }
}

impl Links {
    /// A relay that will dial others, or one that chains nothing.
    ///
    /// `None` is the default and is what a relay did before chaining.
    pub fn new(dialer: MaybeDialer) -> Self {
        Self(Arc::new(Inner {
            dialer,
            links: DashMap::new(),
        }))
    }

    /// Whether this relay chains at all.
    pub(super) fn can_chain(&self) -> bool {
        self.0.dialer.is_some()
    }

    /// Fetches another relay's circuit key, if this relay does that at all.
    pub(super) async fn fetch_circuit_key(&self, url: &str) -> Option<String> {
        let dialer = self.0.dialer.clone()?;
        dialer.fetch_circuit_key(url.to_owned()).await
    }

    /// Opens a circuit at `url`, carrying `sealed` for that relay to read.
    ///
    /// Returns once the far relay has answered, or false if it did not.
    pub(super) async fn open_circuit(
        &self,
        url: &str,
        sealed: Bytes,
        back: mpsc::Sender<RelayToClientMsg>,
        owner_circuit: u32,
    ) -> Option<u32> {
        let Some(dialer) = self.0.dialer.clone() else {
            return None;
        };

        let to = self.link_to(url, dialer)?;

        // The id this link will know the circuit by. Chosen here because the
        // side that names a circuit is the side that will use the name, and
        // this relay is the one talking to the far one.
        let circuit = rand::random();
        let (answer, answered) = oneshot::channel();
        if to
            .send(Request::Open {
                circuit,
                sealed,
                answer,
                back,
                owner_circuit,
            })
            .await
            .is_err()
        {
            self.0.links.remove(url);
            return None;
        }

        match answered.await {
            Ok(true) => Some(circuit),
            // Either the far relay said no, or the link went while we waited.
            _ => None,
        }
    }

    /// Sends along a circuit that is already open on a link.
    pub(super) fn carry(&self, url: &str, circuit: u32, datagrams: Datagrams) {
        let Some(link) = self.0.links.get(url) else {
            debug!("no link to carry this circuit any more");
            return;
        };
        if link.to.try_send(Request::Carry { circuit, datagrams }).is_err() {
            debug!("the link is gone or too far behind, dropping");
        }
    }

    /// The link to `url`, dialling if there is not one yet.
    fn link_to(&self, url: &str, dialer: Arc<dyn RelayDialer>) -> Option<mpsc::Sender<Request>> {
        if let Some(link) = self.0.links.get(url) {
            if !link.to.is_closed() {
                return Some(link.to.clone());
            }
        }

        let (to, requests) = mpsc::channel(64);
        self.0.links.insert(
            url.to_owned(),
            Link {
                to: to.clone(),
            },
        );

        let url_owned = url.to_owned();
        tokio::task::spawn(async move {
            run_link(url_owned, dialer, requests).await;
        });

        Some(to)
    }

}

/// One link's whole life: dial, carry, and close every circuit when it ends.
///
/// There is no reconnection. A link that drops closes its circuits and the
/// callers rebuild, which is the honest behaviour: a circuit that survived the
/// connection carrying it would be state pretending a failure did not happen.
async fn run_link(
    url: String,
    dialer: Arc<dyn RelayDialer>,
    mut requests: mpsc::Receiver<Request>,
) {
    use rotelyx_future::{SinkExt, StreamExt};

    let client = match dialer.dial(url.clone()).await {
        Ok(client) => client,
        Err(err) => {
            warn!("could not reach the next relay: {err}");
            // Draining rather than dropping: every waiting requester is told no
            // instead of being left holding a channel that will never answer.
            while let Some(request) = requests.recv().await {
                if let Request::Open { answer, .. } = request {
                    let _ = answer.send(false);
                }
            }
            return;
        }
    };

    let (mut stream, mut sink) = client.split();

    // Which circuit on this link belongs to which connection here. The far
    // relay answers by the id this side chose, so this maps that id back to the
    // client waiting for it. Kept in the task rather than shared: nothing
    // outside this link has any use for it, and it dies with the link.
    let mut circuits: HashMap<u32, (mpsc::Sender<RelayToClientMsg>, u32)> = HashMap::new();
    let mut opening: HashMap<u32, oneshot::Sender<bool>> = HashMap::new();

    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else { break };
                match request {
                    Request::Open { circuit, sealed, answer, back, owner_circuit } => {
                        let frame = ClientToRelayMsg::OpenCircuit {
                            circuit,
                            sealed,
                            inner: Bytes::new(),
                        };
                        if sink.send(frame).await.is_err() {
                            let _ = answer.send(false);
                            break;
                        }
                        circuits.insert(circuit, (back, owner_circuit));
                        opening.insert(circuit, answer);
                    }
                    Request::Carry { circuit, datagrams } => {
                        let frame = ClientToRelayMsg::CircuitDatagrams { circuit, datagrams };
                        if sink.send(frame).await.is_err() {
                            break;
                        }
                    }
                }
            }
            frame = stream.next() => {
                let Some(Ok(frame)) = frame else { break };
                match frame {
                    RelayToClientMsg::CircuitOpened { circuit } => {
                        if let Some(answer) = opening.remove(&circuit) {
                            let _ = answer.send(true);
                        }
                    }
                    RelayToClientMsg::CircuitClosed { circuit, .. } => {
                        if let Some(answer) = opening.remove(&circuit) {
                            let _ = answer.send(false);
                        }
                        if let Some((back, owner_circuit)) = circuits.remove(&circuit) {
                            let _ = back.try_send(RelayToClientMsg::CircuitClosed {
                                circuit: owner_circuit,
                                reason: super::client::CIRCUIT_FAR_END_GONE,
                            });
                        }
                    }
                    RelayToClientMsg::CircuitDatagrams { circuit, datagrams } => {
                        match circuits.get(&circuit) {
                            Some((back, owner_circuit)) => {
                                if back
                                    .try_send(RelayToClientMsg::CircuitDatagrams {
                                        circuit: *owner_circuit,
                                        datagrams,
                                    })
                                    .is_err()
                                {
                                    debug!("the waiting connection is gone or too far behind");
                                }
                            }
                            None => debug!("a reply for a circuit this link does not hold"),
                        }
                    }
                    // A relay is a client here and receives what any client
                    // receives. Nothing else on this connection concerns
                    // circuits, and answering it would be answering traffic
                    // that was never addressed to this relay as a person.
                    _ => {}
                }
            }
        }
    }

    // Whatever ended it, nothing on this link survives it.
    for answer in opening.into_values() {
        let _ = answer.send(false);
    }
    for (back, owner_circuit) in circuits.into_values() {
        let _ = back.try_send(RelayToClientMsg::CircuitClosed {
            circuit: owner_circuit,
            reason: super::client::CIRCUIT_FAR_END_GONE,
        });
    }
    debug!(%url, "link ended");
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rotelyx_transport_base::SecretKey;
    use rotelyx_error::{Result, StdResultExt};
    use rotelyx_future::{Sink, SinkExt, Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use tokio::sync::mpsc;

    use super::*;
    use crate::protos::relay::SEALED_HOP_LEN;

    /// Hands out one end of a pipe, and keeps the other for the test to be the
    /// far relay on.
    #[derive(Debug)]
    struct PipeDialer {
        far: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
        /// What the test expects to be asked for, so a dial to anywhere else
        /// fails rather than quietly succeeding.
        url: String,
    }

    impl RelayDialer for PipeDialer {
        /// These tests are about the link, not about fetching keys.
        fn fetch_circuit_key(&self, _url: String) -> KeyFuture {
            Box::pin(async move { None })
        }

        fn dial(&self, url: String) -> DialFuture {
            let taken = if url == self.url {
                self.far.lock().expect("not poisoned").take()
            } else {
                None
            };
            Box::pin(async move {
                match taken {
                    Some(io) => Ok(crate::client::Client::test(io)),
                    None => Err(DialError("nothing to dial".to_owned())),
                }
            })
        }
    }

    /// A dialler that never reaches anything.
    #[derive(Debug)]
    struct DeadDialer;

    impl RelayDialer for DeadDialer {
        fn fetch_circuit_key(&self, _url: String) -> KeyFuture {
            Box::pin(async move { None })
        }

        fn dial(&self, _url: String) -> DialFuture {
            Box::pin(async move { Err(DialError("unreachable".to_owned())) })
        }
    }

    const URL: &str = "https://relay.example.invalid";

    /// A circuit opens at the far relay, carries a datagram each way, and the
    /// two ends never share an id.
    #[tokio::test]
    #[traced_test]
    async fn a_circuit_opens_at_the_far_relay_and_carries_both_ways() -> Result {
        let (near, far) = tokio::io::duplex(8192);
        let mut far = crate::server::streams::RelayedStream::test(far);
        let links = Links::new(Some(std::sync::Arc::new(PipeDialer {
            far: std::sync::Mutex::new(Some(near)),
            url: URL.to_owned(),
        })));

        // The queue a waiting connection's writer reads.
        let (back, mut written) = mpsc::channel(16);

        let descriptor = Bytes::from(vec![0x99u8; SEALED_HOP_LEN]);
        let opening = tokio::task::spawn({
            let links = links.clone();
            let descriptor = descriptor.clone();
            async move { links.open_circuit(URL, descriptor, back, 42).await }
        });

        // The far relay hears the request.
        let Some(Ok(ClientToRelayMsg::OpenCircuit {
            circuit: far_circuit,
            sealed,
            inner,
        })) = far.next().await
        else {
            panic!("the far relay was not asked to open a circuit");
        };
        assert_eq!(sealed, descriptor, "the descriptor was not passed on whole");
        assert!(
            inner.is_empty(),
            "a third layer appeared on a two hop circuit"
        );
        assert_ne!(
            far_circuit, 42,
            "the two ends of the circuit share an id, so two relays could find \
             it in each other's tables"
        );

        far.send(RelayToClientMsg::CircuitOpened {
            circuit: far_circuit,
        })
        .await?;

        let opened = opening.await.std_context("join")?;
        assert_eq!(opened, Some(far_circuit), "the open did not report back");

        // Out.
        links.carry(URL, far_circuit, Datagrams::from(&b"outbound"[..]));
        let Some(Ok(ClientToRelayMsg::CircuitDatagrams { circuit, datagrams })) = far.next().await
        else {
            panic!("nothing reached the far relay");
        };
        assert_eq!(circuit, far_circuit);
        assert_eq!(datagrams.contents, &b"outbound"[..]);

        // And back, renamed to the id the near end uses.
        far.send(RelayToClientMsg::CircuitDatagrams {
            circuit: far_circuit,
            datagrams: Datagrams::from(&b"inbound"[..]),
        })
        .await?;
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), written.recv())
            .await
            .std_context("waiting for the reply")?;
        assert_eq!(
            frame,
            Some(RelayToClientMsg::CircuitDatagrams {
                circuit: 42,
                datagrams: Datagrams::from(&b"inbound"[..]),
            }),
            "the reply did not come back under the near end's own id"
        );
        Ok(())
    }

    /// A far relay that refuses is reported as a refusal, not as a hang.
    #[tokio::test]
    #[traced_test]
    async fn a_refusal_at_the_far_relay_comes_back_as_one() -> Result {
        let (near, far) = tokio::io::duplex(8192);
        let mut far = crate::server::streams::RelayedStream::test(far);
        let links = Links::new(Some(std::sync::Arc::new(PipeDialer {
            far: std::sync::Mutex::new(Some(near)),
            url: URL.to_owned(),
        })));
        let (back, _written) = mpsc::channel(16);

        let opening = tokio::task::spawn({
            let links = links.clone();
            async move {
                links
                    .open_circuit(URL, Bytes::from(vec![0u8; SEALED_HOP_LEN]), back, 1)
                    .await
            }
        });

        let Some(Ok(ClientToRelayMsg::OpenCircuit { circuit, .. })) = far.next().await else {
            panic!("the far relay was not asked");
        };
        far.send(RelayToClientMsg::CircuitClosed { circuit, reason: 2 })
            .await?;

        assert_eq!(
            opening.await.std_context("join")?,
            None,
            "a refusal at the far relay should be a refusal here"
        );
        Ok(())
    }

    /// A dial that fails is a refusal, and every waiting request is told.
    #[tokio::test]
    #[traced_test]
    async fn a_relay_that_cannot_be_reached_refuses_rather_than_hangs() -> Result {
        let links = Links::new(Some(std::sync::Arc::new(DeadDialer)));
        let (back, _written) = mpsc::channel(16);

        let opened = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            links.open_circuit(URL, Bytes::from(vec![0u8; SEALED_HOP_LEN]), back, 1),
        )
        .await
        .std_context("a failed dial should not hang")?;

        assert_eq!(opened, None, "an unreachable relay should be a refusal");
        Ok(())
    }

    /// When the link ends, every circuit on it closes.
    #[tokio::test]
    #[traced_test]
    async fn the_link_ending_closes_the_circuits_it_carried() -> Result {
        let (near, far) = tokio::io::duplex(8192);
        let mut far = crate::server::streams::RelayedStream::test(far);
        let links = Links::new(Some(std::sync::Arc::new(PipeDialer {
            far: std::sync::Mutex::new(Some(near)),
            url: URL.to_owned(),
        })));
        let (back, mut written) = mpsc::channel(16);

        let opening = tokio::task::spawn({
            let links = links.clone();
            async move {
                links
                    .open_circuit(URL, Bytes::from(vec![0u8; SEALED_HOP_LEN]), back, 7)
                    .await
            }
        });
        let Some(Ok(ClientToRelayMsg::OpenCircuit { circuit, .. })) = far.next().await else {
            panic!("the far relay was not asked");
        };
        far.send(RelayToClientMsg::CircuitOpened { circuit }).await?;
        assert!(opening.await.std_context("join")?.is_some());

        // The far relay goes.
        drop(far);

        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), written.recv())
            .await
            .std_context("waiting for the close")?;
        assert_eq!(
            frame,
            Some(RelayToClientMsg::CircuitClosed {
                circuit: 7,
                reason: super::super::client::CIRCUIT_FAR_END_GONE,
            }),
            "the circuit was not closed when the link carrying it ended"
        );
        Ok(())
    }
}
