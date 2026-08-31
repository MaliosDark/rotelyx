//! The server-side representation of an ongoing client relaying connection.

use bytes::Bytes;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

/// Why a circuit is not open. See `RelayToClientMsg::CircuitClosed`.
///
/// Named here rather than written as bare numbers at the call sites, which is
/// what stops a second author inventing a second meaning for 2.
///
/// `EXPIRED` is deliberately never sent. A descriptor that has expired, one
/// sealed to another relay and one that is not a descriptor at all are all
/// answered with `REFUSED`, because distinguishing them would let somebody hold
/// a captured descriptor up to each relay in turn and learn which one it was
/// for. It is kept because the number means that on the wire and a later author
/// must not reuse it for something else.
#[allow(dead_code, reason = "reserved: telling this apart from REFUSED would leak")]
const CIRCUIT_EXPIRED: u8 = 0;
#[allow(dead_code, reason = "the rest are used once the circuit table exists")]
pub(super) const CIRCUIT_FAR_END_GONE: u8 = 1;
const CIRCUIT_REFUSED: u8 = 2;
#[allow(dead_code, reason = "the rest are used once the circuit table exists")]
const CIRCUIT_RELAY_GOING_AWAY: u8 = 3;

use rotelyx_transport_base::{EndpointId, Signature};
use rotelyx_error::{e, stack_error};
use rotelyx_future::{SinkExt, StreamExt};
use rand::RngExt;
use time::{Date, OffsetDateTime};
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, trace, warn};

use crate::{
    PingTracker,
    defaults::timeouts::SERVER_WRITE_TIMEOUT,
    http::ProtocolVersion,
    protos::{
        relay::{
            ClientToRelayMsg, Datagrams, PER_CLIENT_SEND_QUEUE_DEPTH, PING_INTERVAL,
            RelayToClientMsg, Status,
        },
        streams::BytesStreamSink,
    },
    server::{
        ConnectionId, OnDisconnectGuard,
        circuits::{CircuitEvent, Continuation, Forward, MAX_CIRCUITS_PER_CONNECTION},
        clients::Clients,
        links::Links,
        metrics::Metrics,
        streams::{RecvError as RelayRecvError, RelayedStream, SendError as RelaySendError},
    },
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    src: EndpointId,
    /// The data packet bytes.
    data: Datagrams,
    /// Set when this arrived for a circuit this connection opened.
    ///
    /// The frame written differs: a circuit reply names the circuit and nobody
    /// else, where an ordinary one names the sender. Carried on the packet
    /// rather than looked up again here because the lookup already happened,
    /// in the one place that holds the table.
    circuit: Option<u32>,
}

/// Configuration for a client connection.
///
/// Generic over the stream type to support different WebSocket implementations.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config<S> {
    /// Reports the disconnect once the connection ends.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    pub guard: OnDisconnectGuard,
    /// The relayed stream connection
    pub stream: RelayedStream<S>,
    /// Write timeout for the client connection
    pub write_timeout: Duration,
    /// Channel capacity for internal message queues
    pub channel_capacity: usize,
    /// Protocol version negotiated for this client
    pub protocol_version: ProtocolVersion,
}

impl<S> Config<S> {
    /// Creates a new config with sensible default values for `write_timeout` and `channel_capacity`.
    ///
    /// The endpoint and connection ids are taken from `guard`.
    pub fn new(
        guard: OnDisconnectGuard,
        stream: RelayedStream<S>,
        protocol_version: ProtocolVersion,
    ) -> Self {
        Self {
            guard,
            stream,
            protocol_version,
            write_timeout: SERVER_WRITE_TIMEOUT,
            channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
        }
    }
}

/// The [`Server`] side representation of a [`Client`]'s connection.
///
/// [`Server`]: crate::server::Server
/// [`Client`]: crate::client::Client
#[derive(Debug)]
pub(super) struct Client {
    /// Identity of the connected peer.
    endpoint_id: EndpointId,
    /// Connection identifier.
    connection_id: ConnectionId,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: AbortOnDropHandle<()>,
    /// Channel to send packets intended for the client.
    packet_queue: mpsc::Sender<Packet>,
    /// Channel to send non-packet messages to the client.
    message_queue: mpsc::Sender<RelayToClientMsg>,
    /// Relay protocol version negotiated for this client.
    protocol_version: ProtocolVersion,
}

impl Client {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    ///
    /// The `guard` is moved into the connection actor and reports the disconnect to access
    /// control once the connection ends.
    ///
    /// Call [`Client::shutdown`] to close the read and write loops before dropping the [`Client`]
    pub(super) fn new<S>(config: Config<S>, clients: &Clients, metrics: Arc<Metrics>) -> Client
    where
        S: BytesStreamSink + Send + 'static,
    {
        let Config {
            guard,
            stream,
            write_timeout,
            channel_capacity,
            protocol_version,
        } = config;
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;

        let (packet_send_queue_s, packet_send_queue_r) = mpsc::channel(channel_capacity);
        let (message_send_queue_s, message_send_queue_r) = mpsc::channel(channel_capacity);
        // One per circuit this connection may hold, so a burst of opens cannot
        // block on reporting back.
        let (circuit_events_s, circuit_events_r) =
            mpsc::channel(MAX_CIRCUITS_PER_CONNECTION);
        let done = CancellationToken::new();

        let actor = Actor {
            stream,
            timeout: write_timeout,
            packet_send_queue: packet_send_queue_r,
            message_send_queue: message_send_queue_r,
            guard,
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            metrics,
            to_self: message_send_queue_s.clone(),
            links: clients.links(),
            protocol_version,
            to_circuits: circuit_events_s,
            circuit_events: circuit_events_r,
            circuits: HashMap::new(),
        };

        // start io loop
        let io_done = done.clone();
        let handle = tokio::task::spawn(actor.run(io_done).instrument(tracing::info_span!(
            "client-connection-actor",
            remote_endpoint = %endpoint_id.fmt_short(),
            connection_id = %connection_id
        )));

        Client {
            endpoint_id,
            connection_id,
            handle: AbortOnDropHandle::new(handle),
            done,
            packet_queue: packet_send_queue_s,
            message_queue: message_send_queue_s,
            protocol_version,
        }
    }

    pub(super) fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Shutdown the reader and writer loops and closes the connection.
    ///
    /// Any shutdown errors will be logged as warnings.
    pub(super) async fn shutdown(self) {
        self.start_shutdown();
        if let Err(e) = self.handle.await {
            warn!(
                remote_endpoint = %self.endpoint_id.fmt_short(),
                "error closing actor loop: {e:#?}",
            );
        };
    }

    /// Starts the process of shutdown.
    pub(super) fn start_shutdown(&self) {
        self.done.cancel();
    }

    pub(super) fn try_send_packet(
        &self,
        src: EndpointId,
        data: Datagrams,
        circuit: Option<u32>,
    ) -> Result<(), TrySendError<Packet>> {
        self.packet_queue.try_send(Packet { src, data, circuit })
    }

    /// Tells this connection one of its circuits has ended.
    ///
    /// Sent as a message rather than a packet because it carries no data, and
    /// on the same queue as the other out-of-band frames so it cannot overtake
    /// data already queued for that circuit.
    pub(super) fn try_send_circuit_closed(
        &self,
        circuit: u32,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        self.message_queue.try_send(RelayToClientMsg::CircuitClosed {
            circuit,
            reason: CIRCUIT_FAR_END_GONE,
        })
    }

    pub(super) fn try_send_peer_gone(
        &self,
        key: EndpointId,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        self.message_queue
            .try_send(RelayToClientMsg::EndpointGone(key))
    }

    pub(super) fn try_send_health(
        &self,
        status: Status,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        // Matched by boundary rather than by naming every version, so that a
        // version four does not silently fall into the version one branch.
        let message = match self.protocol_version {
            v if v >= ProtocolVersion::V2 => RelayToClientMsg::Status(status),
            _ => RelayToClientMsg::Health {
                problem: status.to_string(),
            },
        };
        self.message_queue.try_send(message)
    }
}

/// Error when handling an incoming frame from a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum HandleFrameError {
    #[error(transparent)]
    ForwardPacket { source: ForwardPacketError },
    #[error("Stream terminated")]
    StreamTerminated {},
    #[error(transparent)]
    Recv { source: RelayRecvError },
    #[error(transparent)]
    Send { source: WriteFrameError },
    /// A frame from a version this connection did not agree to speak.
    #[error("frame from a protocol version this connection did not agree")]
    UnexpectedFrameType {},
}

/// Error when writing a frame to a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum WriteFrameError {
    #[error(transparent)]
    Stream { source: RelaySendError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: tokio::time::error::Elapsed,
    },
}

/// Run error
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RunError {
    #[error(transparent)]
    ForwardPacket {
        #[error(from)]
        source: ForwardPacketError,
    },
    #[error("Flush")]
    Flush {},
    #[error(transparent)]
    HandleFrame {
        #[error(from)]
        source: HandleFrameError,
    },
    #[error("Failed to send packet")]
    PacketSend { source: WriteFrameError },
    #[error("Handle was dropped")]
    HandleDropped {},
    #[error("Writing a frame failed")]
    WriteFrame { source: WriteFrameError },
    #[error("Tick flush")]
    TickFlush {},
}

/// Manages all the reads and writes to this client. It periodically sends a `KEEP_ALIVE`
/// message to the client to keep the connection alive.
///
/// Call `run` to manage the input and output to and from the connection and the server.
/// Once it hits its first write error or error receiving off a channel,
/// it errors on return.
/// If writes do not complete in the given `timeout`, it will also error.
///
/// On the "write" side, the [`Actor`] can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame to inform the client that a peer they have previously sent messages to
///    is gone from the network
///  - packets from other peers
///
/// On the "read" side, it can:
///     - receive a ping and write a pong back
///     to speak to the endpoint ID associated with that client.
#[derive(Debug)]
struct Actor<S> {
    /// IO Stream to talk to the client
    stream: RelayedStream<S>,
    /// Maximum time we wait to complete a write to the client
    timeout: Duration,
    /// Receiver for packets to be sent to the client.
    packet_send_queue: mpsc::Receiver<Packet>,
    /// Receiver for non-packet messages to be sent to the client.
    message_send_queue: mpsc::Receiver<RelayToClientMsg>,
    /// Reports the disconnect to access control when dropped.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    guard: OnDisconnectGuard,
    /// Reference to the other connected clients.
    clients: Clients,
    /// Statistics about the connected clients
    client_counter: ClientCounter,
    ping_tracker: PingTracker,
    metrics: Arc<Metrics>,
    /// A sender to this connection's own writer.
    ///
    /// Held so that work finished off the read loop can queue a frame: opening
    /// a circuit at another relay is a network round trip, and waiting for it
    /// inside the read loop would stop this connection carrying anything else
    /// while it waited.
    to_self: mpsc::Sender<RelayToClientMsg>,
    /// Links to other relays, for the circuits that do not end here.
    links: Links,
    /// What this connection agreed to speak at the handshake.
    ///
    /// Held so that this relay never answers with a frame the far side agreed
    /// it would not understand. A frame a peer cannot decode does not get
    /// refused, it ends the connection.
    protocol_version: ProtocolVersion,
    /// Where a chained open reports back, carrying what a frame cannot say.
    to_circuits: mpsc::Sender<CircuitEvent>,
    circuit_events: mpsc::Receiver<CircuitEvent>,
    /// Circuits this connection opened, by the id it was told.
    ///
    /// Held here rather than in the shared table on purpose: an id is only ever
    /// meaningful on the connection that was given it, and a table that lives
    /// in the connection makes that true by construction instead of by a check
    /// somebody has to remember to write. It goes when the connection goes.
    circuits: HashMap<u32, Forward>,
}

impl<S> Actor<S>
where
    S: BytesStreamSink,
{
    async fn run(mut self, done: CancellationToken) {
        // Note the accept and disconnects metrics must be in a pair.  Technically the
        // connection is accepted long before this in the HTTP server, but it is clearer to
        // handle the metric here.
        self.metrics.accepts.inc();
        if self.client_counter.update(self.guard.endpoint_id()) {
            self.metrics.unique_client_keys.inc();
        }
        match self.run_inner(done).await {
            Err(e) => {
                warn!("actor errored {e:#}, exiting");
            }
            Ok(()) => {
                debug!("actor finished, exiting");
            }
        }

        self.clients.unregister(self.guard, &self.metrics);
        self.metrics.disconnects.inc();
    }

    async fn run_inner(&mut self, done: CancellationToken) -> Result<(), RunError> {
        // Add some jitter to ping pong interactions, to avoid all pings being sent at the same time
        let next_interval = || {
            let random_secs = rand::rng().random_range(1..=5);
            Duration::from_secs(random_secs) + PING_INTERVAL
        };

        let mut ping_interval = tokio::time::interval(next_interval());
        // ticks immediately
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ping_interval.tick().await;

        loop {
            tokio::select! {
                biased;

                _ = done.cancelled() => {
                    trace!("actor loop cancelled, exiting");
                    // final flush
                    self.stream.flush().await.map_err(|_| e!(RunError::Flush))?;
                    break;
                }
                maybe_frame = self.stream.next() => {
                    self
                        .handle_frame(maybe_frame)
                        .await?;
                    // reset the ping interval, we just received a message
                    ping_interval.reset();
                }
                // Second priority, sending regular packets
                packet = self.packet_send_queue.recv() => {
                    let packet = packet.ok_or_else(|| e!(RunError::HandleDropped))?;
                    self.send_packet(packet)
                        .await
                        .map_err(|err| e!(RunError::PacketSend, err))?;
                }
                // A chained open has finished, one way or the other. Before
                // the message queue, because this decides what the table says
                // and a reply on the same circuit must not be written first.
                event = self.circuit_events.recv() => {
                    let event = event.ok_or_else(|| e!(RunError::HandleDropped))?;
                    let frame = match event {
                        CircuitEvent::Opened { circuit, url, far } => {
                            match self.circuits.get_mut(&circuit) {
                                Some(forward) => {
                                    forward.next = Some(Continuation::Open { url, far });
                                    RelayToClientMsg::CircuitOpened { circuit }
                                }
                                // The client gave up on it while the far relay
                                // was answering. Say nothing: it is not waiting.
                                None => continue,
                            }
                        }
                        CircuitEvent::Refused { circuit } => {
                            // The entry went in when the request did, so that
                            // datagrams arriving meanwhile were refused rather
                            // than misrouted. It comes out again here.
                            self.circuits.remove(&circuit);
                            RelayToClientMsg::CircuitClosed {
                                circuit,
                                reason: CIRCUIT_REFUSED,
                            }
                        }
                    };
                    self.write_frame(frame)
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
                // Last priority, sending other message
                message = self.message_send_queue.recv() => {
                    let message = message.ok_or_else(|| e!(RunError::HandleDropped))?;
                    trace!("send {message:?}");
                    // A closed circuit is forgotten here as well as told. The
                    // shared table released the return key already; leaving the
                    // entry would let dead circuits fill this connection's
                    // allowance and stop it opening live ones.
                    if let RelayToClientMsg::CircuitClosed { circuit, .. } = &message {
                        self.circuits.remove(circuit);
                    }
                    self.write_frame(message)
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
                _ = self.ping_tracker.timeout() => {
                    trace!("pong timed out");
                    break;
                }
                _ = ping_interval.tick() => {
                    trace!("keep alive ping");
                    // new interval
                    ping_interval.reset_after(next_interval());
                    let data = self.ping_tracker.new_ping();
                    self.write_frame(RelayToClientMsg::Ping(data))
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
            }

            self.stream
                .flush()
                .await
                .map_err(|_| e!(RunError::TickFlush))?;
        }
        Ok(())
    }

    /// Writes the given frame to the connection.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn write_frame(&mut self, frame: RelayToClientMsg) -> Result<(), WriteFrameError> {
        tokio::time::timeout(self.timeout, self.stream.send(frame)).await??;
        Ok(())
    }

    /// Writes contents to the client in a `RECV_PACKET` frame.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    /// Does not flush.
    async fn send_raw(&mut self, packet: Packet) -> Result<(), WriteFrameError> {
        let remote_endpoint_id = packet.src;
        let datagrams = packet.data;

        if let Ok(len) = datagrams.contents.len().try_into() {
            self.metrics.bytes_sent.inc_by(len);
        }
        // A circuit reply names the circuit and nothing else. Writing the
        // sender here instead would hand the client the one fact the circuit
        // exists to withhold, and would do it silently.
        let frame = match packet.circuit {
            Some(circuit) => RelayToClientMsg::CircuitDatagrams { circuit, datagrams },
            None => RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            },
        };
        self.write_frame(frame).await
    }

    async fn send_packet(&mut self, packet: Packet) -> Result<(), WriteFrameError> {
        trace!("send packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                self.metrics.send_packets_sent.inc();
                Ok(())
            }
            Err(err) => {
                self.metrics.send_packets_dropped.inc();
                Err(err)
            }
        }
    }

    /// Handles frame read results.
    async fn handle_frame(
        &mut self,
        maybe_frame: Option<Result<ClientToRelayMsg, RelayRecvError>>,
    ) -> Result<(), HandleFrameError> {
        trace!(?maybe_frame, "handle incoming frame");
        let frame = match maybe_frame {
            Some(frame) => frame?,
            None => return Err(e!(HandleFrameError::StreamTerminated)),
        };

        // Circuits are version three. A connection that agreed to speak an
        // older version and then sends these has said two things that cannot
        // both be true, and there is no way to tell it so: every answer this
        // relay could give is a frame that version does not know, and a frame a
        // peer cannot decode ends its connection rather than being refused. So
        // the connection ends here instead, which is what it would have got
        // from a relay built before circuits.
        if self.protocol_version < ProtocolVersion::V3 {
            if let ClientToRelayMsg::OpenCircuit { .. }
            | ClientToRelayMsg::CircuitDatagrams { .. }
            | ClientToRelayMsg::AskRelayKey { .. } = frame
            {
                warn!("circuit frames on a connection that agreed an older version");
                return Err(e!(HandleFrameError::UnexpectedFrameType));
            }
        }

        match frame {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst_key,
                datagrams,
            } => {
                let packet_len = datagrams.contents.len();
                if let Err(err @ ForwardPacketError { .. }) =
                    self.handle_frame_send_packet(dst_key, datagrams)
                {
                    warn!("failed to handle send packet frame: {err:#}");
                }
                self.metrics.bytes_recv.inc_by(packet_len as u64);
            }
            ClientToRelayMsg::AskRelayKey { url } => {
                self.handle_frame_ask_relay_key(url);
            }
            ClientToRelayMsg::OpenCircuit {
                circuit,
                sealed,
                inner,
            } => {
                if let Some(answer) = self.handle_frame_open_circuit(circuit, &sealed, &inner) {
                    self.write_frame(answer).await?;
                }
            }
            ClientToRelayMsg::CircuitDatagrams { circuit, datagrams } => {
                let packet_len = datagrams.contents.len();
                if let Some(refusal) = self.handle_frame_circuit_datagrams(circuit, datagrams) {
                    self.write_frame(refusal).await?;
                }
                self.metrics.bytes_recv.inc_by(packet_len as u64);
            }
            ClientToRelayMsg::Ping(data) => {
                self.metrics.got_ping.inc();
                // TODO: add rate limiter
                self.write_frame(RelayToClientMsg::Pong(data)).await?;
                self.metrics.sent_pong.inc();
            }
            ClientToRelayMsg::Pong(data) => {
                self.ping_tracker.pong_received(data);
            }
            ClientToRelayMsg::BindAlias { alias, signature } => {
                self.handle_bind_alias(alias, signature);
            }
        }
        Ok(())
    }

    /// Also answer to `alias` on this connection, if the caller can prove it
    /// holds that key.
    ///
    /// # What is verified, and what a failure does
    ///
    /// A signature by `alias` over this connection's key and the alias, in that
    /// order. Covering the connection's key is what stops a captured frame
    /// being replayed onto somebody else's connection to be handed that key's
    /// traffic.
    ///
    /// A bad signature, or a key already answered elsewhere, is logged and
    /// dropped. Not an error to the client and not a disconnection: telling a
    /// caller which of those it was is telling them who else is connected here.
    fn handle_bind_alias(&self, alias: EndpointId, signature: [u8; 64]) {
        let primary = self.guard.endpoint_id;
        let message = crate::protos::relay::alias_binding_message(&primary, &alias);

        let signature = Signature::from_bytes(&signature);
        if alias.verify(&message, &signature).is_err() {
            debug!(alias = %alias.fmt_short(), "alias signature did not verify");
            return;
        }

        if self.clients.register_alias(alias, primary) {
            debug!(
                alias = %alias.fmt_short(),
                primary = %primary.fmt_short(),
                "connection now answers to an alias"
            );
        }
    }

    /// Fetches another relay's circuit key on a caller's behalf.
    ///
    /// Answered off the read loop, like a chained open and for the same reason:
    /// it is a request to another machine, and waiting for it here would stop
    /// this connection carrying anything else.
    ///
    /// Every failure is the same answer, an empty key. A relay that told a
    /// caller why would be saying which addresses it is willing to reach.
    fn handle_frame_ask_relay_key(&mut self, url: Bytes) {
        let links = self.links.clone();
        let to_self = self.to_self.clone();
        tokio::task::spawn(async move {
            let key = match std::str::from_utf8(&url) {
                Ok(text) => links.fetch_circuit_key(text).await.unwrap_or_default(),
                // Not an address, so nothing to ask. Answered rather than
                // dropped: a request with no reply is a caller waiting for ever.
                Err(_) => String::new(),
            };
            let _ = to_self
                .send(RelayToClientMsg::RelayKey {
                    url,
                    key: Bytes::from(key),
                })
                .await;
        });
    }

    /// Opens a circuit, or says no in a way that tells the caller nothing.
    ///
    /// Every refusal is the same refusal. A descriptor sealed to a different
    /// relay, one whose hour has passed and one that is not a descriptor at all
    /// are answered identically, because answering them differently would let
    /// somebody hold a captured descriptor up to each relay in turn and learn
    /// which one it was for.
    fn handle_frame_open_circuit(
        &mut self,
        circuit: u32,
        sealed: &[u8],
        inner: &[u8],
    ) -> Option<RelayToClientMsg> {
        // The refusal names the circuit the requester asked for, so it can tell
        // which of its requests was turned down. `None` is not a refusal: it
        // means the answer is not known yet and will be written when it is.
        let refused = Some(RelayToClientMsg::CircuitClosed {
            circuit,
            reason: CIRCUIT_REFUSED,
        });

        // An id this connection is already using. Refused rather than taken
        // over: the circuit that holds it is somebody's live call.
        if self.circuits.contains_key(&circuit) {
            debug!("that circuit id is already in use on this connection");
            return refused;
        }

        // A relay given no opener refuses every circuit, which is what this
        // relay did before circuits existed.
        let Some(opener) = self.clients.circuit_opener() else {
            return refused;
        };
        if self.circuits.len() >= MAX_CIRCUITS_PER_CONNECTION {
            debug!("connection is holding all the circuits it may");
            return refused;
        }
        let Some(hop) = opener.open(sealed) else {
            return refused;
        };

        // Two ways of saying where the circuit goes, and they have to agree. A
        // descriptor naming a next relay with nothing to hand it, or a second
        // descriptor with no relay to hand it to, is a request whose two halves
        // were built by different beliefs. Refused rather than half served.
        let chain_to = match (hop.next_relay.clone(), inner.is_empty()) {
            (None, true) => None,
            (Some(url), false) => {
                if !self.links.can_chain() {
                    debug!("asked to chain, and this relay was not told it may");
                    return refused;
                }
                Some(url)
            }
            _ => {
                debug!("the descriptor and the frame disagree about whether this chains");
                return refused;
            }
        };

        // Only a circuit that ends here claims one.
        //
        // A return key is a name this relay answers on so that a reply
        // addressed to it comes back on the circuit. That is how the far end of
        // a chain works: the destination is an ordinary client and replies by
        // name. A hop that continues to another relay has no such thing. Its
        // replies arrive over the link, carrying a circuit number and no name
        // at all, and are routed by that number.
        //
        // Claiming one anyway was refused in the one case that matters: the
        // caller's own key is a name this relay already answers, because the
        // caller is connected to it, and `claim_return_key` refuses a name
        // somebody is really using. That check is right; asking it this
        // question was not.
        if chain_to.is_none()
            && !self.clients.claim_return_key(
                hop.return_key,
                self.guard.endpoint_id(),
                circuit,
                hop.destination,
            )
        {
            return refused;
        }

        let Some(url) = chain_to else {
            self.circuits.insert(
                circuit,
                Forward {
                    destination: hop.destination,
                    return_key: hop.return_key,
                    next: None,
                },
            );
            return Some(RelayToClientMsg::CircuitOpened { circuit });
        };

        // The circuit continues, which means a dial and a round trip. Doing
        // that here would stop this connection carrying anything else until the
        // far relay answered, so it is done off the read loop and the answer
        // arrives on the queue this connection's writer already reads.
        //
        // The entry goes in now rather than on success, so that a datagram sent
        // straight after the request is refused by name rather than forwarded
        // to a circuit that has not opened. It is taken out again if the far
        // relay says no.
        self.circuits.insert(
            circuit,
            Forward {
                destination: hop.destination,
                return_key: hop.return_key,
                next: Some(Continuation::Opening),
            },
        );

        let links = self.links.clone();
        let to_self = self.to_self.clone();
        let to_circuits = self.to_circuits.clone();
        let inner = Bytes::copy_from_slice(inner);
        tokio::task::spawn(async move {
            // `to_self` goes to the link, which is where replies on this
            // circuit will be written from. The outcome comes back on the other
            // channel, because it carries more than a frame can say: which link
            // holds the circuit, and what the far relay calls it.
            let event = match links.open_circuit(&url, inner, to_self, circuit).await {
                Some(far) => CircuitEvent::Opened { circuit, url, far },
                None => CircuitEvent::Refused { circuit },
            };
            let _ = to_circuits.send(event).await;
        });

        // Nothing yet. The answer is written when the far relay has given one,
        // and answering now with anything at all would be answering a question
        // that has not been asked yet.
        None
    }

    /// Forwards along an open circuit, presenting the return key as the sender.
    ///
    /// Returns the frame to answer with when the circuit is not one of this
    /// connection's, and nothing when it forwarded.
    fn handle_frame_circuit_datagrams(
        &mut self,
        circuit: u32,
        datagrams: Datagrams,
    ) -> Option<RelayToClientMsg> {
        // Looked up in this connection's own table, which is what makes a
        // circuit id a handle rather than a capability: an id from another
        // connection is simply not here, and needs no check to be refused.
        let Some(forward) = self.circuits.get(&circuit).cloned() else {
            return Some(RelayToClientMsg::CircuitClosed {
                circuit,
                reason: CIRCUIT_REFUSED,
            });
        };

        self.metrics.send_packets_recv.inc();
        match forward.next {
            // Ends here. The return key, not this connection's key: the
            // destination replies to what it sees, and what it must see is the
            // name the caller sealed in.
            None => {
                if let Err(err @ ForwardPacketError { .. }) = self.clients.send_packet(
                    forward.destination,
                    datagrams,
                    forward.return_key,
                    &self.metrics,
                ) {
                    warn!("failed to forward circuit datagrams: {err:#}");
                }
                None
            }
            // Asked for and not yet answered. Dropped rather than queued: a
            // datagram held for a circuit that may never open is a datagram
            // delivered late to somewhere nobody is waiting, and the caller
            // learns the circuit opened before it sends anything real.
            Some(Continuation::Opening) => {
                debug!("a datagram for a circuit that has not opened yet, dropped");
                None
            }
            Some(Continuation::Open { url, far }) => {
                self.links.carry(&url, far, datagrams);
                None
            }
        }
    }

    fn handle_frame_send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
    ) -> Result<(), ForwardPacketError> {
        self.metrics.send_packets_recv.inc();
        self.clients
            .send_packet(dst, data, self.guard.endpoint_id(), &self.metrics)?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum SendError {
    Full,
    Closed,
}

/// Error returned when forwarding a packet to a client fails.
///
/// This error occurs when the relay server cannot deliver a packet to its intended
/// recipient, typically due to the client's send queue being full or the client
/// disconnecting.
#[stack_error(derive, add_meta)]
#[error("failed to forward packet: {reason:?}")]
pub struct ForwardPacketError {
    reason: SendError,
}

/// Tracks how many unique endpoints have been seen during the last day.
#[derive(Debug)]
struct ClientCounter {
    clients: HashSet<EndpointId>,
    last_clear_date: Date,
}

impl Default for ClientCounter {
    fn default() -> Self {
        Self {
            clients: HashSet::new(),
            last_clear_date: OffsetDateTime::now_utc().date(),
        }
    }
}

impl ClientCounter {
    fn check_and_clear(&mut self) {
        let today = OffsetDateTime::now_utc().date();
        if today != self.last_clear_date {
            self.clients.clear();
            self.last_clear_date = today;
        }
    }

    /// Marks this endpoint as seen, returns whether it is new today or not.
    fn update(&mut self, client: EndpointId) -> bool {
        self.check_and_clear();
        self.clients.insert(client)
    }
}

#[cfg(test)]
mod tests {
    use rotelyx_transport_base::SecretKey;
    use rotelyx_error::{Result, StdResultExt, bail_any};
    use rotelyx_future::Stream;
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;
    use tracing::info;

    use super::*;
    use bytes::Bytes;
    use crate::protos::relay::SEALED_HOP_LEN;
    use crate::server::circuits::{CircuitHop, CircuitOpener, MAX_CIRCUITS_TOTAL};
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::Status, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_actor_basic() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (message_s, message_r) = mpsc::channel(10);
        let (events_s, events_r) = mpsc::channel(10);

        let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Conn::test(io_rw, Default::default());
        let stream = RelayedStream::test(io);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let actor = Actor {
            stream,
            timeout: Duration::from_secs(1),
            packet_send_queue: send_queue_r,
            message_send_queue: message_r,
            guard: OnDisconnectGuard::empty(endpoint_id),
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            metrics,
            to_self: message_s.clone(),
            links: clients.links(),
            protocol_version: ProtocolVersion::V3,
            to_circuits: events_s,
            circuit_events: events_r,
            circuits: HashMap::new(),
        };

        let done = CancellationToken::new();
        let io_done = done.clone();
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });

        // Write tests
        println!("-- write");
        let data = b"hello world!";

        // send packet
        println!("  send packet");
        let packet = Packet {
            src: endpoint_id,
            data: Datagrams::from(&data[..]),
            circuit: None,
        };
        send_queue_s
            .send(packet.clone())
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: endpoint_id,
                datagrams: data.to_vec().into()
            }
        );

        // send peer_gone
        println!("send peer gone");
        message_s
            .send(RelayToClientMsg::EndpointGone(endpoint_id))
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::EndpointGone, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(endpoint_id));

        // Read tests
        println!("--read");

        // send ping, expect pong
        let data = b"pingpong";
        io_rw.send(ClientToRelayMsg::Ping(*data)).await?;

        // recv pong
        println!(" recv pong");
        let frame = recv_frame(FrameType::Pong, &mut io_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Pong(*data));

        let target = SecretKey::from_bytes(&rng.random()).public();

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        io_rw
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: target,
                datagrams: Datagrams::from(data),
            })
            .await
            .std_context("send")?;

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// Opens exactly the descriptors this test hands it, and nothing else.
    ///
    /// The sealing has its own tests, in the crate that owns it. What is being
    /// tested here is the table: what the relay does once a descriptor has
    /// opened, and what it does when one has not. A real opener would make
    /// these tests slower and would not make them stronger.
    #[derive(Debug)]
    struct TestOpener {
        known: std::collections::HashMap<Vec<u8>, CircuitHop>,
    }

    impl CircuitOpener for TestOpener {
        fn open(&self, sealed: &[u8]) -> Option<CircuitHop> {
            self.known.get(sealed).cloned()
        }
    }

    /// An actor on a duplex, with the client end to drive it from.
    ///
    /// The two queue senders come back with it and have to be held: the actor
    /// treats either one closing as its handle being dropped and exits, which
    /// looks exactly like a test whose frames went nowhere.
    #[allow(clippy::type_complexity)]
    fn circuit_actor(
        endpoint_id: EndpointId,
        clients: &Clients,
    ) -> (
        Conn,
        CancellationToken,
        tokio::task::JoinHandle<()>,
        (mpsc::Sender<Packet>, mpsc::Sender<RelayToClientMsg>),
    ) {
        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (message_s, message_r) = mpsc::channel(10);
        let (events_s, events_r) = mpsc::channel(10);
        let (io, io_rw) = tokio::io::duplex(4096);
        let actor = Actor {
            stream: RelayedStream::test(io),
            timeout: Duration::from_secs(1),
            packet_send_queue: send_queue_r,
            message_send_queue: message_r,
            guard: OnDisconnectGuard::empty(endpoint_id),
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            metrics: Arc::new(Metrics::default()),
            to_self: message_s.clone(),
            links: clients.links(),
            protocol_version: ProtocolVersion::V3,
            to_circuits: events_s,
            circuit_events: events_r,
            circuits: HashMap::new(),
        };
        let done = CancellationToken::new();
        let io_done = done.clone();
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });
        (
            Conn::test(io_rw, Default::default()),
            done,
            handle,
            (send_queue_s, message_s),
        )
    }

    /// The whole of the exit half, with one relay: a circuit opens, carries a
    /// datagram, and the destination sees the return key as the sender.
    ///
    /// That last part is the one worth stating. If the destination saw the
    /// connection the datagram arrived on, then in a real chain it would see
    /// the first relay, every circuit through that relay would look alike, and
    /// its reply could not be matched back to one of them.
    #[tokio::test]
    #[traced_test]
    async fn a_circuit_opens_and_the_destination_sees_the_return_key() -> Result {
        let caller = SecretKey::from_bytes(&[1u8; 32]).public();
        let destination = SecretKey::from_bytes(&[2u8; 32]).public();
        let return_key = SecretKey::from_bytes(&[3u8; 32]).public();

        let sealed = vec![0xAAu8; SEALED_HOP_LEN];
        let opener = TestOpener {
            known: [(
                sealed.clone(),
                CircuitHop {
                    destination,
                    next_relay: None,
                    return_key,
                },
            )]
            .into_iter()
            .collect(),
        };
        let clients = Clients::with_circuit_opener(Arc::new(opener));
        let metrics = Arc::new(Metrics::default());

        // The destination is an ordinary connected client. It does not know it
        // is on a circuit and is never told.
        let (dst_builder, mut dst_rw) = test_client_builder(destination, ProtocolVersion::V2);
        clients.register(dst_builder, metrics.clone());

        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 1,
                sealed: Bytes::from(sealed),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayOpenedCircuit, &mut caller_rw).await?;
        let RelayToClientMsg::CircuitOpened { circuit } = frame else {
            panic!("expected the circuit to open, got {frame:?}");
        };

        let data = b"along the circuit";
        caller_rw
            .send(ClientToRelayMsg::CircuitDatagrams {
                circuit,
                datagrams: Datagrams::from(&data[..]),
            })
            .await?;

        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut dst_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: return_key,
                datagrams: data.to_vec().into(),
            },
            "the destination was shown the wrong sender"
        );

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// The reply comes back as a circuit frame, naming the circuit and nobody.
    #[tokio::test]
    #[traced_test]
    async fn a_reply_comes_back_on_the_circuit_and_names_nobody() -> Result {
        let caller = SecretKey::from_bytes(&[4u8; 32]).public();
        let destination = SecretKey::from_bytes(&[5u8; 32]).public();
        let return_key = SecretKey::from_bytes(&[6u8; 32]).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        // The caller speaks version three, because it is the end that receives
        // circuit frames. The destination below does not need to and is not
        // given it: the far end of a circuit is an ordinary client that never
        // learns it was on one.
        let (caller_builder, mut caller_rw) = test_client_builder(caller, ProtocolVersion::V3);
        clients.register(caller_builder, metrics.clone());

        assert!(
            clients.claim_return_key(return_key, caller, 9, destination),
            "the return key should have been free"
        );

        // The destination replies to the only name it ever saw.
        let data = b"back again";
        clients.send_packet(
            return_key,
            Datagrams::from(&data[..]),
            destination,
            &metrics,
        )?;

        let frame = recv_frame(FrameType::RelayToClientCircuitDatagram, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitDatagrams {
                circuit: 9,
                datagrams: data.to_vec().into(),
            },
            "the reply should name the circuit and not the sender"
        );
        Ok(())
    }

    /// A descriptor this relay cannot open is refused, and refused the same way
    /// whatever is wrong with it.
    #[tokio::test]
    #[traced_test]
    async fn a_descriptor_that_does_not_open_is_refused() -> Result {
        let caller = SecretKey::from_bytes(&[7u8; 32]).public();
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener {
            known: Default::default(),
        }));
        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        // Well formed as frames, so they reach the opener. A descriptor of the
        // wrong length never gets that far: the decoder refuses it, which is
        // the frame's own business and is tested with the frame.
        for fill in [0u8, 0xFF, 0x5A] {
            let sealed = vec![fill; SEALED_HOP_LEN];
            caller_rw
                .send(ClientToRelayMsg::OpenCircuit {
                    circuit: 2,
                    sealed: Bytes::from(sealed),
                    inner: Bytes::new(),
                })
                .await?;
            let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
            assert_eq!(
                frame,
                RelayToClientMsg::CircuitClosed {
                    circuit: 2,
                    reason: CIRCUIT_REFUSED,
                },
                "an unopenable descriptor should be refused, and told nothing \
                 beyond which request was refused"
            );
        }

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// An id this connection is already using is refused, not taken over.
    ///
    /// The requester picks the id, so a requester that picks badly must not be
    /// able to hand somebody else's live circuit a new destination.
    #[tokio::test]
    #[traced_test]
    async fn an_id_already_in_use_on_this_connection_is_refused() -> Result {
        let caller = SecretKey::from_bytes(&[31u8; 32]).public();
        let destination = SecretKey::from_bytes(&[32u8; 32]).public();
        let elsewhere = SecretKey::from_bytes(&[33u8; 32]).public();

        let first = vec![0x44u8; SEALED_HOP_LEN];
        let second = vec![0x55u8; SEALED_HOP_LEN];
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener {
            known: [
                (
                    first.clone(),
                    CircuitHop {
                        destination,
                        next_relay: None,
                        return_key: SecretKey::from_bytes(&[34u8; 32]).public(),
                    },
                ),
                (
                    second.clone(),
                    CircuitHop {
                        destination: elsewhere,
                        next_relay: None,
                        return_key: SecretKey::from_bytes(&[35u8; 32]).public(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }));
        let metrics = Arc::new(Metrics::default());
        let (dst_builder, mut dst_rw) = test_client_builder(destination, ProtocolVersion::V2);
        clients.register(dst_builder, metrics.clone());

        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 1,
                sealed: Bytes::from(first),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayOpenedCircuit, &mut caller_rw).await?;
        assert_eq!(frame, RelayToClientMsg::CircuitOpened { circuit: 1 });

        // The same id again, for somewhere else.
        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 1,
                sealed: Bytes::from(second),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit: 1,
                reason: CIRCUIT_REFUSED,
            },
            "a second circuit took an id that was already carrying one"
        );

        // And the circuit that held the id still goes where it always did.
        let data = b"still mine";
        caller_rw
            .send(ClientToRelayMsg::CircuitDatagrams {
                circuit: 1,
                datagrams: Datagrams::from(&data[..]),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut dst_rw).await?;
        let RelayToClientMsg::Datagrams { datagrams, .. } = frame else {
            panic!("expected the datagram to arrive at the first destination");
        };
        assert_eq!(datagrams.contents, &data[..], "the circuit was redirected");

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// A request whose two halves disagree about whether it chains is refused.
    ///
    /// The descriptor says where this hop ends; the frame either carries a
    /// second descriptor or does not. A descriptor naming a next relay with
    /// nothing to hand it, and a second descriptor with no relay to hand it to,
    /// are both requests built by two beliefs that were never the same. Serving
    /// half of either would open a circuit that goes somewhere nobody asked
    /// for.
    #[tokio::test]
    #[traced_test]
    async fn a_request_whose_halves_disagree_about_chaining_is_refused() -> Result {
        let caller = SecretKey::from_bytes(&[27u8; 32]).public();
        let destination = SecretKey::from_bytes(&[28u8; 32]).public();

        let chains = vec![0x11u8; SEALED_HOP_LEN];
        let terminates = vec![0x22u8; SEALED_HOP_LEN];
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener {
            known: [
                (
                    chains.clone(),
                    CircuitHop {
                        destination,
                        next_relay: Some("https://relay.example.invalid".to_owned()),
                        return_key: SecretKey::from_bytes(&[29u8; 32]).public(),
                    },
                ),
                (
                    terminates.clone(),
                    CircuitHop {
                        destination,
                        next_relay: None,
                        return_key: SecretKey::from_bytes(&[30u8; 32]).public(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }));
        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        for (sealed, inner, what) in [
            // Names a next relay, hands over nothing to give it.
            (chains.clone(), Bytes::new(), "a chain with no second layer"),
            // Ends here, and carries a layer for a relay that is not coming.
            (
                terminates,
                Bytes::from(vec![0x33u8; SEALED_HOP_LEN]),
                "a second layer with nowhere to go",
            ),
            // And the one that is well formed but not yet carried.
            (
                chains,
                Bytes::from(vec![0x33u8; SEALED_HOP_LEN]),
                "a chain this relay does not carry yet",
            ),
        ] {
            caller_rw
                .send(ClientToRelayMsg::OpenCircuit {
                    circuit: 3,
                    sealed: Bytes::from(sealed),
                    inner,
                })
                .await?;
            let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
            assert_eq!(
                frame,
                RelayToClientMsg::CircuitClosed {
                    circuit: 3,
                    reason: CIRCUIT_REFUSED,
                },
                "{what} was not refused"
            );
        }

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// A relay with no opener refuses circuits, which is what a relay did
    /// before circuits existed and remains the default.
    #[tokio::test]
    #[traced_test]
    async fn a_relay_that_was_given_no_opener_refuses_every_circuit() -> Result {
        let caller = SecretKey::from_bytes(&[8u8; 32]).public();
        let clients = Clients::default();
        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 4,
                sealed: Bytes::from(vec![0xAAu8; SEALED_HOP_LEN]),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit: 4,
                reason: CIRCUIT_REFUSED,
            }
        );

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// An id is a handle on the connection that was given it, never a name
    /// somebody else can use.
    ///
    /// This is the authorisation question for circuits, and the answer is
    /// structural: the table lives in the connection, so another connection's
    /// id is simply not there. The test is here so that a later author moving
    /// the table somewhere shared has to make it fail on purpose.
    #[tokio::test]
    #[traced_test]
    async fn a_circuit_id_from_one_connection_is_not_usable_from_another() -> Result {
        let one = SecretKey::from_bytes(&[10u8; 32]).public();
        let two = SecretKey::from_bytes(&[11u8; 32]).public();
        let destination = SecretKey::from_bytes(&[12u8; 32]).public();
        let return_key = SecretKey::from_bytes(&[13u8; 32]).public();

        let sealed = vec![0xBBu8; SEALED_HOP_LEN];
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener {
            known: [(
                sealed.clone(),
                CircuitHop {
                    destination,
                    next_relay: None,
                    return_key,
                },
            )]
            .into_iter()
            .collect(),
        }));
        let metrics = Arc::new(Metrics::default());
        let (dst_builder, mut dst_rw) = test_client_builder(destination, ProtocolVersion::V2);
        clients.register(dst_builder, metrics.clone());

        let (mut one_rw, one_done, one_handle, _one_queues) = circuit_actor(one, &clients);
        let (mut two_rw, two_done, two_handle, _two_queues) = circuit_actor(two, &clients);

        one_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 5,
                sealed: Bytes::from(sealed),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayOpenedCircuit, &mut one_rw).await?;
        let RelayToClientMsg::CircuitOpened { circuit } = frame else {
            panic!("expected the circuit to open, got {frame:?}");
        };

        // The second connection names the first one's circuit.
        two_rw
            .send(ClientToRelayMsg::CircuitDatagrams {
                circuit,
                datagrams: Datagrams::from(&b"not mine"[..]),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut two_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit,
                reason: CIRCUIT_REFUSED,
            },
            "a circuit id was usable from a connection that did not open it"
        );

        // And the destination heard nothing at all.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), dst_rw.next())
                .await
                .is_err(),
            "the datagram was forwarded for a connection that owned no circuit"
        );

        one_done.cancel();
        two_done.cancel();
        one_handle.await.std_context("join")?;
        two_handle.await.std_context("join")?;
        Ok(())
    }

    /// One connection cannot hold more circuits than its allowance.
    #[tokio::test]
    #[traced_test]
    async fn a_connection_cannot_hold_more_circuits_than_its_allowance() -> Result {
        let caller = SecretKey::from_bytes(&[14u8; 32]).public();
        let destination = SecretKey::from_bytes(&[15u8; 32]).public();

        // A descriptor per circuit, each with its own return key, because two
        // circuits may not share one.
        let mut known = std::collections::HashMap::new();
        for i in 0..=MAX_CIRCUITS_PER_CONNECTION {
            let sealed = vec![i as u8; SEALED_HOP_LEN];
            let mut key_bytes = [0u8; 32];
            key_bytes[0] = 0x40;
            key_bytes[1] = i as u8;
            known.insert(
                sealed,
                CircuitHop {
                    destination,
                    next_relay: None,
                    return_key: SecretKey::from_bytes(&key_bytes).public(),
                },
            );
        }
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener { known }));
        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);

        for i in 0..MAX_CIRCUITS_PER_CONNECTION {
            caller_rw
                .send(ClientToRelayMsg::OpenCircuit {
                    circuit: i as u32,
                    sealed: Bytes::from(vec![i as u8; SEALED_HOP_LEN]),
                    inner: Bytes::new(),
                })
                .await?;
            let frame = recv_frame(FrameType::RelayOpenedCircuit, &mut caller_rw).await?;
            assert!(
                matches!(frame, RelayToClientMsg::CircuitOpened { .. }),
                "circuit {i} of the allowance was refused: {frame:?}"
            );
        }

        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: MAX_CIRCUITS_PER_CONNECTION as u32,
                sealed: Bytes::from(vec![MAX_CIRCUITS_PER_CONNECTION as u8; SEALED_HOP_LEN]),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit: MAX_CIRCUITS_PER_CONNECTION as u32,
                reason: CIRCUIT_REFUSED,
            },
            "one connection was allowed past its circuit allowance"
        );

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// A circuit cannot take a name off somebody who is really here.
    #[tokio::test]
    #[traced_test]
    async fn a_return_key_that_is_already_a_name_here_is_refused() -> Result {
        let caller = SecretKey::from_bytes(&[16u8; 32]).public();
        let destination = SecretKey::from_bytes(&[17u8; 32]).public();
        let bystander = SecretKey::from_bytes(&[18u8; 32]).public();

        let sealed = vec![0xCCu8; SEALED_HOP_LEN];
        let clients = Clients::with_circuit_opener(Arc::new(TestOpener {
            known: [(
                sealed.clone(),
                CircuitHop {
                    destination,
                    next_relay: None,
                    // The name of somebody who is connected.
                    return_key: bystander,
                },
            )]
            .into_iter()
            .collect(),
        }));
        let metrics = Arc::new(Metrics::default());
        let (bystander_builder, _bystander_rw) =
            test_client_builder(bystander, ProtocolVersion::V2);
        clients.register(bystander_builder, metrics.clone());

        let (mut caller_rw, done, handle, _queues) = circuit_actor(caller, &clients);
        caller_rw
            .send(ClientToRelayMsg::OpenCircuit {
                circuit: 8,
                sealed: Bytes::from(sealed),
                inner: Bytes::new(),
            })
            .await?;
        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit: 8,
                reason: CIRCUIT_REFUSED,
            },
            "a circuit claimed a name a connected client answers to"
        );

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    /// When the destination goes, the circuit closes and says only which
    /// circuit.
    ///
    /// Not which endpoint. The connection at the other end of a circuit may be
    /// another relay, and telling it which endpoint has gone would hand it the
    /// destination, which is the one fact the chain exists to keep from it.
    #[tokio::test]
    #[traced_test]
    async fn the_destination_going_away_closes_the_circuit_without_naming_it() -> Result {
        let caller = SecretKey::from_bytes(&[23u8; 32]).public();
        let destination = SecretKey::from_bytes(&[24u8; 32]).public();
        let return_key = SecretKey::from_bytes(&[25u8; 32]).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let (caller_builder, mut caller_rw) = test_client_builder(caller, ProtocolVersion::V3);
        clients.register(caller_builder, metrics.clone());
        // Version two, and it stays that way: a destination is an ordinary
        // client and is never told it was the far end of a circuit.
        let (dst_builder, _dst_rw) = test_client_builder(destination, ProtocolVersion::V2);
        clients.register(dst_builder, metrics.clone());

        assert!(clients.claim_return_key(return_key, caller, 4, destination));

        assert!(
            clients.disconnect(destination, None),
            "the destination should have been connected"
        );

        let frame = recv_frame(FrameType::RelayClosedCircuit, &mut caller_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::CircuitClosed {
                circuit: 4,
                reason: CIRCUIT_FAR_END_GONE,
            },
            "the close should name the circuit and nothing else"
        );

        // And the name is free again, rather than held by a circuit that has
        // nowhere left to go.
        assert!(
            clients.claim_return_key(return_key, caller, 5, destination),
            "the return key was not released when its circuit closed"
        );
        Ok(())
    }

    /// The relay holds a bounded number of circuits across every connection.
    ///
    /// The per-connection allowance alone is not a bound: enough connections
    /// multiply it.
    #[test]
    fn the_relay_holds_a_bounded_number_of_circuits_in_total() {
        let clients = Clients::default();
        let destination = SecretKey::from_bytes(&[26u8; 32]).public();

        for i in 0..MAX_CIRCUITS_TOTAL {
            let mut owner_bytes = [0u8; 32];
            owner_bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut key_bytes = [1u8; 32];
            key_bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(
                clients.claim_return_key(
                    SecretKey::from_bytes(&key_bytes).public(),
                    SecretKey::from_bytes(&owner_bytes).public(),
                    i as u32,
                    destination,
                ),
                "circuit {i} was refused before the bound"
            );
        }

        let mut one_too_many = [2u8; 32];
        one_too_many[0] = 0xFF;
        assert!(
            !clients.claim_return_key(
                SecretKey::from_bytes(&one_too_many).public(),
                destination,
                0,
                destination,
            ),
            "the relay went past the total it will hold"
        );
    }

    /// Two circuits cannot answer on one return key.
    #[test]
    fn two_circuits_cannot_share_a_return_key() {
        let clients = Clients::default();
        let one = SecretKey::from_bytes(&[19u8; 32]).public();
        let two = SecretKey::from_bytes(&[20u8; 32]).public();
        let key = SecretKey::from_bytes(&[21u8; 32]).public();
        let destination = SecretKey::from_bytes(&[22u8; 32]).public();

        assert!(clients.claim_return_key(key, one, 1, destination));
        assert!(
            !clients.claim_return_key(key, two, 1, destination),
            "a second circuit took a return key that was already answered"
        );
    }

    fn test_client_builder(
        key: EndpointId,
        protocol_version: ProtocolVersion,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v1_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // Verify basic packet delivery works with V1.
        let data = b"hello world v1!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v2_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // Verify basic packet delivery works with V2.
        let data = b"hello world v2!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v1 client should receive V1Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v1_receives_v1health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone());

        // Register a second client with the same endpoint ID.
        // The first client should receive a V1Health message.
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V1);
        clients.register(builder_second, metrics.clone());

        let frame = recv_frame(FrameType::Health, &mut first_rw).await?;
        assert!(
            matches!(frame, RelayToClientMsg::Health { .. }),
            "expected V1Health frame for V1 client, got {frame:?}"
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v2 client should receive V2Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v2_receives_health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone());

        // Register a second client with the same endpoint ID.
        // The first client should receive a Health message (V2 frame).
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V2);
        clients.register(builder_second, metrics.clone());

        let frame = recv_frame(FrameType::Status, &mut first_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_rate_limit() -> Result {
        const LIMIT: u32 = 50;
        const MAX_FRAMES: u32 = 100;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // Build the rate limited stream.
        let (io_read, io_write) = tokio::io::duplex((LIMIT * MAX_FRAMES) as _);
        let mut frame_writer = Conn::test(io_write, Default::default());
        // Rate limiter allowing LIMIT bytes/s
        let mut stream = RelayedStream::test_limited(io_read, LIMIT / 10, LIMIT)?;

        // Prepare a frame to send, assert its size.
        let data = Datagrams::from(b"hello world!!!!!");
        let target = SecretKey::from_bytes(&rng.random()).public();
        let frame = ClientToRelayMsg::Datagrams {
            dst_endpoint_id: target,
            datagrams: data.clone(),
        };
        let frame_len = frame.to_bytes().len();
        assert_eq!(frame_len, LIMIT as usize);

        // Send a frame, it should arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        // Next frame does not arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let res = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(res.is_err(), "expecting a timeout");
        info!("-- timeout happened");

        // Wait long enough.
        info!("-- sleep");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Frame arrives.
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        Ok(())
    }
}
