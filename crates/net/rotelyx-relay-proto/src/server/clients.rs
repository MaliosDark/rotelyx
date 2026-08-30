//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use rotelyx_transport_base::EndpointId;
use rotelyx_future::IterExt;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::{
    ConnectionId, OnDisconnectGuard,
    circuits::{CircuitOpener, MAX_CIRCUITS_TOTAL, MaybeOpener, Return},
    links::{Links, MaybeDialer},
    client::{Client, Config, ForwardPacketError},
};
use crate::{
    protos::{
        relay::{Datagrams, Status},
        streams::BytesStreamSink,
    },
    server::{client::SendError, metrics::Metrics},
};

/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
#[derive(Debug, Clone, Default)]
pub struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    /// Additional keys a connection answers to, each pointing at the key it
    /// connected under.
    ///
    /// # Why a connection needs more than one key
    ///
    /// A key is one contact. A person reachable by ten people under ten keys
    /// would otherwise hold ten connections to this relay, each with its own
    /// socket, its own handshake and its own keepalive, which is a cost paid by
    /// every client for a property that costs the relay a map entry.
    ///
    /// # Why an alias rather than a second client
    ///
    /// A `Client` owns the handle that aborts its connection when dropped, so
    /// it cannot be duplicated: a copy going out of scope would kill the
    /// connection the original is still using. An alias is a name, not a
    /// connection, and resolving it reaches the one client that exists.
    ///
    /// Aliases are removed with the connection that registered them, so a name
    /// never outlives the thing it points at.
    aliases: DashMap<EndpointId, EndpointId>,
    /// Return keys, each pointing at the connection and circuit to answer on.
    ///
    /// The forward half of a circuit lives in the connection that opened it,
    /// where an id is a handle on that connection and can never be a name
    /// somebody else guesses. This half cannot: the destination replies to a
    /// key, and the key has to be findable from any connection, the way an
    /// alias is.
    ///
    /// It is resolved last, after real connections and after aliases, so a
    /// circuit can never shadow somebody who is actually here.
    returns: DashMap<EndpointId, Return>,
    /// Opens descriptors, when this relay has been given something that can.
    ///
    /// `None` refuses every circuit, which is what this relay did before
    /// circuits existed.
    opener: MaybeOpener,
    /// Links to other relays, for circuits that continue past this one.
    ///
    /// Held here because this is what every connection already reaches. It is
    /// safe to hold: a link keeps alive only the queues of the connections
    /// waiting on it, never this table, so nothing here keeps anything else
    /// alive in a circle.
    links: Links,
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    /// Shuts down all connected clients.
    ///
    /// This method gracefully disconnects all active client connections managed by
    /// this registry. It will wait for all clients to complete their shutdown before
    /// returning.
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        rotelyx_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    ///
    /// Once the client disconnects, the [`OnDisconnectGuard`] set in `config` will be dropped,
    /// allowing callers to be notified of the disconnect.
    pub fn register<S>(&self, client_config: Config<S>, metrics: Arc<Metrics>)
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.guard.endpoint_id;
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, self, metrics.clone());
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health(Status::SameEndpointIdConnected)
                    .ok();
                state.inactive.push(old_client);
                metrics.clients_inactive_added.inc();
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, guard: OnDisconnectGuard, metrics: &Metrics) {
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            %connection_id, "unregistering client"
        );

        let mut notify_peers = None;

        // Before the connection goes, so nothing can resolve through it in the
        // window between removal and cleanup.
        self.forget_aliases_of(endpoint_id);
        self.forget_circuits_of(endpoint_id);
        self.close_circuits_ending_at(endpoint_id);

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    metrics.clients_inactive_removed.inc();
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Inform the old client that it is healthy again.
                    state.active.try_send_health(Status::Healthy).ok();
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: collect sent_to set for peer-gone notifications.
                    notify_peers = self.0.sent_to.remove(&endpoint_id).map(|(_, peers)| peers);
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                metrics.clients_inactive_removed.inc();
                // Active client is unmodified: keep entry in map.
                false
            }
        });

        // Inform peers that this endpoint is gone.
        // Done outside the remove_if_mut closure to avoid DashMap deadlocks.
        if let Some(peers) = notify_peers {
            for peer_id in peers {
                if let Some(peer) = self.0.clients.get(&peer_id) {
                    match peer.active.try_send_peer_gone(endpoint_id) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "client too busy to receive peer gone notification, dropping"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "can no longer write to client, dropping peer gone notification"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Disconnects connections registered for `endpoint_id`.
    ///
    /// With `Some(connection_id)`, disconnects only that connection (active or
    /// an inactive duplicate). With `None`, disconnects every connection for the
    /// endpoint. Returns `true` if a matching connection was found, or `false`
    /// otherwise.
    ///
    /// Shutdown happens asynchronously: each per-connection actor exits its run
    /// loop and unregisters itself after this call returns.
    pub fn disconnect(&self, endpoint_id: EndpointId, connection_id: Option<ConnectionId>) -> bool {
        let Some(state) = self.0.clients.get(&endpoint_id) else {
            return false;
        };
        let mut clients = state.inactive.iter().chain([&state.active]);
        if let Some(id) = connection_id {
            let Some(client) = clients.find(|c| c.connection_id() == id) else {
                return false;
            };
            client.start_shutdown();
        } else {
            for client in clients {
                client.start_shutdown();
            }
        }
        true
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    /// Answer to another key on this connection.
    ///
    /// The caller has already proved possession of it: this is the bookkeeping,
    /// not the check. Registering a key some other connection is using is
    /// refused rather than stealing their traffic.
    pub(super) fn register_alias(&self, alias: EndpointId, primary: EndpointId) -> bool {
        if self.0.clients.contains_key(&alias) {
            debug!(
                alias = %alias.fmt_short(),
                "refusing an alias that is somebody's connection"
            );
            return false;
        }
        match self.0.aliases.entry(alias) {
            dashmap::Entry::Occupied(entry) if *entry.get() != primary => {
                debug!(alias = %alias.fmt_short(), "alias already answered by another connection");
                false
            }
            dashmap::Entry::Occupied(_) => true,
            dashmap::Entry::Vacant(entry) => {
                entry.insert(primary);
                true
            }
        }
    }

    /// Drop every name a connection answered to.
    ///
    /// Called when it goes, so an alias never outlives its connection and the
    /// next holder of that key is not handed somebody else's traffic.
    fn forget_aliases_of(&self, primary: EndpointId) {
        self.0.aliases.retain(|_alias, target| *target != primary);
    }

    /// Drops every return key answered by this connection.
    ///
    /// The forward half needs no cleanup: it lives in the connection's own
    /// actor and goes when that does. This half is a global name, and a name
    /// that outlived the connection answering it would route replies into
    /// nothing while stopping anybody else from claiming it.
    fn forget_circuits_of(&self, owner: EndpointId) {
        self.0.returns.retain(|_key, entry| entry.owner != owner);
    }

    /// The links this relay holds, for circuits that continue past it.
    pub(super) fn links(&self) -> Links {
        self.0.links.clone()
    }

    /// The opener this relay was built with, if any.
    pub(super) fn circuit_opener(&self) -> Option<&Arc<dyn CircuitOpener>> {
        self.0.opener.as_ref()
    }

    /// Claims a return key for a circuit.
    ///
    /// Refuses a key that is already answered, and a key that belongs to a
    /// connected client or an alias: a circuit must never be able to take a
    /// name off somebody who is really here. Refuses once the relay is holding
    /// as many circuits as it will.
    pub(super) fn claim_return_key(
        &self,
        key: EndpointId,
        owner: EndpointId,
        circuit: u32,
        destination: EndpointId,
    ) -> bool {
        if self.0.returns.len() >= MAX_CIRCUITS_TOTAL {
            debug!("circuit table full, refusing");
            return false;
        }
        if self.0.clients.contains_key(&key) || self.0.aliases.contains_key(&key) {
            debug!("return key is already a name here, refusing");
            return false;
        }
        match self.0.returns.entry(key) {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(entry) => {
                entry.insert(Return {
                    owner,
                    circuit,
                    destination,
                });
                true
            }
        }
    }

    /// Closes every circuit that ended at an endpoint which has just gone.
    ///
    /// The connection that opened the circuit is told by circuit id, not by
    /// endpoint id: it may be another relay, and naming the destination to it
    /// would undo the point of chaining. The key is released here, so the
    /// circuit stops holding a name nobody can answer.
    ///
    /// A scan rather than a reverse index. The table is bounded, this runs once
    /// per disconnect, and a second index is a second thing that can disagree
    /// with the first.
    fn close_circuits_ending_at(&self, destination: EndpointId) {
        let closing: Vec<(EndpointId, Return)> = self
            .0
            .returns
            .iter()
            .filter(|entry| entry.destination == destination)
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();

        for (key, entry) in closing {
            self.0.returns.remove(&key);
            if let Some(client) = self.0.clients.get(&entry.owner) {
                // Best effort, like the peer-gone notification beside it. A
                // client that misses this finds out when its next datagram on
                // that circuit is refused.
                let _ = client.active.try_send_circuit_closed(entry.circuit);
            }
        }
    }

    /// Builds a client table that can open circuits.
    ///
    /// Without this the table refuses them, which is the default and what every
    /// relay did before circuits.
    pub fn with_circuit_opener(opener: Arc<dyn CircuitOpener>) -> Self {
        Self(Arc::new(Inner {
            opener: Some(opener),
            ..Default::default()
        }))
    }

    /// A client table whose relay will also dial other relays.
    pub fn with_circuits(opener: Arc<dyn CircuitOpener>, dialer: MaybeDialer) -> Self {
        Self(Arc::new(Inner {
            opener: Some(opener),
            links: Links::new(dialer),
            ..Default::default()
        }))
    }

    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        metrics: &Metrics,
    ) -> Result<(), ForwardPacketError> {
        // A destination is either a key somebody connected under, a name one of
        // those connections also answers to, or the return key of a circuit.
        // Resolved in that order, so neither an alias nor a circuit can shadow
        // a real connection.
        let mut circuit = None;
        let dst = match self.0.clients.contains_key(&dst) {
            true => dst,
            false => match self.0.aliases.get(&dst) {
                Some(primary) => *primary,
                None => match self.0.returns.get(&dst) {
                    Some(entry) => {
                        // A reply on a circuit is written as a circuit frame,
                        // not as an addressed one. The connection that opened
                        // the circuit knows the id and never learns who sent
                        // this, which is the property the circuit is for.
                        circuit = Some(entry.circuit);
                        entry.owner
                    }
                    None => {
                        debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
                        metrics.send_packets_dropped.inc();
                        return Ok(());
                    }
                },
            },
        };

        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
            return Ok(());
        };
        // Circuit traffic is kept out of this bookkeeping, in both directions.
        // Its only purpose is the peer-gone notification, and that notification
        // names an endpoint: telling the connection at one end of a circuit
        // which endpoint at the other end has gone would hand it exactly the
        // fact the circuit exists to withhold. A circuit learns the far end is
        // gone from `CircuitClosed`, which names the circuit and nobody.
        let is_circuit = circuit.is_some() || self.0.returns.contains_key(&src);
        match client.active.try_send_packet(src, data, circuit) {
            Ok(_) => {
                if !is_circuit {
                    // Record sent_to relationship
                    self.0.sent_to.entry(src).or_default().insert(dst);
                }
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<ConnectionId> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rotelyx_transport_base::SecretKey;
    use rotelyx_error::{Result, StdResultExt};
    use rotelyx_future::{Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::RelayToClientMsg, streams::WsBytesFramed},
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
                    rotelyx_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => rotelyx_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    /// A connection answers to more than one key.
    ///
    /// # Why this exists
    ///
    /// A key is one contact. Somebody reachable by ten people under ten keys
    /// would otherwise hold ten connections here, and the property those ten
    /// keys buy costs this relay a map entry.
    #[tokio::test]
    #[traced_test]
    async fn a_connection_answers_to_an_alias() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7u64);
        let primary = SecretKey::from_bytes(&rng.random()).public();
        let alias = SecretKey::from_bytes(&rng.random()).public();
        let sender = SecretKey::from_bytes(&rng.random()).public();

        let (builder, mut rw) = test_client_builder(primary);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder, metrics.clone());

        assert!(clients.register_alias(alias, primary), "the alias was refused");

        // Addressed to the alias, delivered to the one connection there is.
        let data = b"for the alias";
        clients.send_packet(alias, Datagrams::from(&data[..]), sender, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: sender,
                datagrams: data.to_vec().into(),
            },
            "a packet for the alias did not reach the connection"
        );

        // And to the key it connected under, which the alias must not shadow.
        clients.send_packet(primary, Datagrams::from(&data[..]), sender, &metrics)?;
        recv_frame(FrameType::RelayToClientDatagram, &mut rw).await?;

        Ok(())
    }

    /// An alias cannot be taken over, and cannot shadow a real connection.
    ///
    /// Without this a relay hands one client another's traffic by asking for
    /// it, which is worse than not having aliases at all.
    #[tokio::test]
    #[traced_test]
    async fn an_alias_cannot_take_over_somebody_else() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11u64);
        let a = SecretKey::from_bytes(&rng.random()).public();
        let b = SecretKey::from_bytes(&rng.random()).public();
        let alias = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, _rw_a) = test_client_builder(a);
        let (builder_b, _rw_b) = test_client_builder(b);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());
        clients.register(builder_b, metrics.clone());

        assert!(clients.register_alias(alias, a), "the first claim was refused");
        assert!(
            !clients.register_alias(alias, b),
            "a second connection took over an alias already answered"
        );
        assert!(
            !clients.register_alias(b, a),
            "an alias shadowed a key somebody had connected under"
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // send packet
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.active.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone());
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone());
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        // send packet and verify it is send to a2
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));

        // a1 is marked active again and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::Healthy));

        // a1 should receive packets
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_peer_gone_notification() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // Register both clients
        let (builder_a, _a_rw) = test_client_builder(a_key);
        let (builder_b, mut b_rw) = test_client_builder(b_key);
        clients.register(builder_a, metrics.clone());
        clients.register(builder_b, metrics.clone());

        // A sends a packet to B (records sent_to[A] = {B})
        let data = b"hello b!";
        clients.send_packet(b_key, Datagrams::from(&data[..]), a_key, &metrics)?;

        // B receives the packet
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: data.to_vec().into(),
            }
        );

        // Disconnect A
        {
            let client = clients.0.clients.get(&a_key).unwrap();
            client.active.start_shutdown();
        }

        // Wait for A to unregister
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout waiting for A to unregister")?;

        // B should receive EndpointGone(a_key): notifying B that A is gone
        let frame = recv_frame(FrameType::EndpointGone, &mut b_rw).await?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(a_key));

        clients.shutdown().await;
        Ok(())
    }
}
