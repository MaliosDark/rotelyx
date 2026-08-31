//! Endpoint construction and sessions.
//!
//! This is the only module in the workspace that touches the underlying
//! transport directly. Everything above it goes through [`NetEndpoint`], which
//! is what makes the zero-foreign-infrastructure guarantee auditable: there is
//! one place to check.

use anyhow::{Context, Result};
use rotelyx_transport::endpoint::{presets, Connection, RecvStream, SendStream};
use rotelyx_transport::{
    Endpoint, EndpointAddr, EndpointId, NetReportConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
};

use crate::config::{NetConfig, RelayPolicy};
use crate::path::MetadataResistantSelector;

/// A bound transport endpoint. Cheap to clone.
#[derive(Debug, Clone)]
pub struct NetEndpoint {
    inner: Endpoint,
    config: NetConfig,
    /// The resolved relay mode this endpoint was actually bound with.
    ///
    /// Kept so the guard test can assert against what was handed to the
    /// transport rather than against what the config *said*. Those differ
    /// exactly when there is a bug worth catching.
    relay_mode: RelayMode,
}

impl NetEndpoint {
    /// Bind an endpoint.
    ///
    /// Uses `presets::Minimal`, which sets the TLS crypto provider and nothing
    /// else. The n0 preset, which registers a pkarr publisher, a pkarr
    /// resolver and a DNS lookup against `dns.iroh.link`, and loads Number 0's
    /// production relay map: is never constructed. Relays and lookup come from
    /// [`NetConfig`] alone.
    pub async fn bind(secret: SecretKey, config: NetConfig, alpn: &[u8]) -> Result<Self> {
        let relay_mode = match config.relays() {
            // Not `RelayMode::Default` and not `RelayMode::Staging`: both point
            // at infrastructure operated by Number 0.
            RelayPolicy::DirectOnly => RelayMode::Disabled,
            RelayPolicy::SelfHosted(urls) => {
                if urls.is_empty() {
                    RelayMode::Disabled
                } else {
                    RelayMode::Custom(RelayMap::from_iter(urls.iter().cloned()))
                }
            }
        };

        let inner = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(relay_mode.clone())
            // Rotelyx's objective function, not upstream's: any direct path beats
            // any relayed path regardless of latency. Without this the endpoint
            // silently falls back to the RTT-ordered default and `PathPolicy`
            // is decoration.
            .path_selector(MetadataResistantSelector::shared(config.paths()))
            // Address lookup is off by default on `Minimal`; clearing it again
            // is deliberate belt-and-braces, so that adding a preset later
            // cannot silently reintroduce a publisher.
            .clear_address_lookup()
            // No captive portal probe. See `net_report` at the end of this file.
            .net_report_config(net_report())
            .bind()
            .await
            .context("binding transport endpoint")?;

        Ok(Self {
            inner,
            config,
            relay_mode,
        })
    }

    /// Also accept connections addressed to `key`.
    ///
    /// One endpoint, several addresses, so that a contact reaching you does not
    /// tell anything carrying the traffic who you are. What it does not do is
    /// make that address findable: a relay has to route it here, which is a
    /// separate arrangement.
    /// Returns whether the endpoint is also *reachable* at that address, not
    /// only able to answer there. See [`rotelyx_transport::endpoint::Endpoint::also_answer_as`].
    #[must_use]
    pub fn also_answer_as(&self, key: &SecretKey) -> bool {
        self.inner.also_answer_as(key)
    }

    /// Carry traffic to `peer` through a circuit on the relay at `url`.
    ///
    /// One relay learns who is talking to whom, which is ADV-3 in the threat
    /// model and inherent to relayed transport. A circuit through two splits
    /// that: the first learns the caller and that a circuit was opened through
    /// the second; the second learns the destination and that traffic arrives
    /// from the first.
    ///
    /// # Why this takes bytes and does not seal them
    ///
    /// Sealing a descriptor is the message layer's hybrid construction, and
    /// this crate is L0/L1. It carries what it is given and reads none of it,
    /// which is the same rule the relay itself follows. `rotelyx-core` builds
    /// them from an invitation's `ExitRelay`.
    ///
    /// Returns whether the request was taken, not whether the circuit opened.
    /// **A relay that refuses one leaves traffic addressed to the peer**, so a
    /// caller whose whole reason for asking was the property has to check
    /// rather than assume.
    /// Asks the relay at `at` for the circuit key of the relay at `about`.
    ///
    /// # Why a caller asks one relay about another
    ///
    /// To seal a circuit to the exit relay a caller needs its key, and must not
    /// ask it: that would put the caller's address in front of the one party
    /// the chain exists to keep it from, before any circuit exists. So the
    /// caller's own relay asks. It learns which relay is being chained through,
    /// which it learns anyway the moment it forwards.
    ///
    /// **What comes back is not trusted.** The relay doing the asking could
    /// answer with a key of its own and read every circuit sealed to it. Check
    /// it with [`rotelyx_core::access::ExitRelay::accepts`] against the
    /// fingerprint the invitation carried, which is the whole reason that
    /// fingerprint exists.
    pub async fn fetch_relay_key(&self, at: RelayUrl, about: String) -> Option<Vec<u8>> {
        self.inner.fetch_relay_key(at, about).await
    }

    #[must_use]
    pub fn route_through_circuit(
        &self,
        url: RelayUrl,
        peer: EndpointId,
        sealed: bytes::Bytes,
        inner: bytes::Bytes,
    ) -> bool {
        self.inner.route_through_circuit(url, peer, sealed, inner)
    }

    /// Peers whose circuit is gone and needs a fresh descriptor.
    ///
    /// # Why a caller has to watch this
    ///
    /// A descriptor carries the hour it was sealed in and stops opening once
    /// that hour has passed. So a circuit that drops is rebuilt from the one
    /// already held, and one that has been down long enough is not. When that
    /// happens the peer's traffic is **dropped rather than sent addressed**,
    /// which keeps the property and stops the conversation.
    ///
    /// A caller that ignores this has a contact who silently went quiet. One
    /// that watches it seals a fresh descriptor and calls
    /// [`Self::route_through_circuit`] again, which is the fix.
    ///
    /// Empty is the ordinary case.
    pub fn circuits_needing_a_new_descriptor(&self) -> std::collections::BTreeSet<EndpointId> {
        self.inner.circuits_needing_a_new_descriptor()
    }

    /// Which of this endpoint's addresses answered `session`.
    ///
    /// The caller names an address in the TLS server name, and one it does not
    /// hold is answered by this endpoint's own key. This reports what was
    /// answered rather than what was asked, which is the only one of the two a
    /// hostile caller does not choose.
    pub fn answered_at(&self, session: &NetSession) -> EndpointId {
        self.answered_as(session.asked_for())
    }

    /// Which address answers a caller that asked for `wanted`.
    ///
    /// `None`, or a name this endpoint does not hold, is answered by the key it
    /// was bound with. Exposed so the rule can be tested for what it is: the
    /// point where a caller's claim stops being taken at face value.
    pub fn answered_as(&self, wanted: Option<EndpointId>) -> EndpointId {
        self.inner.answered_as(wanted)
    }

    pub fn id(&self) -> EndpointId {
        self.inner.id()
    }

    pub fn config(&self) -> &NetConfig {
        &self.config
    }

    /// This endpoint's dialable address, to be handed to a peer out of band.
    pub fn addr(&self) -> EndpointAddr {
        self.inner.addr()
    }

    /// The relays this endpoint will actually use.
    ///
    /// Resolved from the [`RelayMode`] the endpoint was bound with, so this is
    /// what the transport holds rather than what the config intended.
    pub fn active_relay_hosts(&self) -> Vec<String> {
        self.relay_mode
            .relay_map()
            .urls::<Vec<_>>()
            .iter()
            .filter_map(|u| u.host_str().map(str::to_owned))
            .collect()
    }

    pub async fn connect(&self, addr: impl Into<EndpointAddr>, alpn: &[u8]) -> Result<NetSession> {
        let addr: EndpointAddr = addr.into();
        let peer = addr.id;
        let conn = self
            .inner
            .connect(addr, alpn)
            .await
            .with_context(|| format!("connecting to {peer}"))?;
        let (send, recv) = conn.open_bi().await.context("opening bi stream")?;
        Ok(NetSession {
            peer,
            conn,
            send,
            recv,
        })
    }

    pub async fn accept(&self) -> Result<NetSession> {
        let incoming = self.inner.accept().await.context("endpoint closed")?;
        let conn = incoming.await.context("completing inbound handshake")?;
        // Authenticated during the QUIC handshake, so this is the real remote
        // key, not a self-asserted one.
        let peer = conn.remote_id();
        let (send, recv) = conn.accept_bi().await.context("accepting bi stream")?;
        Ok(NetSession {
            peer,
            conn,
            send,
            recv,
        })
    }

    /// Wait until a relay has registered this endpoint.
    ///
    /// # Why publishing an address is not enough
    ///
    /// An address naming a relay says where this endpoint *will* be reachable.
    /// It becomes true when the relay has completed its handshake and knows
    /// which connection belongs to this endpoint id, and not before. Between
    /// binding and that moment, an address is a promise: anybody dialling it
    /// through the relay is asking for somebody the relay has never heard of.
    ///
    /// That gap is small and it is exactly where a call lands. The address goes
    /// out in an answer, the far side dials immediately, and the dial fails
    /// while both ends believe they agreed on a call. So the address is not
    /// published until this has returned.
    ///
    /// Returns whether it came online inside `within`. False is not fatal on its
    /// own: the endpoint may still be reachable directly, and a caller that has
    /// nothing better to offer may publish anyway and say so.
    pub async fn online(&self, within: std::time::Duration) -> bool {
        tokio::time::timeout(within, self.inner.online())
            .await
            .is_ok()
    }

    /// Accept a connection without waiting for a stream on it.
    ///
    /// # Why this exists beside `accept`
    ///
    /// [`NetEndpoint::accept`] waits for a bidirectional stream, which is right
    /// for everything that talks in frames. It is wrong for anything that talks
    /// only in datagrams, and a call is exactly that: audio never touches a
    /// stream.
    ///
    /// The trap is that a stream is invisible until it carries a byte. A dialler
    /// that opens one and writes nothing has, as far as the peer is concerned,
    /// opened nothing, so `accept` waits forever while the dialler believes it
    /// is connected and starts sending audio into a call that was never
    /// answered. Both ends look connected and neither hears anything, which is
    /// what a real phone and a real desktop did.
    ///
    /// So a caller that only wants datagrams asks for this instead, and does not
    /// depend on the other side happening to write first.
    pub async fn accept_media(&self) -> Result<(EndpointId, Connection)> {
        let incoming = self.inner.accept().await.context("endpoint closed")?;
        let conn = incoming.await.context("completing inbound handshake")?;
        // Authenticated during the QUIC handshake, so this is the real remote
        // key rather than a self-asserted one.
        let peer = conn.remote_id();
        Ok((peer, conn))
    }

    /// Whether traffic to `peer` is currently on a direct path.
    ///
    /// Returns `None` when the peer is unknown. Surface this in the UI: a user
    /// deserves to know when a third party is carrying their session, even a
    /// blind one.
    pub async fn is_direct(&self, peer: EndpointId) -> Option<bool> {
        let info = self.inner.remote_info(peer).await?;
        let direct = info.addrs().any(|a| a.addr().is_ip());
        Some(direct)
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

/// An authenticated session with one peer.
///
/// The peer identity is established by the QUIC handshake before this value
/// exists, so [`NetSession::peer`] is trustworthy at the transport level. It
/// says nothing about whether the human behind that key is who you think,
/// that is what safety numbers are for.
#[derive(Debug)]
pub struct NetSession {
    peer: EndpointId,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl NetSession {
    pub fn peer(&self) -> EndpointId {
        self.peer
    }

    /// What the caller *asked* for in the TLS server name, if anything.
    ///
    /// Not to be trusted on its own: it is the caller's own word, and an
    /// unknown name is answered by this endpoint's built-in key anyway. Pass it
    /// to [`NetEndpoint::answered_at`] to find out which address really
    /// answered.
    pub fn asked_for(&self) -> Option<EndpointId> {
        self.conn.dialled_id()
    }

    pub fn send_stream(&mut self) -> &mut SendStream {
        &mut self.send
    }

    pub fn recv_stream(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    /// Split into owned halves so a read loop and a write loop can run as
    /// separate tasks.
    pub fn split(self) -> (SendStream, RecvStream, Connection) {
        (self.send, self.recv, self.conn)
    }

    /// Signal that no more data will be written, and wait for what was written
    /// to be delivered.
    ///
    /// **Not optional.** Dropping a QUIC send stream without finishing it
    /// resets the stream, and anything still in flight is discarded: the write
    /// appears to have succeeded and the peer never receives it. Call this
    /// before dropping a session whose last write matters.
    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().context("finishing send stream")?;
        self.send.stopped().await.ok();
        Ok(())
    }

    /// Finish the stream, then close the connection.
    ///
    /// Finishing first is what stops the close from truncating data the caller
    /// believes it already sent.
    pub async fn close(mut self) {
        let _ = self.finish().await;
        self.conn.close(0u32.into(), b"bye");
    }
}

/// What the endpoint is allowed to measure about the network it is on.
///
/// # The captive portal probe is off, and that is the whole reason this exists
///
/// Upstream's default runs one on the first report after an endpoint binds. It
/// picks a relay from the map, sends a **cleartext HTTP** `GET /generate_204`
/// to port 80 of that host, and reads the answer to decide whether a hotel wifi
/// is in the way.
///
/// Three things are wrong with that here.
///
/// **It names us in the clear.** The request carries a distinctive header, and
/// renaming that header from upstream's spelling to ours made it worse rather
/// than better: before, it blended into the traffic of a much larger project;
/// after, it announces which software this is to anyone on the path. A
/// messenger whose claim is metadata resistance should not open by saying its
/// own name unencrypted.
///
/// **It never worked.** The two halves of that exchange live in two crates and
/// the rename moved only one, so the answer never matched and every fresh
/// endpoint concluded it was behind a captive portal. That is fixed, and fixing
/// it is what made the point above visible.
///
/// **And it buys little.** Knowing about a captive portal makes the endpoint
/// retry relays more eagerly. Rotelyx already copes with a relay it cannot
/// reach.
///
/// `https_probes` stays on: it measures relay latency over a connection that is
/// encrypted and that the endpoint was going to open anyway.
fn net_report() -> NetReportConfig {
    // Built by mutation rather than as a struct expression, which the type's
    // `non_exhaustive` refuses across a crate boundary. That is also what keeps
    // this honest: a field added upstream arrives at its own default instead of
    // silently taking one from here.
    let mut config = NetReportConfig::default();
    config.captive_portal_check = false;
    config
}
