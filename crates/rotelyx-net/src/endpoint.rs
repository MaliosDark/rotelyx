//! Endpoint construction and sessions.
//!
//! This is the only module in the workspace that touches the underlying
//! transport directly. Everything above it goes through [`NetEndpoint`], which
//! is what makes the zero-foreign-infrastructure guarantee auditable: there is
//! one place to check.

use anyhow::{Context, Result};
use rotelyx_transport::endpoint::{presets, Connection, RecvStream, SendStream};
use rotelyx_transport::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey};

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

    /// Which of this endpoint's addresses the caller dialled, if it said.
    ///
    /// `None` on a session this endpoint opened, and on an accepted one whose
    /// caller sent no TLS server name.
    pub fn dialled(&self) -> Option<EndpointId> {
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
