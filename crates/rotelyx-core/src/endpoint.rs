//! The Rotelyx protocol session (L1 framing over the transport).
//!
//! Transport policy: relays, path selection, address lookup , lives in
//! `rotelyx-net` and is not configurable from here. This module is only
//! concerned with turning a transport session into a stream of Rotelyx frames.

use anyhow::{bail, Result};
use rotelyx_net::{EndpointAddr, NetConfig, NetEndpoint, NetSession};

use crate::access::{Admission, Gate};
use crate::identity::{Identity, RotelyxId};
use crate::wire::{Frame, FrameKind, WireError};

/// ALPN for the Rotelyx control/chat protocol.
///
/// Versioned deliberately: a future incompatible wire format takes a new ALPN
/// rather than negotiating a version in band. There is no version field for an
/// attacker to strip, so there is no downgrade to negotiate.
pub const ALPN: &[u8] = b"rotelyx/chat/1";

/// A bound Rotelyx endpoint. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RotelyxEndpoint {
    net: NetEndpoint,
    id: RotelyxId,
}

impl RotelyxEndpoint {
    /// Bind an endpoint for this identity.
    ///
    /// The [`NetConfig`] must be stated explicitly: there is no default that
    /// could reach infrastructure we do not operate. Use
    /// [`NetConfig::direct_only`] for the maximum-privacy posture.
    pub async fn bind(identity: &Identity, config: NetConfig) -> Result<Self> {
        let net = NetEndpoint::bind(identity.secret_key(), config, ALPN).await?;
        Ok(Self {
            id: identity.id(),
            net,
        })
    }

    pub fn id(&self) -> RotelyxId {
        self.id
    }

    /// This endpoint's dialable address, to hand to a peer out of band.
    ///
    /// Address lookup is disabled by design, so this never reaches a directory
    /// server. Rendezvous belongs at L3, sealed, not at L0 as a public record.
    pub fn addr(&self) -> EndpointAddr {
        self.net.addr()
    }

    pub fn transport(&self) -> &NetEndpoint {
        &self.net
    }

    pub async fn connect(&self, addr: impl Into<EndpointAddr>) -> Result<Session> {
        let net = self.net.connect(addr, ALPN).await?;
        Ok(Session::new(net))
    }

    /// Dial a peer and present admission evidence as the first frame.
    pub async fn connect_with(
        &self,
        addr: impl Into<EndpointAddr>,
        evidence: &Admission,
    ) -> Result<Session> {
        let mut session = self.connect(addr).await?;
        session
            .send(&Frame::new(FrameKind::Admission, evidence.to_bytes()))
            .await?;
        Ok(session)
    }

    /// Wait for an inbound session, admitting it only if `gate` allows.
    ///
    /// The caller's first frame must be its admission evidence. Reading it
    /// before anything else means an unauthorised peer never reaches the MLS
    /// handshake, so it cannot make us do group-crypto work it was never
    /// entitled to ask for.
    ///
    /// `current_epoch` comes from the caller: see
    /// [`crate::access::epoch_at`], so this stays testable and clock skew is
    /// an explicit concern.
    pub async fn accept_with(&self, gate: &Gate, current_epoch: u64) -> Result<Session> {
        let net = self.net.accept().await?;
        let mut session = Session::new(net);

        let frame = session.recv().await?;
        if frame.kind != FrameKind::Admission {
            // Anything before admission is a protocol violation. Say nothing
            // useful about why: a detailed refusal is an oracle for what this
            // identity's policy is.
            session.close().await;
            bail!("peer sent {:?} before admission", frame.kind);
        }

        let evidence = Admission::from_bytes(&frame.payload)?;
        if let Err(e) = gate.admit(&session.peer(), &self.id, &evidence, current_epoch) {
            session.close().await;
            return Err(e.into());
        }

        Ok(session)
    }

    /// Accept without any admission control.
    ///
    /// Only for peers already authorised out of band, and for tests. A device
    /// exposed to the network should use [`RotelyxEndpoint::accept_with`].
    pub async fn accept(&self) -> Result<Session> {
        let net = self.net.accept().await?;
        Ok(Session::new(net))
    }

    /// Whether traffic to `peer` is on a direct path rather than through a
    /// relay. `None` if the peer is unknown.
    pub async fn is_direct(&self, peer: RotelyxId) -> Option<bool> {
        self.net.is_direct(peer.endpoint_id()).await
    }

    pub async fn close(&self) {
        self.net.close().await;
    }
}

/// An authenticated session with one peer, carrying framed L2 ciphertext.
///
/// Anything passed to [`Session::send`] must already be encrypted by L2. This
/// type provides transport confidentiality only.
#[derive(Debug)]
pub struct Session {
    peer: RotelyxId,
    net: NetSession,
}

impl Session {
    fn new(net: NetSession) -> Self {
        Self {
            peer: RotelyxId::from(net.peer()),
            net,
        }
    }

    pub fn peer(&self) -> RotelyxId {
        self.peer
    }

    pub async fn send(&mut self, frame: &Frame) -> Result<(), WireError> {
        frame.write(self.net.send_stream()).await
    }

    pub async fn recv(&mut self) -> Result<Frame, WireError> {
        Frame::read(self.net.recv_stream()).await
    }

    /// Split into owned halves so reading and writing can run concurrently.
    ///
    /// The caller becomes responsible for finishing the send half: see
    /// [`rotelyx_net::NetSession::finish`]. Dropping it instead resets the stream
    /// and discards anything still in flight.
    pub fn split_for_chat(
        self,
    ) -> (
        rotelyx_net::SendStream,
        rotelyx_net::RecvStream,
        rotelyx_net::Connection,
    ) {
        self.net.split()
    }

    /// Finish the send stream, then close.
    ///
    /// Async because finishing waits for delivery: dropping a QUIC send stream
    /// without finishing resets it and silently discards data the caller
    /// believes it already sent.
    pub async fn close(self) {
        self.net.close().await;
    }
}
