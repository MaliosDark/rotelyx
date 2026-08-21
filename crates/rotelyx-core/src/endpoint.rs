//! The Rotelyx protocol session (L1 framing over the transport).
//!
//! Transport policy: relays, path selection, address lookup , lives in
//! `rotelyx-net` and is not configurable from here. This module is only
//! concerned with turning a transport session into a stream of Rotelyx frames.

use anyhow::{bail, Result};
use rotelyx_net::{EndpointAddr, NetConfig, NetEndpoint, NetSession, SecretKey};

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
    /// The transport key is the identity key, so the address this endpoint
    /// hands out **is** the identity, and so is what a relay sees. That is the
    /// behaviour every caller has today. [`bind_as`](Self::bind_as) is the one
    /// that separates them.
    ///
    /// The [`NetConfig`] must be stated explicitly: there is no default that
    /// could reach infrastructure we do not operate. Use
    /// [`NetConfig::direct_only`] for the maximum-privacy posture.
    pub async fn bind(identity: &Identity, config: NetConfig) -> Result<Self> {
        Self::bind_as(identity, identity.secret_key(), config).await
    }

    /// Bind under a transport key that is not this identity.
    ///
    /// # What this is for
    ///
    /// A relay carries traffic it cannot read, and still learns which endpoint
    /// talks to which, because the endpoint key is the identity key and never
    /// changes. That is the disclosure this project has recorded as inherent
    /// and it is only inherent while those two keys are the same key.
    ///
    /// Given a transport key of its own, an endpoint is reachable and the relay
    /// learns a value that means nothing beyond this session. The identity is
    /// still authenticated, inside, where an operator cannot see it.
    ///
    /// # Why the invitation still binds
    ///
    /// An invitation proof is a MAC over the caller's transport identity, so
    /// that a proof captured on the wire cannot be replayed by somebody else.
    /// That argument does not depend on the key being permanent: an attacker
    /// replaying a captured proof presents their own transport key, the MAC is
    /// over a different value, and it fails exactly as before.
    ///
    /// # What it does cost
    ///
    /// Blocking. A blocklist holds identities, and an identity that changes
    /// every session cannot be listed. The answer is not a longer list: it is
    /// that a contact reached under a key of their own is blocked by discarding
    /// that key, which is stronger, because a discarded key is not refused, it
    /// is unreachable. That is the next piece and it is not built yet.
    pub async fn bind_as(
        identity: &Identity,
        transport: SecretKey,
        config: NetConfig,
    ) -> Result<Self> {
        let net = NetEndpoint::bind(transport, config, ALPN).await?;
        Ok(Self {
            id: identity.id(),
            net,
        })
    }

    /// Also answer at another invitation's address on this endpoint.
    ///
    /// # Why one endpoint rather than one per invitation
    ///
    /// Answering several invitations otherwise means several endpoints: several
    /// sockets, several handshakes, and several connections to a relay, all for
    /// one person. This is the same endpoint proving it holds more than one
    /// key, which the transport picks between using the address the caller
    /// dialled.
    ///
    /// # Being found, as well as answering
    ///
    /// Those are two arrangements and this makes both: the relay is asked to
    /// route the address here, which it does only for a connection that proved
    /// it holds the key, and the TLS resolver is given the key so it can answer
    /// there. The relay half is kept in the relay's memory, so it is re-made on
    /// reconnect but not across a restart of this process: a caller that wants
    /// a key answered next time has to ask again.
    /// Returns `false` if the relay could not be asked, which leaves this
    /// endpoint able to answer at that address but not reachable there. Worth
    /// telling the user: it looks like a working setup until somebody calls.
    #[must_use]
    pub fn also_answer_as(&self, transport: &SecretKey) -> bool {
        self.net.also_answer_as(transport)
    }

    /// A transport key for one session, belonging to no identity.
    ///
    /// Generated from the OS entropy source and never written down. Pair it
    /// with [`bind_as`](Self::bind_as).
    pub fn ephemeral_transport_key() -> SecretKey {
        SecretKey::generate()
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
        let dialled = session.dialled();
        if let Err(e) = gate.admit(&session.peer(), &self.id, &evidence, current_epoch, dialled)
        {
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

    /// Which of this identity's addresses the caller dialled, if it said.
    ///
    /// An identity answering one invitation per address needs this to check
    /// that a caller's permission is for the address it actually used.
    pub fn dialled(&self) -> Option<RotelyxId> {
        self.net.dialled().map(RotelyxId::from)
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
