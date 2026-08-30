//! Common types between the [`super::handshake`] and [`super::relay`] protocols.
//!
//! Hosts the [`FrameType`] enum to make sure we're not accidentally reusing frame type
//! integers for different frames.

use bytes::{Buf, BufMut};
use rotelyx_error::{e, stack_error};
use rotelyx_quic_proto::{
    VarInt,
    coding::{Decodable, Encodable, UnexpectedEnd},
};

/// Possible frame types during handshaking
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, num_enum::IntoPrimitive, strum::FromRepr)]
// needs to be pub due to being exposed in error types
#[non_exhaustive]
pub enum FrameType {
    /// The server frame type for the challenge response
    ServerChallenge = 0,
    /// The client frame type for the authentication frame
    ClientAuth = 1,
    /// The server frame type for authentication confirmation
    ServerConfirmsAuth = 2,
    /// The server frame type for authentication denial
    ServerDeniesAuth = 3,
    /// 32B dest pub key + ECN bytes + one datagram's content
    ClientToRelayDatagram = 4,
    /// 32B dest pub key + ECN byte + segment size u16 + datagrams contents
    ClientToRelayDatagramBatch = 5,
    /// 32B src pub key + ECN bytes + one datagram's content
    RelayToClientDatagram = 6,
    /// 32B src pub key + ECN byte + segment size u16 + datagrams contents
    RelayToClientDatagramBatch = 7,
    /// Sent from server to client to signal that a previous sender is no longer connected.
    ///
    /// That is, if A sent to B, and then if A disconnects, the server sends `FrameType::PeerGone`
    /// to B so B can forget that a reverse path exists on that connection to get back to A
    ///
    /// 32B pub key of peer that's gone
    EndpointGone = 8,
    /// 8 byte ping payload, to be echoed back in a [`FrameType::Pong`].
    Ping = 9,
    /// 8 byte payload, the contents of ping being replied to
    Pong = 10,
    /// REMOVED since relay-protocol-v2, use `Self::Status` instead.
    ///
    /// Sent from server to client to tell the client if their connection is unhealthy somehow.
    /// Contains only UTF-8 bytes.
    Health = 11,

    /// Sent from server to client for the server to declare that it's restarting.
    /// Payload is two big endian u32 durations in milliseconds: when to reconnect,
    /// and how long to try total.
    Restarting = 12,

    /// Sent from server to client to declare the connection health state.
    ///
    /// Added in `rotelyx-relay-v2` protocol. May not be sent to `rotelyx-relay-v1` clients.
    ///
    /// Uses a binary-encoded [`Status`] payload.
    ///
    /// [`Status`]: super::relay::Status
    Status = 13,
    /// A client asking this connection to also answer to another key.
    ///
    /// 32B the key, then a 64B signature by it over the binding. See
    /// `ClientToRelayMsg::BindAlias`.
    ClientBindsAlias = 14,

    // ---- relay chaining ------------------------------------------------
    //
    // A relay learns which endpoint talks to which because the client says so
    // in `ClientToRelayDatagram`. Chaining two relays splits that. The design
    // is in `docs/RELAY-CHAINING.md` and the order of work in
    // `docs/RELAY-CHAINING-PLAN.md`.
    //
    // These are additions beside the existing frames rather than a change to
    // any of them: a relay that never receives one behaves exactly as it does
    // today, which is what lets this be built in pieces without a branch
    // nobody can ship.
    /// A client asking to open a circuit through this relay to another.
    ///
    /// The payload is a sealed descriptor this relay cannot read unless it is
    /// the exit: `rotelyx_crypto::circuit::SealedHop`, a fixed
    /// `SEALED_HOP_LEN` bytes.
    ClientOpensCircuit = 15,

    /// The relay answering that a circuit is open.
    ///
    /// 4B big-endian circuit id, valid on this connection only.
    RelayOpenedCircuit = 16,

    /// The relay saying a circuit is finished, and why.
    ///
    /// 4B big-endian circuit id, then 1B reason. Carrying a reason at all is
    /// deliberate: a circuit that closes silently is indistinguishable from a
    /// network that went quiet, and this project has already paid for one
    /// failure that looked like an ordinary condition.
    RelayClosedCircuit = 17,

    /// Datagrams along an open circuit, client to relay.
    ///
    /// 4B circuit id, then the datagrams. **No endpoint id**, which is the
    /// entire point: after setup, nothing on the wire names either end.
    ClientToRelayCircuitDatagram = 18,

    /// Datagrams along an open circuit, relay to client.
    ///
    /// 4B circuit id, then the datagrams.
    RelayToClientCircuitDatagram = 19,

    /// A batch of datagrams along an open circuit, client to relay.
    ///
    /// The batch form of frame 18, split off for the same reason
    /// `ClientToRelayDatagramBatch` is split off from
    /// `ClientToRelayDatagram`: the segment size is only on the wire when
    /// there is a segment size, and the frame type is what says so. One
    /// frame type for both forms would mean the decoder has to guess, and
    /// a decoder that guesses wrong here prepends two bytes of segment
    /// size to the payload instead of failing.
    ClientToRelayCircuitDatagramBatch = 20,

    /// A batch of datagrams along an open circuit, relay to client.
    RelayToClientCircuitDatagramBatch = 21,

    /// Ask this relay to fetch another relay's circuit key.
    ///
    /// # Why the asking goes through a relay
    ///
    /// To seal a circuit to the exit relay, a caller needs that relay's key.
    /// Asking the exit relay directly would put the caller's address in front
    /// of the one party the chain exists to keep it from, before any circuit
    /// exists. So the caller's own relay asks, which learns which relay is
    /// being chained through and learns that anyway the moment it forwards.
    ///
    /// The caller checks what comes back against a hash it was handed out of
    /// band, so a relay that answers with a key of its own choosing is caught.
    ClientAsksRelayKey = 22,

    /// The answer, naming which relay it is for.
    ///
    /// Named rather than numbered: the answer carries the address that was
    /// asked about, so two asks in flight are told apart without a second
    /// number meaning almost what the address means.
    RelayAnswersRelayKey = 23,
}

#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum FrameTypeError {
    #[error("not enough bytes to parse frame type")]
    UnexpectedEnd {
        #[error(std_err)]
        source: UnexpectedEnd,
    },
    #[error("frame type unknown")]
    UnknownFrameType { tag: VarInt },
}

impl FrameType {
    /// Writes the frame type to the buffer (as a QUIC-encoded varint).
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        VarInt::from(*self).encode(&mut dst);
        dst
    }

    /// Returns the amount of bytes that [`Self::write_to`] would write.
    pub(crate) fn encoded_len(&self) -> usize {
        // Copied implementation from `VarInt::size`
        let x: u32 = (*self).into();
        if x < 2u32.pow(6) {
            1 // this will pretty much always be the case
        } else if x < 2u32.pow(14) {
            2
        } else if x < 2u32.pow(30) {
            4
        } else {
            unreachable!("Impossible FrameType primitive representation")
        }
    }

    /// Parses the frame type (as a QUIC-encoded varint) from the first couple of bytes given
    /// and returns the frame type and the rest.
    pub(crate) fn from_bytes(buf: &mut impl Buf) -> Result<Self, FrameTypeError> {
        let tag = VarInt::decode(buf).map_err(|err| e!(FrameTypeError::UnexpectedEnd, err))?;
        let tag_u32 = u32::try_from(u64::from(tag))
            .map_err(|_| e!(FrameTypeError::UnknownFrameType { tag }))?;
        let frame_type = FrameType::from_repr(tag_u32)
            .ok_or_else(|| e!(FrameTypeError::UnknownFrameType { tag }))?;
        Ok(frame_type)
    }
}

impl From<FrameType> for VarInt {
    fn from(value: FrameType) -> Self {
        (value as u32).into()
    }
}
