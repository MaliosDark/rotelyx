//! This module implements the send/recv relaying protocol.
//!
//! Protocol flow:
//!  * server occasionally sends [`FrameType::Ping`]
//!  * client responds to any [`FrameType::Ping`] with a [`FrameType::Pong`]
//!  * clients sends [`FrameType::ClientToRelayDatagram`] or [`FrameType::ClientToRelayDatagramBatch`]
//!  * server then sends [`FrameType::RelayToClientDatagram`] or [`FrameType::RelayToClientDatagramBatch`] to recipient
//!  * server sends [`FrameType::EndpointGone`] when the other client disconnects

use std::num::NonZeroU16;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rotelyx_transport_base::{EndpointId, KeyParsingError};
use rotelyx_error::{e, ensure, stack_error};
use rotelyx_future::time::Duration;

use super::common::{FrameType, FrameTypeError};
use crate::{KeyCache, http::ProtocolVersion};

/// The maximum size of a packet sent over relay.
/// (This only includes the data bytes visible to the socket, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

/// The maximum frame size.
///
/// This is also the minimum burst size that a rate-limiter has to accept.
#[cfg(not(wasm_browser))]
pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
#[cfg(feature = "server")]
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(15);

/// The number of packets buffered for sending per client
#[cfg(feature = "server")]
pub const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512;

/// Protocol send errors.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Error {
    #[error("unexpected frame: got {got:?}, expected {expected:?}")]
    UnexpectedFrame { got: FrameType, expected: FrameType },
    #[error("Frame is too large, has {frame_len} bytes")]
    FrameTooLarge { frame_len: usize },
    #[error(transparent)]
    FrameTypeError { source: FrameTypeError },
    #[error("Invalid public key")]
    InvalidPublicKey { source: KeyParsingError },
    #[error("Invalid frame encoding")]
    InvalidFrame {},
    #[error("Invalid frame type: {frame_type:?}")]
    InvalidFrameType { frame_type: FrameType },
    #[error("Invalid protocol message encoding")]
    InvalidProtocolMessageEncoding {
        #[error(std_err)]
        source: std::str::Utf8Error,
    },
    #[error("Received a frame not allowed in this protocol version.")]
    FrameNotAllowedInVersion,
    #[error("Too few bytes")]
    TooSmall {},
}

/// Bytes in a sealed circuit descriptor.
///
/// Owned by `rotelyx_crypto::circuit::SEALED_HOP_LEN` and repeated here rather
/// than imported: this is the vendored transport, and a dependency from it onto
/// the message-layer crypto would invert the layering the whole design rests
/// on. L0 must not know what L2 is.
///
/// Two constants that must agree is the shape of defect this project has spent
/// a day removing, so they are not left to agree by hope:
/// `rotelyx-relay/tests/circuit_frame.rs` fails the build if they drift, using
/// a dev-dependency that never reaches the shipped relay.
pub const SEALED_HOP_LEN: usize = 1328;

/// The messages that a relay sends to clients or the clients receive from the relay.
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
#[non_exhaustive]
pub enum RelayToClientMsg {
    /// Represents datagrams sent from relays (originally sent to them by another client).
    Datagrams {
        /// The [`EndpointId`] of the original sender.
        remote_endpoint_id: EndpointId,
        /// The datagrams and related metadata.
        datagrams: Datagrams,
    },
    /// A circuit asked for is open, under this id.
    CircuitOpened {
        /// Valid on this connection only.
        circuit: u32,
    },

    /// A circuit is finished.
    ///
    /// The reason is carried rather than left to be inferred: a circuit that
    /// stops without saying so is indistinguishable from a network gone quiet,
    /// and a failure shaped like an ordinary condition is the shape of defect
    /// this project has already spent a week finding once.
    CircuitClosed {
        /// The circuit that is over.
        circuit: u32,
        /// 0 expired, 1 the far end went, 2 refused, 3 the relay is going away.
        reason: u8,
    },

    /// Another relay's circuit key, or nothing if it could not be had.
    ///
    /// Carries the address it is about, so a caller with two asks in flight
    /// knows which is which without a second number to keep in step.
    RelayKey {
        /// The address this is about, at most 255 bytes.
        url: Bytes,
        /// The key, base64url as that relay publishes it. Empty means it could
        /// not be fetched, which covers a relay that does not chain, one that
        /// is unreachable, and one this relay will not dial.
        key: Bytes,
    },

    /// Datagrams arriving along a circuit. Carries no endpoint id.
    CircuitDatagrams {
        /// The circuit they arrived on.
        circuit: u32,
        /// The datagrams and related metadata.
        datagrams: Datagrams,
    },

    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the relay.
    EndpointGone(EndpointId),
    /// A one-way message from relay to client, declaring the connection health state.
    Status(Status),
    /// A one-way message from relay to client, advertising that the relay is restarting.
    Restarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the relay to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A relay should not send a `try_for` duration more
        /// than a few seconds.
        try_for: Duration,
    },
    /// Request from the relay to reply to the
    /// other side with a [`ClientToRelayMsg::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`ClientToRelayMsg::Ping`] from a client
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),

    // -- Deprecated variants --
    // We don't use `#[deprecated]` because this would throw warnings for the derived serde impls.
    /// Removed since relay-protocol-v2:
    /// A one-way message from relay to client, declaring the connection health state.
    ///
    /// Use [`Self::Status`] instead.
    Health {
        /// Description of why the connection is unhealthy.
        ///
        /// The default condition is healthy, so the relay doesn't broadcast a [`RelayToClientMsg::Health`]
        /// until a problem exists.
        problem: String,
    },
}

/// One-way message from server to client indicating issues with the relay connection.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[non_exhaustive]
pub enum Status {
    /// The connection is healthy and recovered from previous problems.
    #[display("The connection is healthy and has recovered from previous problems")]
    Healthy,
    /// Another endpoint connected with the same endpoint id. No more messages will be received.
    #[display(
        "Another endpoint connected with the same endpoint id. No more messages will be received."
    )]
    SameEndpointIdConnected,
    /// Placeholder for backwards-compatibility for future new health status variants.
    #[display("Unsupported health message ({_0})")]
    Unknown(u8),
}

impl Status {
    #[cfg(feature = "server")]
    fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        match self {
            Status::Healthy => dst.put_u8(0),
            Status::SameEndpointIdConnected => dst.put_u8(1),
            Status::Unknown(discriminant) => dst.put_u8(*discriminant),
        }
        dst
    }

    #[cfg(feature = "server")]
    fn encoded_len(&self) -> usize {
        1
    }

    fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        ensure!(!bytes.is_empty(), Error::InvalidFrame);
        let discriminant = bytes.get_u8();
        match discriminant {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::SameEndpointIdConnected),
            n => Ok(Self::Unknown(n)),
        }
    }
}

/// Messages that clients send to relays.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientToRelayMsg {
    /// Request from the client to the server to reply to the
    /// other side with a [`RelayToClientMsg::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`RelayToClientMsg::Ping`] from a server
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
    /// Request from the client to relay datagrams to given remote endpoint.
    Datagrams {
        /// The remote endpoint to relay to.
        dst_endpoint_id: EndpointId,
        /// The datagrams and related metadata to relay.
        datagrams: Datagrams,
    },
    /// Ask this connection to also answer to `alias`.
    ///
    /// # What the signature covers, and why it is that
    ///
    /// The key this connection authenticated with, then the alias. Both, in
    /// that order, under a domain separator.
    ///
    /// Covering the alias alone would let anybody who saw the frame replay it
    /// on their own connection and be handed that key's traffic. Covering the
    /// connection's key as well ties the request to one connection: replaying
    /// it elsewhere is verified against a different first half and fails.
    ///
    /// No challenge is needed for the same reason. Binding an alias requires
    /// the alias's private key **and** control of a connection authenticated as
    /// that primary, and the second of those is not something a captured frame
    /// confers.
    /// Open a circuit through this relay.
    ///
    /// Two layers, because a chain is two hops and each relay may read only its
    /// own. See `rotelyx_crypto::circuit`.
    OpenCircuit {
        /// The id this connection will use for the circuit, chosen by the
        /// connection that will use it.
        ///
        /// # Why the requester picks it and not the relay
        ///
        /// An id is a handle on one connection and means nothing anywhere else,
        /// so the party that will name it is the party that may as well choose
        /// it. Letting the relay choose looks natural and costs a correlation
        /// problem: `CircuitOpened` says which circuit opened but not which
        /// request it answers, so two opens in flight on one connection could
        /// not be told apart. The alternatives were serialising opens, which
        /// puts a network round trip between every circuit a busy relay pair
        /// builds, or adding a request id, which is a second number meaning
        /// almost the same as the first. Choosing here removes the problem
        /// instead of numbering it.
        ///
        /// A relay refuses an id this connection is already using.
        circuit: u32,
        /// A `SealedHop` for **this** relay, exactly `SEALED_HOP_LEN` bytes.
        ///
        /// Says where this hop ends and, when it ends at another relay, where
        /// that relay is.
        sealed: Bytes,
        /// The descriptor for the next relay, which this one carries and cannot
        /// read. Empty when the circuit ends here.
        ///
        /// Carried as its own field rather than riding as the circuit's first
        /// datagram: that would make the first relay work out that its
        /// destination is a relay and treat one payload unlike every other. A
        /// field says it outright.
        inner: Bytes,
    },

    /// Ask this relay to fetch another relay's circuit key.
    ///
    /// One byte of length, then the address. A relay that does not chain
    /// answers with an empty key rather than refusing, because whether a relay
    /// chains is not a secret and a refusal and a failure would look alike.
    AskRelayKey {
        /// The relay to ask about, at most 255 bytes.
        url: Bytes,
    },

    /// Datagrams along a circuit that is already open.
    ///
    /// Carries no endpoint id. That is what chaining buys: after setup, a
    /// relay holds a number and a direction, and the identities are in a table
    /// that only the relay which built the circuit can read.
    CircuitDatagrams {
        /// Valid on this connection only. A circuit id is a handle, never a
        /// capability: naming somebody else's does nothing.
        circuit: u32,
        /// The datagrams and related metadata.
        datagrams: Datagrams,
    },

    /// Ask this connection to also answer to `alias`.
    ///
    /// # What the signature covers, and why it is that
    ///
    /// The key this connection authenticated with, then the alias. Both, in
    /// that order, under a domain separator.
    ///
    /// Covering the alias alone would let anybody who saw the frame replay it
    /// on their own connection and be handed that key's traffic. Covering the
    /// connection's key as well ties the request to one connection: replaying
    /// it elsewhere is verified against a different first half and fails.
    ///
    /// No challenge is needed for the same reason. Binding an alias requires
    /// the alias's private key **and** control of a connection authenticated as
    /// that primary, and the second of those is not something a captured frame
    /// confers.
    BindAlias {
        /// The key to also answer to.
        alias: EndpointId,
        /// A signature by `alias` over the binding.
        signature: [u8; 64],
    },
}

/// Domain separation for [`ClientToRelayMsg::BindAlias`] signatures.
const DOMAIN_SEP_ALIAS: &str = "rotelyx relay alias binding v1";

/// What an alias signature is computed over.
///
/// Derived rather than signed raw, for the reason the handshake gives: signing
/// bytes an attacker chooses is a shape to avoid even when no attack is known.
pub fn alias_binding_message(primary: &EndpointId, alias: &EndpointId) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(primary.as_bytes());
    input[32..].copy_from_slice(alias.as_bytes());
    blake3::derive_key(DOMAIN_SEP_ALIAS, &input)
}

/// One or multiple datagrams being transferred via the relay.
///
/// This type is modeled after [`rotelyx_quic_proto::Transmit`]
/// (or even more similarly `rotelyx_quic_udp::Transmit`, but we don't depend on that library here).
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct Datagrams {
    /// Explicit congestion notification bits
    pub ecn: Option<rotelyx_quic_proto::EcnCodepoint>,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<NonZeroU16>,
    /// The contents of the datagram(s)
    #[debug(skip)]
    pub contents: Bytes,
}

impl<T: AsRef<[u8]>> From<T> for Datagrams {
    fn from(bytes: T) -> Self {
        Self {
            ecn: None,
            segment_size: None,
            contents: Bytes::copy_from_slice(bytes.as_ref()),
        }
    }
}

impl Datagrams {
    /// Splits the current datagram into at maximum `num_segments` segments, returning
    /// the batch with at most `num_segments` and leaving only the rest in `self`.
    ///
    /// Calling this on a datagram batch that only contains a single datagram (`segment_size == None`)
    /// will result in returning essentially a clone of `self`, while making `self` empty afterwards.
    ///
    /// Calling this on a datagram batch with e.g. 15 datagrams with `num_segments == 10` will
    /// result in returning a datagram batch that contains the first 10 datagrams and leave `self`
    /// containing the remaining 5 datagrams.
    ///
    /// Calling this on a datagram batch with less than `num_segments` datagrams will result in
    /// making `self` empty and returning essentially a clone of `self`.
    pub fn take_segments(&mut self, num_segments: usize) -> Datagrams {
        let Some(segment_size) = self.segment_size else {
            let contents = std::mem::take(&mut self.contents);
            return Datagrams {
                ecn: self.ecn,
                segment_size: None,
                contents,
            };
        };

        let usize_segment_size = usize::from(u16::from(segment_size));
        let max_content_len = num_segments * usize_segment_size;
        let contents = self
            .contents
            .split_to(std::cmp::min(max_content_len, self.contents.len()));

        let is_datagram_batch = num_segments > 1 && usize_segment_size < contents.len();

        // If this left our batch with only one more datagram, then remove the segment size
        // to uphold the invariant that single-datagram batches don't have a segment size set.
        if self.contents.len() <= usize_segment_size {
            self.segment_size = None;
        }

        Datagrams {
            ecn: self.ecn,
            segment_size: is_datagram_batch.then_some(segment_size),
            contents,
        }
    }

    fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        let ecn = self.ecn.map_or(0, |ecn| ecn as u8);
        dst.put_u8(ecn);
        if let Some(segment_size) = self.segment_size {
            dst.put_u16(segment_size.into());
        }
        dst.put(self.contents.as_ref());
        dst
    }

    fn encoded_len(&self) -> usize {
        1 // ECN byte
        + self.segment_size.map_or(0, |_| 2) // segment size, when None, then a packed representation is assumed
        + self.contents.len()
    }

    #[allow(clippy::len_zero, clippy::result_large_err)]
    fn from_bytes(mut bytes: Bytes, is_batch: bool) -> Result<Self, Error> {
        if is_batch {
            // 1 bytes ECN, 2 bytes segment size
            ensure!(bytes.len() >= 3, Error::InvalidFrame);
        } else {
            ensure!(bytes.len() >= 1, Error::InvalidFrame);
        }

        let ecn_byte = bytes.get_u8();
        let ecn = rotelyx_quic_proto::EcnCodepoint::from_bits(ecn_byte);

        let segment_size = if is_batch {
            let segment_size = bytes.get_u16(); // length checked above
            NonZeroU16::new(segment_size)
        } else {
            None
        };

        Ok(Self {
            ecn,
            segment_size,
            contents: bytes,
        })
    }
}

impl RelayToClientMsg {
    /// Returns this frame's corresponding frame type.
    pub fn typ(&self) -> FrameType {
        match self {
            Self::Datagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::RelayToClientDatagramBatch
                } else {
                    FrameType::RelayToClientDatagram
                }
            }
            Self::RelayKey { .. } => FrameType::RelayAnswersRelayKey,
            Self::CircuitOpened { .. } => FrameType::RelayOpenedCircuit,
            Self::CircuitClosed { .. } => FrameType::RelayClosedCircuit,
            Self::CircuitDatagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::RelayToClientCircuitDatagramBatch
                } else {
                    FrameType::RelayToClientCircuitDatagram
                }
            }
            Self::EndpointGone { .. } => FrameType::EndpointGone,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Status { .. } => FrameType::Status,
            Self::Restarting { .. } => FrameType::Restarting,
            Self::Health { .. } => FrameType::Health,
        }
    }

    #[cfg(feature = "server")]
    pub(crate) fn to_bytes(&self) -> BytesMut {
        self.write_to(BytesMut::with_capacity(self.encoded_len()))
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    #[cfg(feature = "server")]
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst = self.typ().write_to(dst);
        match self {
            Self::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                dst.put(remote_endpoint_id.as_ref());
                dst = datagrams.write_to(dst);
            }
            Self::EndpointGone(endpoint_id) => {
                dst.put(endpoint_id.as_ref());
            }
            Self::RelayKey { url, key } => {
                // One byte of length rather than a fixed field: an address is
                // short and this frame is sent once per contact, so padding
                // every one of them to the longest allowed costs more than the
                // byte that says how long this one is.
                dst.put_u8(url.len() as u8);
                dst.put(&url[..]);
                dst.put(&key[..]);
            }
            Self::CircuitOpened { circuit } => {
                dst.put(&circuit.to_be_bytes()[..]);
            }
            Self::CircuitClosed { circuit, reason } => {
                dst.put(&circuit.to_be_bytes()[..]);
                dst.put_u8(*reason);
            }
            Self::CircuitDatagrams { circuit, datagrams } => {
                dst.put(&circuit.to_be_bytes()[..]);
                dst = datagrams.write_to(dst);
            }
            Self::Ping(data) => {
                dst.put(&data[..]);
            }
            Self::Pong(data) => {
                dst.put(&data[..]);
            }
            Self::Health { problem } => {
                dst.put(problem.as_ref());
            }
            Self::Restarting {
                reconnect_in,
                try_for,
            } => {
                dst.put_u32(reconnect_in.as_millis() as u32);
                dst.put_u32(try_for.as_millis() as u32);
            }
            Self::Status(status) => {
                dst = status.write_to(dst);
            }
        }
        dst
    }

    #[cfg(feature = "server")]
    pub(crate) fn encoded_len(&self) -> usize {
        let payload_len = match self {
            Self::Datagrams { datagrams, .. } => {
                32 // endpointid
                + datagrams.encoded_len()
            }
            Self::EndpointGone(_) => 32,
            Self::RelayKey { url, key } => 1 + url.len() + key.len(),
            Self::CircuitOpened { .. } => 4,
            Self::CircuitClosed { .. } => 4 + 1,
            Self::CircuitDatagrams { datagrams, .. } => 4 + datagrams.encoded_len(),
            Self::Ping(_) | Self::Pong(_) => 8,
            Self::Status(status) => status.encoded_len(),
            Self::Restarting { .. } => {
                4 // u32
                + 4 // u32
            }
            Self::Health { problem } => problem.len(),
        };
        self.typ().encoded_len() + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    ///
    /// `protocol_version` is the negotiated protocol version for this connection.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_bytes(
        mut content: Bytes,
        cache: &KeyCache,
        protocol_version: ProtocolVersion,
    ) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        ensure!(
            frame_len <= MAX_PACKET_SIZE,
            Error::FrameTooLarge { frame_len }
        );

        let res = match frame_type {
            FrameType::RelayToClientDatagram | FrameType::RelayToClientDatagramBatch => {
                ensure!(content.len() >= EndpointId::LENGTH, Error::InvalidFrame);

                let remote_endpoint_id = cache.key_from_slice(&content[..EndpointId::LENGTH])?;
                let datagrams = Datagrams::from_bytes(
                    content.slice(EndpointId::LENGTH..),
                    frame_type == FrameType::RelayToClientDatagramBatch,
                )?;
                Self::Datagrams {
                    remote_endpoint_id,
                    datagrams,
                }
            }
            FrameType::EndpointGone => {
                ensure!(content.len() == EndpointId::LENGTH, Error::InvalidFrame);
                let endpoint_id = cache.key_from_slice(content.as_ref())?;
                Self::EndpointGone(endpoint_id)
            }
            FrameType::RelayAnswersRelayKey => {
                ensure!(
                    protocol_version >= ProtocolVersion::V3,
                    Error::FrameNotAllowedInVersion
                );
                ensure!(!content.is_empty(), Error::InvalidFrame);
                let url_len = content[0] as usize;
                ensure!(content.len() >= 1 + url_len, Error::InvalidFrame);
                let mut rest = content.split_off(1);
                let key = rest.split_off(url_len);
                Self::RelayKey { url: rest, key }
            }
            FrameType::RelayOpenedCircuit => {
                ensure!(
                    protocol_version >= ProtocolVersion::V3,
                    Error::FrameNotAllowedInVersion
                );
                // Exactly, not at least. A frame with room for more is a frame
                // somebody built by hand, and this is the shape the alias frame
                // already refuses for the same reason.
                ensure!(content.len() == 4, Error::InvalidFrame);
                Self::CircuitOpened {
                    circuit: u32::from_be_bytes(content[..4].try_into().expect("checked")),
                }
            }
            FrameType::RelayClosedCircuit => {
                ensure!(
                    protocol_version >= ProtocolVersion::V3,
                    Error::FrameNotAllowedInVersion
                );
                ensure!(content.len() == 5, Error::InvalidFrame);
                Self::CircuitClosed {
                    circuit: u32::from_be_bytes(content[..4].try_into().expect("checked")),
                    reason: content[4],
                }
            }
            FrameType::RelayToClientCircuitDatagram
            | FrameType::RelayToClientCircuitDatagramBatch => {
                ensure!(
                    protocol_version >= ProtocolVersion::V3,
                    Error::FrameNotAllowedInVersion
                );
                ensure!(content.len() >= 4, Error::InvalidFrame);
                let circuit = u32::from_be_bytes(content[..4].try_into().expect("checked"));
                let datagrams = Datagrams::from_bytes(
                    content.slice(4..),
                    frame_type == FrameType::RelayToClientCircuitDatagramBatch,
                )?;
                Self::CircuitDatagrams { circuit, datagrams }
            }
            FrameType::Ping => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            FrameType::Health => {
                ensure!(
                    protocol_version == ProtocolVersion::V1,
                    Error::FrameNotAllowedInVersion
                );
                let problem = std::str::from_utf8(&content)?.to_owned();
                Self::Health { problem }
            }
            FrameType::Restarting => {
                ensure!(content.len() == 4 + 4, Error::InvalidFrame);
                let reconnect_in = u32::from_be_bytes(
                    content[..4]
                        .try_into()
                        .map_err(|_| e!(Error::InvalidFrame))?,
                );
                let try_for = u32::from_be_bytes(
                    content[4..]
                        .try_into()
                        .map_err(|_| e!(Error::InvalidFrame))?,
                );
                let reconnect_in = Duration::from_millis(reconnect_in as u64);
                let try_for = Duration::from_millis(try_for as u64);
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            FrameType::Status => {
                ensure!(
                    protocol_version >= ProtocolVersion::V2,
                    Error::FrameNotAllowedInVersion
                );
                let status = Status::from_bytes(content)?;
                Self::Status(status)
            }
            _ => {
                return Err(e!(Error::InvalidFrameType { frame_type }));
            }
        };
        Ok(res)
    }
}

impl ClientToRelayMsg {
    /// Ask a connection to also answer to a key you hold.
    ///
    /// Takes the secret rather than a signature so that the binding cannot be
    /// computed over the wrong thing: sign the alias alone and a relay would
    /// accept the frame from anybody who copied it. `primary` is the key this
    /// connection authenticated with.
    pub fn bind_alias(alias: &rotelyx_transport_base::SecretKey, primary: &EndpointId) -> Self {
        let public = alias.public();
        Self::BindAlias {
            alias: public,
            signature: alias.sign(&alias_binding_message(primary, &public)).to_bytes(),
        }
    }

    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Self::BindAlias { .. } => FrameType::ClientBindsAlias,
            Self::AskRelayKey { .. } => FrameType::ClientAsksRelayKey,
            Self::OpenCircuit { .. } => FrameType::ClientOpensCircuit,
            Self::CircuitDatagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::ClientToRelayCircuitDatagramBatch
                } else {
                    FrameType::ClientToRelayCircuitDatagram
                }
            }
            Self::Datagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::ClientToRelayDatagramBatch
                } else {
                    FrameType::ClientToRelayDatagram
                }
            }
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
        }
    }

    pub(crate) fn to_bytes(&self) -> BytesMut {
        self.write_to(BytesMut::with_capacity(self.encoded_len()))
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst = self.typ().write_to(dst);
        match self {
            Self::Datagrams {
                dst_endpoint_id,
                datagrams,
            } => {
                dst.put(dst_endpoint_id.as_ref());
                dst = datagrams.write_to(dst);
            }
            Self::Ping(data) => {
                dst.put(&data[..]);
            }
            Self::Pong(data) => {
                dst.put(&data[..]);
            }
            Self::BindAlias { alias, signature } => {
                dst.put(alias.as_ref());
                dst.put(&signature[..]);
            }
            Self::AskRelayKey { url } => {
                dst.put_u8(url.len() as u8);
                dst.put(&url[..]);
            }
            Self::OpenCircuit {
                circuit,
                sealed,
                inner,
            } => {
                dst.put(&circuit.to_be_bytes()[..]);
                dst.put(&sealed[..]);
                dst.put(&inner[..]);
            }
            Self::CircuitDatagrams { circuit, datagrams } => {
                dst.put(&circuit.to_be_bytes()[..]);
                dst = datagrams.write_to(dst);
            }
        }
        dst
    }

    pub(crate) fn encoded_len(&self) -> usize {
        let payload_len = match self {
            Self::Ping(_) | Self::Pong(_) => 8,
            Self::BindAlias { .. } => 32 + 64,
            Self::AskRelayKey { url } => 1 + url.len(),
            Self::OpenCircuit { sealed, inner, .. } => 4 + sealed.len() + inner.len(),
            Self::CircuitDatagrams { datagrams, .. } => 4 + datagrams.encoded_len(),
            Self::Datagrams { datagrams, .. } => {
                32 // endpoint id
                + datagrams.encoded_len()
            }
        };
        self.typ().encoded_len() + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    #[cfg(feature = "server")]
    pub(crate) fn from_bytes(mut content: Bytes, cache: &KeyCache) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        ensure!(
            frame_len <= MAX_PACKET_SIZE,
            Error::FrameTooLarge { frame_len }
        );

        let res = match frame_type {
            FrameType::ClientToRelayDatagram | FrameType::ClientToRelayDatagramBatch => {
                ensure!(content.len() >= EndpointId::LENGTH, Error::InvalidFrame);

                let dst_endpoint_id = cache.key_from_slice(&content[..EndpointId::LENGTH])?;
                let datagrams = Datagrams::from_bytes(
                    content.slice(EndpointId::LENGTH..),
                    frame_type == FrameType::ClientToRelayDatagramBatch,
                )?;
                Self::Datagrams {
                    dst_endpoint_id,
                    datagrams,
                }
            }
            FrameType::Ping => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            FrameType::ClientAsksRelayKey => {
                ensure!(!content.is_empty(), Error::InvalidFrame);
                let url_len = content[0] as usize;
                // Exactly, not at least: a frame with room for more after the
                // address is a frame somebody built by hand.
                ensure!(content.len() == 1 + url_len, Error::InvalidFrame);
                Self::AskRelayKey {
                    url: content.split_off(1),
                }
            }
            FrameType::ClientOpensCircuit => {
                // One descriptor, or two. Both lengths are fixed by the
                // construction: anything else was not produced by
                // `SealedHop::seal`, and reading it would mean deciding what a
                // malformed one means.
                ensure!(
                    content.len() == 4 + SEALED_HOP_LEN
                        || content.len() == 4 + 2 * SEALED_HOP_LEN,
                    Error::InvalidFrame
                );
                let circuit = u32::from_be_bytes(content[..4].try_into().expect("checked"));
                let mut sealed = content.split_off(4);
                let inner = sealed.split_off(SEALED_HOP_LEN);
                Self::OpenCircuit {
                    circuit,
                    sealed,
                    inner,
                }
            }
            FrameType::ClientToRelayCircuitDatagram
            | FrameType::ClientToRelayCircuitDatagramBatch => {
                ensure!(content.len() >= 4, Error::InvalidFrame);
                let circuit = u32::from_be_bytes(content[..4].try_into().expect("checked"));
                let datagrams = Datagrams::from_bytes(
                    content.slice(4..),
                    frame_type == FrameType::ClientToRelayCircuitDatagramBatch,
                )?;
                Self::CircuitDatagrams { circuit, datagrams }
            }
            FrameType::ClientBindsAlias => {
                // Exactly, not at least: a frame with room for more is a frame
                // somebody built by hand.
                ensure!(content.len() == EndpointId::LENGTH + 64, Error::InvalidFrame);
                let alias = cache.key_from_slice(&content[..EndpointId::LENGTH])?;
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&content[EndpointId::LENGTH..]);
                Self::BindAlias { alias, signature }
            }
            _ => {
                return Err(e!(Error::InvalidFrameType { frame_type }));
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
#[cfg(feature = "server")]
mod tests {
    use data_encoding::HEXLOWER;
    use rotelyx_transport_base::SecretKey;
    use rotelyx_error::Result;

    use super::*;

    /// What the constructor builds is what the relay verifies.
    ///
    /// The two live in different places and a mismatch would be silent: every
    /// binding refused, and no way to tell that from a wrong key.
    #[test]
    fn the_constructor_agrees_with_the_verifier() {
        let alias_key = SecretKey::from_bytes(&[5u8; 32]);
        let primary = SecretKey::from_bytes(&[6u8; 32]).public();

        let ClientToRelayMsg::BindAlias { alias, signature } =
            ClientToRelayMsg::bind_alias(&alias_key, &primary)
        else {
            panic!("bind_alias built something else");
        };

        assert_eq!(alias, alias_key.public());
        assert!(
            alias
                .verify(
                    &alias_binding_message(&primary, &alias),
                    &rotelyx_transport_base::Signature::from_bytes(&signature),
                )
                .is_ok(),
            "the relay would refuse what the constructor produced"
        );
    }

    /// A captured alias binding cannot be replayed onto another connection.
    ///
    /// This is the property the whole frame rests on. Without it, anybody who
    /// saw the frame could present it on their own connection and be handed
    /// that key's traffic by the relay.
    #[test]
    fn an_alias_binding_does_not_transfer_to_another_connection() {
        let alias_key = SecretKey::from_bytes(&[7u8; 32]);
        let alias = alias_key.public();
        let mine = SecretKey::from_bytes(&[1u8; 32]).public();
        let theirs = SecretKey::from_bytes(&[2u8; 32]).public();

        let signature = alias_key.sign(&alias_binding_message(&mine, &alias));

        assert!(
            alias.verify(&alias_binding_message(&mine, &alias), &signature).is_ok(),
            "a binding did not verify on the connection it was made for"
        );
        assert!(
            alias.verify(&alias_binding_message(&theirs, &alias), &signature).is_err(),
            "a binding verified on somebody else's connection"
        );
    }

    /// The binding also names which key is being claimed, so one signature
    /// cannot be reused to claim a different one.
    #[test]
    fn an_alias_binding_names_the_key_being_claimed() {
        let alias_key = SecretKey::from_bytes(&[7u8; 32]);
        let alias = alias_key.public();
        let other = SecretKey::from_bytes(&[9u8; 32]).public();
        let primary = SecretKey::from_bytes(&[1u8; 32]).public();

        let signature = alias_key.sign(&alias_binding_message(&primary, &alias));
        assert!(
            alias.verify(&alias_binding_message(&primary, &other), &signature).is_err(),
            "a binding for one key verified for another"
        );
    }

    /// The frame survives its own encoding.
    #[test]
    fn a_bind_alias_frame_round_trips() {
        let alias_key = SecretKey::from_bytes(&[3u8; 32]);
        let alias = alias_key.public();
        let primary = SecretKey::from_bytes(&[4u8; 32]).public();
        let signature = alias_key.sign(&alias_binding_message(&primary, &alias)).to_bytes();

        let frame = ClientToRelayMsg::BindAlias { alias, signature };
        let bytes = frame.to_bytes().freeze();
        assert_eq!(bytes.len(), frame.encoded_len(), "encoded_len disagrees with to_bytes");

        let back = ClientToRelayMsg::from_bytes(bytes, &KeyCache::test()).expect("decode");
        assert_eq!(back, frame, "the frame did not survive the round trip");
    }

    /// A frame of the wrong length is refused rather than parsed.
    #[test]
    fn a_bind_alias_frame_of_the_wrong_length_is_refused() {
        for extra in [0usize, 1, 32, 63, 65, 128] {
            let mut body = FrameType::ClientBindsAlias.write_to(BytesMut::new());
            body.put_bytes(0x41, extra);
            assert!(
                ClientToRelayMsg::from_bytes(body.freeze(), &KeyCache::test()).is_err(),
                "accepted a body of {extra} bytes"
            );
        }
    }

    fn check_expected_bytes(frames: Vec<(Vec<u8>, &str)>) {
        for (bytes, expected_hex) in frames {
            let stripped: Vec<u8> = expected_hex
                .chars()
                .filter_map(|s| {
                    if s.is_ascii_whitespace() {
                        None
                    } else {
                        Some(s as u8)
                    }
                })
                .collect();
            let expected_bytes = HEXLOWER.decode(&stripped).unwrap();
            assert_eq!(HEXLOWER.encode(&bytes), HEXLOWER.encode(&expected_bytes));
        }
    }

    #[test]
    fn test_relay_client_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                RelayToClientMsg::Health {
                    problem: "Hello? Yes this is dog.".into(),
                }
                .write_to(Vec::new()),
                "0b 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (
                RelayToClientMsg::EndpointGone(client_key.public()).write_to(Vec::new()),
                "08 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61",
            ),
            (
                RelayToClientMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0a 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(rotelyx_quic::EcnCodepoint::Ce),
                        segment_size: NonZeroU16::new(6),
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // segment size
                // hello world contents bytes
                "07
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(rotelyx_quic::EcnCodepoint::Ce),
                        segment_size: None,
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // hello world contents bytes
                "06
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                RelayToClientMsg::Restarting {
                    reconnect_in: Duration::from_millis(10),
                    try_for: Duration::from_millis(20),
                }
                .write_to(Vec::new()),
                "0c 00 00 00 0a 00 00 00 14",
            ),
            (
                RelayToClientMsg::Status(Status::SameEndpointIdConnected).write_to(Vec::new()),
                "0d 01",
            ),
        ]);

        Ok(())
    }

    #[test]
    fn test_client_relay_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                ClientToRelayMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0a 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(rotelyx_quic::EcnCodepoint::Ce),
                        segment_size: NonZeroU16::new(6),
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // Segment size
                // hello world contents
                "05
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(rotelyx_quic::EcnCodepoint::Ce),
                        segment_size: None,
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // hello world contents
                "04
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
        ]);

        Ok(())
    }

    /// The circuit frames survive a trip through the wire and back.
    ///
    /// These are the only frames whose payload the relay never inspects, so a
    /// codec that quietly loses a field would not show up as a decode error.
    /// It would show up as a circuit that opens and carries nothing.
    #[test]
    fn the_circuit_frames_round_trip() {
        let sealed = Bytes::from(vec![0xABu8; SEALED_HOP_LEN]);

        let open = ClientToRelayMsg::OpenCircuit {
            circuit: 77,
            sealed: sealed.clone(),
            inner: Bytes::new(),
        };
        let encoded = open.write_to(Vec::new());
        assert_eq!(encoded.len(), open.encoded_len(), "OpenCircuit misreports its length");
        let ClientToRelayMsg::OpenCircuit {
            circuit: back_circuit,
            sealed: back,
            inner: back_inner,
        } =
            ClientToRelayMsg::from_bytes(Bytes::from(encoded), &KeyCache::test())
                .expect("OpenCircuit should decode")
        else {
            panic!("decoded as the wrong frame");
        };
        assert_eq!(back_circuit, 77, "the requested circuit id did not survive");
        assert_eq!(back, sealed, "the descriptor did not survive the trip");
        assert!(back_inner.is_empty(), "an inner layer appeared from nowhere");

        // And the two layer form, which is what a chain sends.
        let chained = ClientToRelayMsg::OpenCircuit {
            circuit: 5,
            sealed: sealed.clone(),
            inner: Bytes::from(vec![0xCDu8; SEALED_HOP_LEN]),
        };
        let encoded = chained.write_to(Vec::new());
        assert_eq!(
            encoded.len(),
            chained.encoded_len(),
            "a chained OpenCircuit misreports its length"
        );
        let ClientToRelayMsg::OpenCircuit {
            circuit: _,
            sealed,
            inner,
        } =
            ClientToRelayMsg::from_bytes(Bytes::from(encoded), &KeyCache::test())
                .expect("a chained OpenCircuit should decode")
        else {
            panic!("decoded as the wrong frame");
        };
        assert_eq!(sealed.len(), SEALED_HOP_LEN, "the outer layer changed size");
        assert_eq!(
            inner,
            Bytes::from(vec![0xCDu8; SEALED_HOP_LEN]),
            "the inner layer did not survive the trip"
        );

        // One and a half descriptors is not a request anybody built.
        let mut ragged = FrameType::ClientOpensCircuit.write_to(BytesMut::new());
        ragged.put_bytes(0xEE, 4 + SEALED_HOP_LEN + SEALED_HOP_LEN / 2);
        assert!(
            ClientToRelayMsg::from_bytes(ragged.freeze(), &KeyCache::test()).is_err(),
            "a descriptor and a half was accepted"
        );

        let carry = ClientToRelayMsg::CircuitDatagrams {
            circuit: 0xDEAD_BEEF,
            datagrams: Datagrams {
                ecn: Some(rotelyx_quic::EcnCodepoint::Ce),
                segment_size: NonZeroU16::new(6),
                contents: "Hello World!".into(),
            },
        };
        let encoded = carry.write_to(Vec::new());
        assert_eq!(encoded.len(), carry.encoded_len(), "CircuitDatagrams misreports its length");
        let ClientToRelayMsg::CircuitDatagrams { circuit, datagrams } =
            ClientToRelayMsg::from_bytes(Bytes::from(encoded), &KeyCache::test())
                .expect("CircuitDatagrams should decode")
        else {
            panic!("decoded as the wrong frame");
        };
        assert_eq!(circuit, 0xDEAD_BEEF, "the circuit number was lost");
        assert_eq!(datagrams.contents, "Hello World!", "the payload was lost");
        assert_eq!(datagrams.segment_size, NonZeroU16::new(6), "the segment size was lost");

        for msg in [
            RelayToClientMsg::CircuitOpened { circuit: 7 },
            RelayToClientMsg::CircuitClosed { circuit: 7, reason: 2 },
            RelayToClientMsg::CircuitDatagrams {
                circuit: 7,
                datagrams: Datagrams {
                    ecn: None,
                    segment_size: None,
                    contents: "back".into(),
                },
            },
        ] {
            let encoded = msg.write_to(Vec::new());
            assert_eq!(encoded.len(), msg.encoded_len(), "{msg:?} misreports its length");
            let back = RelayToClientMsg::from_bytes(
                Bytes::from(encoded),
                &KeyCache::test(),
                ProtocolVersion::V3,
            )
            .expect("should decode");
            assert_eq!(back.typ(), msg.typ(), "{msg:?} came back as a different frame");
        }
    }

    /// The key frames survive a trip through the wire and back.
    #[test]
    fn the_relay_key_frames_round_trip() {
        for url in ["", "h", "https://relay.example.invalid", &"h".repeat(255)] {
            let ask = ClientToRelayMsg::AskRelayKey {
                url: Bytes::from(url.to_owned()),
            };
            let encoded = ask.write_to(Vec::new());
            assert_eq!(encoded.len(), ask.encoded_len(), "AskRelayKey misreports its length");
            let ClientToRelayMsg::AskRelayKey { url: back } =
                ClientToRelayMsg::from_bytes(Bytes::from(encoded), &KeyCache::test())
                    .expect("AskRelayKey should decode")
            else {
                panic!("decoded as the wrong frame");
            };
            assert_eq!(back, Bytes::from(url.to_owned()), "the address was lost");

            for key in ["", "AAAA"] {
                let answer = RelayToClientMsg::RelayKey {
                    url: Bytes::from(url.to_owned()),
                    key: Bytes::from(key.to_owned()),
                };
                let encoded = answer.write_to(Vec::new());
                assert_eq!(
                    encoded.len(),
                    answer.encoded_len(),
                    "RelayKey misreports its length"
                );
                let back = RelayToClientMsg::from_bytes(
                    Bytes::from(encoded),
                    &KeyCache::test(),
                    ProtocolVersion::V3,
                )
                .expect("RelayKey should decode");
                assert_eq!(back, answer, "the answer did not survive the trip");
            }
        }
    }

    /// An address longer than the frame says is refused, not read past.
    ///
    /// The length byte comes from the network. A decoder that trusted it and
    /// sliced would panic on a frame somebody built by hand.
    #[test]
    fn a_key_frame_that_lies_about_its_length_is_refused() {
        for (len, extra) in [(200u8, 3usize), (255, 0), (1, 0), (5, 2)] {
            let mut wire = FrameType::ClientAsksRelayKey.write_to(BytesMut::new());
            wire.put_u8(len);
            wire.put_bytes(b'h', extra);
            assert!(
                ClientToRelayMsg::from_bytes(wire.freeze(), &KeyCache::test()).is_err(),
                "a frame claiming {len} bytes of address with {extra} was accepted"
            );

            let mut wire = FrameType::RelayAnswersRelayKey.write_to(BytesMut::new());
            wire.put_u8(len);
            wire.put_bytes(b'h', extra);
            let decoded =
                RelayToClientMsg::from_bytes(wire.freeze(), &KeyCache::test(), ProtocolVersion::V3);
            assert!(
                decoded.is_err(),
                "an answer claiming {len} bytes of address with {extra} was accepted"
            );
        }
    }

    /// A client that agreed version two refuses every circuit frame.
    ///
    /// This is what the version is for. A relay must never send these to a
    /// connection that did not agree to speak them, and the check is here so
    /// that a relay which does is caught by a decode failure rather than by a
    /// client that quietly stops working.
    #[test]
    fn a_connection_that_agreed_version_two_refuses_the_circuit_frames() {
        let frames = [
            RelayToClientMsg::CircuitOpened { circuit: 1 },
            RelayToClientMsg::CircuitClosed {
                circuit: 1,
                reason: 2,
            },
            RelayToClientMsg::CircuitDatagrams {
                circuit: 1,
                datagrams: Datagrams::from(&b"x"[..]),
            },
            RelayToClientMsg::RelayKey {
                url: Bytes::from_static(b"h"),
                key: Bytes::from_static(b"k"),
            },
        ];

        for frame in frames {
            let encoded = Bytes::from(frame.write_to(Vec::new()));

            let old = RelayToClientMsg::from_bytes(
                encoded.clone(),
                &KeyCache::test(),
                ProtocolVersion::V2,
            );
            assert!(
                matches!(old, Err(Error::FrameNotAllowedInVersion { .. })),
                "{frame:?} was accepted by a connection that agreed version two: {old:?}"
            );

            // And version three takes it, so what is being tested is the
            // version and not a frame that never decoded.
            assert!(
                RelayToClientMsg::from_bytes(encoded, &KeyCache::test(), ProtocolVersion::V3)
                    .is_ok(),
                "{frame:?} did not decode at version three either"
            );
        }
    }

    /// Version three is offered, and it is the newest.
    #[test]
    fn version_three_is_what_a_handshake_prefers() {
        assert_eq!(
            ProtocolVersion::ALL.first(),
            Some(&ProtocolVersion::V3),
            "the newest version is not offered first"
        );
        assert_eq!(
            ProtocolVersion::default(),
            ProtocolVersion::V3,
            "the default is not the newest version"
        );
        assert!(
            ProtocolVersion::V3 > ProtocolVersion::V2,
            "the ordering the version checks rely on is wrong"
        );
    }

    /// A relay that predates circuits refuses the frames by name.
    ///
    /// This is the property the whole staged rollout rests on. An unknown frame
    /// type must be an error, not something read as the nearest known frame: a
    /// `CircuitDatagrams` misread as `Datagrams` would send the payload to
    /// whatever endpoint id its first 32 bytes happened to spell.
    #[test]
    fn an_older_relay_refuses_the_circuit_frames_rather_than_misreading_them() {
        // This relay does know them, so they decode. The point of saying so
        // here is that the refusal below is about the frame type and not about
        // a frame that was malformed anyway.
        for (typ, body) in [
            (FrameType::ClientOpensCircuit, vec![0u8; 4 + SEALED_HOP_LEN]),
            (FrameType::ClientToRelayCircuitDatagram, vec![0u8; 4 + 8]),
        ] {
            let mut wire = typ.write_to(BytesMut::new());
            wire.extend_from_slice(&body);

            let decoded = ClientToRelayMsg::from_bytes(wire.freeze(), &KeyCache::test());
            assert!(
                decoded.is_ok(),
                "this relay knows {typ:?}, so it must decode it: {decoded:?}"
            );
        }

        // And the number that stands for "not a frame I know" is still refused,
        // which is what an older relay does with the numbers above.
        let mut unknown = BytesMut::new();
        unknown.put_u8(200);
        unknown.extend_from_slice(&[0u8; 64]);
        // Refused while reading the type, before any of it is interpreted:
        // `FrameTypeError`, not a decode of the nearest known frame. That is
        // what a relay built before circuits does with frames 15 through 21.
        let refused = ClientToRelayMsg::from_bytes(unknown.freeze(), &KeyCache::test());
        assert!(
            matches!(
                refused,
                Err(Error::FrameTypeError { .. }) | Err(Error::InvalidFrameType { .. })
            ),
            "a frame type this relay does not know must be refused by name, not \
             read as the nearest frame it does know: {refused:?}"
        );
    }

    /// A datagram frame must contain at least an EndpointId (32 bytes) after
    /// the frame type. A frame consisting only of the frame type byte used to
    /// panic when slicing the destination endpoint id.
    #[test]
    fn regression_client_to_relay_undersized_datagram_rejected() {
        for frame_type in [
            FrameType::ClientToRelayDatagram,
            FrameType::ClientToRelayDatagramBatch,
        ] {
            let encoded = frame_type.write_to(BytesMut::new()).freeze();
            let result = ClientToRelayMsg::from_bytes(encoded, &KeyCache::test());
            assert!(
                matches!(result, Err(Error::InvalidFrame { .. })),
                "expected InvalidFrame for {:?}, got {:?}",
                frame_type,
                result
            );
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod proptests {
    use rotelyx_transport_base::SecretKey;
    use proptest::{collection::vec, prelude::*};
    use test_strategy::proptest;

    use super::*;

    fn secret_key() -> impl Strategy<Value = SecretKey> {
        prop::array::uniform32(any::<u8>()).prop_map(SecretKey::from)
    }

    fn key() -> impl Strategy<Value = EndpointId> {
        secret_key().prop_map(|key| key.public())
    }

    fn ecn() -> impl Strategy<Value = Option<rotelyx_quic_proto::EcnCodepoint>> {
        (0..=3).prop_map(|n| match n {
            1 => Some(rotelyx_quic_proto::EcnCodepoint::Ce),
            2 => Some(rotelyx_quic_proto::EcnCodepoint::Ect0),
            3 => Some(rotelyx_quic_proto::EcnCodepoint::Ect1),
            _ => None,
        })
    }

    fn datagrams() -> impl Strategy<Value = Datagrams> {
        // The max payload size (conservatively, since with segment_size = 0 we'd have slightly more space)
        const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - EndpointId::LENGTH - 1 /* ECN bytes */ - 2 /* segment size */;
        (
            ecn(),
            prop::option::of(MAX_PAYLOAD_SIZE / 20..MAX_PAYLOAD_SIZE),
            vec(any::<u8>(), 0..MAX_PAYLOAD_SIZE),
        )
            .prop_map(|(ecn, segment_size, data)| Datagrams {
                ecn,
                segment_size: segment_size
                    .map(|ss| std::cmp::min(data.len(), ss) as u16)
                    .and_then(NonZeroU16::new),
                contents: Bytes::from(data),
            })
    }

    /// Generates a random valid frame
    fn relay_client_frame() -> impl Strategy<Value = RelayToClientMsg> {
        let recv_packet = (key(), datagrams()).prop_map(|(remote_endpoint_id, datagrams)| {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            }
        });
        let endpoint_gone = key().prop_map(RelayToClientMsg::EndpointGone);
        let ping = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Pong);
        let v1health = ".{0,65536}"
            .prop_filter("exceeds MAX_PACKET_SIZE", |s| {
                s.len() < MAX_PACKET_SIZE // a single unicode character can match a regex "." but take up multiple bytes
            })
            .prop_map(|problem| RelayToClientMsg::Health { problem });
        let health = Just(Status::SameEndpointIdConnected).prop_map(RelayToClientMsg::Status);
        let restarting = (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| {
            RelayToClientMsg::Restarting {
                reconnect_in: Duration::from_millis(reconnect_in.into()),
                try_for: Duration::from_millis(try_for.into()),
            }
        });
        prop_oneof![
            recv_packet,
            endpoint_gone,
            ping,
            pong,
            v1health,
            restarting,
            health
        ]
        .boxed()
    }

    fn client_relay_frame() -> impl Strategy<Value = ClientToRelayMsg> {
        let send_packet = (key(), datagrams()).prop_map(|(dst_endpoint_id, datagrams)| {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id,
                datagrams,
            }
        });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(ClientToRelayMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(ClientToRelayMsg::Pong);
        prop_oneof![send_packet, ping, pong]
    }

    /// The earliest protocol version in which `frame` is allowed.
    fn allowed_version(frame: &RelayToClientMsg) -> ProtocolVersion {
        match frame {
            RelayToClientMsg::Health { .. } => ProtocolVersion::V1,
            _ => ProtocolVersion::V2,
        }
    }

    #[test]
    fn v1health_rejected_in_v2() {
        let frame = RelayToClientMsg::Health {
            problem: "test".into(),
        };
        let encoded = frame.to_bytes().freeze();
        let result = RelayToClientMsg::from_bytes(encoded, &KeyCache::test(), ProtocolVersion::V2);
        assert!(matches!(
            result,
            Err(Error::FrameNotAllowedInVersion { .. })
        ));
    }

    #[test]
    fn status_rejected_in_v1() {
        let frame = RelayToClientMsg::Status(Status::SameEndpointIdConnected);
        let encoded = frame.to_bytes().freeze();
        let result = RelayToClientMsg::from_bytes(encoded, &KeyCache::test(), ProtocolVersion::V1);
        assert!(matches!(
            result,
            Err(Error::FrameNotAllowedInVersion { .. })
        ));
    }

    #[proptest]
    fn relay_client_frame_roundtrip(#[strategy(relay_client_frame())] frame: RelayToClientMsg) {
        let version = allowed_version(&frame);
        let encoded = frame.to_bytes().freeze();
        let decoded = RelayToClientMsg::from_bytes(encoded, &KeyCache::test(), version).unwrap();
        prop_assert_eq!(frame, decoded);
    }

    #[proptest]
    fn client_relay_frame_roundtrip(#[strategy(client_relay_frame())] frame: ClientToRelayMsg) {
        let encoded = frame.to_bytes().freeze();
        let decoded = ClientToRelayMsg::from_bytes(encoded, &KeyCache::test()).unwrap();
        prop_assert_eq!(frame, decoded);
    }

    #[proptest]
    fn relay_client_frame_encoded_len(#[strategy(relay_client_frame())] frame: RelayToClientMsg) {
        let claimed_encoded_len = frame.encoded_len();
        let actual_encoded_len = frame.to_bytes().len();
        prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
    }

    #[proptest]
    fn client_relay_frame_encoded_len(#[strategy(client_relay_frame())] frame: ClientToRelayMsg) {
        let claimed_encoded_len = frame.encoded_len();
        let actual_encoded_len = frame.to_bytes().len();
        prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
    }

    #[proptest]
    fn datagrams_encoded_len(#[strategy(datagrams())] datagrams: Datagrams) {
        let claimed_encoded_len = datagrams.encoded_len();
        let actual_encoded_len = datagrams.write_to(Vec::new()).len();
        prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
    }

    const MAX_TEST_MSG_SIZE: usize = 100_000;

    fn perturb_encoding(
        inner: impl Strategy<Value = BytesMut> + Clone + 'static,
    ) -> impl Strategy<Value = Bytes> + 'static {
        #[derive(Debug, test_strategy::Arbitrary)]
        enum GenStrategy {
            ArbitraryBytes,
            FlipBits,
            Truncate,
        }

        any::<GenStrategy>().prop_ind_flat_map(move |strategy| match strategy {
            GenStrategy::ArbitraryBytes => vec(any::<u8>(), 0..MAX_TEST_MSG_SIZE)
                .prop_map(Bytes::from)
                .boxed(),
            GenStrategy::FlipBits => (vec(any::<u16>(), 0..20), any::<u8>(), inner.clone())
                .prop_map(|(byte_positions, mask, mut bytes)| {
                    let len = bytes.len();
                    for pos in byte_positions {
                        bytes[(pos as usize).min(len.saturating_sub(1))] ^= mask;
                    }
                    bytes.freeze()
                })
                .boxed(),
            GenStrategy::Truncate => (vec(any::<u16>(), 0..20), inner.clone())
                .prop_map(|(mut truncations, mut bytes)| {
                    truncations.sort();
                    let mut bytes_truncated = 0;
                    for [trunc_start, trunc_end] in truncations.as_chunks::<2>().0 {
                        let len = bytes.len();
                        let start = usize::from(*trunc_start).saturating_sub(bytes_truncated);
                        let end = usize::from(*trunc_end).saturating_sub(bytes_truncated);
                        let rest = bytes.split_off(end.min(len));
                        bytes.truncate(start.min(len));
                        bytes.extend_from_slice(&rest);
                        bytes_truncated += end - start;
                    }
                    bytes.freeze()
                })
                .boxed(),
        })
    }

    #[proptest]
    fn client_relay_frame_decode_no_panic(
        #[strategy(perturb_encoding(client_relay_frame().boxed().prop_map(|msg| msg.to_bytes())))]
        bytes: Bytes,
    ) {
        let _ = ClientToRelayMsg::from_bytes(bytes, &KeyCache::test()); // only assert no panic
    }

    #[proptest]
    fn relay_client_frame_decode_no_panic(
        #[strategy(perturb_encoding(relay_client_frame().boxed().prop_map(|msg| msg.to_bytes())))]
        bytes: Bytes,
        version: ProtocolVersion,
    ) {
        let _ = RelayToClientMsg::from_bytes(bytes, &KeyCache::test(), version); // only assert no panic
    }
}
