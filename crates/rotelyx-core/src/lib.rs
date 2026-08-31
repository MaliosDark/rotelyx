//! # rotelyx-core
//!
//! Layers L0 and L1 of the Rotelyx stack: peer identity, the iroh transport
//! endpoint, and the framed wire format that sits inside a QUIC stream.
//!
//! ## What this crate is *not*
//!
//! This crate provides **transport** security only: QUIC + TLS 1.3, terminated
//! at the two endpoints. That protects against the network and against relay
//! operators. It does not provide forward secrecy across sessions, post-compromise
//! security, group keys, or asynchronous delivery.
//!
//! Message confidentiality is the job of `rotelyx-crypto` (L2, MLS + hybrid PQ),
//! and it is deliberately independent: no key material crosses between the two
//! layers, so breaking one does not break the other.
//!
//! Anything handed to [`Session::send`] must already be L2 ciphertext.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod access;
pub mod backup;
#[cfg(feature = "transport")]
pub mod endpoint;
pub mod identity;
pub mod sealed;
pub mod store;
pub mod wire;

pub use access::{
    epoch_at, estimated_cost, peer_identity, solve, verify_proof, AccessError, Admission,
    ContactProof, Gate, Invitation, ReachabilityPolicy, EPOCH_SECONDS,
};
#[cfg(feature = "transport")]
pub use endpoint::{RotelyxEndpoint, Session, ALPN};
pub use identity::{safety_number, Identity, RotelyxId};
pub use sealed::{is_sealed, SealError};
pub use store::{Paths, StoreError, StoredInvitation};
pub use wire::{Frame, FrameKind, WireError, MAX_FRAME_LEN, WIRE_VERSION};
