//! # rotelyx-mailbox
//!
//! Rotelyx's L3: blind store-and-forward for peers who are offline.
//!
//! When both peers are online, messages and calls go directly over the
//! transport and touch no server. This crate exists only for the case where the
//! recipient is not there, which, on phones, is most of the time.
//!
//! ## The design constraint
//!
//! The operator must learn as little as physically possible while still routing
//! a message. What it necessarily learns is: an envelope arrived, roughly when,
//! and which opaque tag it was addressed to. Everything else is removed by
//! construction:
//!
//! - **No sender field.** Nothing in an envelope identifies who deposited it.
//! - **No recipient identity.** Delivery is to a rotating tag derived from a
//!   secret only the two parties hold; without that secret, two tags for the
//!   same pair are indistinguishable from tags for different pairs.
//! - **No plaintext length.** Every payload is padded to one of five fixed
//!   buckets, and the real length is never written in the clear.
//! - **No content.** The payload is L2 ciphertext. This crate performs no
//!   encryption and holds no message key.
//!
//! ## What it does not solve
//!
//! Timing correlation between a deposit and a collection, and an operator that
//! simply retains everything. Deletion is enforced by this code, not by the
//! protocol: a hostile operator can keep copies and no client can tell.
//!
//! The mitigation is not technical: the mailbox is a single self-hostable
//! binary, so seizing any one operator compromises one community rather than a
//! population. See `docs/THREAT-MODEL.md` ADV-4 and ADV-5.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod envelope;
pub mod store;

pub use envelope::{Bucket, Envelope, EnvelopeError, Tag, TagKey};
pub use store::{Mailbox, StoreError, DEFAULT_TTL_SECONDS, MAX_PER_TAG};
