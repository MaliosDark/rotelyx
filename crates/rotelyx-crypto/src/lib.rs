//! # rotelyx-crypto
//!
//! Rotelyx's L2: message and group confidentiality.
//!
//! Two rules govern this crate, and they are the reason it looks boring:
//!
//! 1. **We do not write a ratchet.** Group and message crypto is MLS
//!    (RFC 9420) via OpenMLS. The failure modes of hand-written ratchets are
//!    not algebraic: they are nonce reuse under concurrency, state rollback
//!    after a backup restore, unbounded skipped-key retention, and replay
//!    across device re-registration. A specification does not prevent any of
//!    those; a widely reviewed implementation mostly does.
//!
//! 2. **We do not write a KEM combiner either.** Post-quantum protection comes
//!    from X-Wing (ML-KEM-768 + X25519), which is published, peer-reviewed and
//!    deployed. Its security argument is: secure if SHA3 is secure *and* either
//!    X25519 or ML-KEM-768 is secure.
//!
//! What *is* ours is how the two are joined: see [`hybrid`]. RFC 9420's
//! ciphersuites are all classical, so the post-quantum secret is mixed into the
//! MLS key schedule as an external pre-shared key rather than by forking MLS.
//! That composition is the one novel thing here, it is small on purpose, and it
//! is the specific item that must be independently reviewed before release.
//!
//! See `docs/THREAT-MODEL.md` §5 for the review gates.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod circuit;
pub mod group;
pub mod hybrid;

pub use circuit::{circuit_binding, Hop, SealedHop, SEALED_HOP_LEN};
pub use group::{
    deserialize_key_package, serialize_key_package, Conversation, GroupError, Member, MemberState,
    MembershipChange, Participant, Received, CIPHERSUITE,
};
pub use hybrid::{
    derive_psk, psk_binding, HybridCiphertext, HybridError, HybridKem, HybridPublicKey,
    HybridSecretKey, PqBinding, PqSecret, WrappedPqSecret, CIPHERTEXT_LEN, PUBLIC_KEY_LEN,
    SECRET_KEY_LEN, WRAPPED_SECRET_LEN,
};
