//! Sealing the next hop of a relay circuit.
//!
//! # What this is for
//!
//! A relay carrying a session learns which endpoint is talking to which,
//! because the client tells it where to forward. Chaining two relays splits
//! that: the first learns who is sending, the second who is receiving, and
//! neither holds the pair. The design is in `docs/RELAY-CHAINING.md`, including
//! what it does **not** buy, which is anything at all against two operators who
//! collude.
//!
//! This module is the one piece of that which is ours and which can be reviewed
//! on its own: the sealed descriptor the first relay carries and cannot read.
//! It is written and specified before the protocol work, deliberately, because
//! the protocol work is in 13,605 lines vendored from somebody else and is the
//! expensive half.
//!
//! **Nothing calls this yet.** It is a construction with vectors, not a
//! feature, and it is said here rather than left for somebody to discover.
//!
//! # Why it is shaped like the group wrap
//!
//! Because that construction exists, is specified in `docs/PQ-COMPOSITION.md`
//! section 5b, and has been reviewed. A second sealing construction in the same
//! codebase would be a second thing to get right and a second thing to check.
//!
//! # Why hybrid, for a routing descriptor
//!
//! The obvious objection is that a circuit lives for minutes and post-quantum
//! protection is for decades. That is the wrong way round here. What this seals
//! is *who talked to whom*, and a recording of that is worth as much to somebody
//! in fifteen years as it is today: the harvest-now-decrypt-later argument the
//! message layer already makes, applied to the social graph rather than to
//! content.
//!
//! The cost is 1192 bytes, paid **once per circuit** rather than per datagram.
//! A per-packet seal at that size would be impossible fifty times a second, and
//! that is why the design carries an id afterwards rather than resealing.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::hybrid::{
    HybridCiphertext, HybridError, HybridPublicKey, HybridSecretKey, PqSecret, CIPHERTEXT_LEN,
};

/// Domain separator. Versioned: a change to the construction takes a new one
/// rather than reusing this, so an implementation of version 1 and one of
/// version 2 cannot silently agree on a key.
const CIRCUIT_CONTEXT: &str = "rotelyx relay circuit v1";
const CIRCUIT_LABEL: &[u8] = b"rotelyx relay circuit v1";

/// Bytes on the wire: the KEM ciphertext, the nonce, the sealed body, the tag.
///
/// The body is a 32 byte endpoint id and an 8 byte hour.
pub const SEALED_HOP_LEN: usize = CIRCUIT_LEN_KEM + 24 + 40 + 16;
const CIRCUIT_LEN_KEM: usize = CIRCUIT_KEM;
const CIRCUIT_KEM: usize = CIPHERTEXT_LEN;

/// What the first relay carries and cannot open.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedHop {
    kem: HybridCiphertext,
    nonce: [u8; 24],
    sealed: Vec<u8>,
}

impl core::fmt::Debug for SealedHop {
    /// Says the shape and never the bytes: the whole point of this type is that
    /// what is inside does not leak, and a `Debug` that printed it would put
    /// the destination in a log the first time somebody was diagnosing
    /// something else.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SealedHop({} bytes, opaque)", SEALED_HOP_LEN)
    }
}

/// What the exit relay reads out: where to forward, and when this stops being
/// valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    /// The endpoint this circuit ends at.
    pub destination: [u8; 32],
    /// Hours since the Unix epoch. Bound into the associated data as well, so a
    /// captured request cannot be replayed tomorrow to reopen a path.
    pub hour: u64,
}

/// The associated data both sides compute and neither transmits.
///
/// Every field is length-prefixed, for the reason section 6.1 of
/// `docs/PQ-COMPOSITION.md` gives about the other binding: without it, two
/// different splits of the same bytes produce the same input, and a binding
/// that is ambiguous is a binding that can be moved.
///
/// Public because it is part of the specification rather than an internal
/// detail: the sealing itself cannot be checked against a published vector,
/// since the nonce and the encapsulation are random, so what a reimplementation
/// can check is this and the key derivation. `psk_binding` is public for the
/// same reason.
pub fn circuit_binding(exit_id: &[u8; 32], hour: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CIRCUIT_LABEL.len() + 32 + 24);
    out.extend_from_slice(&(CIRCUIT_LABEL.len() as u64).to_be_bytes());
    out.extend_from_slice(CIRCUIT_LABEL);
    out.extend_from_slice(&(exit_id.len() as u64).to_be_bytes());
    out.extend_from_slice(exit_id);
    out.extend_from_slice(&hour.to_be_bytes());
    out
}

fn circuit_key(kem_secret: &PqSecret) -> Zeroizing<[u8; 32]> {
    crate::hybrid::derive_key(kem_secret, CIRCUIT_CONTEXT)
}

impl SealedHop {
    /// Seal the next hop to the exit relay.
    ///
    /// `exit_id` is the exit relay's endpoint id, bound into the associated
    /// data so a descriptor sealed for one relay cannot be handed to another:
    /// the encapsulation already ties it to that relay's key, and binding the
    /// id as well means the two cannot disagree.
    pub fn seal(
        exit_key: &HybridPublicKey,
        exit_id: &[u8; 32],
        hop: &Hop,
    ) -> Result<Self, HybridError> {
        let (kem, kem_secret) = exit_key.encapsulate();
        let key = circuit_key(&kem_secret);

        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| HybridError::Entropy)?;

        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&hop.destination);
        body.extend_from_slice(&hop.hour.to_be_bytes());

        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &body,
                    aad: &circuit_binding(exit_id, hop.hour),
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;

        Ok(Self { kem, nonce, sealed })
    }

    /// Read the next hop, as the exit relay.
    ///
    /// `now_hour` is the hour the relay believes it is. A descriptor for
    /// another hour is refused rather than accepted and logged: accepting it
    /// would make a captured request replayable, which is the thing the hour is
    /// bound in to prevent.
    ///
    /// One hour of slack in each direction, for the same reason the mailbox
    /// tags carry a lookback: two machines disagree about the time, and refusing
    /// a circuit over a clock skew is an outage rather than a defence.
    pub fn open(
        &self,
        exit_secret: &HybridSecretKey,
        exit_id: &[u8; 32],
        now_hour: u64,
    ) -> Result<Hop, HybridError> {
        let kem_secret = exit_secret.decapsulate(&self.kem);
        let key = circuit_key(&kem_secret);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;

        // The hour is in the associated data, so the right one has to be
        // guessed before anything opens. Try the window rather than trusting a
        // value from inside a message nobody has authenticated yet.
        for hour in [now_hour, now_hour.wrapping_sub(1), now_hour.wrapping_add(1)] {
            let Ok(body) = cipher.decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.sealed,
                    aad: &circuit_binding(exit_id, hour),
                },
            ) else {
                continue;
            };

            if body.len() != 40 {
                return Err(HybridError::BadCiphertext);
            }
            let mut destination = [0u8; 32];
            destination.copy_from_slice(&body[..32]);
            let mut h = [0u8; 8];
            h.copy_from_slice(&body[32..40]);
            let inner = u64::from_be_bytes(h);

            // The hour appears twice, and both must agree. Sealing it only in
            // the associated data would leave the body's copy unchecked, and a
            // reader that trusted the body would be reading a number the
            // authentication never covered.
            if inner != hour {
                return Err(HybridError::BadCiphertext);
            }
            return Ok(Hop { destination, hour });
        }

        Err(HybridError::BadCiphertext)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_HOP_LEN);
        out.extend_from_slice(&self.kem.to_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != SEALED_HOP_LEN {
            return Err(HybridError::BadCiphertext);
        }
        let kem = HybridCiphertext::from_bytes(&bytes[..CIPHERTEXT_LEN])?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[CIPHERTEXT_LEN..CIPHERTEXT_LEN + 24]);
        Ok(Self {
            kem,
            nonce,
            sealed: bytes[CIPHERTEXT_LEN + 24..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKem;

    fn relay() -> (HybridSecretKey, HybridPublicKey, [u8; 32]) {
        let (sk, pk) = HybridKem::generate();
        (sk, pk, [7u8; 32])
    }

    #[test]
    fn the_exit_relay_reads_the_destination_and_nobody_else_can() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [9u8; 32], hour: 400_000 };

        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");
        let out = sealed.open(&secret, &exit_id, 400_000).expect("open");
        assert_eq!(out, hop);

        // The whole point: the destination is not in the bytes the first relay
        // carries. If it were, chaining would buy nothing at all.
        let wire = sealed.to_bytes();
        assert!(
            !wire.windows(32).any(|w| w == hop.destination),
            "the destination appears in the sealed bytes, so the carrying relay \
             can read who this circuit is for"
        );
    }

    #[test]
    fn another_relay_cannot_open_it() {
        let (_, public, exit_id) = relay();
        let (other_secret, _, _) = relay();
        let hop = Hop { destination: [3u8; 32], hour: 400_000 };

        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");
        assert!(sealed.open(&other_secret, &exit_id, 400_000).is_err());
    }

    #[test]
    fn a_descriptor_for_one_relay_is_refused_at_another() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [3u8; 32], hour: 400_000 };
        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");

        // Same key, different claimed identity. The id is in the associated
        // data, so a descriptor cannot be relabelled onto another relay that
        // happens to hold the key.
        assert!(sealed.open(&secret, &[8u8; 32], 400_000).is_err());
    }

    #[test]
    fn yesterdays_circuit_request_does_not_open_today() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [3u8; 32], hour: 400_000 };
        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");

        // Replay is what the hour is bound in to stop: a captured request would
        // otherwise reopen a path to somebody for as long as the relay lives.
        assert!(sealed.open(&secret, &exit_id, 400_100).is_err());
        assert!(sealed.open(&secret, &exit_id, 399_900).is_err());
    }

    #[test]
    fn an_hour_either_side_still_opens() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [3u8; 32], hour: 400_000 };
        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");

        // Two machines disagree about the time. Refusing a circuit over a clock
        // skew is an outage rather than a defence, which is why the mailbox
        // tags carry a lookback for the same reason.
        assert!(sealed.open(&secret, &exit_id, 399_999).is_ok());
        assert!(sealed.open(&secret, &exit_id, 400_001).is_ok());
    }

    #[test]
    fn a_flipped_bit_anywhere_is_refused() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [5u8; 32], hour: 400_000 };
        let wire = SealedHop::seal(&public, &exit_id, &hop).expect("seal").to_bytes();

        for i in (0..wire.len()).step_by(37) {
            let mut broken = wire.clone();
            broken[i] ^= 1;
            let refused = match SealedHop::from_bytes(&broken) {
                Err(_) => true,
                Ok(s) => s.open(&secret, &exit_id, 400_000).is_err(),
            };
            assert!(refused, "a corrupted descriptor opened, at byte {i}");
        }
    }

    #[test]
    fn two_seals_of_one_hop_do_not_look_alike() {
        let (_, public, exit_id) = relay();
        let hop = Hop { destination: [5u8; 32], hour: 400_000 };

        // A first relay watching one sender open circuits must not be able to
        // tell that two of them go to the same place.
        let a = SealedHop::seal(&public, &exit_id, &hop).expect("seal").to_bytes();
        let b = SealedHop::seal(&public, &exit_id, &hop).expect("seal").to_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn the_wire_form_round_trips_and_the_length_is_fixed() {
        let (secret, public, exit_id) = relay();
        let hop = Hop { destination: [1u8; 32], hour: 12 };
        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");
        let wire = sealed.to_bytes();

        assert_eq!(wire.len(), SEALED_HOP_LEN);
        let back = SealedHop::from_bytes(&wire).expect("parse");
        assert_eq!(back.open(&secret, &exit_id, 12).expect("open"), hop);

        assert!(SealedHop::from_bytes(&wire[..wire.len() - 1]).is_err());
        assert!(SealedHop::from_bytes(&[0u8; 4]).is_err());
    }

    #[test]
    fn debug_never_leaks_the_destination() {
        let (_, public, exit_id) = relay();
        let hop = Hop { destination: [0xABu8; 32], hour: 5 };
        let sealed = SealedHop::seal(&public, &exit_id, &hop).expect("seal");
        let shown = format!("{sealed:?}");
        assert!(!shown.contains("ab"), "the destination reached a log: {shown}");
        assert!(shown.contains("opaque"));
    }
}
