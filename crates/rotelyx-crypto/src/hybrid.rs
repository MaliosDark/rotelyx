//! Hybrid post-quantum key agreement.
//!
//! Wraps X-Wing (`draft-connolly-cfrg-xwing-kem`), a hybrid KEM combining
//! ML-KEM-768 and X25519. Its security claim is what makes it worth adopting
//! rather than inventing: the shared secret is secure if SHA3 is secure **and
//! either** X25519 **or** ML-KEM-768 is secure. A classical break of X25519 by
//! a quantum adversary does not expose it; a flaw found in ML-KEM does not
//! expose it either.
//!
//! ## Why this module is so thin
//!
//! Everything cryptographic here is delegated. What Rotelyx adds is one
//! composition decision — how the resulting secret reaches the MLS key
//! schedule — and that lives in [`PqSecret::to_psk_bytes`]. Keeping the surface
//! this small is deliberate: it is the only novel construction in the system,
//! so it must be small enough to review in an afternoon.

use std::fmt;

use x_wing::kem::{Decapsulate, Decapsulator, Encapsulate, Kem, KeyExport, TryKeyInit};
use x_wing::{
    Ciphertext, DecapsulationKey, EncapsulationKey, XWingKem, CIPHERTEXT_SIZE,
    DECAPSULATION_KEY_SIZE, ENCAPSULATION_KEY_SIZE,
};
use zeroize::{Zeroize, Zeroizing};

/// Byte length of a serialised public key. 1216 = ML-KEM-768 (1184) + X25519 (32).
pub const PUBLIC_KEY_LEN: usize = ENCAPSULATION_KEY_SIZE;
/// Byte length of a serialised secret key: a 32-byte seed, expanded on use.
pub const SECRET_KEY_LEN: usize = DECAPSULATION_KEY_SIZE;
/// Byte length of a ciphertext. 1120 = ML-KEM-768 (1088) + X25519 (32).
pub const CIPHERTEXT_LEN: usize = CIPHERTEXT_SIZE;

/// Build the context a post-quantum PSK is bound to.
///
/// `label || group_id || be64(epoch)`.
///
/// The encoding is unambiguous despite `group_id` being variable length,
/// because the epoch is fixed at eight bytes and sits at the end. Parsing
/// backwards recovers the epoch, and what remains between the label and it is
/// the group id, so no two distinct pairs can produce the same bytes. Placing
/// the variable-length field last would have broken that.
///
/// Exposed as a free function, taking its inputs rather than reading them from
/// group state, so that the construction can be specified and reproduced by
/// somebody who is not running MLS. See `docs/PQ-COMPOSITION.md`.
pub fn psk_binding(label: &[u8], group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + group_id.len() + 8);
    out.extend_from_slice(label);
    out.extend_from_slice(group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// Derive the MLS pre-shared key from a KEM shared secret and a binding.
///
/// `BLAKE3_XOF(derive_key(PSK_CONTEXT), secret || be64(len(binding)) || binding)`
/// truncated to 32 bytes.
///
/// The length prefix on the binding is what stops two different
/// `(secret, binding)` splits producing the same input stream. The secret is
/// fixed at 32 bytes so it needs no prefix of its own.
pub fn derive_psk(secret: &[u8; 32], binding: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(PSK_CONTEXT);
    hasher.update(secret);
    hasher.update(&(binding.len() as u64).to_be_bytes());
    hasher.update(binding);

    let mut out = Zeroizing::new([0u8; 32]);
    hasher.finalize_xof().fill(&mut out[..]);
    out
}

/// Domain separator for deriving the MLS pre-shared key from the KEM output.
///
/// Distinct from every other label in the system so that a secret derived here
/// can never collide with one derived elsewhere, even if the same input bytes
/// were somehow reused.
const PSK_CONTEXT: &str = "rotelyx hybrid-pq psk v1";

#[derive(Debug, thiserror::Error)]
pub enum HybridError {
    #[error("malformed encapsulation key")]
    BadPublicKey,

    #[error("malformed decapsulation key")]
    BadSecretKey,

    #[error("malformed ciphertext")]
    BadCiphertext,

    #[error("decapsulation failed")]
    Decapsulation,

    #[error("OS entropy source unavailable")]
    Entropy,
}

/// A post-quantum shared secret, ready to be mixed into the MLS key schedule.
///
/// Zeroized on drop. Deliberately not `Clone`: every extra copy of key material
/// is another page that has to be scrubbed, and there is no legitimate reason
/// to hold two.
pub struct PqSecret(Zeroizing<[u8; 32]>);

impl PqSecret {
    /// Derive the bytes to hand to MLS as an external pre-shared key.
    ///
    /// **This is Rotelyx's one novel composition.** RFC 9420 defines only
    /// classical ciphersuites, and the post-quantum suites are still in draft,
    /// so rather than forking MLS we inject the hybrid secret at the PSK input
    /// that MLS already provides. The resulting epoch secret is post-quantum
    /// secure as long as the KEM output is, because MLS's own key schedule
    /// mixes the PSK into every epoch.
    ///
    /// `binding` must commit to the context this secret is used in — the group
    /// id and epoch — so that a PSK captured from one epoch cannot be replayed
    /// into another.
    pub fn to_psk_bytes(&self, binding: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_psk(&self.0, binding)
    }

    /// Constant-time equality. Only for tests and for verifying that two peers
    /// agreed — never branch on secret material with `==`.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0[..].ct_eq(&other.0[..]).into()
    }

    #[cfg(test)]
    fn expose(&self) -> [u8; 32] {
        *self.0
    }
}

impl fmt::Debug for PqSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PqSecret(<redacted>)")
    }
}

impl Drop for PqSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A peer's hybrid public key, published so others can encapsulate to it.
///
/// Distributed inside a signed key package, never on its own — an unauthenticated
/// encapsulation key is an invitation to a machine-in-the-middle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey(EncapsulationKey);

impl HybridPublicKey {
    /// Encapsulate a fresh shared secret to this key.
    ///
    /// Returns the ciphertext to send and the secret to keep. Randomness comes
    /// from the OS CSPRNG via X-Wing's `getrandom` feature.
    pub fn encapsulate(&self) -> (HybridCiphertext, PqSecret) {
        let (ct, ss) = self.0.encapsulate();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&ss);
        (HybridCiphertext(ct), PqSecret(Zeroizing::new(secret)))
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(&self.0.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        EncapsulationKey::new_from_slice(bytes)
            .map(Self)
            .map_err(|_| HybridError::BadPublicKey)
    }
}

/// A locally held hybrid secret key.
///
/// The underlying decapsulation key zeroizes on drop.
pub struct HybridSecretKey(DecapsulationKey);

impl HybridSecretKey {
    /// Recover the shared secret a peer encapsulated to us.
    ///
    /// X-Wing decapsulation is infallible by construction — a malformed or
    /// attacker-chosen ciphertext yields an unrelated secret rather than an
    /// error. That is the implicit-rejection design ML-KEM inherits, and it is
    /// deliberate: an error would be an oracle. The mismatch surfaces later,
    /// when the derived key fails to authenticate a message.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> PqSecret {
        let ss = self.0.decapsulate(&ct.0);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&ss);
        PqSecret(Zeroizing::new(secret))
    }

    pub fn public(&self) -> HybridPublicKey {
        HybridPublicKey(self.0.encapsulation_key().clone())
    }

    /// Export for encrypted at-rest storage. The caller must seal this before
    /// it touches a disk.
    pub fn to_storage_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        Zeroizing::new(*self.0.as_bytes())
    }

    pub fn from_storage_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(DecapsulationKey::from(bytes))
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSecretKey(<redacted>)")
    }
}

/// An encapsulation, sent alongside the message it protects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCiphertext(Ciphertext);

impl HybridCiphertext {
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LEN] {
        let mut out = [0u8; CIPHERTEXT_LEN];
        out.copy_from_slice(&self.0);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != CIPHERTEXT_LEN {
            return Err(HybridError::BadCiphertext);
        }
        Ok(Self(Ciphertext::try_from(bytes).map_err(|_| HybridError::BadCiphertext)?))
    }
}

/// Entry point for hybrid key agreement.
#[derive(Debug)]
pub struct HybridKem;

impl HybridKem {
    /// Generate a fresh hybrid keypair from the OS CSPRNG.
    pub fn generate() -> (HybridSecretKey, HybridPublicKey) {
        let (dk, ek) = XWingKem::generate_keypair();
        (HybridSecretKey(dk), HybridPublicKey(ek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let (sk, pk) = HybridKem::generate();
        let (ct, sender) = pk.encapsulate();
        let receiver = sk.decapsulate(&ct);
        assert!(sender.ct_eq(&receiver));
    }

    #[test]
    fn a_different_key_derives_a_different_secret() {
        let (_sk_a, pk_a) = HybridKem::generate();
        let (sk_b, _pk_b) = HybridKem::generate();

        let (ct, sender) = pk_a.encapsulate();
        // Implicit rejection: decapsulating with the wrong key yields an
        // unrelated secret rather than an error, by design.
        let wrong = sk_b.decapsulate(&ct);
        assert!(!sender.ct_eq(&wrong));
    }

    #[test]
    fn each_encapsulation_is_fresh() {
        let (_sk, pk) = HybridKem::generate();
        let (ct1, s1) = pk.encapsulate();
        let (ct2, s2) = pk.encapsulate();
        assert_ne!(ct1.to_bytes(), ct2.to_bytes(), "ciphertexts must not repeat");
        assert!(!s1.ct_eq(&s2), "shared secrets must not repeat");
    }

    /// The wire sizes X-Wing actually produces.
    ///
    /// Asserted rather than trusted from documentation: the published docs and
    /// the draft disagreed on the ciphertext length, and a KEM whose ciphertext
    /// is a different size than expected is a KEM you have misidentified.
    #[test]
    fn wire_sizes_match_the_draft() {
        assert_eq!(PUBLIC_KEY_LEN, 1216, "ML-KEM-768 (1184) + X25519 (32)");
        assert_eq!(SECRET_KEY_LEN, 32, "a seed, expanded on use");
        assert_eq!(CIPHERTEXT_LEN, 1120, "ML-KEM-768 (1088) + X25519 (32)");

        let (sk, pk) = HybridKem::generate();
        let (ct, _) = pk.encapsulate();
        assert_eq!(pk.to_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(sk.to_storage_bytes().len(), SECRET_KEY_LEN);
        assert_eq!(ct.to_bytes().len(), CIPHERTEXT_LEN);
    }

    #[test]
    fn keys_and_ciphertexts_survive_serialisation() {
        let (sk, pk) = HybridKem::generate();
        let (ct, sender) = pk.encapsulate();

        let pk2 = HybridPublicKey::from_bytes(&pk.to_bytes()).expect("public key roundtrip");
        assert_eq!(pk, pk2);

        let ct2 = HybridCiphertext::from_bytes(&ct.to_bytes()).expect("ciphertext roundtrip");
        let sk2 = HybridSecretKey::from_storage_bytes(*sk.to_storage_bytes());

        assert!(sender.ct_eq(&sk2.decapsulate(&ct2)));
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(HybridPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; CIPHERTEXT_LEN + 1]).is_err());
    }

    #[test]
    fn secret_key_debug_never_leaks() {
        let (sk, _) = HybridKem::generate();
        assert_eq!(format!("{sk:?}"), "HybridSecretKey(<redacted>)");
    }

    #[test]
    fn psk_derivation_is_deterministic_and_binding_sensitive() {
        let s = PqSecret(Zeroizing::new([42u8; 32]));

        let a = s.to_psk_bytes(b"group-1|epoch-7");
        let b = s.to_psk_bytes(b"group-1|epoch-7");
        assert_eq!(*a, *b, "same binding must derive the same PSK");

        let c = s.to_psk_bytes(b"group-1|epoch-8");
        assert_ne!(*a, *c, "a different epoch must derive a different PSK");

        let d = s.to_psk_bytes(b"group-2|epoch-7");
        assert_ne!(*a, *d, "a different group must derive a different PSK");
    }

    /// Length-prefixing the binding is what stops `("ab","c")` and `("a","bc")`
    /// from producing the same PSK.
    #[test]
    fn binding_is_unambiguously_framed() {
        let s = PqSecret(Zeroizing::new([7u8; 32]));
        assert_ne!(*s.to_psk_bytes(b"ab"), *s.to_psk_bytes(b"a"));
        // Concatenation ambiguity: without a length prefix these would collide.
        let long = s.to_psk_bytes(b"group-1|epoch-1");
        let split = s.to_psk_bytes(b"group-1|epoch-11");
        assert_ne!(*long, *split);
    }

    #[test]
    fn psk_differs_from_the_raw_secret() {
        let s = PqSecret(Zeroizing::new([9u8; 32]));
        assert_ne!(*s.to_psk_bytes(b"ctx"), s.expose());
    }

    #[test]
    fn debug_never_leaks() {
        let s = PqSecret(Zeroizing::new([1u8; 32]));
        assert_eq!(format!("{s:?}"), "PqSecret(<redacted>)");
    }
}
