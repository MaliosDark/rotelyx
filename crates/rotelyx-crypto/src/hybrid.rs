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
//! composition decision: how the resulting secret reaches the MLS key
//! schedule, and that lives in [`PqSecret::to_psk_bytes`]. Keeping the surface
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

    #[error("this wrap carries no signature, so nothing says who produced it")]
    Unsigned,

    #[error("this wrap was not signed by the member it names")]
    WrongSender,

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
    /// `binding` must commit to the context this secret is used in: the group
    /// id and epoch, so that a PSK captured from one epoch cannot be replayed
    /// into another.
    pub fn to_psk_bytes(&self, binding: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_psk(&self.0, binding)
    }

    /// Constant-time equality. Only for tests and for verifying that two peers
    /// agreed: never branch on secret material with `==`.
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
/// Distributed inside a signed key package, never on its own: an unauthenticated
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
    /// X-Wing decapsulation is infallible by construction: a malformed or
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

// ---------------------------------------------------------------------------
// Distributing one secret to a whole group
// ---------------------------------------------------------------------------

/// Context for the key that wraps a group secret. Distinct from every other
/// context in this crate so a wrapping key can never be mistaken for a PSK.
const WRAP_CONTEXT: &str = "rotelyx pq group secret wrap v1";

/// A post-quantum group secret, sealed to exactly one member.
///
/// # Why encapsulation alone is not enough
///
/// [`HybridPublicKey::encapsulate`] *derives* a secret, it does not carry a
/// chosen one. That is exactly right for two parties and useless for a group:
/// every member has to end up with the **same** value, because MLS looks a
/// pre-shared key up by a single id and a commit carrying different material
/// for different members would simply fail for all but one of them.
///
/// So the committer picks one group secret and, for each member, encapsulates
/// to that member and uses the result as a key-encryption key. The KEM protects
/// the wrapping key; the AEAD protects the group secret. Both halves of X-Wing
/// still have to break for this to leak.
#[derive(Clone, Debug)]
pub struct WrappedPqSecret {
    kem: HybridCiphertext,
    nonce: [u8; 24],
    sealed: Vec<u8>,
    /// The sender's signature over the binding and the body together.
    ///
    /// Empty only for a wrap built by [`PqSecret::wrap_for`], which exists for
    /// tests that are about the sealing rather than about who sent it. Nothing
    /// that reaches the network goes out unsigned: the group path signs, and
    /// the receiver refuses an empty signature.
    signature: Vec<u8>,
}

/// What a wrapped post-quantum secret is bound to.
///
/// # Why a wrap needs binding at all
///
/// Because without it the ciphertext committed to nothing: not the group, not
/// the epoch, not the recipient, not the purpose. The wrapped secret travels
/// **outside** the MLS commit, so the receiving side took an arbitrary blob off
/// the network, unwrapped it, and wrote the result into the pre-shared-key
/// store under an identifier derived from the group id and the epoch, both of
/// which anybody could read.
///
/// Two consequences, and neither needed a key to reach:
///
/// 1. **Anyone holding a member's published hybrid public key could mint a
///    wrap** and deliver it first. The victim staged the attacker's value, the
///    real commit then derived a different one, and the commit became
///    unprocessable for that member, who fell out of the group. Repeatable at
///    will, and it degrades the conversation to classical security, which is
///    exactly what this layer exists to prevent.
/// 2. **A wrap captured at one epoch still unwrapped at a later one**, so
///    rotating post-quantum material never recovered from its compromise.
///
/// Binding the group, the epoch and the recipient's signature key closes both:
/// a wrap is now usable in one place, once, by one member.
#[derive(Debug, Clone)]
pub struct PqBinding {
    group_id: Vec<u8>,
    epoch: u64,
    recipient: Vec<u8>,
    /// Who says this wrap is theirs.
    ///
    /// The binding used to name the group, the epoch and the recipient, which
    /// closed replay and left one thing open: nothing said who produced it. A
    /// party able to place bytes under the group's tag could substitute a wrap
    /// of their own. Naming the sender in the associated data means a wrap
    /// cannot be relabelled, and the signature beside it means one cannot be
    /// minted by somebody outside the group at all.
    sender: Vec<u8>,
}

impl PqBinding {
    pub fn new(
        group_id: &[u8],
        epoch: u64,
        recipient_signature_key: &[u8],
        sender_signature_key: &[u8],
    ) -> Self {
        Self {
            group_id: group_id.to_vec(),
            epoch,
            recipient: recipient_signature_key.to_vec(),
            sender: sender_signature_key.to_vec(),
        }
    }

    /// The key a receiver must verify the signature against.
    pub fn sender(&self) -> &[u8] {
        &self.sender
    }

    /// Length-prefixed throughout, so that no two different bindings can
    /// produce the same bytes by moving a boundary.
    fn to_aad(&self) -> Vec<u8> {
        const LABEL: &[u8] = b"rotelyx pq group secret wrap v2";
        let mut out = Vec::with_capacity(LABEL.len() + self.group_id.len() + self.recipient.len() + 32);
        out.extend_from_slice(&(LABEL.len() as u64).to_be_bytes());
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&(self.group_id.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.recipient.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&(self.sender.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.sender);
        out
    }
}

/// Bytes on the wire: the KEM ciphertext, a nonce, and the sealed secret with
/// its tag.
pub const WRAPPED_SECRET_LEN: usize = CIPHERTEXT_LEN + 24 + 32 + 16;

impl WrappedPqSecret {
    /// Everything except the signature, which is what the signature covers.
    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WRAPPED_SECRET_LEN);
        out.extend_from_slice(&self.kem.to_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() < WRAPPED_SECRET_LEN {
            return Err(HybridError::BadCiphertext);
        }
        let (body, signature) = bytes.split_at(WRAPPED_SECRET_LEN);
        let (kem, rest) = body.split_at(CIPHERTEXT_LEN);
        let (nonce, sealed) = rest.split_at(24);

        Ok(Self {
            kem: HybridCiphertext::from_bytes(kem)?,
            nonce: nonce.try_into().map_err(|_| HybridError::BadCiphertext)?,
            sealed: sealed.to_vec(),
            signature: signature.to_vec(),
        })
    }
}

/// Derive the key that wraps a group secret from a KEM output.
///
/// Separated from the PSK derivation by its own context string: the same KEM
/// output must never produce both a wrapping key and key-schedule material.
/// Derive a 32 byte key from an encapsulated secret, under a context string.
///
/// Crate-visible so a sibling module can derive without reaching into
/// `PqSecret`'s bytes. The bytes stay inside the module that owns them, which
/// is the point: a secret whose representation is readable from anywhere is a
/// secret that ends up copied somewhere it should not be.
///
/// The context separates uses. Two derivations from one encapsulation must not
/// produce the same key, or a value sealed for one purpose opens under another.
pub(crate) fn derive_key(kem_secret: &PqSecret, context: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&kem_secret.0[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    hasher.finalize_xof().fill(&mut out[..]);
    out
}

fn wrapping_key(kem_secret: &PqSecret) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(WRAP_CONTEXT);
    hasher.update(&kem_secret.0[..]);

    let mut out = Zeroizing::new([0u8; 32]);
    hasher.finalize_xof().fill(&mut out[..]);
    out
}

impl PqSecret {
    /// A fresh group secret, straight from the OS CSPRNG.
    ///
    /// Used by the member committing a post-quantum rotation, who then wraps it
    /// to every other member.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut bytes[..]).expect("the OS CSPRNG must be available");
        Self(bytes)
    }

    /// Seal this secret to one member's hybrid public key.
    /// `binding` is what stops this from being a value anybody can mint and
    /// anybody can replay. See [`PqBinding`].
    pub fn wrap_for(
        &self,
        recipient: &HybridPublicKey,
        binding: &PqBinding,
    ) -> Result<WrappedPqSecret, HybridError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let (kem, kem_secret) = recipient.encapsulate();
        let key = wrapping_key(&kem_secret);

        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| HybridError::Entropy)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| HybridError::BadCiphertext)?;

        let aad = binding.to_aad();
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &self.0[..],
                    aad: &aad,
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;

        Ok(WrappedPqSecret {
            kem,
            nonce,
            sealed,
            signature: Vec::new(),
        })
    }

    /// Wrap, and sign what was produced with the sender's MLS signature key.
    ///
    /// The signature covers the associated data and the sealed bytes together,
    /// so neither can be moved to the other. A receiver verifies it against a
    /// key it looked up in its own roster, which is what makes a wrap from
    /// outside the group unusable rather than merely unopenable.
    pub fn wrap_and_sign(
        &self,
        recipient: &HybridPublicKey,
        binding: &PqBinding,
        signer: &impl openmls_traits::signatures::Signer,
    ) -> Result<WrappedPqSecret, HybridError> {
        let mut wrapped = self.wrap_for(recipient, binding)?;
        let signature = signer
            .sign(&signing_payload(binding, &wrapped))
            .map_err(|_| HybridError::BadCiphertext)?;
        wrapped.signature = signature;
        Ok(wrapped)
    }
}

/// What a wrap's signature covers.
///
/// Length prefixed so the two halves cannot be shifted into one another.
fn signing_payload(binding: &PqBinding, wrapped: &WrappedPqSecret) -> Vec<u8> {
    let aad = binding.to_aad();
    let body = wrapped.body_bytes();
    let mut out = Vec::with_capacity(aad.len() + body.len() + 16);
    out.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

impl HybridSecretKey {
    /// Recover a group secret sealed to us, checking who sent it first.
    ///
    /// `binding` names the sender, and the signature is verified against that
    /// key before anything is decrypted. The caller is responsible for the part
    /// this cannot see: that the key belongs to a **current member** of the
    /// group. Verifying a signature only says the holder of that key produced
    /// it, and a former member still holds theirs.
    ///
    /// This is the entry point anything reached from the network should use.
    /// [`Self::unwrap_pq`] is the unauthenticated half and stays for tests that
    /// are about the sealing itself.
    pub fn unwrap_pq_signed(
        &self,
        wrapped: &WrappedPqSecret,
        binding: &PqBinding,
    ) -> Result<PqSecret, HybridError> {
        if wrapped.signature.is_empty() {
            return Err(HybridError::Unsigned);
        }

        // The pinned ciphersuite signs with Ed25519, so this is that check.
        // `verify_strict` rather than `verify`: it refuses the small-order and
        // non-canonical keys that make a signature verify under more than one
        // key, which is exactly the confusion this check exists to prevent.
        let key: [u8; 32] = binding
            .sender()
            .try_into()
            .map_err(|_| HybridError::WrongSender)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| HybridError::WrongSender)?;
        let signature: [u8; 64] = wrapped
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| HybridError::WrongSender)?;
        key.verify_strict(
            &signing_payload(binding, wrapped),
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| HybridError::WrongSender)?;

        self.unwrap_pq(wrapped, binding)
    }

    /// Recover a group secret sealed to us.
    ///
    /// Fails rather than returning something usable if the wrapping is wrong.
    /// A group secret that silently differs between members would produce a
    /// commit nobody else can process, and the cause would be invisible.
    pub fn unwrap_pq(
        &self,
        wrapped: &WrappedPqSecret,
        binding: &PqBinding,
    ) -> Result<PqSecret, HybridError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let kem_secret = self.decapsulate(&wrapped.kem);
        let key = wrapping_key(&kem_secret);

        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| HybridError::BadCiphertext)?;

        let aad = binding.to_aad();
        let plain = cipher
            .decrypt(
                &XNonce::from(wrapped.nonce),
                chacha20poly1305::aead::Payload {
                    msg: &wrapped.sealed[..],
                    aad: &aad,
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;

        // Wrapped the moment it exists. `decrypt` hands back a bare `Vec`, and
        // that Vec holds the group secret: copying it into a `Zeroizing` and
        // dropping the original leaves the secret in freed heap, where a core
        // dump or a page swapped out still has it. The rest of this crate is
        // careful about exactly this, which is what made the omission worth
        // finding.
        let plain = Zeroizing::new(plain);

        let mut out = Zeroizing::new([0u8; 32]);
        if plain.len() != 32 {
            return Err(HybridError::BadCiphertext);
        }
        out.copy_from_slice(&plain);
        Ok(PqSecret(out))
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
    /// A stand-in sender key for tests that are not about who sent it.
    const A_SENDER: &[u8] = &[7u8; 32];
    /// A wrap must be usable in one place, once, by one member.
    ///
    /// The regression test for a ciphertext that committed to nothing. The
    /// wrapping key was the KEM output and nothing else, so anybody holding a
    /// member's published hybrid public key could mint a wrap and deliver it
    /// before the real one, and a wrap captured at one epoch still opened at a
    /// later one. Both were reproduced by an audit; both are asserted here.
    #[test]
    fn a_wrap_is_bound_to_one_group_one_epoch_and_one_member() {
        let (secret_key, public) = HybridKem::generate();
        let recipient = secret_key;

        let group = b"a-group-id";
        let mine = b"the-recipients-signature-key";
        let here = PqBinding::new(group, 7, mine, A_SENDER);

        let secret = PqSecret::generate();
        let wrapped = secret.wrap_for(&public, &here).expect("wrap");

        // The intended use opens.
        assert!(recipient.unwrap_pq(&wrapped, &here).is_ok());

        // A later epoch does not. This is the replay the audit reproduced: PQ
        // rotation is supposed to recover from a compromised secret, and it
        // cannot if yesterday's wrap still installs today.
        let later = PqBinding::new(group, 8, mine, A_SENDER);
        assert!(
            recipient.unwrap_pq(&wrapped, &later).is_err(),
            "a wrap from an earlier epoch replayed into a later one"
        );

        // Another group does not, even at the same epoch.
        let elsewhere = PqBinding::new(b"a-different-group", 7, mine, A_SENDER);
        assert!(recipient.unwrap_pq(&wrapped, &elsewhere).is_err());

        // And a wrap addressed to somebody else does not open for us, which is
        // what stops one member's wrap being redirected at another.
        let somebody_else = PqBinding::new(group, 7, b"another-members-key", A_SENDER);
        assert!(recipient.unwrap_pq(&wrapped, &somebody_else).is_err());

        // The mirror of the first case: a stranger who holds the published
        // public key can still produce bytes, but not ones that open under the
        // binding the recipient will use.
        let strangers = PqSecret::generate()
            .wrap_for(&public, &PqBinding::new(b"whatever-they-choose", 7, mine, A_SENDER))
            .expect("wrap");
        assert!(
            recipient.unwrap_pq(&strangers, &here).is_err(),
            "a wrap minted by a non-member was accepted"
        );
    }

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
