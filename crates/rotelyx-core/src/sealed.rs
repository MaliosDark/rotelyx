//! Identity keys sealed at rest.
//!
//! An identity key is the whole of an Rotelyx account. Anyone who reads it can
//! impersonate its owner permanently, because there is no server to revoke
//! against and no password to reset. File permissions are not sufficient
//! protection for that: they do not survive a backup, a stolen disk, a
//! misconfigured sync folder, or a forensic image.
//!
//! ## Construction
//!
//! ```text
//! magic (8) ‖ version (1) ‖ salt (16) ‖ nonce (24) ‖ XChaCha20-Poly1305(key, nonce, secret ‖ tag)
//!                                                    key = Argon2id(passphrase, salt)
//! ```
//!
//! XChaCha20-Poly1305 rather than ChaCha20-Poly1305: the 24 byte nonce can be
//! drawn at random without a birthday bound worth worrying about, so sealing
//! needs no counter and no state carried between saves. A 12 byte nonce would
//! have required tracking one.
//!
//! Argon2id rather than a plain hash: a passphrase is low entropy and the only
//! defence against an offline attacker holding the file is making each guess
//! expensive in both time and memory.
//!
//! ## What this does not protect
//!
//! A device that is compromised while unlocked. The passphrase is in memory
//! while the process runs, and so is the identity. Sealing at rest defends a
//! file at rest, which is exactly and only what its name says.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::identity::Identity;

const MAGIC: &[u8; 8] = b"ROTELYX\x01";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const SECRET_LEN: usize = 32;

/// Argon2id cost parameters.
///
/// 64 MiB and three passes is the OWASP baseline for interactive use. It costs
/// a legitimate user roughly a tenth of a second on a laptop and costs an
/// attacker 64 MiB of memory per parallel guess, which is what makes large
/// scale offline cracking expensive rather than merely slow.
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

/// Bytes prepended to the passphrase before derivation, so a key derived here
/// can never collide with one derived for another purpose from the same input.
const KDF_CONTEXT: &[u8] = b"rotelyx sealed identity v1";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("not a sealed Rotelyx identity")]
    BadMagic,

    #[error("sealed identity uses format version {found}, this build understands {understood}")]
    UnsupportedVersion { found: u8, understood: u8 },

    #[error("sealed identity is truncated: {len} bytes, minimum is {min}")]
    Truncated { len: usize, min: usize },

    #[error("wrong passphrase, or the file has been modified")]
    Unopenable,

    #[error("key derivation failed")]
    Kdf,

    #[error("OS entropy source unavailable")]
    Entropy,
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, SealError> {
    let params =
        Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(KEY_LEN)).map_err(|_| SealError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut input = Zeroizing::new(Vec::with_capacity(KDF_CONTEXT.len() + passphrase.len()));
    input.extend_from_slice(KDF_CONTEXT);
    input.extend_from_slice(passphrase);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(&input, salt, &mut key[..])
        .map_err(|_| SealError::Kdf)?;
    Ok(key)
}

/// The minimum length of a well formed sealed file.
const MIN_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + SECRET_LEN + 16;

/// Seal an identity under a passphrase.
///
/// The header is authenticated as associated data, so an attacker cannot
/// downgrade the version field or swap a salt without the tag failing.
pub fn seal(identity: &Identity, passphrase: &str) -> Result<Vec<u8>, SealError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| SealError::Entropy)?;
    getrandom::fill(&mut nonce).map_err(|_| SealError::Entropy)?;

    let key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SealError::Kdf)?;

    let mut header = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let secret = identity.to_storage_bytes();
    let xnonce = XNonce::try_from(&nonce[..]).map_err(|_| SealError::Kdf)?;
    let ciphertext = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: &secret[..],
                aad: &header,
            },
        )
        .map_err(|_| SealError::Kdf)?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed identity.
///
/// A wrong passphrase and a modified file are the same error on purpose.
/// Distinguishing them would tell an attacker holding the file whether a guess
/// was close, and there is nothing a legitimate user does differently in the
/// two cases.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<Identity, SealError> {
    if bytes.len() < MIN_LEN {
        return Err(SealError::Truncated {
            len: bytes.len(),
            min: MIN_LEN,
        });
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(SealError::BadMagic);
    }

    let version = bytes[MAGIC.len()];
    if version != VERSION {
        return Err(SealError::UnsupportedVersion {
            found: version,
            understood: VERSION,
        });
    }

    let salt_at = MAGIC.len() + 1;
    let nonce_at = salt_at + SALT_LEN;
    let body_at = nonce_at + NONCE_LEN;

    let salt = &bytes[salt_at..nonce_at];
    let nonce = &bytes[nonce_at..body_at];
    let header = &bytes[..body_at];

    let key = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SealError::Kdf)?;

    let xnonce = XNonce::try_from(nonce).map_err(|_| SealError::Unopenable)?;
    let plaintext = cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: &bytes[body_at..],
                aad: header,
            },
        )
        .map_err(|_| SealError::Unopenable)?;

    let secret: [u8; SECRET_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Unopenable)?;

    Ok(Identity::from_bytes(secret))
}

/// Whether a file looks like a sealed identity rather than a raw key.
///
/// Lets a client migrate an existing plaintext key file rather than refusing to
/// start, which is the difference between a security improvement people adopt
/// and one they work around.
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_roundtrip() {
        let identity = Identity::generate();
        let sealed = seal(&identity, "correct horse battery staple").expect("seal");
        let opened = open(&sealed, "correct horse battery staple").expect("open");
        assert_eq!(identity.id(), opened.id());
    }

    #[test]
    fn the_wrong_passphrase_fails() {
        let identity = Identity::generate();
        let sealed = seal(&identity, "right").expect("seal");
        assert!(matches!(
            open(&sealed, "wrong"),
            Err(SealError::Unopenable)
        ));
    }

    /// The secret must not be recoverable by reading the file.
    #[test]
    fn the_sealed_file_does_not_contain_the_secret() {
        let identity = Identity::generate();
        let secret = identity.to_storage_bytes();
        let sealed = seal(&identity, "passphrase").expect("seal");

        assert!(
            !sealed.windows(SECRET_LEN).any(|w| w == &secret[..]),
            "the secret key appears verbatim in the sealed file"
        );
    }

    /// Two seals of the same identity under the same passphrase must differ,
    /// or the file leaks that nothing changed between two backups.
    #[test]
    fn sealing_twice_produces_different_files() {
        let identity = Identity::generate();
        let a = seal(&identity, "same").expect("seal");
        let b = seal(&identity, "same").expect("seal");
        assert_ne!(a, b);

        // Both still open.
        assert_eq!(open(&a, "same").unwrap().id(), open(&b, "same").unwrap().id());
    }

    /// Every byte of the header is authenticated, so tampering is detected
    /// rather than silently producing a different key.
    #[test]
    fn any_modification_is_detected() {
        let identity = Identity::generate();
        let sealed = seal(&identity, "pass").expect("seal");

        for i in [MAGIC.len() + 1, MAGIC.len() + 5, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&tampered, "pass").is_err(),
                "modification at byte {i} was not detected"
            );
        }
    }

    #[test]
    fn a_truncated_file_is_rejected_rather_than_panicking() {
        let identity = Identity::generate();
        let sealed = seal(&identity, "pass").expect("seal");

        for cut in 0..sealed.len() {
            // Must never panic, whatever the prefix.
            let _ = open(&sealed[..cut], "pass");
        }
        assert!(matches!(open(&[], "pass"), Err(SealError::Truncated { .. })));
    }

    #[test]
    fn a_raw_key_file_is_not_mistaken_for_a_sealed_one() {
        let raw = [7u8; 32];
        assert!(!is_sealed(&raw));
        assert!(matches!(open(&raw, "pass"), Err(SealError::Truncated { .. })));

        let sealed = seal(&Identity::generate(), "pass").expect("seal");
        assert!(is_sealed(&sealed));
    }

    #[test]
    fn a_future_version_is_refused_clearly() {
        let identity = Identity::generate();
        let mut sealed = seal(&identity, "pass").expect("seal");
        sealed[MAGIC.len()] = 99;

        assert!(matches!(
            open(&sealed, "pass"),
            Err(SealError::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn an_empty_passphrase_still_seals() {
        // Weak, and the caller's problem to prevent, but it must not corrupt.
        let identity = Identity::generate();
        let sealed = seal(&identity, "").expect("seal");
        assert_eq!(open(&sealed, "").unwrap().id(), identity.id());
    }
}
