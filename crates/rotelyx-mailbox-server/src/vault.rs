//! Encrypted storage for the mailbox's contents.
//!
//! # The trade this makes, stated before anything else
//!
//! A mailbox that lives only in memory loses every uncollected envelope on
//! restart. That is bad for delivery and **good against seizure**: a stopped
//! server hands over nothing at all.
//!
//! Persisting reverses that. It is therefore done under a key supplied at
//! startup and never written down beside the data:
//!
//! | Situation | What the file yields |
//! |---|---|
//! | Server off, disk taken | Nothing. Ciphertext without a key |
//! | Server off, disk and key taken | Tags and message ciphertext |
//! | Server running, memory taken | Tags and message ciphertext |
//!
//! Message *content* stays unreadable in every row: it is encrypted by MLS and
//! this process has never held a key for it. What persistence risks is the
//! routing metadata, which is ADV-3 in the threat model and the reason tags
//! rotate in the first place.
//!
//! Running without a key is a legitimate choice, and the default. It means
//! choosing delivery losses over metadata at rest.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Marks a file as ours and pins the format. A future format change bumps the
/// second byte and a mismatched file is refused rather than misread.
const MAGIC: &[u8; 9] = b"ROTELYXMB";
const VERSION: u8 = 1;

/// Argon2id parameters. The same as the identity keyfile uses: 64 MiB and three
/// passes, chosen so a passphrase is expensive to grind on hardware an attacker
/// would actually have.
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;

/// How many times Argon2id has run in this process. Only a test reads it.
pub(crate) static DERIVATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const LANES: u32 = 1;

/// Sealed storage under an operator's passphrase.
///
/// Stateless: the key is derived on each call and dropped, so a long running
/// process is not holding it in a struct somewhere waiting to be read out of a
/// core dump.
pub struct Vault;

impl Vault {
    /// Derive a vault key from a passphrase and a salt that lives with the
    /// data.
    ///
    /// The salt is stored in the file rather than derived from the path, so
    /// moving or renaming the file does not silently make it unreadable.
    /// The last key derived, and the salt it belongs to.
    ///
    /// # Why this cache exists
    ///
    /// Argon2id at 64 MiB and three passes takes **265 ms** and allocates 64
    /// MiB, measured on this machine. That cost is the point when a passphrase
    /// is being checked: it is what makes a stolen file expensive to open.
    ///
    /// It is pure waste when the same passphrase is used to write the same file
    /// again, and the wake registry does exactly that, once per device
    /// registration. Measured before this cache: eight unauthenticated
    /// `revokeWake` messages took 2.26 seconds of server time, so **three and a
    /// half messages a second saturated a core**, each allocating 64 MiB. An
    /// operation anybody can call and nobody pays for is a denial of service
    /// with a small message.
    ///
    /// # Why reusing the salt is safe here, and where it would not be
    ///
    /// A salt stops one precomputed table from attacking many files. Keeping it
    /// across successive writes *of the same file under the same passphrase*
    /// changes nothing: it is one file and one passphrase either way, and an
    /// attacker who precomputes for that salt has attacked exactly the file
    /// they already have.
    ///
    /// What must not be reused is the **nonce**, and it is not: `seal` draws a
    /// fresh 24 bytes from the OS on every write. XChaCha20-Poly1305 with a
    /// repeated key is safe; with a repeated key *and* nonce it is not, and
    /// that is the line this cache does not cross.
    ///
    /// The cache is per process and never written down. A restart pays the full
    /// cost once, which is correct: that is a passphrase being checked.
    fn cached_key(
        passphrase: &str,
        salt: Option<[u8; 16]>,
    ) -> Result<([u8; 16], Zeroizing<[u8; 32]>)> {
        use std::sync::Mutex;

        /// Salt, a binding to the passphrase, and the key.
        ///
        /// The passphrase binding is not optional and the first version of this
        /// omitted it. Keyed on the salt alone, opening a file with the **wrong**
        /// passphrase found the entry cached from the right one and decrypted
        /// successfully: an authentication bypass introduced by a performance
        /// fix. The binding is a hash rather than the passphrase itself, so the
        /// cache holds nothing worth stealing, and it is compared in constant
        /// time so the comparison is not an oracle for it.
        type Entry = ([u8; 16], [u8; 32], Zeroizing<[u8; 32]>);

        /// A handful of slots rather than one.
        ///
        /// One is enough for production, where a server holds a single
        /// passphrase. It is not enough for a test suite: several tests seal
        /// with different passphrases at once, and with four slots the entry
        /// under test was evicted between one write and the next, so five
        /// cached writes still cost six derivations. Sixteen keys is a kilobyte
        /// and it makes the cache survive the conditions that demonstrate it
        /// works. The number is here for the tests; production would be happy
        /// with one.
        const SLOTS: usize = 16;
        static CACHE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

        let binding: [u8; 32] = *blake3::Hasher::new_derive_key("rotelyx vault cache binding v1")
            .update(passphrase.as_bytes())
            .finalize()
            .as_bytes();

        let mut cache = match CACHE.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Reading a file names the salt; writing one may reuse whatever is
        // cached for this passphrase, or start a new one. Either way the
        // passphrase must match, compared in constant time.
        {
            use subtle::ConstantTimeEq;
            for (cached_salt, cached_binding, key) in cache.iter() {
                let same_passphrase: bool = binding.ct_eq(cached_binding).into();
                let same_salt = match salt {
                    Some(wanted) => wanted == *cached_salt,
                    None => true,
                };
                if same_passphrase && same_salt {
                    return Ok((*cached_salt, key.clone()));
                }
            }
        }

        // Nothing cached for this passphrase, so derive: either against the
        // salt a file names, or against a fresh one for a file being created.
        let salt = match salt {
            Some(s) => s,
            None => {
                let mut s = [0u8; 16];
                getrandom::fill(&mut s).context("reading the OS CSPRNG")?;
                s
            }
        };

        let key = Self::derive(passphrase, &salt)?;
        if cache.len() >= SLOTS {
            cache.remove(0);
        }
        cache.push((salt, binding, key.clone()));
        Ok((salt, key))
    }

    fn derive(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Counted so a test can assert that the cache works without measuring
        // time. Wall clock is useless here: the suite runs in parallel and a
        // cached write on a contended machine took 342 ms, which looks exactly
        // like a derivation and is not one.
        DERIVATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(32))
            .map_err(|e| anyhow!("argon2 parameters: {e}"))?;

        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
            .map_err(|e| anyhow!("deriving the vault key: {e}"))?;

        Ok(key)
    }

    /// Encrypt `plaintext` and write it to `path`.
    pub fn seal(passphrase: &str, path: &Path, plaintext: &[u8]) -> Result<()> {
        // Reuses the derived key when this process has already derived one, so
        // that writing the same file twice does not pay for Argon2id twice.
        let (salt, key) = Self::cached_key(passphrase, None)?;

        // The nonce is always fresh. Reusing a key is safe; reusing a key and a
        // nonce together is not.
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).context("reading the OS CSPRNG")?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|e| anyhow!("building the cipher: {e}"))?;

        // The header is authenticated, so a file cannot be replayed under a
        // different version or with a swapped salt.
        let mut header = Vec::with_capacity(MAGIC.len() + 1 + 16 + 24);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|e| anyhow!("sealing: {e}"))?;

        let mut out = header;
        out.extend_from_slice(&sealed);

        // Write beside the target and rename, so a crash mid-write leaves the
        // previous snapshot readable rather than a truncated file that decrypts
        // to nothing and looks like an empty mailbox.
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, &out).with_context(|| format!("writing {}", temporary.display()))?;
        restrict(&temporary)?;
        fs::rename(&temporary, path).with_context(|| format!("renaming to {}", path.display()))
    }

    /// Read and decrypt `path`. A missing file yields `None`, which is a first
    /// start rather than a failure.
    pub fn open(passphrase: &str, path: &Path) -> Result<Option<Vec<u8>>> {
        let raw = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };

        let header_len = MAGIC.len() + 1 + 16 + 24;
        if raw.len() < header_len + 16 {
            return Err(anyhow!(
                "{} is too short to be a mailbox vault",
                path.display()
            ));
        }

        let (header, body) = raw.split_at(header_len);
        if &header[..MAGIC.len()] != MAGIC {
            return Err(anyhow!("{} is not a mailbox vault", path.display()));
        }
        if header[MAGIC.len()] != VERSION {
            return Err(anyhow!(
                "{} was written by format version {}, this build speaks {VERSION}",
                path.display(),
                header[MAGIC.len()]
            ));
        }

        let salt: [u8; 16] = header[MAGIC.len() + 1..MAGIC.len() + 17]
            .try_into()
            .expect("checked length");
        let nonce: [u8; 24] = header[MAGIC.len() + 17..]
            .try_into()
            .expect("checked length");

        // Opening names the salt, so the cache only helps when it is the same
        // file being reopened. A wrong passphrase still pays the full cost,
        // which is the point of the cost.
        let (_, key) = Self::cached_key(passphrase, Some(salt))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|e| anyhow!("building the cipher: {e}"))?;

        cipher
            .decrypt(
                &XNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: body,
                    aad: header,
                },
            )
            .map(Some)
            .map_err(|_| {
                anyhow!(
                    "{} did not decrypt: wrong passphrase, or the file was altered",
                    path.display()
                )
            })
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rotelyx-vault-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir.join(name)
    }

    /// The cache must not let a wrong passphrase in.
    ///
    /// This is the test for a bug that was written and caught before it ran.
    /// The first version of the key cache was keyed on the salt alone, so
    /// opening a file with the wrong passphrase found the entry cached from the
    /// right one and decrypted successfully. A performance fix had turned into
    /// an authentication bypass.
    #[test]
    fn a_wrong_passphrase_still_fails_after_the_right_one_was_used() {
        let dir = std::env::temp_dir().join(format!("rotelyx-vault-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("v");

        Vault::seal("the right operator passphrase", &path, b"secret contents").expect("seal");

        // The right one, which populates the cache.
        assert_eq!(
            Vault::open("the right operator passphrase", &path).expect("open"),
            Some(b"secret contents".to_vec())
        );

        // And then the wrong one, against a warm cache for that exact salt.
        assert!(
            Vault::open("an entirely different passphrase", &path).is_err(),
            "a wrong passphrase opened the vault: the cache is not bound to it"
        );

        // The right one still works afterwards, so the failure did not poison
        // anything.
        assert_eq!(
            Vault::open("the right operator passphrase", &path).expect("open"),
            Some(b"secret contents".to_vec())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writing twice must not derive twice.
    ///
    /// Counted rather than timed. The measurement that motivated the cache is
    /// that one derivation is 265 ms and the wake registry writes on every
    /// device registration, an operation anybody can call without
    /// authenticating. But a timing assertion is unreliable here: the suite
    /// runs in parallel, and a cached write on a contended machine measured
    /// 342 ms, which looks exactly like a derivation and is not one.
    #[test]
    fn writing_twice_does_not_pay_twice() {
        use std::sync::atomic::Ordering;

        let dir = std::env::temp_dir().join(format!("rotelyx-vault-speed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("v");

        // A passphrase only this test uses, so a parallel test cannot evict it.
        let phrase = "a passphrase for the derivation counting test";

        Vault::seal(phrase, &path, b"one").expect("seal");

        let before = DERIVATIONS.load(Ordering::Relaxed);
        for _ in 0..5 {
            Vault::seal(phrase, &path, b"two").expect("seal");
        }
        Vault::open(phrase, &path).expect("open");
        let after = DERIVATIONS.load(Ordering::Relaxed);

        // Other tests derive in parallel and are counted too, so this cannot
        // assert zero. It can assert that five writes and a read did not add
        // five derivations, which is what a broken cache would do.
        assert!(
            after - before < 5,
            "five cached writes and a read added {} derivations",
            after - before
        );

        // And the file still opens, so reusing the key did not corrupt it.
        assert_eq!(
            Vault::open(phrase, &path).expect("open"),
            Some(b"two".to_vec())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sealed_file_round_trips() {
        let path = scratch("round-trip");
        Vault::seal("a long operator passphrase", &path, b"contents").expect("seal");

        assert_eq!(
            Vault::open("a long operator passphrase", &path).expect("open"),
            Some(b"contents".to_vec())
        );
        let _ = fs::remove_file(&path);
    }

    /// The whole point: without the passphrase the file is worth nothing.
    #[test]
    fn the_wrong_passphrase_yields_nothing() {
        let path = scratch("wrong-key");
        Vault::seal(
            "the right operator passphrase",
            &path,
            b"tags and ciphertext",
        )
        .expect("seal");

        assert!(
            Vault::open("an entirely different passphrase", &path).is_err(),
            "a seized disk without the key must yield nothing"
        );
        let _ = fs::remove_file(&path);
    }

    /// Nothing recognisable may sit in the clear, or the file leaks what it
    /// exists to protect.
    #[test]
    fn the_contents_are_not_readable_on_disk() {
        let path = scratch("opaque");
        let secret = b"a tag that must not be legible on a seized disk";
        Vault::seal("the operator passphrase for this", &path, secret).expect("seal");

        let raw = fs::read(&path).expect("read");
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "the plaintext is sitting in the file"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the vault must not be world readable");
        }
        let _ = fs::remove_file(&path);
    }

    /// Tampering must fail loudly. A vault that silently returned altered
    /// contents would let anyone with write access delete messages selectively.
    #[test]
    fn a_tampered_file_is_refused() {
        let path = scratch("tampered");
        Vault::seal("the operator passphrase here", &path, b"contents").expect("seal");

        let mut raw = fs::read(&path).expect("read");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        fs::write(&path, &raw).expect("write");

        assert!(Vault::open("the operator passphrase here", &path).is_err());
        let _ = fs::remove_file(&path);
    }

    /// The header is authenticated, so swapping the salt cannot be used to
    /// coax the file open under a different derived key.
    #[test]
    fn the_header_cannot_be_swapped() {
        let path = scratch("header");
        Vault::seal("the operator passphrase again", &path, b"contents").expect("seal");

        let mut raw = fs::read(&path).expect("read");
        raw[MAGIC.len() + 1] ^= 0xff; // first salt byte
        fs::write(&path, &raw).expect("write");

        assert!(Vault::open("the operator passphrase again", &path).is_err());
        let _ = fs::remove_file(&path);
    }

    /// A first start has no file, and that is not a failure.
    #[test]
    fn a_missing_vault_is_a_first_start() {
        let path = scratch("absent");
        let _ = fs::remove_file(&path);
        assert_eq!(
            Vault::open("any long passphrase at all", &path).expect("open"),
            None
        );
    }

    /// A file from a format this build does not speak must be refused rather
    /// than misread.
    #[test]
    fn a_future_format_is_refused_rather_than_misread() {
        let path = scratch("version");
        Vault::seal("the operator passphrase now", &path, b"contents").expect("seal");

        let mut raw = fs::read(&path).expect("read");
        raw[MAGIC.len()] = VERSION + 1;
        fs::write(&path, &raw).expect("write");

        let error = Vault::open("the operator passphrase now", &path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("format version"), "got: {error}");
        let _ = fs::remove_file(&path);
    }
}
