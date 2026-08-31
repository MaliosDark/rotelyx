//! Loading and creating a sealed identity, with migration from plaintext.
//!
//! Shared by every binary so there is one place where a passphrase is read and
//! one place where a key file is written.
//!
//! ## Where the passphrase comes from
//!
//! `ROTELYX_PASSPHRASE` if it is set, otherwise an interactive prompt with the
//! echo turned off. The environment variable exists so scripts and tests can
//! run unattended; it is worse than the prompt, because the environment of a
//! process is readable by anything running as the same user, and the binary
//! says so when it uses it.

use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;
use rotelyx_core::{sealed, Identity};

const PASSPHRASE_ENV: &str = "ROTELYX_PASSPHRASE";

/// Read a passphrase, preferring the environment so unattended runs work.
fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(from_env) = std::env::var(PASSPHRASE_ENV) {
        eprintln!(
            "using {PASSPHRASE_ENV}. The environment of a process is readable by \
             anything running as this user; prefer the prompt for real keys."
        );
        return Ok(Zeroizing::new(from_env));
    }
    Ok(Zeroizing::new(
        rpassword::prompt_password(prompt).context("reading passphrase")?,
    ))
}

fn confirm_new_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(from_env) = std::env::var(PASSPHRASE_ENV) {
        return Ok(Zeroizing::new(from_env));
    }
    let first = rpassword::prompt_password("Choose a passphrase for this identity: ")
        .context("reading passphrase")?;
    let again = rpassword::prompt_password("Repeat it: ").context("reading passphrase")?;

    if first != again {
        bail!("the two passphrases do not match");
    }
    if first.is_empty() {
        // Refused rather than warned about. An empty passphrase means the file
        // is sealed with a key an attacker already knows.
        bail!("an empty passphrase seals the key with a value everybody knows");
    }
    Ok(Zeroizing::new(first))
}

fn restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    let _ = path;
    Ok(())
}

/// Load an identity, creating and sealing one if the file does not exist.
///
/// A plaintext key file left over from an earlier build is migrated in place
/// rather than rejected: refusing to start would just push people back to the
/// old binary.
/// The same, keeping the passphrase.
///
/// A saved conversation is sealed under the identity's passphrase, because it
/// is the same secret protecting the same person and asking for a second one
/// would mean two things to remember and one of them written down. The caller
/// gets it back rather than prompting again: a person asked twice for the same
/// passphrase in one command reasonably concludes the first attempt failed.
pub fn load_with_passphrase(path: &Path) -> Result<(Identity, Zeroizing<String>)> {
    if !path.exists() {
        let passphrase = confirm_new_passphrase()?;
        let identity = Identity::generate();
        let blob = sealed::seal(&identity, &passphrase).context("sealing new identity")?;

        std::fs::write(path, &blob).with_context(|| format!("writing {}", path.display()))?;
        restrict(path)?;

        eprintln!("new identity sealed to {}", path.display());
        eprintln!("identity {}", identity.id());
        eprintln!();
        eprintln!("There is no way to recover this key. There is no server holding a");
        eprintln!("copy and no password reset. Losing it loses the identity.");
        return Ok((identity, passphrase));
    }

    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    if sealed::is_sealed(&bytes) {
        let passphrase = read_passphrase("Passphrase: ")?;
        let identity = sealed::open(&bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("opening sealed identity")?;
        return Ok((identity, passphrase));
    }

    // Legacy plaintext key.
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("key file is neither sealed nor 32 raw bytes")?;
    let identity = Identity::from_bytes(raw);

    eprintln!("WARNING: {} holds an unsealed key. Sealing it now.", path.display());
    let passphrase = confirm_new_passphrase()?;
    let blob = sealed::seal(&identity, &passphrase).context("sealing migrated identity")?;
    std::fs::write(path, &blob).with_context(|| format!("writing {}", path.display()))?;
    restrict(path)?;
    eprintln!("sealed. The plaintext key is gone from {}.", path.display());

    Ok((identity, passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that touch the passphrase variable.
    ///
    /// The environment is process wide and cargo runs these tests as threads
    /// of one process, so without this each test clears the variable the other
    /// one is relying on. The result was a failure roughly one run in three,
    /// in whichever test lost the race, which is the worst kind: it looked
    /// like flakiness in the code under test rather than in the harness.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set the passphrase for the duration of a test and clear it afterwards,
    /// holding the lock across both.
    #[allow(
        dead_code,
        reason = "the guard is held for the value's lifetime, never read"
    )]
    struct Passphrase(std::sync::MutexGuard<'static, ()>);

    impl Passphrase {
        fn set() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: the lock is held for as long as this value lives, and
            // it is the only thing in this crate that touches the variable.
            unsafe { std::env::set_var(PASSPHRASE_ENV, "test-passphrase") };
            Self(guard)
        }
    }

    impl Drop for Passphrase {
        fn drop(&mut self) {
            // SAFETY: still under the lock, since the guard is a field here.
            unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rotelyx-keyfile-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_new_identity_is_sealed_on_disk() {
        let _passphrase = Passphrase::set();
        let path = tmp("new");

        let (identity, _) = load_with_passphrase(&path).expect("create");
        let bytes = std::fs::read(&path).expect("read");

        assert!(sealed::is_sealed(&bytes), "the key file is not sealed");
        assert_ne!(bytes.len(), 32, "the key was written raw");

        // And it opens again to the same identity.
        let (again, _) = load_with_passphrase(&path).expect("reopen");
        assert_eq!(identity.id(), again.id());

        let _ = std::fs::remove_file(&path);
    }

    /// A key file from an older build must be upgraded rather than rejected.
    #[test]
    fn a_plaintext_key_is_migrated_in_place() {
        let _passphrase = Passphrase::set();
        let path = tmp("migrate");
        let original = Identity::generate();
        std::fs::write(&path, &*original.to_storage_bytes()).expect("write raw");
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);

        let (loaded, _) = load_with_passphrase(&path).expect("migrate");

        assert_eq!(loaded.id(), original.id(), "migration changed the identity");
        assert!(
            sealed::is_sealed(&std::fs::read(&path).unwrap()),
            "the file is still plaintext after migration"
        );

        let _ = std::fs::remove_file(&path);
    }
}
