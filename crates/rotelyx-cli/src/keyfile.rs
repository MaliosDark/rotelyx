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
use rotelyx_core::{sealed, Identity};

const PASSPHRASE_ENV: &str = "ROTELYX_PASSPHRASE";

/// Read a passphrase, preferring the environment so unattended runs work.
fn read_passphrase(prompt: &str) -> Result<String> {
    if let Ok(from_env) = std::env::var(PASSPHRASE_ENV) {
        eprintln!(
            "using {PASSPHRASE_ENV}. The environment of a process is readable by \
             anything running as this user; prefer the prompt for real keys."
        );
        return Ok(from_env);
    }
    rpassword::prompt_password(prompt).context("reading passphrase")
}

fn confirm_new_passphrase() -> Result<String> {
    if let Ok(from_env) = std::env::var(PASSPHRASE_ENV) {
        return Ok(from_env);
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
    Ok(first)
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
pub fn load_or_create(path: &Path) -> Result<Identity> {
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
        return Ok(identity);
    }

    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    if sealed::is_sealed(&bytes) {
        let passphrase = read_passphrase("Passphrase: ")?;
        return sealed::open(&bytes, &passphrase)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("opening sealed identity");
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

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rotelyx-keyfile-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_new_identity_is_sealed_on_disk() {
        let path = tmp("new");
        // SAFETY-adjacent: single threaded test, no other test reads this var.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "test-passphrase") };

        let identity = load_or_create(&path).expect("create");
        let bytes = std::fs::read(&path).expect("read");

        assert!(sealed::is_sealed(&bytes), "the key file is not sealed");
        assert_ne!(bytes.len(), 32, "the key was written raw");

        // And it opens again to the same identity.
        let again = load_or_create(&path).expect("reopen");
        assert_eq!(identity.id(), again.id());

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let _ = std::fs::remove_file(&path);
    }

    /// A key file from an older build must be upgraded rather than rejected.
    #[test]
    fn a_plaintext_key_is_migrated_in_place() {
        let path = tmp("migrate");
        let original = Identity::generate();
        std::fs::write(&path, &*original.to_storage_bytes()).expect("write raw");
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);

        unsafe { std::env::set_var(PASSPHRASE_ENV, "test-passphrase") };
        let loaded = load_or_create(&path).expect("migrate");

        assert_eq!(loaded.id(), original.id(), "migration changed the identity");
        assert!(
            sealed::is_sealed(&std::fs::read(&path).unwrap()),
            "the file is still plaintext after migration"
        );

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let _ = std::fs::remove_file(&path);
    }
}
