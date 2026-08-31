//! Opening circuit descriptors, and the key that does it.
//!
//! The vendored transport defines what it needs as a trait and never learns how
//! the sealing works. This is where the two meet: the relay binary is allowed
//! to know about both, so the implementation lives here rather than one layer
//! down.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rotelyx_crypto::circuit::SealedHop;
use rotelyx_crypto::hybrid::{HybridSecretKey, SECRET_KEY_LEN};
use rotelyx_net::EndpointId;
use rotelyx_relay_proto::server::circuits::{CircuitHop, CircuitOpener};

/// This relay's circuit key, and the id descriptors are bound to.
pub struct Opener {
    secret: HybridSecretKey,
    /// The relay's own endpoint id, bound into every descriptor's associated
    /// data so one sealed for another relay does not open here.
    exit_id: [u8; 32],
}

/// Deliberately says nothing about the key.
impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opener(circuit key held)")
    }
}

impl Opener {
    /// Loads the key at `path`, generating one the first time.
    ///
    /// # Why the key is written unsealed
    ///
    /// `HybridSecretKey::to_storage_bytes` says the caller should seal this
    /// before it touches a disk, and for a person's device that is right: there
    /// is a passphrase to seal with. A relay is unattended and restarts without
    /// anybody present, so there is no passphrase, and a key sealed with a key
    /// stored beside it is not sealed. It is written at `0600` and protected by
    /// the same thing that protects the relay's TLS key.
    ///
    /// What an operator who loses this file loses: the ability to terminate
    /// circuits, and nothing about anybody's messages. Delete it and the relay
    /// makes another.
    pub fn load_or_create(path: &Path, exit_id: EndpointId) -> Result<Self> {
        let secret = match std::fs::read(path) {
            Ok(bytes) => {
                let bytes: [u8; SECRET_KEY_LEN] =
                    bytes.as_slice().try_into().with_context(|| {
                        format!(
                            "{} is {} bytes, and a circuit key is {SECRET_KEY_LEN}",
                            path.display(),
                            bytes.len()
                        )
                    })?;
                HybridSecretKey::from_storage_bytes(bytes)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let (secret, _) = rotelyx_crypto::hybrid::HybridKem::generate();
                write_private(path, &secret.to_storage_bytes()[..])
                    .with_context(|| format!("writing {}", path.display()))?;
                tracing::info!(path = %path.display(), "made a circuit key");
                secret
            }
            Err(err) => bail!("reading {}: {err}", path.display()),
        };

        Ok(Self {
            secret,
            exit_id: *exit_id.as_bytes(),
        })
    }

    /// The half an operator publishes, so callers can seal circuits to it.
    pub fn public_key(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(&self.secret.public().to_bytes())
    }
}

impl CircuitOpener for Opener {
    fn open(&self, sealed: &[u8]) -> Option<CircuitHop> {
        let hop = SealedHop::from_bytes(sealed)
            .ok()?
            .open(&self.secret, &self.exit_id, current_hour())
            .ok()?;

        Some(CircuitHop {
            destination: EndpointId::from_bytes(&hop.destination).ok()?,
            return_key: EndpointId::from_bytes(&hop.return_key).ok()?,
            next_relay: hop.next_relay,
        })
    }
}

/// Hours since the Unix epoch, as the descriptor counts them.
fn current_hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0)
}

/// Writes a file only its owner can read.
///
/// The mode is set as the file is created, not after: a key that is briefly
/// world readable is a key that was world readable.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The relay's own opener opens what the crypto seals, and refuses what it
    /// should.
    ///
    /// The server's unit tests use a fake opener, because what they are about is
    /// the table. This is the seam those tests deliberately do not cross: the real
    /// key, the real sealing, and the conversion into the types the transport uses.
    #[test]
    fn the_relays_opener_opens_a_real_descriptor_and_refuses_the_rest() {
        let dir = std::env::temp_dir().join(format!("rotelyx-circuit-{}", std::process::id()));
        let key_path = dir.join("circuit.key");
        let _ = std::fs::remove_file(&key_path);

        let exit_id = rotelyx_net::SecretKey::from_bytes(&[11u8; 32]).public();
        let opener =
            Opener::load_or_create(&key_path, exit_id).expect("a key should be made on first use");

        let destination = rotelyx_net::SecretKey::from_bytes(&[12u8; 32]).public();
        let return_key = rotelyx_net::SecretKey::from_bytes(&[13u8; 32]).public();

        let exit_public = rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(
            &data_encoding::BASE64URL_NOPAD
                .decode(opener.public_key().as_bytes())
                .expect("the published key should decode"),
        )
        .expect("the published key should be a key");

        let hour = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
            / 3600;

        let sealed = rotelyx_crypto::circuit::SealedHop::seal(
            &exit_public,
            exit_id.as_bytes(),
            &rotelyx_crypto::circuit::Hop {
                destination: *destination.as_bytes(),
                return_key: *return_key.as_bytes(),
                next_relay: None,
                hour,
            },
        )
        .expect("seal");

        let hop = opener
            .open(&sealed.to_bytes())
            .expect("the relay should open a descriptor sealed to it");
        assert_eq!(
            hop.destination, destination,
            "the destination did not survive"
        );
        assert_eq!(hop.return_key, return_key, "the return key did not survive");

        assert!(
            opener.open(&[0u8; 8]).is_none(),
            "something that is not a descriptor was opened"
        );
        assert!(
            opener.open(&vec![0u8; sealed.to_bytes().len()]).is_none(),
            "a descriptor of the right length but no meaning was opened"
        );

        // The key persists, so a restart does not orphan every published address.
        let again = Opener::load_or_create(&key_path, exit_id)
            .expect("the key should load the second time");
        assert_eq!(
            again.public_key(),
            opener.public_key(),
            "the relay made a new key instead of loading the one it had"
        );

        let _ = std::fs::remove_file(&key_path);
    }
}
