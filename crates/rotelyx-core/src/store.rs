//! On disk state for a device.
//!
//! Three files sit next to each other, named from the identity path:
//!
//! ```text
//!   alice.key       sealed identity, see the `sealed` module
//!   alice.invites   invitations this identity has issued
//! ```
//!
//! The blocklist is a file rather than memory for a reason that is easy to miss:
//! a block that does not survive a restart is not a block. The person you
//! blocked reaches you again the next time the app starts, and nothing tells
//! you it happened.
//!
//! Invitations are stored in the clear. They are already known to
//! the parties they concern, and neither can be used to read a message. The
//! identity key is the only thing here worth sealing, and it is sealed.

use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;

use crate::access::Invitation;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("writing {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} line {line}: {reason}")]
    Malformed {
        path: PathBuf,
        line: usize,
        reason: String,
    },
}

/// Paths derived from one identity file.
#[derive(Debug, Clone)]
pub struct Paths {
    pub identity: PathBuf,
    pub invitations: PathBuf,
    /// Where a conversation is kept between runs, sealed.
    pub conversation: PathBuf,
}

impl Paths {
    pub fn from_identity(identity: impl AsRef<Path>) -> Self {
        let identity = identity.as_ref().to_path_buf();
        Self {
            invitations: identity.with_extension("invites"),
            conversation: identity.with_extension("conversation"),
            identity,
        }
    }

    /// Where the conversation reached at `address` is kept.
    ///
    /// # Why per address rather than one file
    ///
    /// A device has as many conversations as it has live invitations, because
    /// every invitation is answered on its own transport key and therefore at
    /// its own address. One file would mean the second conversation overwrote
    /// the first, silently, and the person would find one of them gone.
    ///
    /// The address is the right name for the file for the same reason it is the
    /// right thing to derive a per-conversation name from: it is what both sides
    /// share and neither chose. It is also not secret, so a filename carrying it
    /// tells somebody reading the directory exactly what the directory listing
    /// already told them, which is that a conversation exists.
    pub fn conversation_at(&self, address: &crate::identity::RotelyxId) -> PathBuf {
        let short: String = address.to_string().chars().take(16).collect();
        self.conversation.with_extension(format!("{short}.conversation"))
    }
}

/// Restrict a file to its owner. A world readable key or blocklist tells
/// anyone with an account on the machine who you talk to and who you avoid.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn write_restricted(path: &Path, contents: &str) -> Result<(), StoreError> {
    std::fs::write(path, contents).map_err(|source| StoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    restrict(path).map_err(|source| StoreError::Write {
        path: path.to_path_buf(),
        source,
    })
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

/// One issued invitation as it appears on disk.
#[derive(Debug, Clone)]
pub struct StoredInvitation {
    pub secret: [u8; 32],
    /// The transport key this invitation is answered on.
    ///
    /// Stored rather than derived, because the holder of the code must not be
    /// able to work it out: it is the private key of the endpoint they call.
    pub transport: [u8; 32],
    pub expires_at_epoch: u64,
}

impl StoredInvitation {
    pub fn to_invitation(&self) -> Invitation {
        Invitation::from_parts(self.secret, self.transport, self.expires_at_epoch)
    }

    /// The code to hand to the person being invited: the secret, and the
    /// address to call. Sixty four bytes rather than thirty two, because an
    /// address that is not the identity has to travel somehow.
    pub fn code(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(&self.to_invitation().code()[..])
    }
}

/// Load issued invitations, dropping any that expired before `now_epoch`.
///
/// Pruning on load rather than only on save means a stale file cannot silently
/// keep an expired invitation working.
pub fn load_invitations(path: &Path, now_epoch: u64) -> Result<Vec<StoredInvitation>, StoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let malformed = |reason: &str| StoreError::Malformed {
            path: path.to_path_buf(),
            line: n + 1,
            reason: reason.into(),
        };

        // `secret transport expiry`. A line with two fields is from a build
        // before invitations had an address, and is dropped rather than
        // migrated: it was answered on the identity, there is no transport key
        // to invent for it, and inventing one would produce an address the
        // holder of that code has never been told. Reissuing is the migration.
        let mut fields = line.split_whitespace();
        let (Some(code), Some(transport), Some(expiry)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };

        let decode32 = |s: &str, what: &str| -> Result<[u8; 32], StoreError> {
            let bytes = data_encoding::BASE64URL_NOPAD
                .decode(s.as_bytes())
                .map_err(|_| malformed(&format!("{what} is not valid base64")))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| malformed(&format!("{what} is not 32 bytes")))
        };

        let secret = decode32(code, "secret")?;
        let transport = decode32(transport, "transport key")?;
        let expires_at_epoch: u64 = expiry
            .trim()
            .parse()
            .map_err(|_| malformed("expiry is not a number"))?;

        if expires_at_epoch >= now_epoch {
            out.push(StoredInvitation {
                secret,
                transport,
                expires_at_epoch,
            });
        }
    }
    Ok(out)
}

pub fn save_invitations(path: &Path, invitations: &[StoredInvitation]) -> Result<(), StoreError> {
    let mut out = String::from(
        "# Rotelyx invitations. `secret transport expiry-epoch` per line.\n         # The secret authorises and the transport key is the address it is\n         # answered on. Both are secrets: treat this file as a keyring.\n",
    );
    for inv in invitations {
        out.push_str(&data_encoding::BASE64URL_NOPAD.encode(&inv.secret));
        out.push(' ');
        out.push_str(&data_encoding::BASE64URL_NOPAD.encode(&inv.transport));
        out.push(' ');
        out.push_str(&inv.expires_at_epoch.to_string());
        out.push('\n');
    }
    write_restricted(path, &out)
}

/// Append one invitation, keeping the rest.
///
/// Read, modify, write rather than a bare append, so that expired entries are
/// pruned every time a new one is issued.
/// Write a conversation down, sealed under the same passphrase as the identity.
///
/// # Why sealed and not merely a file
///
/// The bytes are the participant. Whoever holds them can read everything the
/// group's current epochs can read, which is more than any single message. A
/// sealed identity sitting next to an unsealed conversation would make the seal
/// on the identity a decoration.
///
/// The caller decides what the bytes are: this layer does not know what an MLS
/// group looks like and should not have to, so it takes something already
/// serialised and gives it back unchanged.
pub fn save_conversation(
    path: &Path,
    state: &[u8],
    passphrase: &str,
) -> Result<(), StoreError> {
    let sealed = crate::sealed::seal_bytes(state, passphrase).map_err(|e| StoreError::Write {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    std::fs::write(path, sealed).map_err(|source| StoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    // Owner only. A conversation on a shared machine is the participant, and
    // anybody who can read it is in the group.
    restrict(path).map_err(|source| StoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Read a conversation back. `None` when there is no file, which is the
/// ordinary case for a first run rather than an error.
pub fn load_conversation(path: &Path, passphrase: &str) -> Result<Option<Vec<u8>>, StoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    crate::sealed::open_bytes(&bytes, passphrase)
        .map(|p| Some(p.to_vec()))
        .map_err(|e| StoreError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::other(e.to_string()),
        })
}

/// Forget a conversation. Called when one ends, so what is left on the disk is
/// what somebody is actually in.
pub fn forget_conversation(path: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn add_invitation(
    path: &Path,
    invitation: StoredInvitation,
    now_epoch: u64,
) -> Result<(), StoreError> {
    let mut all = load_invitations(path, now_epoch)?;
    all.push(invitation);
    save_invitations(path, &all)
}

/// Retire one issued invitation, by the secret inside its code.
///
/// # Why this is what blocking means here
///
/// There is no identity to ban. A caller presents a per-invitation transport
/// key, and the name anybody sees is derived per conversation, so a blocklist of
/// identities is a list of values that never arrive. What does arrive is an
/// invitation, and an invitation is a thing this side issued and can withdraw.
///
/// So "block this person" is "withdraw the way they get in". It is verified
/// against a secret this side holds rather than against something the caller
/// chose to say about itself, which is why it works where the blocklist did not.
///
/// It stops the next connection, not the current one: a session already open
/// stays open until it closes. Callers should say so rather than implying a
/// hang-up.
pub fn revoke_invitation(
    path: &Path,
    secret: &[u8; 32],
    now_epoch: u64,
) -> Result<bool, StoreError> {
    let all = load_invitations(path, now_epoch)?;
    let before = all.len();
    let kept: Vec<StoredInvitation> = all
        .into_iter()
        .filter(|inv| !bool::from(inv.secret.ct_eq(secret)))
        .collect();

    if kept.len() == before {
        return Ok(false);
    }
    save_invitations(path, &kept)?;
    Ok(true)
}

#[cfg(test)]
mod tests {

    /// A conversation on the disk must be worth nothing without the passphrase.
    ///
    /// # Why this matters more than it looks
    ///
    /// The bytes are the participant, not a message: whoever holds them reads
    /// everything the group's current epochs can read. A sealed identity beside
    /// an unsealed conversation would make the seal on the identity a
    /// decoration, so this asserts the file is sealed rather than merely
    /// written, and that a wrong passphrase gets nothing.
    #[test]
    fn a_saved_conversation_is_sealed() {
        let path = tmp("sealed-conversation");
        let state = b"whatever an MLS group serialises to";

        save_conversation(&path, state, "the right passphrase").expect("save");

        let raw = std::fs::read(&path).expect("read");
        assert!(
            !raw.windows(state.len()).any(|w| w == state),
            "the conversation was written in the clear"
        );
        assert!(
            crate::sealed::is_sealed(&raw),
            "the file is not in the sealed format"
        );

        assert_eq!(
            load_conversation(&path, "the right passphrase").expect("load"),
            Some(state.to_vec())
        );
        assert!(
            load_conversation(&path, "a different passphrase").is_err(),
            "a wrong passphrase opened it"
        );
    }

    /// No file is an ordinary first run, not a failure.
    #[test]
    fn no_saved_conversation_is_not_an_error() {
        let path = tmp("no-conversation");
        assert_eq!(load_conversation(&path, "anything").expect("load"), None);

        // And forgetting one that is not there is not a failure either: a
        // conversation ends the same way whether or not it was ever saved.
        forget_conversation(&path).expect("forget");
    }

    /// Forgetting must actually remove it.
    #[test]
    fn a_forgotten_conversation_is_gone() {
        let path = tmp("forgotten-conversation");
        save_conversation(&path, b"state", "phrase").expect("save");
        forget_conversation(&path).expect("forget");
        assert_eq!(load_conversation(&path, "phrase").expect("load"), None);
    }

    use super::*;
    use crate::identity::Identity;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rotelyx-store-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    // --- invitations ---

    #[test]
    fn invitations_roundtrip() {
        let path = tmp("invites");
        let inv = StoredInvitation {
            secret: [3u8; 32],
            transport: [0x5a; 32],
            expires_at_epoch: 500,
        };
        save_invitations(&path, &[inv.clone()]).expect("save");

        let back = load_invitations(&path, 100).expect("load");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].secret, inv.secret);
        let _ = std::fs::remove_file(&path);
    }

    /// An expired invitation must not come back to life because the file still
    /// mentions it.
    #[test]
    fn expired_invitations_are_dropped_on_load() {
        let path = tmp("invites-expiry");
        save_invitations(
            &path,
            &[
                StoredInvitation { secret: [1u8; 32], transport: [0x5a; 32], expires_at_epoch: 50 },
                StoredInvitation { secret: [2u8; 32], transport: [0x5a; 32], expires_at_epoch: 500 },
            ],
        )
        .expect("save");

        let live = load_invitations(&path, 100).expect("load");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].secret, [2u8; 32]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn adding_an_invitation_prunes_expired_ones() {
        let path = tmp("invites-prune");
        save_invitations(
            &path,
            &[StoredInvitation { secret: [1u8; 32], transport: [0x5a; 32], expires_at_epoch: 50 }],
        )
        .expect("save");

        add_invitation(
            &path,
            StoredInvitation { secret: [9u8; 32], transport: [0x5a; 32], expires_at_epoch: 500 },
            100,
        )
        .expect("add");

        let all = load_invitations(&path, 100).expect("load");
        assert_eq!(all.len(), 1, "the expired invitation was kept");
        assert_eq!(all[0].secret, [9u8; 32]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn paths_are_derived_from_the_identity_file() {
        let p = Paths::from_identity("/tmp/alice.key");
        assert!(p.invitations.ends_with("alice.invites"));
    }

    #[cfg(unix)]
    #[test]
    fn saved_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("perms");
        save_invitations(&path, &[]).expect("save");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "an invitation file is readable by others");
        let _ = std::fs::remove_file(&path);
    }
}
