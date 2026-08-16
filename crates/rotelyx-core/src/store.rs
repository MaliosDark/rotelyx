//! On disk state for a device.
//!
//! Three files sit next to each other, named from the identity path:
//!
//! ```text
//!   alice.key       sealed identity, see the `sealed` module
//!   alice.invites   invitations this identity has issued
//!   alice.blocks    identities this device refuses
//! ```
//!
//! The blocklist is a file rather than memory for a reason that is easy to miss:
//! a block that does not survive a restart is not a block. The person you
//! blocked reaches you again the next time the app starts, and nothing tells
//! you it happened.
//!
//! Invitations and blocks are stored in the clear. Both are already known to
//! the parties they concern, and neither can be used to read a message. The
//! identity key is the only thing here worth sealing, and it is sealed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::access::Invitation;
use crate::identity::RotelyxId;

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
    pub blocks: PathBuf,
}

impl Paths {
    pub fn from_identity(identity: impl AsRef<Path>) -> Self {
        let identity = identity.as_ref().to_path_buf();
        Self {
            invitations: identity.with_extension("invites"),
            blocks: identity.with_extension("blocks"),
            identity,
        }
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

fn write_restricted(path: &Path, contents: &str) -> Result<(), StoreError> {
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
// Blocklist
// ---------------------------------------------------------------------------

/// Identities this device refuses, persisted across restarts.
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    entries: HashSet<RotelyxId>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a blocklist. A missing file is an empty list, not an error: a
    /// device that has blocked nobody has nothing to load.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let mut entries = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let id: RotelyxId = line.parse().map_err(|_| StoreError::Malformed {
                path: path.to_path_buf(),
                line: n + 1,
                reason: "not an identity".into(),
            })?;
            entries.insert(id);
        }
        Ok(Self { entries })
    }

    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let mut out = String::from("# Rotelyx blocklist. One identity per line.\n");
        // Sorted so the file does not churn between saves, which makes it
        // reviewable in a diff and in version control.
        let mut ids: Vec<_> = self.entries.iter().map(ToString::to_string).collect();
        ids.sort();
        for id in ids {
            out.push_str(&id);
            out.push('\n');
        }
        write_restricted(path, &out)
    }

    pub fn insert(&mut self, id: RotelyxId) -> bool {
        self.entries.insert(id)
    }

    pub fn remove(&mut self, id: &RotelyxId) -> bool {
        self.entries.remove(id)
    }

    pub fn contains(&self, id: &RotelyxId) -> bool {
        self.entries.contains(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &RotelyxId> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

/// One issued invitation as it appears on disk.
#[derive(Debug, Clone)]
pub struct StoredInvitation {
    pub secret: [u8; 32],
    pub expires_at_epoch: u64,
}

impl StoredInvitation {
    pub fn to_invitation(&self) -> Invitation {
        Invitation::from_secret(self.secret, self.expires_at_epoch)
    }

    /// The code to hand to the person being invited.
    pub fn code(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(&self.secret)
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

        let (code, expiry) = line.split_once(' ').ok_or_else(|| malformed("expected `code expiry`"))?;
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(code.as_bytes())
            .map_err(|_| malformed("code is not valid base64"))?;
        let secret: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| malformed("secret is not 32 bytes"))?;
        let expires_at_epoch: u64 = expiry
            .trim()
            .parse()
            .map_err(|_| malformed("expiry is not a number"))?;

        if expires_at_epoch >= now_epoch {
            out.push(StoredInvitation {
                secret,
                expires_at_epoch,
            });
        }
    }
    Ok(out)
}

pub fn save_invitations(path: &Path, invitations: &[StoredInvitation]) -> Result<(), StoreError> {
    let mut out = String::from("# Rotelyx invitations. `code expiry-epoch` per line. Treat as passwords.\n");
    for inv in invitations {
        out.push_str(&inv.code());
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
pub fn add_invitation(
    path: &Path,
    invitation: StoredInvitation,
    now_epoch: u64,
) -> Result<(), StoreError> {
    let mut all = load_invitations(path, now_epoch)?;
    all.push(invitation);
    save_invitations(path, &all)
}

#[cfg(test)]
mod tests {
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

    // --- blocklist ---

    /// The property this file exists for.
    #[test]
    fn a_block_survives_a_restart() {
        let path = tmp("blocks-survive");
        let blocked = Identity::generate().id();

        let mut list = Blocklist::new();
        list.insert(blocked);
        list.save(&path).expect("save");

        // A fresh process would do exactly this.
        let reloaded = Blocklist::load(&path).expect("load");
        assert!(reloaded.contains(&blocked));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unblocking_persists_too() {
        let path = tmp("blocks-unblock");
        let blocked = Identity::generate().id();

        let mut list = Blocklist::new();
        list.insert(blocked);
        list.save(&path).expect("save");

        let mut list = Blocklist::load(&path).expect("load");
        assert!(list.remove(&blocked));
        list.save(&path).expect("save");

        assert!(!Blocklist::load(&path).expect("load").contains(&blocked));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_blocklist_is_empty_rather_than_an_error() {
        let path = tmp("blocks-missing");
        assert!(Blocklist::load(&path).expect("load").is_empty());
    }

    #[test]
    fn a_malformed_blocklist_line_names_the_line() {
        let path = tmp("blocks-bad");
        std::fs::write(&path, "# ok\nnot-an-identity\n").expect("write");

        match Blocklist::load(&path) {
            Err(StoreError::Malformed { line, .. }) => assert_eq!(line, 2),
            other => panic!("expected a malformed error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_blocklist_file_does_not_churn_between_saves() {
        let path = tmp("blocks-stable");
        let mut list = Blocklist::new();
        for _ in 0..8 {
            list.insert(Identity::generate().id());
        }

        list.save(&path).expect("save");
        let first = std::fs::read_to_string(&path).expect("read");
        Blocklist::load(&path).expect("load").save(&path).expect("save");
        let second = std::fs::read_to_string(&path).expect("read");

        assert_eq!(first, second, "a reload and resave changed the file");
        let _ = std::fs::remove_file(&path);
    }

    // --- invitations ---

    #[test]
    fn invitations_roundtrip() {
        let path = tmp("invites");
        let inv = StoredInvitation {
            secret: [3u8; 32],
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
                StoredInvitation { secret: [1u8; 32], expires_at_epoch: 50 },
                StoredInvitation { secret: [2u8; 32], expires_at_epoch: 500 },
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
            &[StoredInvitation { secret: [1u8; 32], expires_at_epoch: 50 }],
        )
        .expect("save");

        add_invitation(
            &path,
            StoredInvitation { secret: [9u8; 32], expires_at_epoch: 500 },
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
        assert!(p.blocks.ends_with("alice.blocks"));
    }

    #[cfg(unix)]
    #[test]
    fn saved_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("blocks-perms");
        Blocklist::new().save(&path).expect("save");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "blocklist is readable by others");
        let _ = std::fs::remove_file(&path);
    }
}
