//! The conversations this window has, kept between runs.
//!
//! # Why this exists
//!
//! A conversation met through a code lived entirely in memory. Closing the
//! window ended it, and the only way back was to meet again at a new code. The
//! phone client keeps a list and the desktop had none, so the same product
//! behaved like two different ones depending on which screen you were looking
//! at.
//!
//! [`resume`](crate::resume) already does this for the direct transport, where
//! an invitation is the identity of a conversation and a host that starts
//! listening again is already answering where it answered before. Nothing about
//! that applies here: a meeting code is spent the moment the conversation
//! exists, both sides leave the meeting place, and what identifies the
//! conversation afterwards is the group itself.
//!
//! # What is written down, and what that costs
//!
//! Two sealed blobs per conversation. One is the session, which is everything
//! that makes this device a member: signing key, decapsulation key, credential
//! and the group state. The other is the label and the transcript.
//!
//! **The transcript is the one place this program stores readable message text
//! at rest.** Everywhere else plaintext exists in memory for as long as it is on
//! screen. Both blobs are sealed with Argon2id and XChaCha20-Poly1305 under the
//! window's passphrase, the same one the identity is sealed with, because an
//! identity behind a passphrase beside a conversation in the clear makes the
//! passphrase a decoration.
//!
//! # Why a reopened conversation cannot speak until it has rekeyed
//!
//! A file is a copy, and a copy that starts sending is sending at generations
//! the other side has already seen. The core sets `restored_needs_rekey` on
//! reopen and refuses to send until `rekeyAfterRestore` has committed a fresh
//! epoch. The caller has to send that commit before anything else, which is
//! what [`reopen`] returns it for.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rotelyx_wasm::{Session, SessionKey};

/// What the list shows for one conversation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Row {
    /// The file this conversation lives in, and what reopening it takes.
    pub id: String,
    /// What the other side called themselves.
    pub label: String,
    /// The last line, for the list.
    pub last: String,
    /// Seconds since the Unix epoch of the last thing that happened.
    pub at: u64,
    /// How many members, so a conversation with somebody extra in it says so.
    pub members: usize,
}

/// One line of a transcript.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Line {
    pub text: String,
    /// Ours or theirs. A transcript that does not say is not a transcript.
    pub mine: bool,
    pub at: u64,
}

/// Everything about a conversation that is not the session itself.
#[derive(serde::Serialize, serde::Deserialize)]
struct Meta {
    label: String,
    mailbox: String,
    members: usize,
    at: u64,
    lines: Vec<Line>,
}

/// The file on disk: two sealed blobs and nothing readable.
///
/// The id is the file name rather than a field, so a file that is moved or
/// copied cannot claim to be a different conversation than the one it is.
#[derive(serde::Serialize, serde::Deserialize)]
struct Kept {
    session: String,
    meta: String,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Where conversations live: beside the identity, in a directory of their own.
fn dir(identity: &Path) -> PathBuf {
    let mut path = identity.to_path_buf();
    path.set_extension("conversations");
    path
}

fn file(identity: &Path, id: &str) -> PathBuf {
    dir(identity).join(format!("{id}.chat"))
}

/// The key every conversation in this identity is sealed with.
///
/// One key rather than one per conversation, and the reason is the list. A key
/// derived per file means an Argon2id derivation per row, and Argon2id here is
/// 64 MiB and three passes on purpose: a list of ten conversations would take
/// ten seconds to draw. The cost belongs at the door, once.
///
/// The salt lives in a blob of its own rather than in a field, because the only
/// way to recover a `SessionKey` from a salt is to unlock something sealed with
/// it. That blob holds nothing: what it is for is its own header.
pub fn key(identity: &Path, passphrase: &str) -> Result<SessionKey> {
    let directory = dir(identity);
    let anchor = directory.join("anchor");

    if let Ok(existing) = std::fs::read_to_string(&anchor) {
        let existing = existing.trim();
        return SessionKey::unlock(passphrase, existing).map_err(|e| {
            anyhow::anyhow!(
                "the conversations here were sealed with a different passphrase: {}",
                e
            )
        });
    }

    let fresh = SessionKey::create(passphrase).map_err(|e| anyhow::anyhow!("{e}"))?;
    let marker = rotelyx_wasm::seal_blob(&fresh, &data_encoding::BASE64.encode(b"rotelyx"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    std::fs::create_dir_all(&directory)
        .with_context(|| format!("making {}", directory.display()))?;
    restrict(&directory)?;
    std::fs::write(&anchor, marker).with_context(|| format!("writing {}", anchor.display()))?;
    restrict(&anchor)?;

    Ok(fresh)
}

/// A conversation's name on disk.
///
/// Taken from the group id, so the same conversation keeps the same file across
/// every epoch it ever moves through. A name taken from the label would collide
/// the moment two people chose the same one, and a name taken from the meeting
/// code would be a name for something already spent.
pub fn id_of(session: &Session) -> Result<String> {
    let id = session
        .group_id()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(id.chars().filter(|c| c.is_ascii_alphanumeric()).take(32).collect())
}

/// Write a conversation down, replacing whatever was there.
///
/// Called after every send and every receive, not on a timer and not on exit.
/// The ratchet turns on both, so a blob saved a message late cannot decrypt what
/// comes next, and a window that is killed rather than closed is the ordinary
/// way a program ends.
#[allow(clippy::too_many_arguments)]
pub fn save(
    identity: &Path,
    key: &SessionKey,
    session: &Session,
    label: &str,
    mailbox: &str,
    members: usize,
    lines: &[Line],
) -> Result<String> {
    let id = id_of(session)?;

    let sealed = session
        .seal_session(key)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let meta = Meta {
        label: label.to_string(),
        mailbox: mailbox.to_string(),
        members,
        at: now(),
        lines: lines.to_vec(),
    };
    let meta_json = serde_json::to_vec(&meta)?;
    let meta_sealed = rotelyx_wasm::seal_blob(key, &data_encoding::BASE64.encode(&meta_json))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let kept = Kept {
        session: sealed,
        meta: meta_sealed,
    };

    let directory = dir(identity);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("making {}", directory.display()))?;
    restrict(&directory)?;

    let path = file(identity, &id);
    std::fs::write(&path, serde_json::to_vec(&kept)?)
        .with_context(|| format!("writing {}", path.display()))?;
    restrict(&path)?;

    Ok(id)
}

/// Everything on disk, newest first.
///
/// A file that cannot be opened is skipped rather than fatal. The usual reason
/// is a different passphrase, which is not a corrupted file and not something to
/// stop the window over: the other conversations are still readable.
pub fn list(identity: &Path, key: &SessionKey) -> Vec<Row> {
    let directory = dir(identity);
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };

    let mut rows: Vec<Row> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|e| e == "chat"))
        .filter_map(|entry| {
            let id = entry.path().file_stem()?.to_string_lossy().into_owned();
            let meta = read_meta(&entry.path(), key).ok()?;
            Some(Row {
                id,
                label: meta.label,
                last: meta
                    .lines
                    .last()
                    .map(|line| line.text.clone())
                    .unwrap_or_default(),
                at: meta.at,
                members: meta.members,
            })
        })
        .collect();

    rows.sort_by(|a, b| b.at.cmp(&a.at));
    rows
}

/// Open one, and the commit that has to go out before it can speak.
///
/// The commit is not optional and not a detail the caller may skip. Until the
/// other side has applied it, this copy is sending at generations they have
/// already seen, which is why the core refuses to send at all before it.
pub fn reopen(
    identity: &Path,
    key: &SessionKey,
    id: &str,
) -> Result<(Session, String, Vec<Line>, String)> {
    let path = file(identity, id);
    let raw = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let kept: Kept = serde_json::from_slice(&raw).context("this is not a conversation file")?;

    let session =
        Session::unseal_session(&kept.session, key).map_err(|e| anyhow::anyhow!("{e}"))?;

    let meta = read_meta(&path, key)?;
    Ok((session, meta.label, meta.lines, meta.mailbox))
}

/// Forget one.
///
/// Removes the file and nothing else. The group still holds this device as a
/// member, so forgetting is not leaving: the others go on addressing a leaf that
/// no longer answers. Saying so is the caller's job.
pub fn forget(identity: &Path, id: &str) -> Result<()> {
    let path = file(identity, id);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

fn read_meta(path: &Path, key: &SessionKey) -> Result<Meta> {
    let raw = std::fs::read(path)?;
    let kept: Kept = serde_json::from_slice(&raw)?;

    let opened = rotelyx_wasm::open_blob(key, &kept.meta).map_err(|e| anyhow::anyhow!("{e}"))?;
    let bytes = data_encoding::BASE64.decode(opened.as_bytes())?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}
