//! Carrying state off a device and bringing it back, without handing somebody a
//! way to rewind it.
//!
//! # A backup is a rollback vector. That is what a backup is
//!
//! There is no format that changes this, so the first thing to be honest about
//! is what is actually on the table. A file that restores a group to the state
//! it held an hour ago restores everything about that hour: the message keys
//! that were used and deleted, the generations already spent, the members who
//! have since left. Forward secrecy is the deletion of those keys, and a backup
//! is a copy of them made before the deletion.
//!
//! So this does not prevent rollback. It does three narrower things, and each
//! one is worth having on its own:
//!
//! 1. **The file is sealed**, under the same Argon2id and XChaCha20-Poly1305 as
//!    the identity. A backup left on a laptop is otherwise the whole
//!    conversation in the clear, which would make the seal on the identity a
//!    decoration.
//! 2. **The device notices.** A restore that moves the group backwards is
//!    refused, because the device keeps a high-water mark of the furthest epoch
//!    it has ever held and that mark does not live inside the backup.
//! 3. **The restored copy cannot send until it has rekeyed.** `Group::reopen`
//!    already sets `restored_needs_rekey`, so a restored member has to commit a
//!    fresh epoch before it can encrypt anything. Without that it would reuse a
//!    generation, and reusing a generation with the same key is the failure
//!    every one of these mechanisms exists to prevent.
//!
//! # What the high-water mark does not defend against
//!
//! It is a file on the same device. An attacker who can restore the whole
//! device restores the mark with it, and then the rollback is invisible.
//!
//! That is not a hole to be closed here, because closing it needs somewhere the
//! device cannot rewrite: a hardware counter, or the other member noticing. The
//! other member noticing is the real defence and it already exists, in that a
//! rolled-back copy must rekey before it speaks, and the rekey is a commit the
//! other side sees. What the mark stops is the ordinary case, which is somebody
//! restoring an old file by accident, and that case is far more likely than the
//! other one.

use std::path::Path;

use crate::sealed::{open_bytes, seal_bytes, SealError};
use crate::store::{write_restricted, StoreError};

/// Recognises a backup before anything tries to open it.
const MAGIC: &[u8; 8] = b"RTLXBAK\0";

/// Format version, so a future change is refused rather than misread.
const VERSION: u8 = 1;

/// `MAGIC` + version + sequence + epoch + created + length.
const HEADER_LEN: usize = 8 + 1 + 8 + 8 + 8 + 4;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("not a Rotelyx backup")]
    BadMagic,

    #[error("backup uses format version {found}, this build understands {understood}")]
    UnsupportedVersion { found: u8, understood: u8 },

    #[error("backup is truncated: {len} bytes, at least {min} needed")]
    Truncated { len: usize, min: usize },

    #[error(
        "refusing to restore: this backup holds epoch {backup}, and this device has \
         already been at epoch {seen}. Restoring would reuse message keys that were \
         spent after this file was written"
    )]
    Rollback { backup: u64, seen: u64 },

    #[error(transparent)]
    Seal(#[from] SealError),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// One backup, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// Increases with every backup this device writes, so two files can be
    /// ordered without trusting their timestamps.
    pub sequence: u64,
    /// The group epoch the state inside is at. This is what rollback is measured
    /// in: epochs only ever go forwards.
    pub epoch: u64,
    /// When it was written, in the project's hour-long epochs. For a person
    /// reading a list of files, not for any decision made here.
    pub created_at_epoch: u64,
    /// The sealed payload: whatever `store::save_conversation` would have kept.
    pub state: Vec<u8>,
}

/// Seal a backup into bytes.
///
/// The header travels in the clear so a file can be recognised, ordered and
/// refused without the passphrase. It says which epoch the state is at and
/// nothing about what is in it: an attacker who can read the file already knows
/// they have a Rotelyx backup, and learning that it is at epoch 41 tells them
/// how long a conversation has been running, which they can also learn from the
/// file's date.
///
/// The header is **authenticated**, not merely present, because it is the input
/// to the rollback check: an attacker who could edit the epoch in the clear
/// could walk any backup past that check. It goes in as associated data by
/// being sealed alongside the state rather than beside it.
pub fn seal(backup: &Backup, passphrase: &str) -> Result<Vec<u8>, BackupError> {
    let mut payload = Vec::with_capacity(HEADER_LEN + backup.state.len());
    payload.extend_from_slice(MAGIC);
    payload.push(VERSION);
    payload.extend_from_slice(&backup.sequence.to_be_bytes());
    payload.extend_from_slice(&backup.epoch.to_be_bytes());
    payload.extend_from_slice(&backup.created_at_epoch.to_be_bytes());
    payload.extend_from_slice(&(backup.state.len() as u32).to_be_bytes());
    payload.extend_from_slice(&backup.state);

    Ok(seal_bytes(&payload, passphrase)?)
}

/// Open a backup. Says nothing about whether restoring it is safe: see
/// [`refuse_rollback`].
pub fn open(bytes: &[u8], passphrase: &str) -> Result<Backup, BackupError> {
    let payload = open_bytes(bytes, passphrase)?;

    if payload.len() < HEADER_LEN {
        return Err(BackupError::Truncated {
            len: payload.len(),
            min: HEADER_LEN,
        });
    }
    if &payload[..8] != MAGIC {
        return Err(BackupError::BadMagic);
    }
    if payload[8] != VERSION {
        return Err(BackupError::UnsupportedVersion {
            found: payload[8],
            understood: VERSION,
        });
    }

    let u64_at = |at: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&payload[at..at + 8]);
        u64::from_be_bytes(buf)
    };
    let sequence = u64_at(9);
    let epoch = u64_at(17);
    let created_at_epoch = u64_at(25);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&payload[33..37]);
    let len = u32::from_be_bytes(len_bytes) as usize;

    if payload.len() < HEADER_LEN + len {
        return Err(BackupError::Truncated {
            len: payload.len(),
            min: HEADER_LEN + len,
        });
    }

    Ok(Backup {
        sequence,
        epoch,
        created_at_epoch,
        state: payload[HEADER_LEN..HEADER_LEN + len].to_vec(),
    })
}

/// The furthest epoch this device has ever held, for one group.
///
/// Kept outside every backup on purpose. A mark that travelled inside the file
/// would be restored along with it and would agree with whatever it was asked
/// to agree with.
pub fn high_water(path: &Path) -> Result<u64, BackupError> {
    if !path.exists() {
        return Ok(0);
    }
    let text = std::fs::read_to_string(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(text.trim().parse().unwrap_or(0))
}

/// Record that this device has reached `epoch`.
///
/// Only ever moves forwards. A caller that passes an older epoch is not an error
/// and does not move the mark: that is the ordinary case of an old copy being
/// opened, and the mark exists precisely so that it does not count.
pub fn record_epoch(path: &Path, epoch: u64) -> Result<(), BackupError> {
    let seen = high_water(path)?;
    if epoch <= seen {
        return Ok(());
    }
    write_restricted(path, &format!("{epoch}\n"))?;
    Ok(())
}

/// Refuse a restore that would move this device backwards.
///
/// Equal epochs are allowed: restoring the state you already have is a no-op,
/// and refusing it would make a backup useless as a way of moving a
/// conversation between two devices that are already in step.
pub fn refuse_rollback(mark: &Path, backup: &Backup) -> Result<(), BackupError> {
    let seen = high_water(mark)?;
    if backup.epoch < seen {
        return Err(BackupError::Rollback {
            backup: backup.epoch,
            seen,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rotelyx-backup-{name}"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn sample() -> Backup {
        Backup {
            sequence: 7,
            epoch: 41,
            created_at_epoch: 480_000,
            state: b"whatever save_conversation would have kept".to_vec(),
        }
    }

    #[test]
    fn a_backup_survives_the_round_trip() {
        let sealed = seal(&sample(), "a passphrase").expect("seal");
        assert_eq!(open(&sealed, "a passphrase").expect("open"), sample());
    }

    /// The property the seal exists for.
    #[test]
    fn the_state_is_not_in_the_file() {
        let backup = sample();
        let sealed = seal(&backup, "a passphrase").expect("seal");
        assert!(
            !sealed
                .windows(backup.state.len())
                .any(|w| w == backup.state.as_slice()),
            "the conversation state is sitting in the backup in the clear"
        );
    }

    #[test]
    fn the_wrong_passphrase_gets_nothing() {
        let sealed = seal(&sample(), "a passphrase").expect("seal");
        assert!(open(&sealed, "the wrong one").is_err());
    }

    /// The header decides whether a restore is refused, so editing it must not
    /// be possible without the passphrase.
    #[test]
    fn the_epoch_cannot_be_edited_by_somebody_who_cannot_open_it() {
        let mut sealed = seal(&sample(), "a passphrase").expect("seal");
        let last = sealed.len() - 1;

        // The header sits inside the ciphertext, so a sample is enough: the
        // salt, the nonce, the first byte of the body where the magic and the
        // epoch live, somewhere in the middle, and the tag. Every byte would be
        // an Argon2id run each and half a minute of test for a property the
        // AEAD provides uniformly.
        for at in [9, 30, 49, sealed.len() / 2, last] {
            sealed[at] ^= 0x01;
            assert!(
                open(&sealed, "a passphrase").is_err(),
                "byte {at} was changed and the backup still opened"
            );
            sealed[at] ^= 0x01;
        }
    }

    /// The property the whole file exists for.
    #[test]
    fn a_backup_from_before_the_group_moved_on_is_refused() {
        let mark = tmp("rollback");
        record_epoch(&mark, 41).expect("record");
        record_epoch(&mark, 45).expect("record");

        let old = Backup {
            epoch: 41,
            ..sample()
        };
        assert!(
            matches!(
                refuse_rollback(&mark, &old),
                Err(BackupError::Rollback {
                    backup: 41,
                    seen: 45
                })
            ),
            "a backup from four epochs ago was allowed to restore"
        );

        let current = Backup {
            epoch: 45,
            ..sample()
        };
        assert!(
            refuse_rollback(&mark, &current).is_ok(),
            "restoring the epoch this device is already at was refused"
        );

        let _ = std::fs::remove_file(&mark);
    }

    #[test]
    fn the_mark_only_moves_forwards() {
        let mark = tmp("forwards");
        record_epoch(&mark, 90).expect("record");
        record_epoch(&mark, 12).expect("record");
        assert_eq!(
            high_water(&mark).expect("read"),
            90,
            "opening an old copy dragged the mark backwards, which is the thing \
             it exists to survive"
        );
        let _ = std::fs::remove_file(&mark);
    }

    #[test]
    fn a_device_that_has_never_recorded_anything_refuses_nothing() {
        let mark = tmp("fresh");
        assert_eq!(high_water(&mark).expect("read"), 0);
        assert!(refuse_rollback(&mark, &sample()).is_ok());
    }

    #[test]
    fn something_that_is_not_a_backup_is_refused_by_name() {
        let sealed = crate::sealed::seal_bytes(b"not a backup", "a passphrase").expect("seal");
        assert!(matches!(
            open(&sealed, "a passphrase"),
            Err(BackupError::Truncated { .. }) | Err(BackupError::BadMagic)
        ));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_misread() {
        let mut payload = Vec::new();
        payload.extend_from_slice(MAGIC);
        payload.push(VERSION + 1);
        payload.extend_from_slice(&[0u8; 28]);
        let sealed = crate::sealed::seal_bytes(&payload, "a passphrase").expect("seal");

        assert!(matches!(
            open(&sealed, "a passphrase"),
            Err(BackupError::UnsupportedVersion { .. })
        ));
    }
}
