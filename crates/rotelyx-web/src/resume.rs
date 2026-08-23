//! Carrying a conversation across a restart.
//!
//! # The decision this encodes
//!
//! Saving was always the easy half. To carry on, the two sides have to find each
//! other again, and there were three ways to arrange that: `listen` reopening on
//! the same invitation, a `resume` command, or the mailbox.
//!
//! It is the first, and no new command. **An invitation already is the identity
//! of a conversation.** Every one is answered on its own transport key and
//! therefore at its own address; the per-conversation name both sides show each
//! other is derived from that address; and the file this module writes is named
//! after it. So a host that starts listening again is already answering where it
//! answered before, and a guest holding the same code already dials there. The
//! only thing missing was that neither of them looked to see whether they had
//! been here before.
//!
//! A `resume` command would have been a second way to do what `listen` does, and
//! the mailbox would have made a conversation depend on a server that the direct
//! path exists to avoid.
//!
//! # What is saved, and what that means if it is stolen
//!
//! Everything that makes somebody a participant: the signing key, the hybrid
//! decapsulation key, the credential, and OpenMLS's own storage, which is where
//! the group state lives. Whoever holds it can read what the group can read.
//!
//! So it is sealed with the same Argon2id and XChaCha20-Poly1305 as the identity
//! and under the same passphrase. An identity behind a passphrase next to a
//! conversation in the clear would make the passphrase on the identity a
//! decoration.
//!
//! # Why a restored conversation cannot speak until it has rekeyed
//!
//! A file is a copy, and a copy that starts sending is sending at generations
//! the other side has already seen. `Group::reopen` sets `restored_needs_rekey`
//! and `send` refuses until `rekey_after_restore` has committed a fresh epoch,
//! which the other side sees. That is not this module's cleverness; it is why
//! that flag exists, and this is the caller it was waiting for.

use anyhow::{Context, Result};
use rotelyx_core::store::{self, Paths};
use rotelyx_core::RotelyxId;
use rotelyx_crypto::{Conversation, Member, MemberState};

/// What is kept between runs: a participant, and which group they are in.
#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    member: MemberState,
    group_id: Vec<u8>,
}

/// Write the conversation reached at `address`.
pub fn save(
    paths: &Paths,
    address: &RotelyxId,
    member: &Member,
    conversation: &Conversation,
    passphrase: &str,
) -> Result<()> {
    let saved = Saved {
        member: member.export().context("exporting the member")?,
        group_id: conversation.group_id(),
    };
    let bytes = postcard::to_allocvec(&saved).context("encoding the conversation")?;
    store::save_conversation(&paths.conversation_at(address), &bytes, passphrase)
        .context("saving the conversation")?;
    Ok(())
}

/// Reopen the conversation reached at `address`, if there is one.
///
/// `None` means there is no file, which is the ordinary first run rather than a
/// failure. An error means there is one and it could not be used, which the
/// caller should say rather than quietly starting a new conversation: a person
/// who has talked to somebody before and is silently given a fresh conversation
/// gets a fresh safety number and no reason for it.
pub fn reopen(
    paths: &Paths,
    address: &RotelyxId,
    passphrase: &str,
) -> Result<Option<(Member, Conversation)>> {
    let path = paths.conversation_at(address);
    let Some(bytes) = store::load_conversation(&path, passphrase).with_context(|| {
        format!(
            "opening {}. The passphrase is the identity's; a conversation \
             sealed under a different one cannot be reopened",
            path.display()
        )
    })?
    else {
        return Ok(None);
    };

    let saved: Saved =
        postcard::from_bytes(&bytes).context("decoding the saved conversation")?;
    let member = Member::restore(saved.member).context("restoring the member")?;

    // `None` here means the file predates this conversation: the member is real
    // and the group is not in their storage. Told apart from a read failure on
    // purpose, because the answers differ: this one starts fresh, that one
    // stops.
    match Conversation::reopen(&member, &saved.group_id).context("reopening the conversation")? {
        Some(conversation) => Ok(Some((member, conversation))),
        None => Ok(None),
    }
}

/// Forget the conversation reached at `address`.
pub fn forget(paths: &Paths, address: &RotelyxId) -> Result<()> {
    store::forget_conversation(&paths.conversation_at(address))
        .context("forgetting the conversation")?;
    Ok(())
}
