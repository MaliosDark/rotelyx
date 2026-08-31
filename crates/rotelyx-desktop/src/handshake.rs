//! Bringing an MLS conversation up over a live transport session.
//!
//! MLS needs three things moved between two devices before anyone can speak: a
//! key package from the joiner, a welcome from the inviter, and the public
//! ratchet tree. This module carries them over the framed session and nothing
//! else: no negotiation, no options, no fallbacks.
//!
//! ## Roles are fixed by who dialled
//!
//! The listener creates the group and invites; the dialer joins. That is
//! arbitrary but it must be *decided*, because two peers who both try to create
//! a group end up in two different groups that can never converge. Deciding it
//! by who dialled needs no extra round trip and cannot deadlock.
//!
//! ## What this does not do
//!
//! Verify that the peer is who you think. The transport authenticates the
//! peer's *key*; whether that key belongs to the person you mean is what safety
//! numbers are for, and the caller must show them.

use anyhow::{bail, Context, Result};
use rotelyx_core::{Frame, FrameKind, Session, WIRE_VERSION};
use rotelyx_crypto::{Conversation, Member};

/// Wire form of the inviter's reply: welcome and ratchet tree, length-prefixed.
///
/// Two variable-length blobs in one frame, so the length prefix is mandatory,
/// without it the boundary is guesswork.
fn encode_welcome(welcome: &[u8], tree: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + welcome.len() + tree.len());
    out.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    out.extend_from_slice(welcome);
    out.extend_from_slice(&(tree.len() as u32).to_be_bytes());
    out.extend_from_slice(tree);
    out
}

fn decode_welcome(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.len() < 4 {
        bail!("welcome frame truncated");
    }
    let w_len = u32::from_be_bytes(bytes[0..4].try_into()?) as usize;
    let rest = &bytes[4..];
    if rest.len() < w_len + 4 {
        bail!("welcome frame truncated");
    }
    let welcome = &rest[..w_len];
    let rest = &rest[w_len..];
    let t_len = u32::from_be_bytes(rest[0..4].try_into()?) as usize;
    let rest = &rest[4..];
    if rest.len() < t_len {
        bail!("ratchet tree truncated");
    }
    Ok((welcome, &rest[..t_len]))
}

/// Say which wire this build speaks, before anything that depends on it.
///
/// This costs one round trip at the start of a conversation, and it is written
/// down rather than hidden because an earlier draft of this comment claimed it
/// did not. It could be folded into the frame that follows and it is not worth
/// the tangle: this runs once when two people start talking, not once per
/// message, and the thing it buys is that a build which cannot be talked to is
/// named instead of misunderstood.
///
/// See [`WIRE_VERSION`].
async fn say_hello(session: &mut Session) -> Result<()> {
    session
        .send(&Frame::new(
            FrameKind::Hello,
            WIRE_VERSION.to_be_bytes().to_vec(),
        ))
        .await
        .context("announcing the wire version")
}

/// Read the other side's version and refuse a build that cannot be talked to.
///
/// A peer that says nothing is older than this check, which is worth naming
/// rather than reporting as a parse failure three frames later.
fn check_hello(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Hello {
        bail!(
            "the other side did not say which wire it speaks, so it is running a \
             build older than this one. Both ends have to be rebuilt from the \
             same source: they will not fail cleanly otherwise"
        );
    }
    let theirs = match frame.payload.as_slice() {
        [a, b] => u16::from_be_bytes([*a, *b]),
        _ => bail!("the other side's version is not a version"),
    };
    if theirs != WIRE_VERSION {
        bail!(
            "the other side speaks wire version {theirs} and this build speaks \
             {WIRE_VERSION}. Rebuild both ends from the same source"
        );
    }
    Ok(())
}

/// What happened when the two sides asked each other about a conversation they
/// might both still hold.
///
/// # Why the variants are allowed to differ in size
///
/// `Resumed` is 3,304 bytes against `Fresh`'s 1,128, and clippy would rather
/// the larger one were boxed. It is not, and the reason is where this value is
/// produced: **once, at the end of opening a conversation**, immediately after
/// a network round trip and a key exchange. One memcpy of three kilobytes on
/// that path is not measurable, and boxing would put an allocation and a
/// pointer hop on every caller in three crates to save it.
///
/// The lint is right about hot paths and about values that move often. This is
/// neither, and saying so here is cheaper than making everyone who reads it
/// work that out again.
#[allow(clippy::large_enum_variant)]
pub enum Opened {
    /// Newly created. Nobody had been here before, or only one of them had, and
    /// the caller keeps using the member it built.
    Fresh(Conversation),
    /// Carried across a restart. The listener has already committed a fresh
    /// epoch and the dialer has processed it.
    ///
    /// The member comes back with it because it is not the one the caller made:
    /// it is the one that was restored, holding the signing key the group knows.
    Resumed {
        member: Member,
        conversation: Conversation,
    },
}

impl Opened {}

/// Dialer side: publish a key package and join the group we are welcomed into.
pub async fn join(session: &mut Session, me: &Member) -> Result<Conversation> {
    let bundle = me.key_package().context("building key package")?;
    let encoded = rotelyx_crypto::serialize_key_package(bundle.key_package())
        .context("encoding key package")?;

    session
        .send(&Frame::new(FrameKind::Handshake, encoded))
        .await
        .context("sending key package")?;

    let frame = session.recv().await.context("waiting for welcome")?;
    if frame.kind != FrameKind::Handshake {
        bail!("expected a handshake frame, got {:?}", frame.kind);
    }

    let (welcome, tree) = decode_welcome(&frame.payload)?;
    Conversation::join(me, welcome, tree).context("joining the conversation")
}

/// Listener side, with a conversation it may already hold.
///
/// # The exchange, and why it cannot deadlock
///
/// The dialer speaks first, as it always has. If it has state for this address
/// it says so with a [`FrameKind::Resume`] frame carrying the group it holds; if
/// it has none it sends a key package and nothing here changes.
///
/// A listener that gets a resume request and has nothing answers with an empty
/// payload, and the dialer then sends a key package as usual. So the two never
/// end up waiting for different frames: whoever has less decides, and the
/// fallback is the path that already worked.
pub async fn host_resuming(
    session: &mut Session,
    me: &Member,
    saved: Option<(Member, Conversation)>,
) -> Result<Opened> {
    // Their version, then ours. Read first so a build that cannot be talked to
    // is named here rather than misunderstood three frames later.
    //
    // One round trip, once per conversation. See `say_hello`.
    let hello = session
        .recv()
        .await
        .context("waiting for the first frame")?;
    check_hello(&hello)?;
    say_hello(session).await?;

    let frame = session
        .recv()
        .await
        .context("waiting for the first frame")?;

    match frame.kind {
        FrameKind::Handshake => {
            // An ordinary dialer. Whatever we were holding is not what they want.
            let conversation = host_from_key_package(session, me, &frame.payload).await?;
            Ok(Opened::Fresh(conversation))
        }
        FrameKind::Resume => {
            let Some((saved_member, mut conversation)) = saved else {
                // Nothing here. Say so, and let them start again.
                session
                    .send(&Frame::new(FrameKind::Resume, Vec::new()))
                    .await
                    .context("declining to resume")?;

                let frame = session.recv().await.context("waiting for key package")?;
                if frame.kind != FrameKind::Handshake {
                    bail!(
                        "expected a key package after declining, got {:?}",
                        frame.kind
                    );
                }
                let conversation = host_from_key_package(session, me, &frame.payload).await?;
                return Ok(Opened::Fresh(conversation));
            };

            if frame.payload != conversation.group_id() {
                bail!(
                    "the other side is holding a different conversation for this \
                     address. Neither can be resumed into the other"
                );
            }

            // A restored copy may not speak until it has moved to an epoch the
            // other side has not seen. See `Conversation::rekey_after_restore`.
            let commit = conversation
                .rekey_after_restore(&saved_member)
                .context("rekeying after restore")?;

            session
                .send(&Frame::new(FrameKind::Resume, commit))
                .await
                .context("sending the rekey")?;

            Ok(Opened::Resumed {
                member: saved_member,
                conversation,
            })
        }
        other => bail!("expected a handshake or resume frame, got {other:?}"),
    }
}

/// Dialer side, with a conversation it may already hold.
pub async fn join_resuming(
    session: &mut Session,
    me: &Member,
    saved: Option<(Member, Conversation)>,
) -> Result<Opened> {
    say_hello(session).await?;
    let hello = session
        .recv()
        .await
        .context("waiting for the wire version")?;
    check_hello(&hello)?;

    let Some((saved_member, mut conversation)) = saved else {
        return Ok(Opened::Fresh(join(session, me).await?));
    };

    session
        .send(&Frame::new(FrameKind::Resume, conversation.group_id()))
        .await
        .context("asking to resume")?;

    let frame = session.recv().await.context("waiting for the answer")?;
    if frame.kind != FrameKind::Resume {
        bail!("expected an answer about resuming, got {:?}", frame.kind);
    }

    if frame.payload.is_empty() {
        // They have nothing. Start again, with the member we would have used
        // anyway rather than the one we restored.
        let conversation = join(session, me).await?;
        return Ok(Opened::Fresh(conversation));
    }

    conversation
        .receive(&saved_member, &frame.payload)
        .context("processing the rekey")?;

    Ok(Opened::Resumed {
        member: saved_member,
        conversation,
    })
}

/// The original listener path, once a key package has arrived.
async fn host_from_key_package(
    session: &mut Session,
    me: &Member,
    payload: &[u8],
) -> Result<Conversation> {
    let key_package = rotelyx_crypto::deserialize_key_package(payload)
        .context("parsing the peer's key package")?;

    let mut conversation = Conversation::create(me).context("creating the conversation")?;
    let (_commit, welcome) = conversation
        .invite(me, &key_package)
        .context("inviting the peer")?;
    let tree = conversation
        .ratchet_tree()
        .context("exporting ratchet tree")?;

    session
        .send(&Frame::new(
            FrameKind::Handshake,
            encode_welcome(&welcome, &tree),
        ))
        .await
        .context("sending welcome")?;

    Ok(conversation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build that cannot be talked to is named, not misunderstood.
    ///
    /// # Why this matters more than it looks
    ///
    /// Two builds that disagree about a format do not fail cleanly. On the
    /// change that made a credential `person_len ‖ person ‖ device`, a peer on
    /// the older build was understood seven times in eight and misunderstood the
    /// eighth, depending on the first byte of a key. The eighth is not an error:
    /// it is a safety number that does not match, with no reason given, for that
    /// pair, for ever.
    #[test]
    fn a_peer_on_another_wire_is_refused_by_name() {
        let ours = Frame::new(FrameKind::Hello, WIRE_VERSION.to_be_bytes().to_vec());
        assert!(check_hello(&ours).is_ok());

        let theirs = Frame::new(FrameKind::Hello, (WIRE_VERSION + 1).to_be_bytes().to_vec());
        let refused = check_hello(&theirs).expect_err("a different wire was accepted");
        let said = format!("{refused}");
        assert!(
            said.contains("wire version") && said.contains("Rebuild"),
            "the refusal does not say what to do about it: {said}"
        );

        // A build older than this check says nothing at all, which is its own
        // answer and a different one.
        let silent = Frame::new(FrameKind::Handshake, b"a key package".to_vec());
        let refused = check_hello(&silent).expect_err("a silent peer was accepted");
        assert!(
            format!("{refused}").contains("older"),
            "a peer that said nothing was not identified as an older build"
        );

        // And a version that is not a version.
        for payload in [vec![], vec![1u8], vec![1u8, 2, 3]] {
            assert!(check_hello(&Frame::new(FrameKind::Hello, payload)).is_err());
        }
    }

    #[test]
    fn welcome_framing_roundtrips() {
        let encoded = encode_welcome(b"welcome-bytes", b"tree-bytes");
        let (w, t) = decode_welcome(&encoded).expect("decode");
        assert_eq!(w, b"welcome-bytes");
        assert_eq!(t, b"tree-bytes");
    }

    /// Empty blobs are legal and must not be mistaken for truncation.
    #[test]
    fn empty_sections_roundtrip() {
        let encoded = encode_welcome(b"", b"");
        let (w, t) = decode_welcome(&encoded).expect("decode");
        assert!(w.is_empty() && t.is_empty());
    }

    #[test]
    fn truncated_frames_are_rejected_rather_than_panicking() {
        let encoded = encode_welcome(b"welcome", b"tree");
        for cut in 0..encoded.len() {
            // Every prefix must produce an error, never an index-out-of-bounds.
            let _ = decode_welcome(&encoded[..cut]);
        }
        assert!(decode_welcome(&[]).is_err());
        assert!(decode_welcome(&[0, 0, 0, 255]).is_err());
    }

    /// A length field claiming more than the frame holds is the classic parser
    /// bug; it must be an error, not a panic or an over-read.
    #[test]
    fn an_oversized_length_prefix_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"short");
        assert!(decode_welcome(&bytes).is_err());
    }
}
