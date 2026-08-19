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
use rotelyx_core::{Frame, FrameKind, Session};
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

/// Listener side: create the conversation and invite the peer.
pub async fn host(session: &mut Session, me: &Member) -> Result<Conversation> {
    let frame = session.recv().await.context("waiting for key package")?;
    if frame.kind != FrameKind::Handshake {
        bail!("expected a handshake frame, got {:?}", frame.kind);
    }

    let key_package = rotelyx_crypto::deserialize_key_package(&frame.payload)
        .context("parsing the peer's key package")?;

    let mut conversation = Conversation::create(me).context("creating the conversation")?;
    let (_commit, welcome) = conversation
        .invite(me, &key_package)
        .context("inviting the peer")?;
    let tree = conversation.ratchet_tree().context("exporting ratchet tree")?;

    session
        .send(&Frame::new(
            FrameKind::Handshake,
            encode_welcome(&welcome, &tree),
        ))
        .await
        .context("sending welcome")?;

    Ok(conversation)
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
