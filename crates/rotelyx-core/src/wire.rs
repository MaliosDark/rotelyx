//! Framing for the Rotelyx control/chat stream.
//!
//! QUIC gives us a reliable ordered byte stream, not messages, so we frame:
//!
//! ```text
//! ┌────────────┬──────┬───────────────────────────┐
//! │ len: u32be │ kind │ payload (len - 1 bytes)   │
//! └────────────┴──────┴───────────────────────────┘
//! ```
//!
//! `len` counts the kind byte plus the payload, so the minimum legal frame is
//! `len == 1`. The length cap is a hard requirement, not a nicety: an attacker
//! who can make us allocate an arbitrary buffer from a 4-byte header has a
//! remote memory-exhaustion primitive. See `THREAT-MODEL.md` §"Resource
//! exhaustion".

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest accepted frame body. Chosen to comfortably hold an MLS commit for a
/// large group while staying far below anything that pressures a phone.
pub const MAX_FRAME_LEN: usize = 1 << 20; // 1 MiB

const HEADER_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer announced a {announced} byte frame, cap is {cap}")]
    FrameTooLarge { announced: usize, cap: usize },

    #[error("frame is empty: a frame must carry at least a kind byte")]
    EmptyFrame,

    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
}

/// What a frame carries. The transport never inspects the payload beyond this
/// tag — routing decisions are made here, decryption happens at L2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// L2 ciphertext: an MLS application message.
    Message = 0x01,
    /// L2 handshake: an MLS proposal, commit, or welcome.
    Handshake = 0x02,
    /// Call setup and teardown. Media itself does not use this stream.
    CallControl = 0x03,
    /// Liveness probe. Also carries cover traffic — see L3 padding.
    Ping = 0x04,
    /// Response to [`FrameKind::Ping`].
    Pong = 0x05,
    /// Admission: the caller's evidence that it is allowed to reach us.
    ///
    /// Always the first frame a dialer sends. Anything else before it is a
    /// protocol violation and the session is dropped.
    Admission = 0x06,
}

impl FrameKind {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            0x01 => Self::Message,
            0x02 => Self::Handshake,
            0x03 => Self::CallControl,
            0x04 => Self::Ping,
            0x05 => Self::Pong,
            0x06 => Self::Admission,
            other => return Err(WireError::UnknownKind(other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameKind, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            payload: payload.into(),
        }
    }

    /// Write a frame. Returns an error rather than truncating if the payload
    /// exceeds the cap, so an oversized local message is a bug we see rather
    /// than corruption the peer sees.
    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), WireError> {
        let body_len = self.payload.len() + 1;
        if body_len > MAX_FRAME_LEN {
            return Err(WireError::FrameTooLarge {
                announced: body_len,
                cap: MAX_FRAME_LEN,
            });
        }

        let mut buf = Vec::with_capacity(HEADER_LEN + body_len);
        buf.extend_from_slice(&(body_len as u32).to_be_bytes());
        buf.push(self.kind as u8);
        buf.extend_from_slice(&self.payload);

        w.write_all(&buf).await?;
        w.flush().await?;
        Ok(())
    }

    /// Read one frame.
    ///
    /// The length is validated *before* any allocation, which is the whole
    /// point of the cap.
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, WireError> {
        let mut header = [0u8; HEADER_LEN];
        r.read_exact(&mut header).await?;
        let body_len = u32::from_be_bytes(header) as usize;

        if body_len == 0 {
            return Err(WireError::EmptyFrame);
        }
        if body_len > MAX_FRAME_LEN {
            return Err(WireError::FrameTooLarge {
                announced: body_len,
                cap: MAX_FRAME_LEN,
            });
        }

        let mut kind = [0u8; 1];
        r.read_exact(&mut kind).await?;
        let kind = FrameKind::from_u8(kind[0])?;

        let mut payload = vec![0u8; body_len - 1];
        r.read_exact(&mut payload).await?;

        Ok(Self { kind, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip() {
        let frame = Frame::new(FrameKind::Message, b"ciphertext".to_vec());
        let mut buf = Vec::new();
        frame.write(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let back = Frame::read(&mut cursor).await.unwrap();
        assert_eq!(frame, back);
    }

    #[tokio::test]
    async fn roundtrip_empty_payload() {
        let frame = Frame::new(FrameKind::Ping, Vec::new());
        let mut buf = Vec::new();
        frame.write(&mut buf).await.unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 1);

        let mut cursor = Cursor::new(buf);
        assert_eq!(Frame::read(&mut cursor).await.unwrap(), frame);
    }

    #[tokio::test]
    async fn several_frames_share_a_stream() {
        let frames = vec![
            Frame::new(FrameKind::Handshake, b"welcome".to_vec()),
            Frame::new(FrameKind::Message, b"one".to_vec()),
            Frame::new(FrameKind::Message, b"two".to_vec()),
        ];
        let mut buf = Vec::new();
        for f in &frames {
            f.write(&mut buf).await.unwrap();
        }

        let mut cursor = Cursor::new(buf);
        for expected in &frames {
            assert_eq!(&Frame::read(&mut cursor).await.unwrap(), expected);
        }
    }

    /// The memory-exhaustion guard: a 4 GiB announcement must be rejected from
    /// the header alone, without allocating.
    #[tokio::test]
    async fn oversized_announcement_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut cursor = Cursor::new(buf);
        let err = Frame::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, WireError::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn zero_length_frame_is_rejected() {
        let mut cursor = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(matches!(
            Frame::read(&mut cursor).await.unwrap_err(),
            WireError::EmptyFrame
        ));
    }

    #[tokio::test]
    async fn unknown_kind_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(0xFF);

        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            Frame::read(&mut cursor).await.unwrap_err(),
            WireError::UnknownKind(0xFF)
        ));
    }

    #[tokio::test]
    async fn oversized_write_errors_rather_than_truncating() {
        let frame = Frame::new(FrameKind::Message, vec![0u8; MAX_FRAME_LEN]);
        let mut buf = Vec::new();
        assert!(matches!(
            frame.write(&mut buf).await.unwrap_err(),
            WireError::FrameTooLarge { .. }
        ));
        assert!(buf.is_empty(), "nothing should reach the wire");
    }
}
