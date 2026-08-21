//! The wire frame reader, given a stream that is not a peer.
//!
//! `Frame::read` is the first thing a connection touches. It reads a kind byte
//! and a length, and then it reads that many bytes: the classic shape for a
//! parser that allocates whatever an attacker asks it to. Nothing has
//! authenticated the stream at that point, because authentication is carried in
//! the frames it has not read yet.
//!
//! Systematic mutation rather than a fuzzer, so that it runs on every change
//! rather than in a tool nobody starts.
//!
//! The contract is that a frame may be rejected, and may not panic, hang, or
//! allocate a gigabyte because a length field said so.

use rotelyx_core::wire::{Frame, FrameKind};
use std::io::Cursor;

/// A genuine frame's bytes.
fn specimen() -> Vec<u8> {
    let mut out = Vec::new();
    futures_lite::future::block_on(
        Frame::new(FrameKind::Message, b"an ordinary payload".to_vec()).write(&mut out),
    )
    .expect("write");
    out
}

fn parse(bytes: &[u8]) -> bool {
    futures_lite::future::block_on(Frame::read(&mut Cursor::new(bytes.to_vec()))).is_ok()
}

#[test]
fn no_truncation_panics() {
    let valid = specimen();
    for len in 0..=valid.len() {
        parse(&valid[..len]);
    }
}

#[test]
fn no_single_byte_corruption_panics() {
    let valid = specimen();
    for position in 0..valid.len() {
        for byte in 0u16..=255 {
            let mut corrupted = valid.clone();
            corrupted[position] = byte as u8;
            parse(&corrupted);
        }
    }
}

/// A length field claiming more than any frame is allowed to be.
///
/// This is the one that matters. A reader that trusts the length and reserves
/// that much memory is a remote out-of-memory with a four byte packet, and it
/// costs the attacker nothing to send.
#[test]
fn an_enormous_length_is_refused_rather_than_reserved() {
    // Length first, then kind. This used to build them the other way round, so
    // the reader took `[kind, len0, len1, len2]` as the length and the test
    // passed for reasons that had nothing to do with the cap it names.
    for kind in 0u8..=8 {
        for length in [u32::MAX, u32::MAX - 1, 1 << 31, 1 << 24, (1 << 20) + 1] {
            let mut frame = length.to_be_bytes().to_vec();
            frame.push(kind);
            // No body at all: an honest reader has to notice the stream ended.
            assert!(
                !parse(&frame),
                "a frame declaring {length} bytes with none behind it was accepted"
            );
        }
    }
}

#[test]
fn no_arbitrary_input_panics() {
    let mut state = 0xa076_1d64_78bd_642fu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for len in [0usize, 1, 2, 4, 5, 6, 64, 1024, 65_535] {
        parse(&vec![0x00; len]);
        parse(&vec![0xff; len]);
        for _ in 0..20 {
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            parse(&bytes);
        }
    }
}

/// The genuine frame still reads, so that rejecting everything cannot pass.
#[test]
fn the_valid_case_still_works() {
    assert!(parse(&specimen()), "a written frame must read back");
}

/// The length cap is checked before the body is read, not after.
///
/// # What this pins
///
/// The header of this file states the contract: a frame may be rejected, and
/// may not panic, hang, or allocate a gigabyte because a length field said so.
/// The tests around it call the parser and discard the result, which catches a
/// panic and neither of the other two. This one catches the allocation.
///
/// A reader that trusted the length would size a buffer from it and only then
/// discover the stream is four bytes long. The error it returns would look the
/// same from outside, so asserting *which* error comes back is the difference
/// between checking the cap and checking that reading past the end fails.
#[test]
fn a_huge_declared_length_is_refused_before_anything_is_allocated() {
    use rotelyx_core::{WireError, MAX_FRAME_LEN};

    let mut header = 0xffff_ffffu32.to_be_bytes().to_vec();
    header.push(FrameKind::Message as u8);

    let err = futures_lite::future::block_on(Frame::read(&mut Cursor::new(header)))
        .expect_err("a frame announcing four gigabytes was accepted");

    match err {
        WireError::FrameTooLarge { announced, cap } => {
            assert_eq!(announced, 0xffff_ffff);
            assert_eq!(cap, MAX_FRAME_LEN);
        }
        other => panic!(
            "the length was not checked before the read: got {other:?}, which is what \
             a reader that already sized a buffer would return"
        ),
    }
}

/// Anything the reader accepts must write back to the bytes it consumed.
///
/// # What this pins
///
/// A parser with two encodings for one value is a parser an attacker can use to
/// make two peers disagree about what was said while both believe they read the
/// same frame. The mutation tests above only ask that nothing crashes, so a
/// reader that quietly normalised a length, or reordered a field, would pass
/// every one of them.
///
/// The comparison is against the prefix the reader consumed rather than the
/// whole buffer, because `read` takes a stream: bytes after one frame are the
/// next frame, not a malformation.
#[test]
fn anything_accepted_re_encodes_to_itself() {
    let valid = specimen();
    let mut checked = 0;

    for position in 0..valid.len() {
        for byte in [0x00u8, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff] {
            let mut mutated = valid.clone();
            mutated[position] = byte;

            let mut cursor = Cursor::new(mutated.clone());
            let Ok(frame) = futures_lite::future::block_on(Frame::read(&mut cursor)) else {
                continue;
            };
            let consumed = cursor.position() as usize;

            let mut written = Vec::new();
            futures_lite::future::block_on(frame.write(&mut written)).expect("write back");
            assert_eq!(
                written,
                &mutated[..consumed],
                "byte {position} set to {byte:#04x} was accepted and re-encoded differently, \
                 so this frame has more than one encoding"
            );
            checked += 1;
        }
    }

    assert!(
        checked > 0,
        "no mutation was accepted, so nothing was actually checked"
    );
}
