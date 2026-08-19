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
    for kind in 0u8..=8 {
        for length in [u32::MAX, u32::MAX - 1, 1 << 31, 1 << 24, 1 << 20] {
            let mut frame = vec![kind];
            frame.extend_from_slice(&length.to_be_bytes());
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
