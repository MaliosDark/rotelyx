//! The L1 frame reader, given a stream that is not a peer.
//!
//! `Frame::read` is the first thing a connection touches, before anything has
//! been authenticated: authentication is carried in the frames it has not read
//! yet. It reads a length and then reads that many bytes, which is the classic
//! shape for a parser that allocates whatever it is told to.
//!
//! The contract is that a frame may be rejected, and may not panic, hang, or
//! allocate on an attacker's say-so. A panic here is a remote denial of service
//! against a chat client, reachable by anybody who can open a connection.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rotelyx_core::wire::Frame;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data.to_vec());
    let Ok(frame) = futures_lite::future::block_on(Frame::read(&mut cursor)) else {
        return;
    };
    let consumed = cursor.position() as usize;

    // Whatever was accepted has to write back to the bytes it came from. Two
    // encodings of one frame is a way to make two peers disagree about what was
    // said while each believes it read the same thing.
    let mut written = Vec::new();
    futures_lite::future::block_on(frame.write(&mut written)).expect("a parsed frame must write");
    assert_eq!(
        written,
        &data[..consumed],
        "a frame was accepted and re-encoded differently"
    );
});
