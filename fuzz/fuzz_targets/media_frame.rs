//! The media frame parser, given a datagram from anybody who can reach the port.
//!
//! A call is datagrams over a relay, and a relay forwards what it is handed. So
//! this parser sees whatever arrives, before any key is used and before
//! anything has been authenticated: `claimed_sender` reads the header of an
//! unauthenticated packet by design, because a receiver has to know which key
//! to try before it can try one.
//!
//! It is also the parser that most wants fuzzing and had none. The suite drives
//! it with truncations and single-byte mutations of valid frames, which is a
//! good test of a decoder and a poor test of a parser: both start from
//! something well formed. This starts from nothing.
//!
//! The property is not that a frame is accepted. Almost none will be. It is
//! that no input reaches a panic, an out-of-bounds read, or an allocation
//! chosen by the attacker.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rotelyx_media::{claimed_sender, CallBinding, Receiver, SenderKeys};

fuzz_target!(|data: &[u8]| {
    // Read before any key exists, which is what a real receiver does.
    let _ = claimed_sender(data);

    let binding = CallBinding::new(b"fuzzing-a-call-0001").expect("long enough");
    let keys = SenderKeys::derive(&[7u8; 32], 0, &binding);
    let Ok(mut receiver) = Receiver::new(keys) else {
        return;
    };

    // Twice, because the replay window carries state between frames and a
    // second pass reaches the branches the first one sets up.
    let _ = receiver.unprotect(data);
    let _ = receiver.unprotect(data);
});
