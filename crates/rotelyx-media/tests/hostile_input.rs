//! Call frames, given input a peer would never send.
//!
//! A media frame arrives as a datagram, and a datagram is whatever the network
//! delivered. The header is parsed *before* the tag is checked, because the
//! header says which key and which counter to check the tag with, so those few
//! bytes are read with no authentication behind them at all. That is the part
//! an attacker reaches first.
//!
//! Systematic mutation rather than a fuzzer: it runs in the ordinary suite on
//! every change instead of in a tool somebody has to remember to start.
//!
//! The contract is that a frame may be rejected and may not panic. On a call, a
//! panic is the call dropping, triggered by one packet from anybody who can put
//! a packet on the path.

use rotelyx_media::{Receiver, Sender, SenderKeys};

/// A fixed binding, for the cases that are not about the binding itself.
fn test_call() -> rotelyx_media::CallBinding {
    rotelyx_media::CallBinding::new(b"a-test-call-0001").expect("long enough")
}

fn receiver() -> Receiver {
    Receiver::new(SenderKeys::derive(&[3u8; 32], 0, &test_call())).expect("receiver")
}

/// A genuine protected frame to mutate.
fn specimen() -> Vec<u8> {
    let mut sender = Sender::new(SenderKeys::derive(&[3u8; 32], 0, &test_call())).expect("sender");
    sender
        .protect(b"twenty milliseconds of speech, more or less")
        .expect("protect")
}

/// A frame from a counter large enough to need every counter byte.
///
/// The header encodes the counter in as few bytes as it fits, so a long call
/// exercises a different parse path from a short one, and a call that runs for
/// hours is the one nobody tests by hand.
fn long_counter_specimen() -> Vec<u8> {
    let mut sender = Sender::new(SenderKeys::derive(&[3u8; 32], 0, &test_call())).expect("sender");
    let mut frame = Vec::new();
    for _ in 0..300 {
        frame = sender.protect(b"later in a long call").expect("protect");
    }
    frame
}

#[test]
fn no_truncation_panics() {
    for valid in [specimen(), long_counter_specimen()] {
        let mut rx = receiver();
        for len in 0..=valid.len() {
            let _ = rx.unprotect(&valid[..len]);
        }
    }
}

/// Every byte value at every position.
///
/// The first byte is the whole config: five bits of sender identity and three
/// of counter length. Every value of it is reachable by an attacker and each
/// one changes how many bytes the parser then reads.
#[test]
fn no_single_byte_corruption_panics() {
    for valid in [specimen(), long_counter_specimen()] {
        for position in 0..valid.len() {
            for byte in 0u16..=255 {
                let mut rx = receiver();
                let mut corrupted = valid.clone();
                corrupted[position] = byte as u8;
                let _ = rx.unprotect(&corrupted);
            }
        }
    }
}

/// A config byte claiming a counter longer than the frame.
///
/// Written out separately from the sweep above because it is the specific
/// confusion the header format invites: the length lives in the same byte as
/// the identity, so a single flipped bit makes the parser want eight bytes of
/// counter out of a two byte frame.
#[test]
fn a_counter_length_longer_than_the_frame_is_refused() {
    for counter_len in 1u8..=8 {
        for frame_len in 1usize..=10 {
            let mut rx = receiver();
            let mut frame = vec![0u8; frame_len];
            frame[0] = (counter_len - 1) << 5;
            assert!(
                rx.unprotect(&frame).is_err(),
                "a {frame_len} byte frame claiming a {counter_len} byte counter \
                 was accepted"
            );
        }
    }
}

#[test]
fn no_extension_panics() {
    let valid = specimen();
    for extra in [1usize, 17, 1024, 65_536] {
        let mut rx = receiver();
        let mut longer = valid.clone();
        longer.extend(std::iter::repeat_n(0xff, extra));
        let _ = rx.unprotect(&longer);
    }
}

#[test]
fn no_arbitrary_input_panics() {
    let mut state = 0x51_7c_c1_b7_27_22_0a_95u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for len in [0usize, 1, 2, 3, 17, 18, 19, 64, 1100, 1101, 65_535] {
        let mut rx = receiver();
        let _ = rx.unprotect(&vec![0x00; len]);
        let _ = rx.unprotect(&vec![0xff; len]);
        for _ in 0..20 {
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = rx.unprotect(&bytes);
        }
    }
}

/// Nothing an attacker sends may authenticate, and the genuine frame must.
///
/// Without the second half this file would pass with an `unprotect` that
/// rejected everything.
#[test]
fn only_the_genuine_frame_authenticates() {
    let valid = specimen();

    let mut rx = receiver();
    assert!(
        rx.unprotect(&valid).is_ok(),
        "a genuine frame must authenticate"
    );

    // Every single-byte change, checked for acceptance rather than for panics.
    // A fresh receiver each time, because replay protection would reject a
    // repeat for the wrong reason and hide an acceptance.
    for position in 0..valid.len() {
        let mut corrupted = valid.clone();
        corrupted[position] ^= 0x01;
        let mut rx = receiver();
        assert!(
            rx.unprotect(&corrupted).is_err(),
            "a frame with bit 0 of byte {position} flipped authenticated"
        );
    }
}
