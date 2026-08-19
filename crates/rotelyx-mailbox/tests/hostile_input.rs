//! Every parser here is reachable by anybody who knows a tag.
//!
//! The mailbox is deliberately blind: it does not know who deposits, and it
//! cannot, because knowing would defeat the point. So a deposit under a tag is
//! attacker-controlled input, and the client parses it before it can possibly
//! know whether it is genuine. That makes these functions the first thing an
//! attacker reaches and the last thing that gets written carefully.
//!
//! There is no fuzzer wired into this project, and this is not one. It is
//! systematic mutation with a fixed seed: every single-byte corruption, every
//! truncation, every length that a length field could claim. It runs in the
//! ordinary test suite on every change rather than in a separate tool nobody
//! remembers to start, and it catches the same class of defect a fuzzer catches
//! on the first thousand cases.
//!
//! The contract under test is narrow and absolute: **a parser may reject
//! anything, and may not panic, hang, or allocate on an attacker's say-so.**
//! Rust turns an out-of-bounds read into a panic, so a panic here would be a
//! remote denial of service in a chat client, reachable by anybody who has ever
//! been in a conversation with the victim.

use rotelyx_mailbox::{Envelope, Tag};

/// A valid envelope to mutate. Small, so the mutation space is exhaustible.
fn specimen() -> Vec<u8> {
    let tag = Tag::from_bytes(&[0x5a; 32]).expect("a 32 byte tag");
    Envelope::seal(tag, b"a plausible ciphertext of ordinary length")
        .expect("seal")
        .to_bytes()
}

/// Every parser reachable from a deposit, behind one signature.
///
/// Returning `bool` rather than the parsed value keeps the harness from having
/// to name types that differ between parsers, and what is under test is whether
/// the call returns at all.
fn parsers() -> Vec<(&'static str, fn(&[u8]) -> bool)> {
    vec![
        ("Envelope::from_bytes", |b| Envelope::from_bytes(b).is_ok()),
        ("Tag::from_bytes", |b| Tag::from_bytes(b).is_ok()),
    ]
}

/// Truncation at every length, including zero.
///
/// A parser that reads a length field and then indexes without checking is
/// found here on the first run: the length still says what it said, and the
/// bytes it points at are gone.
#[test]
fn no_truncation_panics() {
    let valid = specimen();
    for (name, parse) in parsers() {
        for len in 0..=valid.len() {
            parse(&valid[..len]);
            let _ = name;
        }
    }
}

/// Every single-byte value at every position.
///
/// 256 values times the length of the specimen. Exhaustive for one byte, which
/// is where length fields, tags and version bytes live, and those are the bytes
/// that decide how the rest is read.
#[test]
fn no_single_byte_corruption_panics() {
    let valid = specimen();
    for (name, parse) in parsers() {
        for position in 0..valid.len() {
            for byte in 0u16..=255 {
                let mut corrupted = valid.clone();
                corrupted[position] = byte as u8;
                parse(&corrupted);
            }
        }
        let _ = name;
    }
}

/// Bytes appended, which is what a padding oracle or a length confusion looks
/// like from outside.
#[test]
fn no_extension_panics() {
    let valid = specimen();
    for (name, parse) in parsers() {
        for extra in [1usize, 7, 64, 4096] {
            let mut longer = valid.clone();
            longer.extend(std::iter::repeat_n(0xff, extra));
            parse(&longer);

            let mut longer = valid.clone();
            longer.extend(std::iter::repeat_n(0x00, extra));
            parse(&longer);
        }
        let _ = name;
    }
}

/// Input that is not a mutation of anything valid.
///
/// A parser can be correct for every corruption of a real message and still
/// walk off the end of something it has never seen. The all-zero and all-ones
/// cases in particular exercise the paths where a length field reads as zero or
/// as the largest number it can hold.
#[test]
fn no_arbitrary_input_panics() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for (name, parse) in parsers() {
        for len in [0usize, 1, 2, 31, 32, 33, 63, 64, 65, 1023, 1024, 65_535] {
            parse(&vec![0x00; len]);
            parse(&vec![0xff; len]);

            for _ in 0..20 {
                let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
                parse(&bytes);
            }
        }
        let _ = name;
    }
}

/// A valid envelope must still parse after all of that.
///
/// The cheapest way to write a parser that survives every hostile input is to
/// reject everything, and this is what stops that being an accidental outcome.
#[test]
fn the_valid_case_still_works() {
    let valid = specimen();
    let parsed = Envelope::from_bytes(&valid).expect("a sealed envelope must parse");
    assert_eq!(parsed.to_bytes(), valid, "round trip changed the bytes");
}

/// Tag equality must be constant time, and must still be equality.
///
/// The correctness half is the part a test can assert. The timing half cannot
/// be asserted reliably on a shared machine, so what stands in for it is the
/// reasoning recorded on `impl PartialEq for Tag`, plus this: if somebody
/// replaces the implementation with a derive, the comparison below still
/// passes, so the guard is the documentation and the review, not this test.
/// Saying that plainly is better than a flaky timing assertion that gets
/// deleted the first time CI is busy.
#[test]
fn tag_equality_is_still_equality() {
    let a = Tag::from_bytes(&[0x11; 32]).expect("tag");
    let same = Tag::from_bytes(&[0x11; 32]).expect("tag");
    assert_eq!(a, same);

    // Differing in the first byte and in the last: both must compare unequal,
    // which is what a short-circuiting implementation also does. The point of
    // the constant-time version is that these two take the same time, not that
    // they give different answers.
    for position in [0usize, 15, 31] {
        let mut bytes = [0x11u8; 32];
        bytes[position] = 0x12;
        let different = Tag::from_bytes(&bytes).expect("tag");
        assert_ne!(a, different, "tags differing at byte {position} compared equal");
    }
}
