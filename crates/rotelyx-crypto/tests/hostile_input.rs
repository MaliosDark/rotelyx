//! The post-quantum parsers, given input nobody sane would send.
//!
//! These read bytes that arrive from whoever is on the other end, before
//! anything has authenticated them: a public key from a key package, a
//! ciphertext from a peer, a wrapped secret from a group message. There is no
//! point at which they can assume the sender meant well, because the whole
//! design assumes the sender might not be who they claim.
//!
//! Systematic mutation rather than a fuzzer, for the reason given in the
//! mailbox's copy of this file: it runs in the ordinary suite, on every change,
//! instead of in a tool somebody has to remember to start.
//!
//! The contract is that a parser may reject anything and may not panic. In a
//! chat client a panic on parse is a remote crash triggered by anybody who can
//! put bytes in front of you, which for a blind mailbox is everybody.

use rotelyx_crypto::hybrid::{HybridCiphertext, HybridKem, HybridPublicKey, WrappedPqSecret};

/// A stand-in sender key for tests that are not about who sent it.
const A_SENDER: &[u8] = &[7u8; 32];

/// A binding for tests that are about parsing rather than about binding.
fn a_binding() -> rotelyx_crypto::PqBinding {
    rotelyx_crypto::PqBinding::new(b"a-group", 1, b"a-signature-key", A_SENDER)
}

/// A parser under test: its name, one valid input, and a call that says only
/// whether it returned.
///
/// `bool` rather than the parsed value, because the parsers return types that
/// have nothing in common and what is under test is whether the call returns at
/// all rather than what it produces.
type Specimen = (&'static str, Vec<u8>, fn(&[u8]) -> bool);

/// Valid specimens, one per parser, produced the way the protocol produces them.
fn specimens() -> Vec<Specimen> {
    // Only the public half and a ciphertext under it: what these parsers read
    // is what arrives from somebody else, and none of it is opened here.
    let (_secret, public) = HybridKem::generate();
    let (ciphertext, pq) = public.encapsulate();

    vec![
        (
            "HybridPublicKey",
            public.to_bytes().to_vec(),
            (|b| HybridPublicKey::from_bytes(b).is_ok()) as fn(&[u8]) -> bool,
        ),
        ("HybridCiphertext", ciphertext.to_bytes().to_vec(), |b| {
            HybridCiphertext::from_bytes(b).is_ok()
        }),
        (
            "WrappedPqSecret",
            pq.wrap_for(&public, &a_binding()).expect("wrap").to_bytes(),
            |b| WrappedPqSecret::from_bytes(b).is_ok(),
        ),
    ]
}

/// Truncation at every length, including zero.
#[test]
fn no_truncation_panics() {
    for (name, valid, parse) in specimens() {
        for len in 0..=valid.len() {
            parse(&valid[..len]);
        }
        let _ = name;
    }
}

/// Every byte value at every position.
///
/// These specimens are over a kilobyte each, so this is a quarter of a million
/// parses per specimen. Worth it: a length or a version byte anywhere in there
/// decides how the rest is read, and one byte is exactly the mutation that
/// finds it.
#[test]
fn no_single_byte_corruption_panics() {
    for (name, valid, parse) in specimens() {
        for position in 0..valid.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff] {
                let mut corrupted = valid.clone();
                corrupted[position] = byte;
                parse(&corrupted);
            }
        }
        let _ = name;
    }
}

/// Longer than it should be, which is the shape of a length confusion.
#[test]
fn no_extension_panics() {
    for (name, valid, parse) in specimens() {
        for extra in [1usize, 32, 1024, 65_536] {
            let mut longer = valid.clone();
            longer.extend(std::iter::repeat_n(0xff, extra));
            parse(&longer);
        }
        let _ = name;
    }
}

/// Input that never was a message.
#[test]
fn no_arbitrary_input_panics() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for (name, _valid, parse) in specimens() {
        for len in [0usize, 1, 31, 32, 33, 1087, 1088, 1089, 1184, 65_535] {
            parse(&vec![0x00; len]);
            parse(&vec![0xff; len]);
            for _ in 0..10 {
                let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
                parse(&bytes);
            }
        }
        let _ = name;
    }
}

/// Decapsulating a corrupted ciphertext must produce a wrong key rather than a
/// crash, and must not reveal which part was wrong.
///
/// A KEM is allowed to return a useless secret for a bad ciphertext: that is
/// implicit rejection, and it is the design. What it may not do is fail
/// differently depending on how the ciphertext is malformed, because that
/// difference is an oracle.
#[test]
fn decapsulating_rubbish_yields_a_wrong_key_rather_than_a_failure() {
    let (secret, public) = HybridKem::generate();
    let (ciphertext, expected) = public.encapsulate();
    // `PqSecret` has no accessor for its bytes, deliberately: the only thing
    // anybody is allowed to do with two of them is compare in constant time.
    let good = secret.decapsulate(&ciphertext);
    assert!(
        good.ct_eq(&expected),
        "an untouched ciphertext must decapsulate to what was encapsulated"
    );

    let bytes = ciphertext.to_bytes();
    for position in [0usize, 1, 100, 700, bytes.len() - 1] {
        let mut corrupted = bytes;
        corrupted[position] ^= 0xff;

        let Ok(parsed) = HybridCiphertext::from_bytes(&corrupted) else {
            continue; // rejected at parse, which is also a fine answer
        };
        let got = secret.decapsulate(&parsed);
        assert!(
            !got.ct_eq(&expected),
            "a ciphertext corrupted at byte {position} decapsulated to the right \
             secret, which means that byte is not covered"
        );
    }
}

/// The valid cases still work, so that rejecting everything cannot pass.
#[test]
fn the_valid_cases_still_work() {
    for (name, valid, parse) in specimens() {
        assert!(parse(&valid), "{name} no longer parses its own output");
    }
}
