//! The L3 envelope parser, given a deposit from anybody who knows a tag.
//!
//! The mailbox is blind by design, so it cannot vet what it stores, and a client
//! parses an envelope before it can know whether it is genuine. That makes this
//! the first function an attacker reaches.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rotelyx_mailbox::{Envelope, Tag};

fuzz_target!(|data: &[u8]| {
    let _ = Tag::from_bytes(data);

    let Ok(envelope) = Envelope::from_bytes(data) else {
        return;
    };

    // Accepting two byte strings as one envelope would let somebody deposit a
    // second encoding of a message that already exists, and the padding promise
    // is a promise about size, so a second encoding is a second size.
    assert_eq!(
        envelope.to_bytes(),
        data,
        "an envelope was accepted and re-encoded differently"
    );
});
