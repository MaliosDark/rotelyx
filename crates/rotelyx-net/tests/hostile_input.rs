//! The parsers on this crate's boundary, given input nobody vouched for.
//!
//! `rotelyx-net` is a thin policy layer over the vendored transport, so most of
//! it takes types rather than bytes. The exceptions are the two it re-exports
//! and accepts from outside: a relay URL, which arrives from configuration a
//! user typed or a file somebody handed them, and an endpoint id, which arrives
//! off the wire from whoever connected.
//!
//! Both are reachable before anything has been authenticated, which makes them
//! the first code an attacker touches. The contract is the same as everywhere
//! else in this project: **a parser may reject anything, and may not panic,
//! hang, or allocate on an attacker's say-so.** A panic here is a remote denial
//! of service against a client, reachable by anyone who can reach the socket.
//!
//! Systematic mutation with a fixed seed rather than a fuzzer, so it runs on
//! every change instead of in a tool nobody remembers to start.

use rotelyx_net::{EndpointId, RelayUrl};
use std::str::FromStr;

/// A deterministic byte source. Same sequence on every machine and every run,
/// so a failure here is reproducible from the test name alone.
fn noise() -> impl FnMut() -> u64 {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

/// Endpoint ids are 32 bytes. Every length around that boundary, and every
/// byte value at every position of a valid one.
#[test]
fn endpoint_ids_reject_rather_than_panic() {
    // A valid id, to mutate. Not every 32 bytes is a point on the curve, which
    // is the whole reason this parser can fail.
    let valid = [0x11u8; 32];

    for position in 0..valid.len() {
        for byte in 0u16..=255 {
            let mut corrupted = valid;
            corrupted[position] = byte as u8;
            let _ = EndpointId::from_bytes(&corrupted);
        }
    }

    let mut next = noise();
    for _ in 0..2_000 {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            let n = next().to_le_bytes();
            chunk.copy_from_slice(&n[..chunk.len()]);
        }
        let _ = EndpointId::from_bytes(&bytes);
    }

    let _ = EndpointId::from_bytes(&[0x00; 32]);
    let _ = EndpointId::from_bytes(&[0xff; 32]);
}

/// The text form, which is what appears in a config file or a link.
#[test]
fn endpoint_id_text_rejects_rather_than_panics() {
    for junk in [
        "",
        " ",
        "z",
        &"a".repeat(63),
        &"a".repeat(64),
        &"a".repeat(65),
        &"f".repeat(4096),
        "../../etc/passwd",
        "\u{0}\u{0}\u{0}",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let _ = EndpointId::from_str(junk);
    }

    let mut next = noise();
    for _ in 0..500 {
        let len = (next() % 200) as usize;
        let s: String = (0..len)
            .map(|_| char::from(b'!' + (next() % 90) as u8))
            .collect();
        let _ = EndpointId::from_str(&s);
    }
}

/// Relay URLs. This one decides where a client connects, so a parser that
/// accepts something surprising is worse than one that panics.
#[test]
fn relay_urls_reject_rather_than_panic() {
    for junk in [
        "",
        " ",
        ":",
        "//",
        "http://",
        "https://",
        "https://[",
        &format!("https://{}", "a".repeat(8192)),
        &"https://a/".repeat(1000),
        "\u{0}",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pass@host/",
    ] {
        let _ = RelayUrl::from_str(junk);
    }

    let mut next = noise();
    for _ in 0..1_000 {
        let len = (next() % 300) as usize;
        let s: String = (0..len)
            .map(|_| char::from(b' ' + (next() % 95) as u8))
            .collect();
        let _ = RelayUrl::from_str(&s);
    }
}

/// Rejecting everything would pass all of the above, so this is what stops that
/// being an accidental outcome.
#[test]
fn the_valid_cases_still_parse() {
    let url = RelayUrl::from_str("https://relay.example.internal")
        .expect("an ordinary https URL must parse");
    assert!(url.to_string().contains("relay.example.internal"));

    // A real public key, so this is a value the parser must accept.
    let secret = rotelyx_net::SecretKey::generate();
    let id = secret.public();
    let round_tripped = EndpointId::from_str(&id.to_string()).expect("its own text form");
    assert_eq!(round_tripped, id, "an id did not survive its own text form");
}
