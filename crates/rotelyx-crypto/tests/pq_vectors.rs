//! Test vectors for the hybrid post-quantum pre-shared-key derivation.
//!
//! This is the one novel cryptographic construction in Rotelyx and therefore
//! the specific thing an independent reviewer must be able to check. Reading
//! our source is not a review; reproducing our output from a written
//! specification is.
//!
//! The vectors in `pq-vectors.txt` are checked against this implementation on
//! every test run, so the file cannot drift from the code. The written
//! specification lives in `docs/PQ-COMPOSITION.md`.
//!
//! ## Regenerating
//!
//! ```sh
//! cargo test -p rotelyx-crypto --test pq_vectors -- --ignored emit_vectors --nocapture
//! ```
//!
//! Regenerate only when the construction changes on purpose. A changed vector
//! is a changed protocol, and every existing deployment stops interoperating.

use rotelyx_crypto::hybrid::{derive_psk, psk_binding};

/// Parsed line from the vector file.
struct Vector {
    name: String,
    secret: [u8; 32],
    label: Vec<u8>,
    group_id: Vec<u8>,
    epoch: u64,
    expected: [u8; 32],
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load_vectors() -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pq-vectors.txt");
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));

    let mut out = Vec::new();
    let mut current: Option<(String, Vec<(String, String)>)> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("vector ") {
            if let Some((name, fields)) = current.take() {
                out.push(build(name, fields));
            }
            current = Some((name.trim().to_string(), Vec::new()));
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or_else(|| panic!("bad line: {line}"));
        current
            .as_mut()
            .expect("field before any vector header")
            .1
            .push((k.trim().to_string(), v.trim().to_string()));
    }
    if let Some((name, fields)) = current {
        out.push(build(name, fields));
    }
    out
}

fn build(name: String, fields: Vec<(String, String)>) -> Vector {
    let vector_name = name.clone();
    let get = |k: &str| -> String {
        fields
            .iter()
            .find(|(f, _)| f == k)
            .unwrap_or_else(|| panic!("vector {vector_name} is missing {k}"))
            .1
            .clone()
    };

    let secret: [u8; 32] = hex_decode(&get("secret"))
        .try_into()
        .expect("secret must be 32 bytes");
    let expected: [u8; 32] = hex_decode(&get("psk"))
        .try_into()
        .expect("psk must be 32 bytes");

    let label = get("label").into_bytes();
    let group_id = hex_decode(&get("group_id"));
    let epoch = get("epoch").parse().expect("epoch must be a number");

    Vector {
        name,
        secret,
        label,
        group_id,
        epoch,
        expected,
    }
}

/// The vectors must reproduce exactly. A mismatch means either the
/// construction changed or the file is stale, and both are protocol breaks.
#[test]
fn implementation_matches_the_published_vectors() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "no vectors loaded");

    for v in &vectors {
        let binding = psk_binding(&v.label, &v.group_id, v.epoch);
        let got = derive_psk(&v.secret, &binding);

        assert_eq!(
            hex_encode(&*got),
            hex_encode(&v.expected),
            "vector `{}` does not reproduce",
            v.name
        );
    }
}

/// The binding places one variable-length field between two fixed-length ones,
/// which is what makes it unambiguous. This test pins that property: no two
/// distinct (group id, epoch) pairs may produce the same binding.
#[test]
fn the_binding_is_unambiguous() {
    let label = b"rotelyx-pq-psk-v1";

    // A group id whose tail could be mistaken for an epoch, against a shorter
    // group id with a different epoch. Without the fixed-width epoch at the
    // end, these would collide.
    let a = psk_binding(label, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 2);
    let b = psk_binding(label, &[0x01], 0x0000_0000_0000_0002);
    assert_ne!(a, b, "two distinct group id and epoch pairs collided");

    // And the epoch really is the last eight bytes.
    let c = psk_binding(label, b"group", 7);
    assert_eq!(&c[c.len() - 8..], &7u64.to_be_bytes());
}

/// Every input must affect the output. A derivation that ignores one of its
/// inputs is the failure this whole construction exists to avoid.
#[test]
fn every_input_changes_the_output() {
    let secret = [0x11u8; 32];
    let label = b"rotelyx-pq-psk-v1";
    let group = b"group-a";
    let base = derive_psk(&secret, &psk_binding(label, group, 1));

    let other_secret = derive_psk(&[0x12u8; 32], &psk_binding(label, group, 1));
    let other_group = derive_psk(&secret, &psk_binding(label, b"group-b", 1));
    let other_epoch = derive_psk(&secret, &psk_binding(label, group, 2));
    let other_label = derive_psk(&secret, &psk_binding(b"different-label", group, 1));

    assert_ne!(*base, *other_secret, "the secret does not affect the output");
    assert_ne!(*base, *other_group, "the group id does not affect the output");
    assert_ne!(*base, *other_epoch, "the epoch does not affect the output");
    assert_ne!(*base, *other_label, "the label does not affect the output");
}

/// Emits the vector file. Ignored by default: run it deliberately.
#[test]
#[ignore = "regenerates the published vectors, run only when the construction changes"]
fn emit_vectors() {
    let cases: &[(&str, [u8; 32], &[u8], u64)] = &[
        ("all-zero-secret", [0x00; 32], b"", 0),
        ("all-one-secret", [0xff; 32], b"", 0),
        ("counting-secret", {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            s
        }, b"group-alpha", 1),
        ("empty-group-id", [0x42; 32], b"", 7),
        ("long-group-id", [0x42; 32], &[0xab; 64], 7),
        ("epoch-boundary", [0x42; 32], b"g", u64::MAX),
        ("group-id-ending-in-zeros", [0x42; 32], &[0x01, 0, 0, 0, 0, 0, 0, 0], 2),
    ];

    println!("# Rotelyx hybrid post-quantum PSK derivation, test vectors");
    println!("# Generated by `cargo test -p rotelyx-crypto --test pq_vectors -- --ignored emit_vectors`");
    println!("# Specification: docs/PQ-COMPOSITION.md");
    println!("#");
    println!("# psk = BLAKE3_XOF(derive_key(\"rotelyx hybrid-pq psk v1\"),");
    println!("#                  secret || be64(len(binding)) || binding)[0..32]");
    println!("# binding = label || group_id || be64(epoch)");

    for (name, secret, group_id, epoch) in cases {
        let binding = psk_binding(b"rotelyx-pq-psk-v1", group_id, *epoch);
        let psk = derive_psk(secret, &binding);
        println!();
        println!("vector {name}");
        println!("  secret   = {}", hex_encode(secret));
        println!("  label    = rotelyx-pq-psk-v1");
        println!("  group_id = {}", hex_encode(group_id));
        println!("  epoch    = {epoch}");
        println!("  binding  = {}", hex_encode(&binding));
        println!("  psk      = {}", hex_encode(&*psk));
    }
}
