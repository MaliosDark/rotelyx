//! The second guard.
//!
//! The threat model states that every comparison in the first-party crates
//! touching key material, a tag, a token, a proof or a passphrase was located
//! and classified, and lists them. That was true when it was written. Nothing
//! kept it true: the vault's passphrase check and the wake registry's
//! revocation secret were both added afterwards and neither reached the list,
//! so the document went on claiming a completed review of a set that had grown.
//!
//! A claim in a document does not enforce itself, which the sibling guard in
//! `rotelyx-net` says in almost these words. This file enforces this one. Add a
//! constant-time comparison anywhere in the first-party crates and this test
//! fails until §6 of the threat model says what it compares and why.
//!
//! It deliberately does not check *how* a comparison is written. Whether
//! something should be constant time is a judgement; whether somebody wrote it
//! down is not.

use std::path::{Path, PathBuf};

/// Files holding a comparison on secret material, and what §6 says about each.
///
/// Paths are relative to the workspace root. Keep this sorted.
const CLASSIFIED: &[(&str, &str)] = &[
    (
        "crates/rotelyx-core/src/access.rs",
        "an arriving contact proof, and an invitation secret against the revoked list",
    ),
    (
        "crates/rotelyx-core/src/store.rs",
        "an invitation secret against the ones this device issued, when revoking",
    ),
    (
        "crates/rotelyx-crypto/src/hybrid.rs",
        "two post-quantum shared secrets",
    ),
    (
        "crates/rotelyx-mailbox-server/src/vault.rs",
        "a passphrase against the one a cached key was derived from",
    ),
    (
        "crates/rotelyx-mailbox-server/src/wake.rs",
        "a device's revocation secret against the stored hash",
    ),
    (
        "crates/rotelyx-notifier/src/main.rs",
        "the caller secret the mailbox presents against the one this holds",
    ),
    (
        "crates/rotelyx-mailbox/src/envelope.rs",
        "a tag against the one a recipient expected",
    ),
];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/rotelyx-crypto
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// Source lines outside `mod tests`.
///
/// A file whose only constant-time comparison is an assertion in its own tests
/// is not a site anybody has to classify, and counting it would train whoever
/// hits this failure to add noise to the threat model.
fn production_lines(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_tests = false;
    let mut depth: i32 = 0;

    for line in src.lines() {
        if !in_tests && line.contains("mod tests") && line.contains('{') {
            in_tests = true;
            depth = line.matches('{').count() as i32 - line.matches('}').count() as i32;
            continue;
        }
        if in_tests {
            depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            if depth <= 0 {
                in_tests = false;
            }
            continue;
        }
        out.push(line);
    }
    out
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every first-party crate's own source. `crates/net` is derived from upstream
/// and is reviewed as a whole rather than line by line, which §6 says.
fn first_party_sources(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("crates"))
        .expect("crates directory")
        .flatten()
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("rotelyx-") {
            rust_sources(&entry.path().join("src"), &mut files);
        }
    }
    files.sort();
    files
}

#[test]
fn every_secret_comparison_is_one_the_threat_model_classified() {
    let root = workspace_root();
    let mut seen: Vec<String> = Vec::new();

    for file in first_party_sources(&root) {
        let src = std::fs::read_to_string(&file).expect("reading a source file");
        let compares = production_lines(&src).iter().any(|line| {
            let t = line.trim_start();
            !t.starts_with("//") && (t.contains("ct_eq(") || t.contains("secrets_match("))
        });
        if compares {
            let rel = file
                .strip_prefix(&root)
                .expect("inside the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            seen.push(rel);
        }
    }
    seen.sort();

    let classified: Vec<String> = CLASSIFIED.iter().map(|(p, _)| p.to_string()).collect();

    let unlisted: Vec<&String> = seen.iter().filter(|p| !classified.contains(p)).collect();
    assert!(
        unlisted.is_empty(),
        "these compare secret material and section 6 of docs/THREAT-MODEL.md does not \
         mention them: {unlisted:?}. Say what each one compares and whether being \
         constant time is correct for it, then add it to CLASSIFIED here. The document \
         claims the review is complete, so an unlisted site makes it untrue."
    );

    let gone: Vec<&String> = classified.iter().filter(|p| !seen.contains(p)).collect();
    assert!(
        gone.is_empty(),
        "section 6 classifies comparisons in these, and they no longer have any: \
         {gone:?}. Remove them from the threat model and from CLASSIFIED, or the \
         document describes work on code that is not there."
    );
}
