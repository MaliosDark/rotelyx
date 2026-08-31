//! The third guard.
//!
//! `rotelyx-mobile` exists so that the phone and the browser run one engine.
//! The reason is written into its own module docs: two implementations of one
//! handshake diverge, and the divergence is a security bug that presents as an
//! interoperability bug.
//!
//! One engine does not mean one surface. `rotelyx-wasm` exports methods through
//! `wasm_bindgen` and this crate exports them again through a JSON operation
//! name, by hand, one match arm at a time. Nothing joined the two, so a method
//! added to the browser reached the phone only if somebody remembered.
//!
//! Something did not get remembered. `removeMember` is how a member is put out
//! of a group and how a lost device is revoked, and it is on the wasm surface
//! and not on this one. So the browser and the desktop can revoke a stolen
//! phone, and the phone cannot. That is the wrong client to leave it out of.
//!
//! This test does not decide what belongs on the ABI. It fails when the two
//! surfaces drift apart without somebody writing down which it is: reachable
//! from the phone, or deliberately not, and why.

use std::path::{Path, PathBuf};

/// Exported by the browser and **deliberately absent** from the C ABI.
///
/// Every entry needs a reason. An exception list nobody justifies becomes a
/// list of things somebody once forgot.
const BROWSER_ONLY: &[(&str, &str)] = &[
    ("begin", "TokenRequest: buying capacity blindly. Browser-only because \
      there is no store to buy from yet, which TODO.md still carries as open. \
      The phone needs all three the day there is one"),
    ("blinded", "TokenRequest, as above"),
    ("finish", "TokenRequest, as above"),
    ("groupId", "introspection: the phone never needs the raw id"),
    ("newMeetingCode", "the phone mints codes in Dart, character for character, with a test on each side that reads the other's"),
    ("openUnder", "browser storage: the phone seals through the platform vault instead"),
    ("prettyMeetingCode", "formatting, reimplemented in Dart beside the minting"),
    ("protocolVersion", "reachable as the `protocol.version` operation, under its own name"),
    ("ratchetTree", "introspection for the harness's roster panel"),
    ("readMeetingCode", "the phone parses codes in Dart, beside the minting"),
    ("rendezvousTag", "derived in Dart on the phone, from the code it parsed there"),
    ("sealSession", "browser storage: local storage is the browser's only durable place, and the phone has a vault"),
    ("sealUnder", "browser storage, as above"),
    ("unsealSession", "browser storage, as above"),
];

/// On the wasm surface, not on the C ABI, and not deliberate.
///
/// Kept as a named list rather than a silent exception so it reads as a gap
/// rather than as a decision. Empty it by adding the operation, not by adding
/// a line here.
const MISSING_FROM_THE_PHONE: &[(&str, &str)] = &[];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Everything `wasm_bindgen` puts on the browser's surface.
///
/// Two ways in, and the first version of this read only one of them.
///
/// An explicit `js_name` is the obvious one. The other is that a marked `impl`
/// exports **every** public method in it, under a camelCase name derived from
/// the Rust one, with no attribute of its own. Fifteen methods reached the
/// browser that way, `send` and `receive` and `join` among them, and a guard
/// that could not see them was a guard that would have passed while the core
/// of the protocol drifted.
fn wasm_surface(root: &Path) -> Vec<String> {
    let src = std::fs::read_to_string(root.join("crates/rotelyx-wasm/src/lib.rs"))
        .expect("read rotelyx-wasm");
    let lines: Vec<&str> = src.lines().collect();

    let mut out: Vec<String> = Vec::new();
    let mut inside_exported_impl = false;
    let mut depth: i32 = 0;
    let mut impl_is_next = false;

    for (i, raw) in lines.iter().enumerate() {
        let t = raw.trim();

        if let Some(rest) = t.strip_prefix("#[wasm_bindgen(js_name = ") {
            if let Some(name) = rest.split(')').next() {
                out.push(name.trim().to_string());
            }
        }

        // A bare `#[wasm_bindgen]` on an `impl` block exports its methods.
        if t == "#[wasm_bindgen]" {
            impl_is_next = lines
                .iter()
                .skip(i + 1)
                .take(3)
                .any(|l| l.trim_start().starts_with("impl "));
        }
        if impl_is_next && t.starts_with("impl ") {
            inside_exported_impl = true;
            depth = 0;
            impl_is_next = false;
        }

        if inside_exported_impl {
            depth += raw.matches('{').count() as i32 - raw.matches('}').count() as i32;

            if let Some(name) = t
                .strip_prefix("pub async fn ")
                .or_else(|| t.strip_prefix("pub fn "))
            {
                let name = name.split('(').next().unwrap_or("").trim();
                let has_explicit = i
                    .checked_sub(1)
                    .map(|p| lines[p].contains("js_name"))
                    .unwrap_or(false);
                if !has_explicit && !name.is_empty() {
                    out.push(camel(name));
                }
            }

            if depth <= 0 && t == "}" {
                inside_exported_impl = false;
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// `wasm_bindgen`'s own rule for a name it was not given: `snake_case` becomes
/// `camelCase`.
fn camel(rust: &str) -> String {
    let mut out = String::with_capacity(rust.len());
    let mut upper = false;
    for c in rust.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn abi_surface(root: &Path) -> Vec<String> {
    let src = std::fs::read_to_string(root.join("crates/rotelyx-mobile/src/lib.rs"))
        .expect("read rotelyx-mobile");
    let mut out: Vec<String> = src
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            // `"session.safetyNumber" => ...`
            let rest = t.strip_prefix('"')?;
            let (name, tail) = rest.split_once('"')?;
            if !tail.trim_start().starts_with("=>") {
                return None;
            }
            let (_, method) = name.split_once('.')?;
            Some(method.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[test]
fn every_browser_method_is_reachable_from_the_phone_or_written_down() {
    let root = workspace_root();
    let abi = abi_surface(&root);

    let excused: Vec<&str> = BROWSER_ONLY
        .iter()
        .chain(MISSING_FROM_THE_PHONE.iter())
        .map(|(name, _)| *name)
        .collect();

    let mut undocumented = Vec::new();
    for method in wasm_surface(&root) {
        if abi.contains(&method) || excused.contains(&method.as_str()) {
            continue;
        }
        undocumented.push(method);
    }

    assert!(
        undocumented.is_empty(),
        "these are exported by `rotelyx-wasm` and not reachable through the C \
         ABI, and nothing here says which they are: {undocumented:?}\n\n\
         Add the operation to `rotelyx-mobile`, or add it to `BROWSER_ONLY` \
         with the reason it does not belong on a phone. A method that is on one \
         client and not the other is a difference in what the two can protect, \
         and the paper says a project describing several clients with one \
         security claim is making a false statement about at least one of them."
    );
}

/// Every operation on the ABI is written down in `docs/MOBILE.md`.
///
/// The ABI is a published contract and that file is the only description of it
/// anybody outside this repository has. It has drifted twice: once when
/// `session.rekeyAfterRestore` was added and the document was not told, so the
/// one call an application forgets was also the one call it could not look up;
/// and again on the same day this guard was written, when three operations went
/// on in an afternoon.
///
/// It checks that the name appears, not that the description is good. Whether
/// prose is right is a judgement; whether somebody wrote any is not.
#[test]
fn every_operation_is_in_the_document() {
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join("docs/MOBILE.md")).expect("read MOBILE.md");

    let src = std::fs::read_to_string(root.join("crates/rotelyx-mobile/src/lib.rs"))
        .expect("read rotelyx-mobile");

    let mut undocumented = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else {
            continue;
        };
        let Some((name, tail)) = rest.split_once('"') else {
            continue;
        };
        if !tail.trim_start().starts_with("=>") || !name.contains('.') {
            continue;
        }
        if !doc.contains(name) {
            undocumented.push(name.to_string());
        }
    }
    undocumented.sort();
    undocumented.dedup();

    assert!(
        undocumented.is_empty(),
        "these operations are on the ABI and not named anywhere in \
         docs/MOBILE.md: {undocumented:?}\n\n\
         Somebody writing a client has that file and this binary and nothing \
         else. An operation missing from it exists and cannot be found, which \
         is the same as not existing for everyone outside this repository."
    );
}

#[test]
fn an_excuse_that_stops_being_true_fails() {
    let root = workspace_root();
    let wasm = wasm_surface(&root);
    let abi = abi_surface(&root);

    for (name, reason) in BROWSER_ONLY.iter().chain(MISSING_FROM_THE_PHONE.iter()) {
        assert!(
            wasm.iter().any(|m| m == name),
            "`{name}` is excused here and the browser no longer exports it: \
             remove the row rather than leaving an exception for something that \
             is gone. Reason on file: {reason}"
        );
    }

    for (name, reason) in MISSING_FROM_THE_PHONE {
        assert!(
            !abi.contains(&name.to_string()),
            "`{name}` is listed as missing from the phone and the C ABI exposes \
             it now. Move it out of `MISSING_FROM_THE_PHONE`: the gap closed. \
             Reason on file: {reason}"
        );
    }
}
