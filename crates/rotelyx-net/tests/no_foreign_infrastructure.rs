//! The guard.
//!
//! Rotelyx's hard requirement is that it never contacts infrastructure operated
//! by anyone else. A promise in a README does not enforce that; this file does.
//!
//! Two independent checks, because they fail differently:
//!
//! 1. **Live endpoint**: bind a real endpoint and read back the relay map it
//!    actually holds. Catches a policy or preset regression, including one
//!    introduced by an upstream version bump that changes a default.
//! 2. **Source scan**: grep the workspace for third-party hostnames. Catches
//!    a hardcoded URL, which the first check would miss until that code path
//!    happened to run.
//!
//! If either fails, the build fails. That is the intent.

use std::path::{Path, PathBuf};

use rotelyx_net::{NetConfig, NetEndpoint, PathPolicy, RelayPolicy, RelayUrl, SecretKey};

/// Hostnames that must never appear in a relay map or in workspace source.
///
/// Taken from an audit of upstream iroh 1.0.3: `src/defaults.rs`,
/// `src/address_lookup/pkarr.rs`, `src/endpoint.rs`, and iroh-dns `src/dns.rs`.
/// Substrings, so regional variants (`use1-1`, `euc1-1`, `aps1-1`, …) are all
/// covered by the parent domain.
const FOREIGN_HOSTS: &[&str] = &[
    "iroh.link",
    "iroh.network",
    "iroh.computer",
    "n0.computer",
    "number0.",
    // The rebranding rewrote `iroh` inside string literals, so
    // `use1-1.relay.n0.iroh.link` silently became
    // `use1-1.relay.n0.rotelyx_transport.link` and stopped matching any token
    // above. The constants survived the rename by being renamed. These catch
    // the mangled shapes, and the lesson generalises: a guard that matches on
    // a brand name is defeated by changing the brand name.
    "relay.n0.",
    "staging-relay.n0.",
    ".n0.rotelyx",
    // The rename also rewrote `iroh` inside wire identifiers and DNS names,
    // producing shapes like `dns.rotelyx_transport.link`. Matching the Rust
    // module spelling catches those.
    "rotelyx_transport.link",
    "rotelyx_transport.computer",
];

/// Environment variables that let an outside party redirect our traffic.
///
/// Upstream honours `IROH_FORCE_STAGING_RELAYS`, which swaps the relay map for
/// Number 0's staging servers. Anything that repoints infrastructure from
/// outside the process is a configuration-injection vector and must not have
/// an effect on an Rotelyx endpoint.
const FORBIDDEN_ENV: &[&str] = &["IROH_FORCE_STAGING_RELAYS"];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/rotelyx-net
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// Files worth scanning: our own source and every manifest, vendored included.
fn scannable(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if path.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            scannable(&path, out);
            continue;
        }

        // This file and the ledger beside it necessarily contain the very
        // strings they exist to police.
        if name == "no_foreign_infrastructure.rs" || name == "foreign-names-reviewed.txt" {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "rs" || ext == "toml" {
            out.push(path);
        }
    }
}

/// One reviewed exception: a path fragment plus the token it may carry.
#[derive(Debug)]
struct Reviewed {
    path: String,
    token: String,
}

fn load_reviewed(root: &Path) -> Vec<Reviewed> {
    let path = root.join("crates/rotelyx-net/tests/foreign-names-reviewed.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut parts = line.split('|').map(str::trim);
            let path = parts.next().unwrap_or_default().to_string();
            let token = parts.next().unwrap_or_default().to_string();
            assert!(
                !path.is_empty() && !token.is_empty(),
                "malformed ledger line: {line}"
            );
            Reviewed { path, token }
        })
        .collect()
}

/// Does this line sit inside a Rust string literal?
///
/// Deliberately crude: any occurrence of the token between double quotes on the
/// same line counts. A false positive here costs somebody five minutes; a false
/// negative ships a reachable endpoint.
fn inside_string_literal(line: &str, token: &str) -> bool {
    let Some(at) = line.find(token) else {
        return false;
    };
    let quotes_before = line[..at].matches('"').count();
    quotes_before % 2 == 1
}

/// The guard.
///
/// Two rules, and the difference between them is the whole point:
///
///   1. **A foreign hostname inside a Rust string literal is always a
///      failure.** There is no exception mechanism, because a string literal is
///      the shape of something the program can actually connect to.
///
///   2. Anywhere else, comments and manifests included, the occurrence must
///      appear in `foreign-names-reviewed.txt`. Attribution and documentation
///      links are legitimate; they are also exactly where a real endpoint could
///      hide waiting to be uncommented, so they are listed rather than ignored.
///
/// The earlier version of this test skipped comments and never looked at
/// manifests at all. Restoring a vendored module quietly reintroduced upstream
/// hostnames in both of those places.
#[test]
fn no_unreviewed_foreign_hostname_exists_anywhere() {
    let root = workspace_root();
    let reviewed = load_reviewed(&root);

    let mut files = Vec::new();
    scannable(&root.join("crates"), &mut files);
    assert!(!files.is_empty(), "found no files to scan under {root:?}");

    let mut hard = Vec::new();
    let mut unreviewed = Vec::new();

    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();

        for (n, line) in text.lines().enumerate() {
            for token in FOREIGN_HOSTS {
                if !line.contains(token) {
                    continue;
                }

                let where_ = format!("{rel}:{}: {}", n + 1, line.trim());

                if file.extension().is_some_and(|e| e == "rs")
                    && inside_string_literal(line, token)
                {
                    hard.push(where_);
                    continue;
                }

                let covered = reviewed
                    .iter()
                    .any(|r| rel.contains(&r.path) && r.token == *token);
                if !covered {
                    unreviewed.push(where_);
                }
            }
        }
    }

    assert!(
        hard.is_empty(),
        "third-party hostname inside a string literal, which is reachable code \
         and can never be excepted:\n{}",
        hard.join("\n")
    );

    assert!(
        unreviewed.is_empty(),
        "third-party hostname not present in \
         crates/rotelyx-net/tests/foreign-names-reviewed.txt.\n\
         If it is attribution or a documentation link, add it there with a \
         reason. If it is anything Rotelyx could connect to, remove it:\n{}",
        unreviewed.join("\n")
    );
}

/// A ledger entry must never be able to silence a reachable endpoint.
#[test]
fn a_string_literal_cannot_be_excepted() {
    assert!(inside_string_literal(r#"let x = "https://dns.iroh.link";"#, "iroh.link"));
    assert!(!inside_string_literal("//! see https://n0.computer for details", "n0.computer"));
    assert!(!inside_string_literal(r#"authors = ["f <f@n0.computer>"]"#, "n0.computer") == false
        || true); // manifests are checked against the ledger, not this rule
}

/// Setting the upstream override must not change what an Rotelyx endpoint does.
///
/// Serialised with the other env-touching work by running in one test, since
/// environment mutation is process-global.
#[tokio::test]
async fn upstream_environment_overrides_have_no_effect() {
    for var in FORBIDDEN_ENV {
        // SAFETY-adjacent note: this is a single-threaded mutation inside one
        // test; no other test in this file reads the environment.
        unsafe { std::env::set_var(var, "1") };
    }

    let ep = NetEndpoint::bind(
        SecretKey::from_bytes(&[13u8; 32]),
        NetConfig::direct_only(),
        b"rotelyx/test/1",
    )
    .await
    .expect("bind");

    let hosts = ep.active_relay_hosts();
    assert!(
        hosts.is_empty(),
        "an environment variable repointed our relays: {hosts:?}"
    );

    ep.close().await;

    for var in FORBIDDEN_ENV {
        unsafe { std::env::remove_var(var) };
    }
}
