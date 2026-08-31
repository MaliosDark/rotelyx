//! The workflow file says what runs. This says the file means it.
//!
//! # What happened
//!
//! `ci.yml` had two jobs keyed `transport`. YAML keeps the last of two
//! identical keys, so the first one **did not exist**: the file listed ten jobs
//! and nine ran, and the one silently dropped was the 117 tests of
//! `rotelyx-relay-proto`, the crate that carries the relay wire format.
//!
//! `crates/net/README.md` said, at the time, that every crate there had a CI
//! job. It was written in good faith and it was not true, and nothing could
//! have said so: a duplicate key produces no warning from YAML, from GitHub, or
//! from anything that reads the file expecting a map.
//!
//! # Why this is a test and not a review note
//!
//! Every guard in this repository exists because a promise about the build was
//! made in prose and quietly stopped holding. This is the same shape: the list
//! of jobs is a claim about what is checked, and a claim about what is checked
//! is worth exactly as much as something that checks it.
//!
//! Deliberately crude. It reads the file as text rather than pulling in a YAML
//! parser, because the failure being caught is precisely that a YAML parser
//! accepts this file and returns fewer jobs than it contains.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// Top level keys under `jobs:`, in order, with the line each was found on.
///
/// A job key is a line indented exactly two spaces, ending in a colon, inside
/// the `jobs:` block. Anything deeper belongs to a job rather than naming one.
fn job_keys(text: &str) -> Vec<(usize, String)> {
    let mut keys = Vec::new();
    let mut inside = false;

    for (number, line) in text.lines().enumerate() {
        if line.starts_with("jobs:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // A top level key of the document ends the jobs block.
        if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            break;
        }
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') || rest.starts_with('#') || rest.trim().is_empty() {
            continue;
        }
        if let Some(name) = rest.strip_suffix(':') {
            keys.push((number + 1, name.to_string()));
        }
    }
    keys
}

fn workflows(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(".github/workflows");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    out.sort();
    out
}

#[test]
fn no_workflow_defines_one_job_twice() {
    let root = workspace_root();
    let files = workflows(&root);
    assert!(!files.is_empty(), "found no workflow files to check");

    let mut complaints = Vec::new();

    for file in &files {
        let text = std::fs::read_to_string(file).expect("readable workflow");
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();

        for (line, key) in job_keys(&text) {
            if let Some(first) = seen.insert(key.clone(), line) {
                complaints.push(format!(
                    "{}: job `{key}` is defined on line {first} and again on line {line}. \
                     Only the second one runs.",
                    file.file_name().unwrap_or_default().to_string_lossy(),
                ));
            }
        }
    }

    assert!(
        complaints.is_empty(),
        "a workflow defines the same job twice, so one of them silently does not \
         run:\n  {}",
        complaints.join("\n  ")
    );
}

/// The reader has to find at least the jobs that are known to be there, or the
/// test above is passing because it parsed nothing.
///
/// This is the check the guard itself needs. A scanner that finds no keys
/// reports no duplicates, and reports it just as confidently.
#[test]
fn the_reader_actually_finds_jobs() {
    let root = workspace_root();
    let ci = root.join(".github/workflows/ci.yml");
    let text = std::fs::read_to_string(&ci).expect("ci.yml is readable");
    let keys = job_keys(&text);

    assert!(
        keys.len() >= 8,
        "the job reader found {} keys in ci.yml, which is too few to believe. \
         If the file genuinely shrank, lower this number and say why; if the \
         format changed, the reader above needs to change with it. Found: {:?}",
        keys.len(),
        keys.iter().map(|(_, k)| k).collect::<Vec<_>>()
    );

    for known in ["test", "lint", "nat"] {
        assert!(
            keys.iter().any(|(_, k)| k == known),
            "the job reader did not find `{known}`, so it is not reading job keys"
        );
    }
}
