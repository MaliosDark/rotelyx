//! A constellation client, for proving constellation end to end against real
//! mailboxes on real machines. It is the client half of `docs/CONSTELLATION.md`:
//! it reads a directory, computes where a tag is placed, and writes to and
//! reads from every replica, deduplicating by digest.
//!
//!   constellation <directory.json> <phrase> deposit "<message>"
//!   constellation <directory.json> <phrase> collect
//!   constellation <directory.json> <phrase> roundtrip "<message>"
//!
//! The tag is derived from the phrase, so a `deposit` and a later `collect`
//! with the same phrase land on the same mailboxes and name the same tag,
//! without either side being told where the other looked. `roundtrip` does both
//! in one process. To see failover, `deposit` while every replica is up, stop
//! one, then `collect`: the message still arrives from the survivor, because it
//! was written to all `K`.
//!
//! The directory's urls are used as given, so a test against machines without
//! TLS lists `ws://<host>:<port>/mailbox`. This is a test client and does not
//! pin the operator's domain the way the phone does; that guard is the app's.

use std::time::Duration;

use data_encoding::{BASE64, HEXLOWER};
use futures_util::{SinkExt, StreamExt};
use rotelyx_directory::Directory;
use rotelyx_mailbox::{Envelope, Tag};
use tokio_tungstenite::tungstenite::Message;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir_path = args.get(1).cloned().unwrap_or_default();
    let phrase = args.get(2).cloned().unwrap_or_default();
    let mode = args.get(3).cloned().unwrap_or_default();
    let message = args.get(4).cloned().unwrap_or_else(|| "hello constellation".into());

    if dir_path.is_empty() || phrase.is_empty() || mode.is_empty() {
        eprintln!("usage: constellation <directory.json> <phrase> <deposit|collect|roundtrip> [message]");
        std::process::exit(2);
    }

    let bytes = std::fs::read(&dir_path).unwrap_or_else(|e| {
        eprintln!("cannot read {dir_path}: {e}");
        std::process::exit(2);
    });
    let directory = Directory::from_json(&bytes).unwrap_or_else(|e| {
        eprintln!("{dir_path} is not a valid directory: {e}");
        std::process::exit(2);
    });

    let tag = tag_from_phrase(&phrase);
    let placed = directory.placement(tag.as_bytes());
    if placed.is_empty() {
        eprintln!("the directory places this tag on no mailbox: is it empty?");
        std::process::exit(1);
    }

    println!(
        "tag {} places on {} of {} mailboxes (K={}):",
        &HEXLOWER.encode(tag.as_bytes())[..16],
        placed.len(),
        directory.mailboxes.len(),
        directory.replicas
    );
    for m in &placed {
        println!("  {} at {}", m.id, m.url);
    }

    match mode.as_str() {
        "deposit" => {
            let stored = deposit_to_all(&placed, tag, &message).await;
            report_deposit(stored, placed.len());
        }
        "collect" => {
            let got = collect_from_all(&placed, tag).await;
            report_collect(&got, placed.len());
        }
        "roundtrip" => {
            let stored = deposit_to_all(&placed, tag, &message).await;
            report_deposit(stored, placed.len());
            let got = collect_from_all(&placed, tag).await;
            report_collect(&got, placed.len());
        }
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}

/// A 32 byte tag from a phrase, so the two ends agree without sharing a tag.
fn tag_from_phrase(phrase: &str) -> Tag {
    let mut hasher = blake3::Hasher::new_derive_key("rotelyx constellation harness tag v1");
    hasher.update(phrase.as_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    Tag::from_bytes(&out).expect("32 bytes is a tag")
}

/// Deposit one envelope to every replica, returning how many stored it.
async fn deposit_to_all(
    placed: &[rotelyx_directory::Mailbox],
    tag: Tag,
    message: &str,
) -> usize {
    let envelope = Envelope::seal(tag, message.as_bytes()).expect("seal");
    let wire = BASE64.encode(&envelope.to_bytes());
    let mut stored = 0;
    for m in placed {
        match deposit_one(&m.url, &wire).await {
            Ok(()) => {
                println!("  deposited to {}", m.id);
                stored += 1;
            }
            Err(e) => eprintln!("  {} did not store it: {e}", m.id),
        }
    }
    stored
}

async fn deposit_one(url: &str, envelope_b64: &str) -> Result<(), String> {
    let (mut sock, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let deposit = serde_json::json!({"op": "deposit", "envelope": envelope_b64}).to_string();
    sock.send(Message::Text(deposit.into()))
        .await
        .map_err(|e| format!("send: {e}"))?;
    // Wait for the stored reply, with a deadline so a silent mailbox names
    // itself rather than hanging the run.
    loop {
        match tokio::time::timeout(Duration::from_secs(10), sock.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).map_err(|e| e.to_string())?;
                match v["op"].as_str() {
                    Some("stored") => return Ok(()),
                    Some("error") => return Err(format!("mailbox error: {}", v["message"])),
                    // Tier and other informational frames can precede stored.
                    _ => continue,
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => return Err(format!("read: {e}")),
            Ok(None) => return Err("closed before storing".into()),
            Err(_) => return Err("timed out waiting for stored".into()),
        }
    }
}

/// What a collect run recovered: which replicas delivered, and the unique
/// messages after deduplicating by digest.
struct Collected {
    delivered_by: usize,
    messages: Vec<String>,
}

/// Subscribe to the tag on every replica, gather for a few seconds, and
/// deduplicate by digest across all of them.
async fn collect_from_all(placed: &[rotelyx_directory::Mailbox], tag: Tag) -> Collected {
    let tag_hex = HEXLOWER.encode(tag.as_bytes());
    let mut seen: std::collections::HashMap<[u8; 32], String> = std::collections::HashMap::new();
    let mut delivered_by = 0;
    for m in placed {
        match collect_one(&m.url, &tag_hex).await {
            Ok(envelopes) => {
                if !envelopes.is_empty() {
                    delivered_by += 1;
                }
                println!("  {} delivered {}", m.id, envelopes.len());
                for env in envelopes {
                    let digest = env.digest();
                    let text = trim_message(env.payload());
                    seen.entry(digest).or_insert(text);
                }
            }
            Err(e) => eprintln!("  {} could not be collected from: {e}", m.id),
        }
    }
    let mut messages: Vec<String> = seen.into_values().collect();
    messages.sort();
    Collected { delivered_by, messages }
}

async fn collect_one(url: &str, tag_hex: &str) -> Result<Vec<Envelope>, String> {
    let (mut sock, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let subscribe = serde_json::json!({"op": "subscribe", "tags": [tag_hex]}).to_string();
    sock.send(Message::Text(subscribe.into()))
        .await
        .map_err(|e| format!("send: {e}"))?;

    let mut out = Vec::new();
    // Read for a short window: everything waiting comes right after ready, and
    // this is a probe, not a long lived subscription.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, sock.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).map_err(|e| e.to_string())?;
                match v["op"].as_str() {
                    Some("envelope") => {
                        let b64 = v["envelope"].as_str().ok_or("envelope without bytes")?;
                        let bytes = BASE64.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
                        let env = Envelope::from_bytes(&bytes).map_err(|e| format!("{e:?}"))?;
                        out.push(env);
                    }
                    Some("error") => return Err(format!("mailbox error: {}", v["message"])),
                    _ => continue,
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => return Err(format!("read: {e}")),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Recover the text from a padded payload: the harness deposits plain bytes, so
/// the message is everything up to the trailing zero padding.
fn trim_message(payload: &[u8]) -> String {
    let end = payload.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

fn report_deposit(stored: usize, replicas: usize) {
    println!("stored on {stored} of {replicas} replicas");
    if stored == 0 {
        std::process::exit(1);
    }
}

fn report_collect(got: &Collected, replicas: usize) {
    println!(
        "collected from {} of {} replicas, {} unique message(s) after dedup:",
        got.delivered_by, replicas, got.messages.len()
    );
    for m in &got.messages {
        println!("  {m:?}");
    }
    if got.messages.is_empty() {
        std::process::exit(1);
    }
}
