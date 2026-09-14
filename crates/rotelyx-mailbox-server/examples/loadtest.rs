//! How many connections, or how many sessions through a front, one mailbox
//! holds. Not a benchmark of latency: a ceiling. It opens connections in
//! waves and holds them, so the count that stands is the count the mailbox is
//! carrying at once, and reports where it stopped accepting and what it cost.
//!
//!   loadtest <ws-url> direct <count> [tags]
//!   loadtest <ws-url> front  <count> [tags]
//!
//! `direct` opens `count` websocket connections, each subscribing to `tags`
//! random tags, the shape of a device that is not behind a front. `front`
//! opens one connection to the front and `count` sealed sessions inside it,
//! the shape of many devices multiplexed. The url for `front` is the front's
//! base (it fetches the key from `<url>/front-key`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).cloned().unwrap_or_default();
    let mode = args.get(2).cloned().unwrap_or_else(|| "direct".into());
    let count: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let tags: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(40);
    if url.is_empty() {
        eprintln!("usage: loadtest <ws-url> <direct|front> <count> [tags]");
        return;
    }

    let ok = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    match mode.as_str() {
        "direct" => direct(&url, count, tags, ok.clone(), failed.clone()).await,
        "front" => front(&url, count, tags, ok.clone(), failed.clone()).await,
        other => {
            eprintln!("unknown mode {other}");
            return;
        }
    }

    let held = ok.load(Ordering::Relaxed);
    let bad = failed.load(Ordering::Relaxed);
    println!(
        "mode {mode}: asked {count}, holding {held}, refused/failed {bad}, in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    println!("holding them open for 20s so the mailbox's memory can be read...");
    tokio::time::sleep(Duration::from_secs(20)).await;
}

fn random_tags(n: usize) -> Vec<String> {
    (0..n)
        .map(|_| {
            let mut b = [0u8; 32];
            getrandom::fill(&mut b).unwrap();
            b.iter().map(|x| format!("{x:02x}")).collect()
        })
        .collect()
}

async fn direct(url: &str, count: usize, tags: usize, ok: Arc<AtomicU64>, failed: Arc<AtomicU64>) {
    // In waves, so ten thousand connect attempts do not all race the accept
    // queue at once, which measures the listener backlog rather than the
    // ceiling. A held connection stays in its task until the program ends.
    let mut held = Vec::new();
    for chunk in (0..count).collect::<Vec<_>>().chunks(200) {
        let mut wave = Vec::new();
        for _ in chunk {
            let url = url.to_string();
            let ok = ok.clone();
            let failed = failed.clone();
            wave.push(tokio::spawn(async move {
                match tokio_tungstenite::connect_async(&url).await {
                    Ok((mut sock, _)) => {
                        let subscribe = serde_json::json!({"op":"subscribe","tags":random_tags(tags)}).to_string();
                        if sock.send(Message::Text(subscribe.into())).await.is_err() {
                            failed.fetch_add(1, Ordering::Relaxed);
                            return None;
                        }
                        ok.fetch_add(1, Ordering::Relaxed);
                        Some(sock)
                    }
                    Err(_) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }));
        }
        for h in wave {
            if let Ok(Some(sock)) = h.await {
                held.push(sock);
            }
        }
        eprint!("\r  held {} ...", ok.load(Ordering::Relaxed));
    }
    eprintln!();
    // Keep them alive: drain each in a task so a server ping does not close it.
    for mut sock in held {
        tokio::spawn(async move { while sock.next().await.is_some() {} });
    }
}

async fn front(url: &str, count: usize, tags: usize, ok: Arc<AtomicU64>, failed: Arc<AtomicU64>) {
    let http = url.replace("ws://", "http://").replace("wss://", "https://");
    let key_b64 = reqwest::get(format!("{http}/front-key"))
        .await
        .expect("front-key")
        .text()
        .await
        .expect("body");
    let public =
        rotelyx_crypto::HybridPublicKey::from_bytes(&BASE64.decode(key_b64.trim().as_bytes()).unwrap())
            .expect("key");

    let (sock, _) = tokio_tungstenite::connect_async(format!("{url}/front"))
        .await
        .expect("front connection");
    // Split so replies are drained while sessions are opened. Without a reader
    // the server's send buffer fills, its demux loop blocks on the stuck
    // socket, and it stops reading new subscribes: the sessions look sent and
    // never register. A real front reads its replies, so this measures the
    // server, not the harness.
    let (mut write, mut read) = sock.split();
    tokio::spawn(async move { while read.next().await.is_some() {} });

    let mut next_id: u64 = 1;
    for _ in 0..count {
        let id = next_id.to_be_bytes();
        next_id += 1;
        let (mut session, hello) = rotelyx_crypto::FrontSession::open_to(&public, id).unwrap();
        let s_b64 = BASE64.encode(&id);
        if write
            .send(Message::Text(
                serde_json::json!({"s": s_b64, "hello": BASE64.encode(hello.to_bytes().as_slice())})
                    .to_string()
                    .into(),
            ))
            .await
            .is_err()
        {
            failed.fetch_add(1, Ordering::Relaxed);
            break;
        }
        let subscribe = serde_json::json!({"op":"subscribe","tags":random_tags(tags)}).to_string();
        let sealed = session.seal(subscribe.as_bytes()).unwrap();
        if write
            .send(Message::Text(
                serde_json::json!({"s": s_b64, "b": BASE64.encode(&sealed)}).to_string().into(),
            ))
            .await
            .is_err()
        {
            failed.fetch_add(1, Ordering::Relaxed);
            break;
        }
        ok.fetch_add(1, Ordering::Relaxed);
        if ok.load(Ordering::Relaxed) % 500 == 0 {
            eprint!("\r  sessions {} ...", ok.load(Ordering::Relaxed));
        }
    }
    eprintln!();
}
