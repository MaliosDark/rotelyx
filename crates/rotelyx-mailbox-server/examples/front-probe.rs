//! Prove a live front actually carries a session, rather than listening.
//!
//! A front that has lost its connections to the mailbox goes on accepting
//! phones and answering `/front-key` from memory, so every cheap check passes
//! while nothing is delivered: `101 Switching Protocols`, a key of the right
//! length, a landing page saying Operational. The only question worth asking is
//! whether a sealed session gets an answer, which is what this does, exactly as
//! a phone does it: fetch the key, open a session to it, subscribe to a tag
//! nobody uses, and wait for the `ready` that answers a subscribe.
//!
//!     cargo run -p rotelyx-mailbox-server --example front-probe -- wss://HOST
//!
//! The URL is the front's **base**: `/front` and `/front-key` are appended
//! here. Exit status is 0 only if the mailbox behind the front answered.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use data_encoding::{BASE64, HEXLOWER};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let base = std::env::args()
        .nth(1)
        .context("usage: front-probe <front base url, e.g. wss://orvexa.telyx.me>")?;
    let base = base.trim_end_matches('/').to_string();
    let http = base.replace("wss://", "https://").replace("ws://", "http://");

    let key_b64 = reqwest::get(format!("{http}/front-key"))
        .await
        .with_context(|| format!("asking {http}/front-key"))?
        .error_for_status()
        .context("the front served no key")?
        .text()
        .await?
        .trim()
        .to_string();
    let key = rotelyx_crypto::HybridPublicKey::from_bytes(
        &BASE64.decode(key_b64.as_bytes()).context("the key is not base64")?,
    )
    .map_err(|_| anyhow::anyhow!("the key is not a key"))?;

    let url = format!("{base}/front");
    let (mut socket, _) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("connecting to {url}"))?;

    // A session id of this phone's own choosing, and a tag nobody is using, so
    // the probe reads nothing that belongs to anybody.
    let id: [u8; rotelyx_crypto::SESSION_ID_LEN] = rand_bytes();
    let (mut session, hello) = rotelyx_crypto::FrontSession::open_to(&key, id)
        .map_err(|_| anyhow::anyhow!("the session would not open"))?;
    let label = BASE64.encode(&id);

    socket
        .send(Message::Text(
            serde_json::json!({ "s": label, "hello": BASE64.encode(hello.to_bytes().as_slice()) })
                .to_string()
                .into(),
        ))
        .await
        .context("sending the hello")?;

    let tag = HEXLOWER.encode(&rand_bytes::<32>());
    let request = serde_json::json!({ "op": "subscribe", "tags": [tag] }).to_string();
    let sealed = session
        .seal(request.as_bytes())
        .map_err(|_| anyhow::anyhow!("sealing failed"))?;
    socket
        .send(Message::Text(
            serde_json::json!({ "s": label, "b": BASE64.encode(&sealed) })
                .to_string()
                .into(),
        ))
        .await
        .context("sending the subscribe")?;

    // The mailbox answers a subscribe with `ready`. Silence here is the failure
    // this exists to catch: a front with no mailbox behind it never says no.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("{base}: the front took the session and the mailbox never answered");
        }
        let Ok(Some(Ok(message))) = tokio::time::timeout(remaining, socket.next()).await else {
            bail!("{base}: the connection ended before the mailbox answered");
        };
        let Message::Text(text) = message else { continue };
        let Ok(frame) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let Some(body) = frame.get("b").and_then(|b| b.as_str()) else { continue };
        let plain = session
            .open(&BASE64.decode(body.as_bytes()).context("the reply is not base64")?)
            .map_err(|_| anyhow::anyhow!("the reply would not open"))?;
        let reply: serde_json::Value = serde_json::from_slice(&plain)?;
        if reply.get("op").and_then(|o| o.as_str()) == Some("ready") {
            println!("{base}: ready, waiting={}", reply.get("waiting").unwrap_or(&serde_json::json!(0)));
            return Ok(());
        }
        bail!("{base}: the mailbox answered {reply} instead of ready");
    }
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system random source");
    bytes
}
