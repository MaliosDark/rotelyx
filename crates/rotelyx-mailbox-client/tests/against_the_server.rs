//! The client against the server in this repository, over a real socket.
//!
//! # Why this and not a mock
//!
//! The client exists because a protocol had two implementations, one in Dart and
//! one nowhere, and the two ends could not talk. A mock would be a third
//! implementation of the same guesses. The server is here, so it can be run.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use data_encoding::BASE64;
use rotelyx_mailbox_client::Mailbox;

/// The server, on a port of its own, killed when the test ends.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start(port: u16) -> Option<Server> {
    let binary = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/rotelyx-mailbox-server");
    if !std::path::Path::new(binary).exists() {
        println!("\n  no mailbox server built, skipping: cargo build -p rotelyx-mailbox-server");
        return None;
    }

    let child = Command::new(binary)
        .args(["--bind", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Wait for it rather than sleeping a guess.
    for _ in 0..60 {
        if Mailbox::connect(&format!("ws://127.0.0.1:{port}/mailbox"))
            .await
            .is_ok()
        {
            return Some(Server { child, port });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

fn tag(byte: u8) -> String {
    std::iter::repeat_n(format!("{byte:02x}"), 32).collect()
}

/// One side leaves an envelope, the other collects it.
#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_crosses_the_mailbox() {
    let Some(server) = start(3391).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let meeting = "a-meeting-phrase-long-enough";
    let tag_hex = rotelyx_wasm::rendezvous_tag(meeting).expect("tag");

    // The collector listens first, so the deposit is handed over rather than
    // held. Both paths are exercised; this is the one a live pairing takes.
    let mut collector = Mailbox::connect(&url).await.expect("collector connects");
    let waiting = collector
        .subscribe(&[tag_hex.clone()])
        .await
        .expect("subscribe");
    assert!(waiting.is_empty(), "a fresh tag had something under it");

    let payload = BASE64.encode(b"a key package would go here");
    let envelope = rotelyx_wasm::seal_under(&tag_hex, &payload).expect("seal");

    let mut sender = Mailbox::connect(&url).await.expect("sender connects");
    sender.deposit(&envelope).await.expect("deposit");

    let got = collector
        .next_envelope(Duration::from_secs(5))
        .await
        .expect("read")
        .expect("nothing arrived");

    let opened = rotelyx_wasm::open_under(&got, &tag_hex).expect("open");
    assert_eq!(
        BASE64.decode(opened.as_bytes()).expect("decode"),
        b"a key package would go here",
        "what came out is not what went in"
    );
}

/// Nobody listening is held, not lost. That is what a mailbox is for.
#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_with_nobody_listening_is_held() {
    let Some(server) = start(3392).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let tag_hex = rotelyx_wasm::rendezvous_tag("another-meeting-phrase").expect("tag");
    let payload = BASE64.encode(b"left while they slept");
    let envelope = rotelyx_wasm::seal_under(&tag_hex, &payload).expect("seal");

    let mut sender = Mailbox::connect(&url).await.expect("connect");
    sender.deposit(&envelope).await.expect("deposit");

    // And it is there when somebody comes for it.
    let mut collector = Mailbox::connect(&url).await.expect("connect");
    let waiting = collector
        .subscribe(&[tag_hex.clone()])
        .await
        .expect("subscribe");
    assert_eq!(waiting.len(), 1, "the held envelope was not waiting");
    assert!(rotelyx_wasm::open_under(&waiting[0], &tag_hex).is_ok());
}

/// A tag nobody deposited under stays empty, and waiting on it is not an error.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_tag_times_out_rather_than_failing() {
    let Some(server) = start(3393).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let mut client = Mailbox::connect(&url).await.expect("connect");
    assert!(client.subscribe(&[tag(0x5a)]).await.expect("subscribe").is_empty());

    assert!(
        client
            .next_envelope(Duration::from_millis(300))
            .await
            .expect("waiting is not a failure")
            .is_none(),
        "something arrived under a tag nobody used"
    );
}
