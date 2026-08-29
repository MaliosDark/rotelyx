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

/// Delivery does not remove, and acknowledging does.
///
/// This is the property the whole delivery path was rebuilt around, and until
/// now nothing checked it end to end: the server had the behaviour, the client
/// had the call, and no test put the two together. That gap is how the phone
/// and the browser went months without acknowledging anything at all, with
/// every envelope they received sitting until its seven-day TTL and the tag
/// filling at 256, after which deposits are refused and messages are lost.
///
/// Both halves matter and the first is the one that is easy to lose: if
/// delivery removed, a second reader would find nothing, and anybody able to
/// derive a tag could drain it.
#[tokio::test(flavor = "multi_thread")]
async fn delivery_holds_and_a_receipt_releases() {
    let Some(server) = start(3396).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let tag_hex = rotelyx_wasm::rendezvous_tag("a receipt is not a capability").expect("tag");
    let payload = BASE64.encode(b"still here after you read it");
    let envelope = rotelyx_wasm::seal_under(&tag_hex, &payload).expect("seal");

    let mut sender = Mailbox::connect(&url).await.expect("connect");
    sender.deposit(&envelope).await.expect("deposit");

    // Read it once, and do not say anything.
    let mut first = Mailbox::connect(&url).await.expect("connect");
    let waiting = first.subscribe(&[tag_hex.clone()]).await.expect("subscribe");
    assert_eq!(waiting.len(), 1, "the deposit did not arrive");

    // A second reader still finds it. Delivery is not removal, which is what
    // stops a tag being drained by anybody who can compute it.
    let mut second = Mailbox::connect(&url).await.expect("connect");
    let again = second.subscribe(&[tag_hex.clone()]).await.expect("subscribe");
    assert_eq!(
        again.len(),
        1,
        "reading removed it: two devices on one tag would race and one would \
         lose the message, which is what peeking exists to prevent"
    );

    // Now say it arrived.
    second.collected(&again).await.expect("collected");

    // And it is gone for everybody.
    let mut third = Mailbox::connect(&url).await.expect("connect");
    let after = third.subscribe(&[tag_hex.clone()]).await.expect("subscribe");
    assert!(
        after.is_empty(),
        "the receipt did not release it, so the mailbox goes on holding \
         everything until the TTL and the tag fills at 256"
    );
}

/// A receipt only counts for a tag the connection is listening on.
///
/// Otherwise it would be a capability: name any digest and remove it, which is
/// the same power removal-on-delivery handed out and the reason that was taken
/// away.
#[tokio::test(flavor = "multi_thread")]
async fn a_receipt_for_a_tag_nobody_subscribed_to_removes_nothing() {
    let Some(server) = start(3397).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let tag_hex = rotelyx_wasm::rendezvous_tag("not yours to acknowledge").expect("tag");
    let payload = BASE64.encode(b"somebody else's mail");
    let envelope = rotelyx_wasm::seal_under(&tag_hex, &payload).expect("seal");

    let mut sender = Mailbox::connect(&url).await.expect("connect");
    sender.deposit(&envelope).await.expect("deposit");

    // Read it as the owner would, to learn the digest, then acknowledge it from
    // a connection that never subscribed.
    let mut owner = Mailbox::connect(&url).await.expect("connect");
    let waiting = owner.subscribe(&[tag_hex.clone()]).await.expect("subscribe");
    assert_eq!(waiting.len(), 1);

    let mut stranger = Mailbox::connect(&url).await.expect("connect");
    stranger.collected(&waiting).await.expect("sent");

    // Still there.
    let mut owner_again = Mailbox::connect(&url).await.expect("connect");
    let after = owner_again
        .subscribe(&[tag_hex.clone()])
        .await
        .expect("subscribe");
    assert_eq!(
        after.len(),
        1,
        "a receipt from a connection that never listened on the tag removed \
         the envelope, which makes a digest a capability to destroy other \
         people's mail"
    );
}
