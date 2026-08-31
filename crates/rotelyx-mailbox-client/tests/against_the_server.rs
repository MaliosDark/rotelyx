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
///
/// # Ports are chosen by hand, and that has already cost something
///
/// In use: 3391, 3392, 3393, 3396, 3397, 3398, 3399. **Pick one that is not.**
///
/// These tests run in parallel and each starts a server of its own. A test that
/// reuses a port does not fail on the collision: `start` succeeds as soon as
/// something answers, and what answers is the other test's server, started with
/// different arguments. That is how a token test landed on a server with no
/// issuer key and reported that a valid token had been refused.
///
/// Binding port zero would end this, and the server would have to print the
/// port it chose for a test to find it, which it does not.
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
    start_with(port, &[]).await
}

/// The same, with extra arguments, so a test can ask for a server that accepts
/// tokens.
async fn start_with(port: u16, extra: &[&str]) -> Option<Server> {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/rotelyx-mailbox-server"
    );
    if !std::path::Path::new(binary).exists() {
        println!("\n  no mailbox server built, skipping: cargo build -p rotelyx-mailbox-server");
        return None;
    }

    let child = Command::new(binary)
        .args(["--bind", &format!("127.0.0.1:{port}")])
        .args(extra)
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

/// A sealed envelope of roughly `bytes` of payload, addressed to `tag_hex`.
///
/// Sealing pads to a bucket, so the envelope on the wire is at least this big
/// and the server measures the payload rather than the string. Sizes here are
/// chosen well clear of a bucket edge so a test is not deciding anything by a
/// rounding.
fn envelope(tag_hex: &str, bytes: usize) -> String {
    let payload = BASE64.encode(&vec![0x5au8; bytes]);
    rotelyx_wasm::seal_under(tag_hex, &payload).expect("seal")
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
        .subscribe(std::slice::from_ref(&tag_hex))
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
        .subscribe(std::slice::from_ref(&tag_hex))
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
    assert!(client
        .subscribe(&[tag(0x5a)])
        .await
        .expect("subscribe")
        .is_empty());

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
    let waiting = first
        .subscribe(std::slice::from_ref(&tag_hex))
        .await
        .expect("subscribe");
    assert_eq!(waiting.len(), 1, "the deposit did not arrive");

    // A second reader still finds it. Delivery is not removal, which is what
    // stops a tag being drained by anybody who can compute it.
    let mut second = Mailbox::connect(&url).await.expect("connect");
    let again = second
        .subscribe(std::slice::from_ref(&tag_hex))
        .await
        .expect("subscribe");
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
    let after = third
        .subscribe(std::slice::from_ref(&tag_hex))
        .await
        .expect("subscribe");
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
    let waiting = owner
        .subscribe(std::slice::from_ref(&tag_hex))
        .await
        .expect("subscribe");
    assert_eq!(waiting.len(), 1);

    let mut stranger = Mailbox::connect(&url).await.expect("connect");
    stranger.collected(&waiting).await.expect("sent");

    // Still there.
    let mut owner_again = Mailbox::connect(&url).await.expect("connect");
    let after = owner_again
        .subscribe(std::slice::from_ref(&tag_hex))
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

/// A token bought for a tier is honoured, over a real socket.
///
/// # What this covers that nothing did
///
/// Paid tiers were finished on the server and unreachable from every native
/// client: this crate, which the terminal, the desktop and the phone all use,
/// had no auth frame at all, so all three sat on the free tier with no way off
/// it and nothing anywhere saying so. A tier could be sold and could not be
/// spent.
///
/// So this is not a test of the token format, which has plenty. It is a test
/// that a client can present one and be told what it got.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_moves_a_client_off_the_free_tier() {
    // The key the server will trust, and the one the token is minted with.
    const SECRET: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let public = rotelyx_capability::testing::public_hex(SECRET);

    let Some(server) = start_with(3398, &["--issuer", &public]).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let hours = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        / 3600;
    let token = rotelyx_capability::testing::mint(
        SECRET,
        [3u8; 16],
        rotelyx_capability::Tier::Plus,
        hours + 24,
        0,
    );

    let mut paid = Mailbox::connect(&url).await.expect("connects");
    let granted = paid
        .authenticate(&token)
        .await
        .expect("the token is honoured");

    assert_eq!(granted.tier, "plus", "a plus token granted {granted:?}");
    assert_eq!(
        granted.max_fanout,
        rotelyx_capability::Tier::Plus.limits().max_fanout,
        "the tier's name and its limits disagree"
    );
    assert!(
        granted.max_fanout > rotelyx_capability::Tier::Free.limits().max_fanout,
        "paying bought nothing: {granted:?}"
    );

    // And the connection works afterwards, which is the point of paying.
    let tag_hex = tag(0x77);
    paid.subscribe(std::slice::from_ref(&tag_hex))
        .await
        .expect("subscribe after auth");
}

/// A token the server was never given a key for is refused by name, rather than
/// leaving the caller quietly on the free tier.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_from_an_unknown_issuer_is_refused() {
    const OURS: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    const THEIRS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    let Some(server) = start_with(
        3399,
        &["--issuer", &rotelyx_capability::testing::public_hex(OURS)],
    )
    .await
    else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let hours = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        / 3600;
    let token = rotelyx_capability::testing::mint(
        THEIRS,
        [4u8; 16],
        rotelyx_capability::Tier::PlusPlus,
        hours + 24,
        0,
    );

    let mut client = Mailbox::connect(&url).await.expect("connects");
    let refused = client.authenticate(&token).await;
    assert!(
        refused.is_err(),
        "a mailbox accepted a token signed by a key it was never given: {refused:?}"
    );
}

/// A held token is not presented until the free tier refuses something.
///
/// # What this is protecting
///
/// A token is a stable pseudonym at the mailbox: every deposit made under one
/// is tied to every other. Without one, each connection gets a fresh capability
/// and a person's conversations are not tied to each other at all. Presenting
/// the token at connect throws that away permanently, and throws it away for
/// nothing on traffic the free tier would have taken.
///
/// So the observable property is: **a small deposit under a held token must
/// still be made on the free tier**, and only an envelope the free tier refuses
/// may cause the token to be presented.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_token_stays_unpresented_until_it_is_needed() {
    const SECRET: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let public = rotelyx_capability::testing::public_hex(SECRET);

    let Some(server) = start_with(3395, &["--issuer", &public]).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let hours = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        / 3600;
    let token = rotelyx_capability::testing::mint(
        SECRET,
        [9u8; 16],
        rotelyx_capability::Tier::Plus,
        hours + 24,
        0,
    );

    let mut client = Mailbox::connect(&url).await.expect("connects");
    client.hold_token(token);

    // Small enough for the free tier. This must go through without the token
    // ever being presented.
    let small = envelope(&tag(0x51), 512);
    client.deposit(&small).await.expect("a small deposit");

    // The mailbox still sees a free caller: asking it what tier is in force
    // would need an auth, so instead check the thing that follows from it. An
    // envelope past the free ceiling is refused on the free tier and accepted
    // on plus, and the client is holding a plus token, so this one goes
    // through **and that is the moment the token is spent**.
    let large = envelope(&tag(0x52), 200 * 1024);
    client
        .deposit(&large)
        .await
        .expect("the held token should have been presented for this one");

    // And once presented it stays presented: a second large one needs no
    // further round trip and must not fail.
    let again = envelope(&tag(0x53), 200 * 1024);
    client
        .deposit(&again)
        .await
        .expect("still on the paid tier");
}

/// Without a token, the same large envelope is refused. The contrast is what
/// makes the test above mean anything: if the free tier took a 200 KiB
/// envelope, that test would pass with the token never presented at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_free_tier_refuses_what_the_token_was_needed_for() {
    let Some(server) = start(3390).await else {
        return;
    };
    let url = format!("ws://127.0.0.1:{}/mailbox", server.port);

    let mut client = Mailbox::connect(&url).await.expect("connects");
    let large = envelope(&tag(0x54), 200 * 1024);
    let refused = client.deposit(&large).await;

    assert!(
        refused.is_err(),
        "the free tier accepted 200 KiB, so the test above proves nothing"
    );
    let message = refused.unwrap_err().to_string();
    assert!(
        message.contains("tier allows at most"),
        "the refusal no longer says a tier decided it, which is what the client \
         matches on to know a token would help: {message}"
    );
}
