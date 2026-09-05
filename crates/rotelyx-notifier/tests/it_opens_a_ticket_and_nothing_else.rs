//! What the notifier will and will not do when spoken to.
//!
//! Started as a real process and talked to over its real socket, because the
//! properties worth asserting are about what it accepts from a caller, and a
//! caller is the thing a unit test replaces with itself.
//!
//! Push is deliberately not configured. A wake that reached Apple would be a
//! test that needs Apple to pass, and what is being checked here is the half
//! before that: which tickets are opened, which are refused, and what the
//! answer says.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use data_encoding::BASE64;
use rotelyx_crypto::hybrid::HybridPublicKey;
use rotelyx_crypto::{TicketKind, WakeTicket};

const CALLER: &str = "a-shared-secret-between-mailbox-and-notifier";

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock")
        .as_secs()
        / 3600
}

async fn start(port: u16) -> (Running, HybridPublicKey) {
    let dir = std::env::temp_dir().join(format!("rotelyx-notifier-test-{port}"));
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::remove_file(dir.join("key"));

    let secret_path = dir.join("caller");
    std::fs::write(&secret_path, CALLER).expect("write the caller secret");

    let child = Command::new(env!("CARGO_BIN_EXE_rotelyx-notifier"))
        .args([
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--key",
            dir.join("key").to_str().expect("path"),
            "--caller-secret",
            secret_path.to_str().expect("path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the notifier");

    let running = Running(child);

    // Its own key, asked for over the wire rather than read off the disk, so
    // this also covers that the endpoint an operator uses actually answers.
    let client = reqwest::Client::new();
    let mut public = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        if let Ok(r) = client.get(format!("http://127.0.0.1:{port}/key")).send().await {
            if let Ok(text) = r.text().await {
                if let Ok(bytes) = BASE64.decode(text.trim().as_bytes()) {
                    if let Ok(key) = HybridPublicKey::from_bytes(&bytes) {
                        public = Some(key);
                        break;
                    }
                }
            }
        }
    }

    (running, public.expect("the notifier never answered"))
}

async fn post(port: u16, secret: Option<&str>, tickets: Vec<String>) -> (u16, String) {
    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("http://127.0.0.1:{port}/wake"))
        .json(&serde_json::json!({ "tickets": tickets }));
    if let Some(s) = secret {
        request = request.header("x-rotelyx-caller", s);
    }
    let response = request.send().await.expect("post");
    let status = response.status().as_u16();
    (status, response.text().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ticket_is_taken_and_a_stranger_is_not() {
    let port = 34310;
    let (_running, public) = start(port).await;

    let ticket = WakeTicket::seal(&public, TicketKind::Apns, &"a".repeat(64), hour())
        .expect("seal");
    let sealed = BASE64.encode(&ticket.to_bytes());

    // Without the shared secret, nothing happens. Not a privacy control: it is
    // what stops anybody who can reach this from spending somebody's battery.
    let (status, _) = post(port, None, vec![sealed.clone()]).await;
    assert_eq!(status, 403, "an unauthenticated caller was served");

    let (status, _) = post(port, Some("wrong"), vec![sealed.clone()]).await;
    assert_eq!(status, 403, "the wrong secret was served");

    // With it, the ticket is accepted. Nothing is pushed because no push
    // service is configured, and the answer says zero rather than failing:
    // this server is not told which tickets matter and must not treat one it
    // cannot deliver as an error.
    let (status, body) = post(port, Some(CALLER), vec![sealed]).await;
    assert_eq!(status, 200, "a proper caller was refused");
    assert!(body.contains("\"woken\":0"), "unexpected answer: {body}");
}

/// A ticket sealed to somebody else, an expired one, and rubbish all take the
/// same path: skipped in silence.
///
/// Reporting which one failed would tell the caller something about the device
/// behind it, and the caller is the one party that knows which tag the ticket
/// came from. Decoys are built exactly so they cannot be told apart, so this
/// must not be the seam where they are.
#[tokio::test(flavor = "multi_thread")]
async fn what_it_cannot_open_it_does_not_talk_about() {
    let port = 34311;
    let (_running, public) = start(port).await;

    let (stranger, _) = rotelyx_crypto::HybridKem::generate();
    let elsewhere = WakeTicket::seal(&stranger.public(), TicketKind::Apns, &"b".repeat(64), hour())
        .expect("seal");
    let stale = WakeTicket::seal(&public, TicketKind::Apns, &"c".repeat(64), hour() - 1000)
        .expect("seal");

    let (status, body) = post(
        port,
        Some(CALLER),
        vec![
            BASE64.encode(&elsewhere.to_bytes()),
            BASE64.encode(&stale.to_bytes()),
            "not base64 at all".to_owned(),
            BASE64.encode(b"short"),
        ],
    )
    .await;

    assert_eq!(status, 200, "a batch of unopenable tickets was an error");
    assert!(body.contains("\"woken\":0"), "unexpected answer: {body}");
    assert!(
        !body.contains("stranger") && !body.contains("expired") && !body.contains("index"),
        "the answer said which ticket failed: {body}"
    );
}

/// One call must not be able to wake the world.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_cannot_ask_for_an_unbounded_batch() {
    let port = 34312;
    let (_running, public) = start(port).await;

    let one = BASE64.encode(
        &WakeTicket::seal(&public, TicketKind::Apns, &"d".repeat(64), hour())
            .expect("seal")
            .to_bytes(),
    );

    let (status, _) = post(port, Some(CALLER), vec![one; 500]).await;
    assert_eq!(status, 413, "an unbounded batch was accepted");
}
