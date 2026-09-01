//! Does this mailbox know `collected`.
//!
//! The operation that acknowledges an envelope so the server can drop it. A
//! server built before it exists refuses the frame by name, and the client
//! surfaces that as "mailbox refused a frame", which is what a phone showed.
//!
//!     cargo run -p rotelyx-mailbox-client --example collected-probe -- wss://host/mailbox

use std::time::Duration;

use rotelyx_mailbox_client::Mailbox;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://m1.telyx.me/mailbox".to_string());
    println!("\n  {url}");

    let tag: String = std::iter::repeat_n("5c".to_string(), 32).collect();

    let mut client = match Mailbox::connect(&url).await {
        Ok(c) => c,
        Err(e) => return println!("  could not connect: {e}"),
    };
    if let Err(e) = client.subscribe(std::slice::from_ref(&tag)).await {
        return println!("  subscribe refused: {e}");
    }

    let payload = data_encoding::BASE64.encode(b"acknowledge me");
    let envelope = match rotelyx_wasm::seal_under(&tag, &payload) {
        Ok(e) => e,
        Err(e) => return println!("  could not seal: {e:?}"),
    };

    let mut sender = match Mailbox::connect(&url).await {
        Ok(s) => s,
        Err(e) => return println!("  sender could not connect: {e}"),
    };
    if let Err(e) = sender.deposit(&envelope).await {
        return println!("  deposit refused: {e}");
    }

    let Ok(Some(got)) = client.next_envelope(Duration::from_secs(10)).await else {
        return println!("  nothing arrived, so there is nothing to acknowledge");
    };
    println!("  an envelope arrived");

    // The frame under test. A server that does not know it refuses here.
    match client.collected(std::slice::from_ref(&got)).await {
        Ok(()) => println!("  `collected` was accepted"),
        Err(e) => println!("  `collected` was REFUSED: {e}"),
    }

    // And it is gone: a second subscriber sees nothing waiting.
    let mut again = match Mailbox::connect(&url).await {
        Ok(c) => c,
        Err(e) => return println!("  could not reconnect: {e}"),
    };
    match again.subscribe(std::slice::from_ref(&tag)).await {
        Ok(left) if left.is_empty() => {
            println!("  and the mailbox let it go, so it will not be delivered again")
        }
        Ok(left) => println!(
            "  {} still waiting under that tag, so it would be redelivered",
            left.len()
        ),
        Err(e) => println!("  resubscribe refused: {e}"),
    }
}
