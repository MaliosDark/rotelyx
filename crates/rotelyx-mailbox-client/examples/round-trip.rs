//! Does an envelope cross a mailbox right now.
//!
//! One deposit and one collection against a live mailbox, with nothing else in
//! the way: no MLS, no pairing, no application. When a conversation is silent
//! this says whether the mailbox is the reason, in about a second.
//!
//!     cargo run -p rotelyx-mailbox-client --example round-trip -- wss://host/mailbox

use std::time::Duration;

use rotelyx_mailbox_client::Mailbox;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://m1.telyx.me/mailbox".to_string());

    // Nothing installs one for a binary, and `wss` needs it. The terminal
    // client learned this the same way.
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("\n  {url}");

    // A tag nobody else is using. Not derived from anything: this is a test of
    // the mailbox, not of addressing.
    let tag: String = std::iter::repeat_n(format!("{:02x}", rand_byte()), 32).collect();

    let mut collector = match Mailbox::connect(&url).await {
        Ok(c) => c,
        Err(e) => {
            println!("  the collector could not connect: {e}");
            return;
        }
    };
    let waiting = match collector.subscribe(std::slice::from_ref(&tag)).await {
        Ok(w) => w,
        Err(e) => {
            println!("  subscribe was refused: {e}");
            return;
        }
    };
    println!("  subscribed, {} already waiting", waiting.len());

    let payload = data_encoding::BASE64.encode(b"a round trip");
    let envelope = match rotelyx_wasm::seal_under(&tag, &payload) {
        Ok(e) => e,
        Err(e) => {
            println!("  could not seal: {e:?}");
            return;
        }
    };

    let mut sender = match Mailbox::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            println!("  the sender could not connect: {e}");
            return;
        }
    };
    match sender.deposit(&envelope).await {
        Ok(()) => println!("  deposited"),
        Err(e) => {
            println!("  the deposit was refused: {e}");
            return;
        }
    }

    match collector.next_envelope(Duration::from_secs(10)).await {
        Ok(Some(got)) => match rotelyx_wasm::open_under(&got, &tag) {
            Ok(text) if text == payload => {
                println!("  it came back, and it is the same envelope")
            }
            Ok(_) => println!("  something came back and it is not what went in"),
            Err(e) => println!("  something came back and would not open: {e:?}"),
        },
        Ok(None) => println!("  nothing came back in ten seconds"),
        Err(e) => println!("  reading failed: {e}"),
    }
}

fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        % 251) as u8
}
