//! Prove the shared client really uses the constellation, against live mailboxes.
//!
//! Opens what `connect_for` decides for a constellation member, writes an
//! envelope, and reads it back. The point is not that a mailbox works: it is
//! that this client opened the constellation rather than one server, so the
//! clients built on it (the terminal client, the desktop one, meeting) get the
//! same spreading the phone does.
//!
//!   cargo run --release --example constellation-live

use std::time::Duration;

use rotelyx_mailbox_client::{in_constellation, Mailbox, CONSTELLATION};

#[tokio::main]
async fn main() {
    let entry = "wss://orvexa.telyx.me/mailbox";
    println!("members: {}", CONSTELLATION.matches("\"url\"").count());
    println!("is {entry} a member? {}", in_constellation(entry));

    let mut mailbox = match Mailbox::connect_for(entry).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("could not open the constellation: {e}");
            std::process::exit(1);
        }
    };
    println!("opened");

    // An address nobody else is using, and an envelope written to it.
    let mut tag = [0u8; 32];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    tag[..8].copy_from_slice(&seed.to_be_bytes());
    let tag_hex = data_encoding::HEXLOWER.encode(&tag);

    let envelope = rotelyx_mailbox::Envelope::seal(
        rotelyx_mailbox::Tag::from_bytes(&tag).expect("tag"),
        b"through the constellation",
    )
    .expect("seal");
    let wire = data_encoding::BASE64.encode(&envelope.to_bytes());

    let waiting = mailbox.subscribe(&[tag_hex.clone()]).await.expect("subscribe");
    println!("subscribed, {} already waiting", waiting.len());

    // A second client to write with. The mailbox deliberately does not hand an
    // envelope back to the connection that deposited it, so a reader and a
    // writer are two connections here exactly as they are two people in life.
    let mut sender = Mailbox::connect_for(entry).await.expect("sender");
    sender.deposit(&wire).await.expect("deposit");
    println!("deposited by a second client");

    match mailbox.next_envelope(Duration::from_secs(10)).await {
        Ok(Some(back)) => {
            let ok = back == wire;
            println!("collected, same envelope: {ok}");
            if !ok {
                std::process::exit(1);
            }
        }
        Ok(None) => {
            eprintln!("nothing came back");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("collecting failed: {e}");
            std::process::exit(1);
        }
    }

    mailbox.collected(&[wire]).await.expect("collected");
    println!("acknowledged, done");
}
