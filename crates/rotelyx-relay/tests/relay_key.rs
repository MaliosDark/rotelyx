//! Asking one relay for another relay's circuit key.
//!
//! A caller cannot ask the exit relay directly: that would hand it the caller's
//! address before any circuit exists, which is the thing chaining is for. So
//! the caller's own relay asks. This is the test of that path, with both relays
//! running.
//!
//! Ignored by default and driven by `scripts/chain-test`, which starts the two
//! relays and fills in the environment. See `chained_circuit.rs`.

use rotelyx_net::SecretKey;
use rotelyx_relay_proto::client::ClientBuilder;
use rotelyx_relay_proto::protos::relay::{ClientToRelayMsg, RelayToClientMsg};

fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see this file's docs"))
}

async fn connect() -> rotelyx_relay_proto::client::Client {
    let tls = rotelyx_relay_proto::tls::CaTlsConfig::default()
        .client_config(rotelyx_relay_proto::tls::default_provider())
        .expect("a tls config");
    ClientBuilder::new(
        setting("CHAIN_FIRST_URL")
            .parse::<rotelyx_net::RelayUrl>()
            .expect("a relay url"),
        SecretKey::generate(),
        rotelyx_discovery::dns::DnsResolver::new(),
    )
    .tls_client_config(tls)
    .connect()
    .await
    .expect("connecting to the first relay")
}

/// Reads frames until one is not a keepalive.
async fn next_real(client: &mut rotelyx_relay_proto::client::Client) -> RelayToClientMsg {
    use rotelyx_future::{SinkExt, StreamExt};
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            match client.next().await {
                Some(Ok(RelayToClientMsg::Ping(data))) => {
                    let _ = client.send(ClientToRelayMsg::Pong(data)).await;
                }
                Some(Ok(frame)) => return frame,
                other => panic!("the connection ended: {other:?}"),
            }
        }
    })
    .await
    .expect("the relay never answered")
}

/// The first relay fetches the exit relay's key and hands it back.
#[tokio::test]
#[ignore = "needs two relays running; see this file's docs"]
async fn a_relay_fetches_another_relays_key() {
    use rotelyx_future::SinkExt;

    let exit_url = setting("CHAIN_EXIT_URL");
    let mut client = connect().await;

    client
        .send(ClientToRelayMsg::AskRelayKey {
            url: exit_url.clone().into(),
        })
        .await
        .expect("asking");

    match next_real(&mut client).await {
        RelayToClientMsg::RelayKey { url, key } => {
            assert_eq!(
                url,
                bytes::Bytes::from(exit_url),
                "the answer is about a different relay than the one asked about"
            );
            assert_eq!(
                String::from_utf8_lossy(&key),
                setting("CHAIN_EXIT_KEY"),
                "the key fetched is not the key that relay publishes"
            );
        }
        other => panic!("expected a key, got {other:?}"),
    }
}

/// A relay this one will not reach answers with no key, and says nothing about
/// why.
#[tokio::test]
#[ignore = "needs two relays running; see this file's docs"]
async fn a_relay_that_cannot_be_reached_answers_with_no_key() {
    use rotelyx_future::SinkExt;

    let mut client = connect().await;

    for asked in [
        // Not on the first relay's list.
        "http://127.0.0.1:1".to_owned(),
        // Not an address at all.
        "not a url".to_owned(),
        "".to_owned(),
    ] {
        client
            .send(ClientToRelayMsg::AskRelayKey {
                url: asked.clone().into(),
            })
            .await
            .expect("asking");

        match next_real(&mut client).await {
            RelayToClientMsg::RelayKey { url, key } => {
                assert_eq!(
                    String::from_utf8_lossy(&url),
                    asked,
                    "the answer is about a different relay than the one asked about"
                );
                assert!(
                    key.is_empty(),
                    "a key came back for {asked:?}, which should have produced none"
                );
            }
            other => panic!("expected an empty key for {asked:?}, got {other:?}"),
        }
    }
}
