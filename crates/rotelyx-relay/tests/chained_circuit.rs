//! A circuit through two relays, both of them running.
//!
//! Everything else about chaining is tested against relays that exist in one
//! process: the tables against a fake opener, the link against a relay on an
//! in-memory pipe. This is the part those cannot reach, which is the dial
//! itself, and it needs two relays that were actually started.
//!
//! It is ignored by default and reads its two relays from the environment,
//! because it needs something started outside `cargo test`:
//!
//! ```text
//! CHAIN_FIRST_URL=http://127.0.0.1:34221 CHAIN_FIRST_ID=… CHAIN_FIRST_KEY=… \
//! CHAIN_EXIT_URL=http://127.0.0.1:34220  CHAIN_EXIT_ID=…  CHAIN_EXIT_KEY=… \
//!   cargo test -p rotelyx-relay --test chained_circuit -- --ignored --nocapture
//! ```
//!
//! `scripts/chain-test` starts both relays and fills those in.

use rotelyx_crypto::circuit::{Hop, SealedHop};
use rotelyx_crypto::hybrid::HybridPublicKey;
use rotelyx_net::{EndpointId, SecretKey};
use rotelyx_relay_proto::client::ClientBuilder;
use rotelyx_relay_proto::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};

/// Reads one of the six settings, saying which is missing rather than panicking
/// on an unwrap.
fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see this file's docs"))
}

fn key(name: &str) -> HybridPublicKey {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(setting(name).as_bytes())
        .unwrap_or_else(|_| panic!("{name} is not base64url"));
    HybridPublicKey::from_bytes(&bytes).unwrap_or_else(|_| panic!("{name} is not a circuit key"))
}

fn id(name: &str) -> EndpointId {
    setting(name)
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not an endpoint id"))
}

fn hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
        / 3600
}

/// Connects to a relay as an ordinary client.
async fn connect_to(url: &str, key: SecretKey) -> rotelyx_relay_proto::client::Client {
    let tls = rotelyx_relay_proto::tls::CaTlsConfig::default()
        .client_config(rotelyx_relay_proto::tls::default_provider())
        .expect("a tls config");
    ClientBuilder::new(
        url.parse::<rotelyx_net::RelayUrl>().expect("a relay url"),
        key,
        rotelyx_discovery::dns::DnsResolver::new(),
    )
    .tls_client_config(tls)
    .connect()
    .await
    .expect("connecting")
}

/// The whole chain: a caller opens a circuit at the first relay, which opens
/// one at the second, and what the caller sends comes out the far end.
#[tokio::test]
#[ignore = "needs two relays running; see this file's docs"]
async fn a_circuit_opens_through_two_relays() {
    let exit_url = setting("CHAIN_EXIT_URL");

    // The caller's own key, made for this call and belonging to no identity,
    // which is what the relays will see.
    let caller = SecretKey::generate();
    let caller_id = caller.public();
    let return_at_exit = SecretKey::generate().public();

    // Somebody really connected to the exit relay, so that what the circuit
    // carries has an end to arrive at. Without this the test could only say
    // the frame was accepted.
    let destination_key = SecretKey::generate();
    let destination = destination_key.public();
    let mut destination_conn = connect_to(&exit_url, destination_key).await;

    // Sealed to the exit relay: where the circuit ends, and the name that relay
    // presents to the destination.
    let inner = SealedHop::seal(
        &key("CHAIN_EXIT_KEY"),
        id("CHAIN_EXIT_ID").as_bytes(),
        &Hop {
            destination: *destination.as_bytes(),
            return_key: *return_at_exit.as_bytes(),
            next_relay: None,
            hour: hour(),
        },
    )
    .expect("sealing for the exit relay");

    // Sealed to the first relay: where to carry this, and how to reach it.
    let outer = SealedHop::seal(
        &key("CHAIN_FIRST_KEY"),
        id("CHAIN_FIRST_ID").as_bytes(),
        &Hop {
            destination: *id("CHAIN_EXIT_ID").as_bytes(),
            // The caller's own connection key, which is what a real client
            // passes and what a freshly generated one hid.
            //
            // The first relay knows this key: the caller is connected to it
            // under exactly this name. A hop that claimed a return key would be
            // asking to answer on a name somebody is already using, and the
            // relay refuses that, correctly. A hop that continues to another
            // relay does not need one at all: its replies come back over the
            // link, carrying a number and no name. This test used a fresh key
            // and so never asked the question that failed.
            return_key: *caller_id.as_bytes(),
            next_relay: Some(exit_url.clone()),
            hour: hour(),
        },
    )
    .expect("sealing for the first relay");

    let mut client = connect_to(&setting("CHAIN_FIRST_URL"), caller).await;

    use rotelyx_future::{SinkExt, StreamExt};

    client
        .send(ClientToRelayMsg::OpenCircuit {
            circuit: 1,
            sealed: outer.to_bytes().into(),
            inner: inner.to_bytes().into(),
        })
        .await
        .expect("asking for the circuit");

    // The answer comes after the first relay has dialled the second and been
    // told yes, so it is worth waiting longer than a frame would take.
    let answer = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            match client.next().await {
                // Keepalives are not the answer.
                Some(Ok(RelayToClientMsg::Ping(data))) => {
                    let _ = client.send(ClientToRelayMsg::Pong(data)).await;
                }
                other => return other,
            }
        }
    })
    .await
    .expect("the first relay never answered");

    match answer {
        Some(Ok(RelayToClientMsg::CircuitOpened { circuit })) => {
            assert_eq!(
                circuit, 1,
                "the relay answered about a circuit nobody asked for"
            );
        }
        Some(Ok(RelayToClientMsg::CircuitClosed { reason, .. })) => {
            panic!("the chain was refused, reason {reason}");
        }
        other => panic!("expected the circuit to open, got {other:?}"),
    }

    // And it carries, all the way to somebody who is really there.
    let data = b"through both";
    client
        .send(ClientToRelayMsg::CircuitDatagrams {
            circuit: 1,
            datagrams: Datagrams::from(&data[..]),
        })
        .await
        .expect("sending along the circuit");

    let arrived = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match destination_conn.next().await {
                Some(Ok(RelayToClientMsg::Ping(ping))) => {
                    let _ = destination_conn.send(ClientToRelayMsg::Pong(ping)).await;
                }
                other => return other,
            }
        }
    })
    .await
    .expect("nothing arrived at the destination");

    match arrived {
        Some(Ok(RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        })) => {
            assert_eq!(
                datagrams.contents,
                &data[..],
                "the payload changed on the way"
            );
            // The whole point of the return key. The destination must see the
            // name the caller sealed in, not the relay the traffic came from
            // and not the caller's own connection to its first relay.
            assert_eq!(
                remote_endpoint_id, return_at_exit,
                "the destination was shown the wrong sender"
            );
        }
        other => panic!("expected a datagram at the destination, got {other:?}"),
    }

    // And back. The destination replies to the only name it ever saw.
    let reply = b"and back";
    destination_conn
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: return_at_exit,
            datagrams: Datagrams::from(&reply[..]),
        })
        .await
        .expect("replying");

    let came_back = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match client.next().await {
                Some(Ok(RelayToClientMsg::Ping(ping))) => {
                    let _ = client.send(ClientToRelayMsg::Pong(ping)).await;
                }
                other => return other,
            }
        }
    })
    .await
    .expect("nothing came back");

    match came_back {
        Some(Ok(RelayToClientMsg::CircuitDatagrams { circuit, datagrams })) => {
            assert_eq!(circuit, 1, "the reply came back on the wrong circuit");
            assert_eq!(
                datagrams.contents,
                &reply[..],
                "the reply changed on the way"
            );
        }
        other => panic!("expected the reply on the circuit, got {other:?}"),
    }
}
