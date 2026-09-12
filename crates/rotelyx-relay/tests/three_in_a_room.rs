//! Three participants in one room, through a real relay on a real socket.
//!
//! Everything about the forwarding decision is tested inside `rotelyx-media`.
//! What cannot be tested there is the part a person would notice: three
//! endpoints, none of them connected to each other, each sending one stream to
//! the relay and receiving the other two back from it. Before this existed, a
//! call between more than two people did not.
//!
//! Driven by `scripts/room-test`, which starts the relay with `--room` and
//! hands its address over in `ROOM_RELAY_URL` and `ROOM_ADDR`. Ignored
//! otherwise, because a test that needs a process nobody started is a test
//! that fails for the wrong reason.

use rotelyx_media::{CallBinding, SenderKeys, Sender, Receiver};
use rotelyx_net::{NetConfig, NetEndpoint, PathPolicy, RelayPolicy, SecretKey};

fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see this file's docs"))
}

/// The room's address, decoded the way a phone decodes one it was given.
fn room_addr() -> rotelyx_net::EndpointAddr {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(setting("ROOM_ADDR").as_bytes())
        .expect("ROOM_ADDR is base64url");
    serde_json::from_slice(&bytes).expect("ROOM_ADDR is an endpoint address")
}

/// An endpoint that only ever dials through the relay, like a phone.
async fn phone() -> NetEndpoint {
    let url: rotelyx_net::RelayUrl = setting("ROOM_RELAY_URL").parse().expect("a relay url");
    let config = NetConfig::new(RelayPolicy::SelfHosted(vec![url]), PathPolicy::RelayOnly);
    NetEndpoint::bind(SecretKey::generate(), config, rotelyx_core::ALPN)
        .await
        .expect("bind")
}

/// The join a participant sends first. Mirrors `room::join_datagram`, which is
/// inside the binary and not a library this test can reach.
fn join(room: &[u8; 32], seat: u8) -> Vec<u8> {
    let mut out = b"RXROOM1".to_vec();
    out.extend_from_slice(room);
    out.push(seat);
    out
}

#[tokio::test]
#[ignore = "needs a relay started with --room; run scripts/room-test"]
async fn what_one_sends_the_other_two_receive_and_the_sender_does_not() {
    // One media key shared by the group, as the MLS epoch would export it,
    // and one call binding. The relay holds neither.
    let base = [42u8; 32];
    let call = CallBinding::new(b"three-in-a-room-1").expect("binding");
    let room = *blake3::hash(b"three-in-a-room-1 room").as_bytes();

    let mut connections = Vec::new();
    for seat in 0u8..3 {
        let endpoint = phone().await;
        let (_send, _recv, conn) = endpoint
            .connect(room_addr(), rotelyx_core::ALPN)
            .await
            .expect("dial the room")
            .split();
        conn.send_datagram(join(&room, seat).into())
            .expect("send the join");
        connections.push((endpoint, conn));
    }

    // Give the joins a moment to be seated before anybody speaks, the way a
    // client waits for the call to be answered.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Seat 0 speaks: three frames, sealed under its own sender key.
    let mut sender = Sender::new(SenderKeys::derive(&base, 0, &call)).expect("sender");
    let spoken: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            sender
                .protect(&[i as u8; 40])
                .expect("protect")
        })
        .collect();
    for frame in &spoken {
        connections[0]
            .1
            .send_datagram(frame.clone().into())
            .expect("send a frame");
    }

    // Seats 1 and 2 each receive all three and can open them.
    for (seat, (_endpoint, conn)) in connections.iter().enumerate().skip(1) {
        let mut receiver = Receiver::new(SenderKeys::derive(&base, 0, &call)).expect("receiver");
        let mut heard = 0;
        for _ in 0..3 {
            let datagram = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                conn.read_datagram(),
            )
            .await
            .unwrap_or_else(|_| panic!("seat {seat} heard nothing"))
            .expect("a datagram");
            let plain = receiver.unprotect(&datagram).expect("opens under the group's key");
            assert_eq!(plain.len(), 40, "the frame did not survive the room");
            heard += 1;
        }
        assert_eq!(heard, 3, "seat {seat} did not hear everything seat 0 said");
    }

    // And seat 0 does not hear itself: nothing arrives on its connection.
    let echo = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        connections[0].1.read_datagram(),
    )
    .await;
    assert!(echo.is_err(), "the room handed a speaker its own frame back");
}
