//! Two endpoints, one real QUIC connection.
//!
//! Everything up to now has been unit tests over in-memory buffers. This is the
//! first test where bytes leave a socket.
//!
//! ## What this proves, and what it does not
//!
//! Proves: the endpoint binds, a peer is authenticated by its public key during
//! the QUIC handshake, streams open in both directions, and framed data
//! survives the round trip — all with relays disabled and address lookup
//! removed, so nothing but the two processes is involved.
//!
//! Does **not** prove NAT traversal. Both endpoints are on loopback, which
//! needs no hole punching. Real traversal requires two machines behind
//! different NATs and cannot be asserted from one host; that is a field test,
//! not a unit test, and it is still outstanding.

use std::time::Duration;

use tokio::io::AsyncWriteExt as _;
use rotelyx_net::{NetConfig, NetEndpoint, SecretKey};

const ALPN: &[u8] = b"rotelyx/test-connect/1";

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Guards every test so a hang shows up as a failure rather than a stalled CI.
async fn with_timeout<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(Duration::from_secs(30), f)
        .await
        .expect("timed out")
}

#[tokio::test(flavor = "multi_thread")]
async fn two_endpoints_exchange_bytes_over_quic() {
    with_timeout(async {
        let listener = NetEndpoint::bind(key(1), NetConfig::direct_only(), ALPN)
            .await
            .expect("bind listener");
        let dialer = NetEndpoint::bind(key(2), NetConfig::direct_only(), ALPN)
            .await
            .expect("bind dialer");

        let listener_addr = listener.addr();
        let listener_id = listener.id();
        let dialer_id = dialer.id();

        let accept = tokio::spawn(async move {
            let mut session = listener.accept().await.expect("accept");
            let peer = session.peer();

            let mut buf = [0u8; 5];
            {
                session
                    .recv_stream()
                    .read_exact(&mut buf)
                    .await
                    .expect("read");
            }

            session.send_stream().write_all(b"pong!").await.expect("write");
            // Without this the session drops, the stream resets, and "pong!"
            // is discarded even though write_all reported success.
            session.finish().await.expect("finish");

            (peer, buf)
        });

        let mut session = dialer
            .connect(listener_addr, ALPN)
            .await
            .expect("connect");

        assert_eq!(
            session.peer(),
            listener_id,
            "the dialer must see the listener's real public key"
        );

        {
            session.send_stream().write_all(b"ping!").await.expect("write");
            session.send_stream().flush().await.expect("flush");
        }

        let mut reply = [0u8; 5];
        {
            session
                .recv_stream()
                .read_exact(&mut reply)
                .await
                .expect("read reply");
        }

        let (seen_peer, seen_bytes) = accept.await.expect("join");

        assert_eq!(&seen_bytes, b"ping!");
        assert_eq!(&reply, b"pong!");
        assert_eq!(
            seen_peer, dialer_id,
            "the listener must see the dialer's real public key, \
             authenticated by the QUIC handshake rather than self-asserted"
        );

        dialer.close().await;
    })
    .await;
}

/// The privacy posture holds on a live endpoint, not just in config: a
/// direct-only endpoint that has actually carried traffic still holds no relay.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_direct_only_endpoint_never_acquires_a_relay() {
    with_timeout(async {
        let listener = NetEndpoint::bind(key(3), NetConfig::direct_only(), ALPN)
            .await
            .expect("bind listener");
        let dialer = NetEndpoint::bind(key(4), NetConfig::direct_only(), ALPN)
            .await
            .expect("bind dialer");

        let addr = listener.addr();
        let accept = tokio::spawn(async move {
            let mut session = listener.accept().await.expect("accept");
            let mut buf = [0u8; 2];
            session.recv_stream().read_exact(&mut buf).await.expect("read");
            assert!(
                listener.active_relay_hosts().is_empty(),
                "a relay appeared on a direct-only endpoint"
            );
            session.peer()
        });

        let mut session = dialer.connect(addr, ALPN).await.expect("connect");
        // QUIC streams are lazy: without a write, the listener never observes
        // the stream at all and accept_bi() fails with "closed by peer".
        session.send_stream().write_all(b"hi").await.expect("write");
        session.send_stream().flush().await.expect("flush");

        accept.await.expect("join");

        assert!(
            dialer.active_relay_hosts().is_empty(),
            "a relay appeared on a direct-only endpoint after connecting"
        );

        dialer.close().await;
    })
    .await;
}

/// A peer speaking a different protocol must be refused. The ALPN is versioned
/// precisely so an incompatible wire format cannot be negotiated into.
#[tokio::test(flavor = "multi_thread")]
async fn a_mismatched_protocol_is_refused() {
    with_timeout(async {
        let listener = NetEndpoint::bind(key(5), NetConfig::direct_only(), ALPN)
            .await
            .expect("bind listener");
        let dialer = NetEndpoint::bind(key(6), NetConfig::direct_only(), b"something/else/1")
            .await
            .expect("bind dialer");

        let addr = listener.addr();
        // Keep the listener alive so the failure is the ALPN, not a dead peer.
        let _accept = tokio::spawn(async move { listener.accept().await });

        assert!(
            dialer.connect(addr, b"something/else/1").await.is_err(),
            "a peer speaking a different ALPN must not be accepted"
        );

        dialer.close().await;
    })
    .await;
}
