//! Whether `RelayOnly` actually keeps traffic off a direct path.
//!
//! # What is being checked
//!
//! `PathPolicy::RelayOnly` is the policy every shipped Rotelyx client uses for
//! a call, and the reason it exists is not speed: a direct path shows the peer
//! this device's address, and the whole point of going through a relay is that
//! nobody learns where anybody is. The selector in `path.rs` is written for
//! that and tested for it: it never returns `Choice::Direct` under this policy.
//!
//! But choosing is not the same as forbidding. This asks the connection itself
//! which address it is actually talking to, after a connection made under
//! `RelayOnly` through a relay. If the answer is an IP, then a direct path was
//! established and is in use, and the policy names a promise the transport is
//! not keeping.
//!
//! # Running it
//!
//! ```text
//! cargo build -p rotelyx-relay
//! cargo test -p rotelyx-net --test relay_only_stays_relayed -- --ignored --nocapture
//! ```

use std::time::Duration;

use rotelyx_net::{
    NetConfig, NetEndpoint, PathPolicy, RelayPolicy, RelayUrl, SecretKey, TransportAddr,
};

const ALPN: &[u8] = b"rotelyx/test-relayonly/1";

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "starts a relay"]
async fn a_relay_only_connection_is_not_carried_directly() {
    let port = 34241;
    let state = std::env::temp_dir().join(format!("rotelyx-relayonly-{port}"));
    let _ = std::fs::create_dir_all(&state);

    let relay_binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/rotelyx-relay");

    let mut relay_process = std::process::Command::new(&relay_binary)
        .args([
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--open",
            "--identity",
            state.join("id").to_str().expect("path"),
            "--circuit-key",
            state.join("ck").to_str().expect("path"),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("cargo build -p rotelyx-relay first");

    tokio::time::sleep(Duration::from_secs(3)).await;

    let relay: RelayUrl = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("relay url");

    let config = NetConfig::new(
        RelayPolicy::SelfHosted(vec![relay.clone()]),
        PathPolicy::RelayOnly,
    );

    let listener = NetEndpoint::bind(key(21), config.clone(), ALPN)
        .await
        .expect("bind listener");
    let dialer = NetEndpoint::bind(key(22), config, ALPN)
        .await
        .expect("bind dialer");

    assert!(listener.online(Duration::from_secs(30)).await, "listener");
    assert!(dialer.online(Duration::from_secs(30)).await, "dialer");

    // Addressed the way a call addresses: no IPs, the relay in their place.
    let mut addr = listener.addr();
    addr.addrs.retain(|a| !matches!(a, TransportAddr::Ip(_)));
    addr.addrs.insert(TransportAddr::Relay(relay));

    let accepting = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        (session, listener)
    });

    let mut session = dialer.connect(addr, ALPN).await.expect("connect");

    use tokio::io::AsyncWriteExt as _;
    session.send_stream().write_all(b"up").await.expect("write");
    session.send_stream().flush().await.expect("flush");
    let far = accepting.await.expect("accepted");

    // Give hole punching every chance to finish. If a direct path is going to
    // appear it appears in the first seconds, and asking too early would
    // report the answer this test wants rather than the true one.
    tokio::time::sleep(Duration::from_secs(10)).await;

    let (_s, _r, connection) = session.split();

    let mut direct_open = 0usize;
    let mut direct_selected = false;
    let mut relay_open = 0usize;
    {
        let paths = connection.paths();
        println!("{} path(s) open under RelayOnly:", paths.len());
        for path in paths.iter() {
            println!(
                "  {:?}  ip={}  relay={}  selected={}",
                path.remote_addr(),
                path.is_ip(),
                path.is_relay(),
                path.is_selected()
            );
            if path.is_ip() {
                direct_open += 1;
                direct_selected |= path.is_selected();
            }
            if path.is_relay() {
                relay_open += 1;
            }
        }
    }
    println!(
        "direct paths open: {direct_open}, one of them selected: {direct_selected}, \
         relay paths open: {relay_open}"
    );

    let _ = relay_process.kill();
    let _ = relay_process.wait();
    drop(far);

    assert!(
        !direct_selected,
        "a RelayOnly connection is carrying application data on a direct path. \
         The policy exists so a peer never learns this device's address, and \
         every document in this project says so."
    );
    assert_eq!(
        direct_open, 0,
        "a RelayOnly connection opened {direct_open} direct path(s). Even \
         unselected, opening one means the addresses were exchanged and probed, \
         which is the disclosure the policy is named for."
    );
}
