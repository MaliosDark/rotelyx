//! What one endpoint registered at a relay costs the relay.
//!
//! # Why measure this rather than reason about it
//!
//! A relay is a stateless forwarder and the temptation is to say so and move
//! on. What it actually holds is a socket per endpoint, whatever the websocket
//! layer buffers behind that socket, and a routing entry. The mailbox turned
//! out to be spending a hundred and thirty six kilobytes a connection on
//! buffers nobody had chosen, and the only reason anybody knows is that it was
//! weighed.
//!
//! # How to read the number
//!
//! Printed rather than asserted. A memory figure that fails a build is a
//! figure that gets raised until it passes, and what this is for is deciding
//! what hardware a relay fits on.
//!
//! ```text
//! cargo build -p rotelyx-relay
//! cargo test -p rotelyx-net --test what_a_relay_costs -- --ignored --nocapture
//! ```

use std::time::Duration;

use rotelyx_net::{NetConfig, NetEndpoint, PathPolicy, RelayPolicy, RelayUrl, SecretKey};

const ALPN: &[u8] = b"rotelyx/test-cost/1";

/// Enough to give a slope, and few enough that the endpoints themselves do not
/// dominate this machine.
const ENDPOINTS: usize = 120;

fn rss_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "starts a relay and weighs it"]
async fn a_relay_holding_endpoints_is_weighed() {
    let port = 34250;
    let state = std::env::temp_dir().join("rotelyx-relay-cost");
    let _ = std::fs::create_dir_all(&state);

    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/rotelyx-relay");

    let mut relay = std::process::Command::new(&binary)
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
        .expect("cargo build --release -p rotelyx-relay first");

    tokio::time::sleep(Duration::from_secs(3)).await;
    let pid = relay.id();
    let idle = rss_kb(pid);
    println!("relay idle: {:.2} MB", idle as f64 / 1024.0);

    let url: RelayUrl = format!("http://127.0.0.1:{port}").parse().expect("url");
    let config = NetConfig::new(
        RelayPolicy::SelfHosted(vec![url]),
        PathPolicy::RelayOnly,
    );

    // Held in a vector: dropping an endpoint closes its socket, and what is
    // being weighed is a relay with endpoints on it.
    let mut held = Vec::with_capacity(ENDPOINTS);
    for n in 0..ENDPOINTS {
        let mut seed = [0u8; 32];
        seed[0] = (n & 0xff) as u8;
        seed[1] = ((n >> 8) & 0xff) as u8;
        let endpoint = NetEndpoint::bind(SecretKey::from_bytes(&seed), config.clone(), ALPN)
            .await
            .expect("bind");
        if !endpoint.online(Duration::from_secs(20)).await {
            println!("endpoint {n} never registered; stopping there");
            break;
        }
        held.push(endpoint);

        if held.len() % 30 == 0 {
            let now = rss_kb(pid);
            println!(
                "  {} registered: relay {:.2} MB  ({:.1} KB each)",
                held.len(),
                now as f64 / 1024.0,
                (now.saturating_sub(idle)) as f64 / held.len() as f64
            );
        }
    }

    let loaded = rss_kb(pid);
    println!(
        "relay with {} endpoints: {:.2} MB, {:.1} KB per endpoint",
        held.len(),
        loaded as f64 / 1024.0,
        (loaded.saturating_sub(idle)) as f64 / held.len().max(1) as f64
    );

    drop(held);
    let _ = relay.kill();
    let _ = relay.wait();
}
