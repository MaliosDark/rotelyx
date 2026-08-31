//! The relay's status page, fetched from a relay that is actually running.
//!
//! The rendering lives in the vendored tree, which is not a workspace member
//! and therefore cannot run tests of its own. Tests written there would never
//! execute, which is worse than none: they read as coverage. So the assertions
//! are here, against a real server on a real socket, which also happens to be
//! the only way to check what a visitor actually receives.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use rotelyx_relay_proto::server::{AllowAll, RelayConfig, Server, ServerConfig};

/// Start a relay on a free port and fetch its landing page.
async fn landing_page() -> (String, Server) {
    // Port 0 lets the OS choose, so a developer with the real relay running
    // does not get a confusing failure.
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut relay = RelayConfig::new(bind);
    relay.access = std::sync::Arc::new(AllowAll);

    let server = Server::spawn(ServerConfig::new(Some(relay), None))
        .await
        .expect("a relay on a free port");
    let addr = server.http_addr().expect("an http address");

    // A hand-written request rather than a client crate: this is one GET, and
    // the dependency would outweigh it.
    // The server binds and then finishes wiring its handlers, so a connection
    // made in the same instant can be accepted and then answered by nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut socket = TcpStream::connect(addr).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n")
        .expect("write");

    // Read until the document ends rather than until the socket does: the
    // server does not necessarily honour `Connection: close`, and
    // `read_to_end` then blocks until the read timeout on every run.
    // Read until the document ends rather than until the socket does: the
    // server does not necessarily honour `Connection: close`.
    //
    // A short read timeout with `Err(_) => break` is the obvious loop and it is
    // wrong: the first read returns `WouldBlock` before the response has
    // arrived, so the loop ends with nothing and the test reports an empty
    // page. `WouldBlock` means "not yet", not "no more".
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    while std::time::Instant::now() < deadline {
        match socket.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.windows(7).any(|w| w == b"</html>") {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    assert!(!raw.is_empty(), "the relay sent nothing within ten seconds");
    (String::from_utf8_lossy(&raw).into_owned(), server)
}

// Multi-threaded on purpose. The reads below are blocking `std` ones, and on
// the default single-threaded runtime they occupy the only thread, so the
// server task never runs and the request is accepted and never answered. The
// symptom is a page that arrives empty after the full timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_shows_a_status_strip() {
    let (page, server) = landing_page().await;

    assert!(
        page.starts_with("HTTP/1.1 200"),
        "not a 200: {}",
        &page[..40.min(page.len())]
    );
    assert!(page.contains("Operational"), "no status");
    assert!(page.contains("class=\"bars\""), "no availability strip");

    // Freshly started: one bucket of history, and it is the newest, so the
    // green bar must be the last one before the strip closes.
    // Counted inside the strip only: the legend below it uses the same classes
    // for its swatches, so counting the whole page inflates every total by one
    // and the arithmetic quietly stops adding to 96.
    let strip = page
        .split("<div class=\"bars\">")
        .nth(1)
        .and_then(|t| t.split("</div>").next())
        .expect("the strip");

    let up = strip.matches("class=\"up\"").count();
    let part = strip.matches("class=\"part\"").count();
    let down = strip.matches("class=\"down\"").count();
    let unknown = strip.matches("class=\"unknown\"").count();

    // With no status file, the only thing known is this process, which started
    // seconds ago: one bucket in progress and no claim about anything before.
    assert_eq!(part, 1, "the bucket in progress");
    assert_eq!(up, 0, "no whole bucket has been served");
    assert_eq!(
        down, 0,
        "with no record, nothing may be asserted as an outage"
    );
    assert_eq!(up + part + down + unknown, 96, "the strip is 96 half hours");
    assert!(
        strip.ends_with("<i class=\"part\"></i>"),
        "the newest bucket must be on the right, beside the `now` label"
    );

    // The legend has to name every colour the strip can draw, or a red bar
    // appears one day with nothing saying what it means.
    for colour in ["up", "part", "down", "unknown"] {
        assert!(
            page.contains(&format!("<i class=\"{colour}\"></i>")),
            "the legend does not show `{colour}`"
        );
    }

    server.shutdown().await.ok();
}

/// A status page that a proxy caches is a status page that lies.
// Multi-threaded on purpose. The reads below are blocking `std` ones, and on
// the default single-threaded runtime they occupy the only thread, so the
// server task never runs and the request is accepted and never answered. The
// symptom is a page that arrives empty after the full timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_is_not_cacheable() {
    let (page, server) = landing_page().await;
    assert!(
        page.to_lowercase().contains("cache-control: no-store"),
        "the page may be cached, so it can be served stale for ever"
    );
    server.shutdown().await.ok();
}

/// The policy that made this page safe to publish at all.
///
/// A relay's entire exposure is which endpoints talk to which. Publishing how
/// many are connected would publish the size and the rhythm of a community to
/// anybody who polled it. This asserts on the bytes a visitor receives, so
/// adding a counter later fails here rather than in a review nobody runs.
// Multi-threaded on purpose. The reads below are blocking `std` ones, and on
// the default single-threaded runtime they occupy the only thread, so the
// server task never runs and the request is accepted and never answered. The
// symptom is a page that arrives empty after the full timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_publishes_no_traffic_and_no_infrastructure() {
    let (page, server) = landing_page().await;
    let body = page.to_lowercase();

    for forbidden in [
        "connected",
        "peers online",
        "clients:",
        "sessions:",
        "bytes served",
        "192.168.",
        "10.0.",
        "/home/",
        "uid=",
        "hostname",
        // The total connection cap is the one limit worth not publishing: it
        // is the number an attacker needs to exceed, and unlike the per
        // identity limits it cannot be found by probing without mounting the
        // attack itself.
        "4096",
    ] {
        assert!(
            !body.contains(forbidden),
            "the landing page contains `{forbidden}`"
        );
    }

    // And the policy that keeps it script-free stays shut. A live status page
    // is the usual reason somebody loosens a CSP; this one did not.
    assert!(
        body.contains("default-src 'none'") && !body.contains("script-src"),
        "the content security policy has been loosened"
    );

    server.shutdown().await.ok();
}
