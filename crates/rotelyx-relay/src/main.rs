//! The Rotelyx relay.
//!
//! A relay exists for one case: two peers that cannot hole-punch through their
//! NATs. It forwards QUIC ciphertext between them and holds no session state,
//! no keys, and no ability to read anything.
//!
//! ## What a relay operator learns, unavoidably
//!
//! **Which endpoint ID is talking to which, and when.** That is the social
//! graph, and it is inherent to relayed transport: no configuration removes
//! it. It is ADV-3 in the threat model and the reason Rotelyx's path selector
//! prefers any direct path over any relayed one regardless of latency.
//!
//! The mitigation is not technical. Run your own. A relay you operate for your
//! own community means that graph is visible to you rather than to a stranger,
//! and seizing it compromises one community rather than a population.
//!
//! ## Deliberate omissions
//!
//! - **No metrics endpoint.** Telemetry in a privacy tool is a liability: it is
//!   an operational dataset about who connects and when, sitting in a second
//!   place with weaker access control than the relay itself.
//! - **Access defaults to an allowlist.** An open relay is available with an
//!   explicit flag, never by omission.

mod access;
mod limits;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use rotelyx_net::EndpointId;
use rotelyx_relay_proto::server::{AllowAll, RelayConfig, Server, ServerConfig};

#[derive(Parser, Debug)]
#[command(name = "rotelyx-relay", about = "Rotelyx relay server")]
struct Cli {
    /// Address to serve on.
    #[arg(long, default_value = "0.0.0.0:3340")]
    bind: SocketAddr,

    /// Where to record availability, for the status strip on the landing page.
    ///
    /// Without it the page can only say "up since this process started", so
    /// every restart looks like the beginning of time and an outage is never
    /// visible. A relay that is down serves no page, so the only way it can
    /// report having been down is to have written something beforehand.
    ///
    /// The file holds half-hour bucket numbers and nothing else: no addresses,
    /// no identifiers, no counts. It records exactly what somebody polling from
    /// outside could have measured anyway.
    #[arg(long, value_name = "PATH")]
    status: Option<PathBuf>,

    /// File of permitted endpoint IDs, one per line. `#` starts a comment.
    ///
    /// Required unless `--open` is passed. Reload by restarting.
    #[arg(long)]
    allow: Option<PathBuf>,

    /// Serve any endpoint that connects.
    ///
    /// Explicit on purpose: an open relay should be a decision somebody made,
    /// never the result of forgetting a flag.
    #[arg(long, conflicts_with = "allow")]
    open: bool,
}

fn read_allowlist(path: &PathBuf) -> Result<Vec<EndpointId>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut ids = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let id: EndpointId = line
            .parse()
            .with_context(|| format!("{}:{}: not an endpoint id", path.display(), n + 1))?;
        ids.push(id);
    }
    Ok(ids)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx_relay=info,warn".into()),
        )
        .init();

    let cli = Cli::parse();

    if let Some(path) = cli.status.clone() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        tracing::info!(path = %path.display(), "recording availability");
        rotelyx_relay_proto::server::record_status_at(path);
    }

    let mut relay = RelayConfig::new(cli.bind);

    // Taken inside the branches below, before the limiter becomes a trait
    // object. See `limits::Limited::counters`.
    let counters: Option<limits::Counters>;

    if cli.open {
        tracing::warn!(
            "serving every endpoint that connects: this relay's logs will \
             cover people you have no relationship with"
        );
        let limited = limits::Limited::new(AllowAll);
        counters = Some(limited.counters());
        relay.access = std::sync::Arc::new(limited);
    } else {
        let Some(path) = cli.allow.as_ref() else {
            bail!("pass --allow <file> with permitted endpoint ids, or --open to serve everyone");
        };
        let ids = read_allowlist(path)?;
        if ids.is_empty() {
            // Falling open on an empty file is the failure nobody notices.
            bail!("{} contains no endpoint ids; refusing to start", path.display());
        }
        tracing::info!(count = ids.len(), "serving an allowlist");
        let limited = limits::Limited::new(access::Allowlist::new(ids));
        counters = Some(limited.counters());
        relay.access = std::sync::Arc::new(limited);
    }

    // The per-connection byte rate, which the vendored server does implement,
    // unlike the accept limits beside it. A relay carries other people's
    // ciphertext, so this bounds what one connection can push through without
    // getting in the way of a call: 512 KiB/s is far above a voice stream and
    // far below a link somebody is using as free transit.
    relay.limits.client_rx = Some(
        rotelyx_relay_proto::server::ClientRateLimit::new(
            std::num::NonZeroU32::new(512 * 1024).expect("non-zero"),
        ),
    );

    // No metrics socket: see the module docs.
    let config = ServerConfig::new(Some(relay), None);

    let server = Server::spawn(config).await.context("starting relay")?;
    tracing::info!(bind = %cli.bind, "relay running");
    println!("relay listening on http://{}", cli.bind);
    println!();
    println!("Point clients at it with RelayPolicy::SelfHosted.");
    println!("Remember: this relay sees which endpoint talks to which. It cannot");
    println!("read anything, but that pairing is the social graph.");

    // The limiter's counters, reported to the operator and to nobody else.
    //
    // These stay out of the public status page on purpose. A live count of open
    // connections is a load signal, and on a relay with few users a load signal
    // correlates with who is talking; the page shows availability instead. The
    // refusal counts are what tells an operator the limiter is doing anything
    // at all, which is otherwise invisible until the relay falls over.
    //
    // Logged on change rather than on a timer, so a quiet relay stays quiet in
    // the journal and a relay under pressure says so.
    if let Some(counters) = counters.clone() {
        tokio::spawn(async move {
            let mut previous = counters.refusals();
            let mut ticks = tokio::time::interval(std::time::Duration::from_secs(60));
            ticks.tick().await;
            loop {
                ticks.tick().await;
                let now = counters.refusals();
                if now != previous {
                    tracing::info!(
                        rate = now.0,
                        concurrent = now.1,
                        total = now.2,
                        open = counters.open(),
                        "admission refusals"
                    );
                    previous = now;
                }
            }
        });
    }

    tokio::signal::ctrl_c().await.context("waiting for ctrl-c")?;
    if let Some(counters) = counters {
        let (rate, concurrent, total) = counters.refusals();
        tracing::info!(rate, concurrent, total, "admission refusals at shutdown");
    }
    tracing::info!("shutting down");
    drop(server);
    Ok(())
}
