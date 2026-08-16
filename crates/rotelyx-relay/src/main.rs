//! The Rotelyx relay.
//!
//! A relay exists for one case: two peers that cannot hole-punch through their
//! NATs. It forwards QUIC ciphertext between them and holds no session state,
//! no keys, and no ability to read anything.
//!
//! ## What a relay operator learns, unavoidably
//!
//! **Which endpoint ID is talking to which, and when.** That is the social
//! graph, and it is inherent to relayed transport — no configuration removes
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

    let mut relay = RelayConfig::new(cli.bind);

    if cli.open {
        tracing::warn!(
            "serving every endpoint that connects — this relay's logs will \
             cover people you have no relationship with"
        );
        relay.access = std::sync::Arc::new(AllowAll);
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
        relay.access = std::sync::Arc::new(access::Allowlist::new(ids));
    }

    // No metrics socket — see the module docs.
    let config = ServerConfig::new(Some(relay), None);

    let server = Server::spawn(config).await.context("starting relay")?;
    tracing::info!(bind = %cli.bind, "relay running");
    println!("relay listening on http://{}", cli.bind);
    println!();
    println!("Point clients at it with RelayPolicy::SelfHosted.");
    println!("Remember: this relay sees which endpoint talks to which. It cannot");
    println!("read anything, but that pairing is the social graph.");

    tokio::signal::ctrl_c().await.context("waiting for ctrl-c")?;
    tracing::info!("shutting down");
    drop(server);
    Ok(())
}
