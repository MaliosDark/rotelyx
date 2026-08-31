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
//! - **Circuits are off.** A relay terminates circuits only with
//!   `--circuit-key`, and carries them onward only with `--chain`. Chaining
//!   means opening connections to addresses that arrive inside descriptors this
//!   relay is the first to read, so it is a decision rather than a default, and
//!   `--chain-to` narrows it to the relays an operator names.

mod access;
mod circuit;
mod dial;
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

    /// Where this relay keeps the key that opens circuits, made on first use.
    ///
    /// Without it the relay refuses every circuit, which is what a relay did
    /// before circuits existed. Terminating circuits is a decision an operator
    /// makes, because it means carrying traffic for callers this relay never
    /// sees: the first relay in the chain is somebody else's.
    ///
    /// Needs `--identity`, because a descriptor is sealed to a named relay and
    /// the name is this relay's endpoint id.
    #[arg(long, value_name = "PATH", requires = "identity")]
    circuit_key: Option<PathBuf>,

    /// Where this relay keeps its transport identity, made on first use.
    ///
    /// Its public half is this relay's endpoint id: the name descriptors are
    /// sealed to, and the name it authenticates as when it dials another relay.
    /// Keep it: losing it renames the relay, and every invitation naming the
    /// old name stops working.
    #[arg(long, value_name = "PATH")]
    identity: Option<PathBuf>,

    /// Carry circuits onward to the relay a descriptor names.
    ///
    /// Off unless asked for, and worth understanding before asking. A relay
    /// that chains opens connections to addresses that arrive inside sealed
    /// descriptors: a stranger's circuit names the host, and this relay is the
    /// first thing that reads it. Use `--chain-to` to name the relays yours
    /// will dial and refuse the rest.
    #[arg(long, requires = "identity")]
    chain: bool,

    /// The relays this one will chain to, one URL per line. `#` starts a
    /// comment.
    ///
    /// Without it, `--chain` dials whatever a descriptor names.
    #[arg(long, value_name = "PATH", requires = "chain")]
    chain_to: Option<PathBuf>,

    /// Who runs this relay, shown on its landing page.
    ///
    /// A relay is operated by somebody, and the page a visitor lands on is
    /// theirs to put a name on. What it says underneath does not change: this
    /// is a Rotelyx relay, it holds no keys, and it cannot read what passes
    /// through it.
    #[arg(long, value_name = "NAME")]
    operator: Option<String>,

    /// A PNG to show in place of the default mark, at most 64 KiB.
    ///
    /// Embedded in the page rather than linked. The page's own policy forbids
    /// fetching anything, deliberately, so a mark either travels inside the
    /// response or does not appear.
    #[arg(long, value_name = "PATH", requires = "operator")]
    logo: Option<PathBuf>,
}

/// The mark is embedded in every response, so a large one is paid for on every
/// page load and by every visitor.
const MAX_LOGO_BYTES: usize = 64 * 1024;

/// Reads a PNG and returns it as a `data:` URI.
fn read_logo(path: &PathBuf) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > MAX_LOGO_BYTES {
        bail!(
            "{} is {} bytes and the most a mark may be is {MAX_LOGO_BYTES}",
            path.display(),
            bytes.len()
        );
    }
    // Checked rather than trusted from the extension: the page declares it as a
    // PNG, and a file that is not one would render as nothing at all with no
    // hint as to why.
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        bail!("{} is not a PNG", path.display());
    }
    Ok(format!(
        "data:image/png;base64,{}",
        data_encoding::BASE64.encode(&bytes)
    ))
}

/// Reads a file of one entry per line, ignoring blanks and `#` comments.
fn read_lines(path: &PathBuf) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect())
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

    // One TLS provider for this process, chosen here rather than by whichever
    // library asks first. The HTTP client that reads another relay's circuit
    // key is built with no provider of its own and would fail without this.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rotelyx_relay_proto::tls::default_provider()
            .as_ref()
            .clone(),
    );

    if let Some(path) = cli.status.clone() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        tracing::info!(path = %path.display(), "recording availability");
        rotelyx_relay_proto::server::record_status_at(path);
    }

    if let Some(operator) = cli.operator.clone() {
        let logo = match cli.logo.as_ref() {
            Some(path) => read_logo(path)?,
            // The name without a mark, which is a reasonable thing to want.
            None => String::new(),
        };
        tracing::info!(%operator, "serving a landing page under an operator's name");
        rotelyx_relay_proto::server::brand_as(rotelyx_relay_proto::server::Brand {
            operator,
            logo,
        });
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
            bail!(
                "{} contains no endpoint ids; refusing to start",
                path.display()
            );
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
    relay.limits.client_rx = Some(rotelyx_relay_proto::server::ClientRateLimit::new(
        std::num::NonZeroU32::new(512 * 1024).expect("non-zero"),
    ));

    let identity = match cli.identity.as_ref() {
        Some(path) => Some(dial::load_or_create_identity(path)?),
        None => None,
    };

    if let Some(path) = cli.circuit_key.as_ref() {
        let secret = identity.as_ref().expect("clap requires it");
        let opener = circuit::Opener::load_or_create(path, secret.public())?;
        println!("endpoint id:  {}", secret.public());
        println!("circuit key:  {}", opener.public_key());
        println!("Callers seal circuits to those two together.");
        println!();
        // Also served, so a caller's own relay can fetch it on the caller's
        // behalf. The caller checks it against a hash from the invitation, so
        // publishing it costs nothing that keeping it quiet would save.
        rotelyx_relay_proto::server::publish_circuit_key(
            secret.public().to_string(),
            opener.public_key(),
        );
        tracing::info!("terminating circuits for callers this relay does not see");
        relay.circuit_opener = Some(std::sync::Arc::new(opener));
    }

    if cli.chain {
        let allowed = match cli.chain_to.as_ref() {
            Some(path) => {
                let urls = read_lines(path)?;
                if urls.is_empty() {
                    // Falling open on an empty file is the failure nobody
                    // notices, the same reason the allowlist refuses to start.
                    bail!("{} names no relays; refusing to start", path.display());
                }
                tracing::info!(count = urls.len(), "chaining to a named set of relays");
                Some(urls)
            }
            None => {
                tracing::warn!(
                    "chaining to whatever a descriptor names: this relay will \
                     open connections to hosts chosen by strangers"
                );
                None
            }
        };
        let secret = identity.as_ref().expect("clap requires it").clone();
        relay.circuit_dialer = Some(std::sync::Arc::new(dial::Dialer::new(secret, allowed)));
    }

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

    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl-c")?;
    if let Some(counters) = counters {
        let (rate, concurrent, total) = counters.refusals();
        tracing::info!(rate, concurrent, total, "admission refusals at shutdown");
    }
    tracing::info!("shutting down");
    drop(server);
    Ok(())
}
