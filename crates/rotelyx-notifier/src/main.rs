//! The half that knows a device and not a conversation.
//!
//! # What this is for
//!
//! Waking a phone the moment something arrives, without anybody holding the
//! link between the phone and what arrived.
//!
//! A push token is stable for months; a mailbox tag rotates every hour, so
//! that two tags from one member cannot be tied together. Any server that
//! knows both at once undoes the rotation, and the server that would normally
//! know both is the mailbox, which is us. Waking everybody on a schedule
//! avoids the question and pays in latency. This is the other answer.
//!
//! # The split
//!
//! A device seals its push token to this server's public key and leaves the
//! result, a [`WakeTicket`], under each tag it listens on. The mailbox stores
//! `tag -> ticket` and cannot read one. When something arrives at a tag, the
//! mailbox hands the ticket here and nothing else.
//!
//! | | knows the tag | knows the device |
//! |---|---|---|
//! | Mailbox | yes | no |
//! | This | **no** | yes |
//! | Apple | no | yes |
//!
//! Neither side writes down a mapping, so there is nothing to read later, and
//! nothing to hand over if somebody asks. What collusion between the two would
//! buy is real time correlation, which is a far weaker thing than a stored
//! table, and is why they are meant to be operated apart.
//!
//! # Decoys
//!
//! The mailbox sends several tickets for every arrival and only one of them
//! matters. This server cannot tell which, because they are indistinguishable
//! once opened: every wake it sends is contentless, and every device it wakes
//! goes and looks and usually finds nothing. Apple sees the same set. The
//! mailbox knows which was real and cannot read any of them.
//!
//! # What this keeps
//!
//! Nothing. There is no registry here, no database, and no file it writes
//! besides its own key. A ticket arrives, is opened, is pushed, and is gone.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use data_encoding::BASE64;
use rotelyx_crypto::hybrid::{HybridSecretKey, SECRET_KEY_LEN};
use rotelyx_crypto::{TicketKind, WakeTicket};
use rotelyx_push::{Apns, Device, Fcm, Pushers};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "rotelyx-notifier", about = "Wakes a device without learning why")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:3342")]
    bind: String,

    /// Where this server's key lives. Made on first run if absent.
    ///
    /// Its public half is what devices seal tickets to, and it is printed at
    /// startup so an operator can put it in a client build. A client pins it
    /// rather than being told it at runtime: a key handed over by whoever is
    /// asked is a key the asker can substitute for their own, and the whole
    /// point is that the mailbox cannot read a ticket.
    #[arg(long, value_name = "PATH")]
    key: PathBuf,

    /// A shared secret the mailbox presents.
    ///
    /// Not a privacy control: a ticket says nothing to whoever holds it and
    /// buys nothing but a contentless wake. This exists so that only the
    /// mailbox can spend somebody's battery.
    #[arg(long, value_name = "PATH")]
    caller_secret: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    apns_key: Option<PathBuf>,

    #[arg(long, value_name = "ID")]
    apns_key_id: Option<String>,

    #[arg(long, value_name = "ID")]
    apns_team_id: Option<String>,

    #[arg(long, value_name = "BUNDLE", default_value = "com.rotelyx.ios")]
    apns_topic: String,

    #[arg(long)]
    apns_sandbox: bool,

    #[arg(long, value_name = "PATH")]
    fcm_service_account: Option<PathBuf>,

    /// The most tickets one request may carry.
    ///
    /// A bound on how much battery one call can spend, and therefore on how
    /// large a decoy set the mailbox can ask for.
    #[arg(long, default_value_t = 64)]
    max_per_request: usize,
}

struct Server {
    key: HybridSecretKey,
    pushers: Pushers,
    caller_secret: Option<String>,
    max_per_request: usize,
}

#[derive(Deserialize)]
struct WakeRequest {
    /// Base64 sealed tickets. One of them may matter; this server is not told
    /// which and has no way to work it out.
    tickets: Vec<String>,
}

#[derive(Serialize)]
struct WakeReply {
    /// How many were opened and pushed.
    ///
    /// A count and never a list. Saying which ticket failed would tell the
    /// caller something about the device behind it, and the caller is the one
    /// party that knows the tag.
    woken: usize,
}

/// Read the key, or make one.
fn load_or_make_key(path: &Path) -> Result<HybridSecretKey> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let bytes: [u8; SECRET_KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a notifier key", path.display()))?;
        return Ok(HybridSecretKey::from_storage_bytes(bytes));
    }

    let (secret, _public) = rotelyx_crypto::HybridKem::generate();
    std::fs::write(path, &secret.to_storage_bytes()[..])
        .with_context(|| format!("writing {}", path.display()))?;

    // The key is the whole secret of this server: anybody holding it can read
    // every ticket the mailbox is storing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("locking down {}", path.display()))?;
    }

    info!(path = %path.display(), "made a notifier key");
    Ok(secret)
}

fn now_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0)
}

/// The public key, so an operator can put it in a client build.
async fn public_key(State(server): State<Arc<Server>>) -> String {
    BASE64.encode(&server.key.public().to_bytes())
}

async fn wake(
    State(server): State<Arc<Server>>,
    headers: HeaderMap,
    Json(request): Json<WakeRequest>,
) -> (StatusCode, Json<WakeReply>) {
    if let Some(expected) = server.caller_secret.as_deref() {
        let given = headers
            .get("x-rotelyx-caller")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        // Constant time, so a caller learns whether it matched and nothing
        // about where it diverged.
        let ok = given.len() == expected.len()
            && bool::from(given.as_bytes().ct_eq(expected.as_bytes()));
        if !ok {
            return (StatusCode::FORBIDDEN, Json(WakeReply { woken: 0 }));
        }
    }

    if request.tickets.len() > server.max_per_request {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(WakeReply { woken: 0 }));
    }

    let hour = now_hour();
    let mut woken = 0usize;

    for sealed in &request.tickets {
        let Ok(bytes) = BASE64.decode(sealed.as_bytes()) else {
            continue;
        };
        let Ok(ticket) = WakeTicket::from_bytes(&bytes) else {
            continue;
        };
        // A ticket that will not open is skipped rather than reported. It is
        // either from another notifier, or expired, or a decoy the mailbox
        // made up, and this server cannot tell those apart and must not try.
        let Ok(opened) = ticket.open(&server.key, hour) else {
            continue;
        };

        let device = Device {
            token: opened.token,
            kind: opened.kind.as_str().to_owned(),
            revoke_hash: String::new(),
        };

        let pushed = match opened.kind {
            TicketKind::Apns => match server.pushers.apns.as_ref() {
                Some(apns) => apns.wake(&device).await,
                None => continue,
            },
            TicketKind::Fcm => match server.pushers.fcm.as_ref() {
                Some(fcm) => fcm.wake(&device).await,
                None => continue,
            },
        };

        match pushed {
            Ok(()) => woken += 1,
            // Logged without the token, which is the one thing here worth not
            // writing to a disk.
            Err(e) => warn!(error = %e, "a wake failed"),
        }
    }

    (StatusCode::OK, Json(WakeReply { woken }))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let key = load_or_make_key(&cli.key)?;

    let mut pushers = Pushers::default();

    if let (Some(path), Some(id), Some(team)) =
        (cli.apns_key.as_ref(), cli.apns_key_id.as_ref(), cli.apns_team_id.as_ref())
    {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        pushers.apns = Some(Arc::new(Apns::new(
            &pem,
            id.clone(),
            team.clone(),
            cli.apns_topic.clone(),
            cli.apns_sandbox,
        )?));
        info!(topic = %cli.apns_topic, sandbox = cli.apns_sandbox, "will wake iPhones");
    } else {
        warn!("no APNs key: a ticket from an iPhone is opened and then dropped");
    }

    if let Some(path) = cli.fcm_service_account.as_ref() {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        pushers.fcm = Some(Arc::new(Fcm::new(&json)?));
        info!("will wake Android devices");
    }

    let caller_secret = match cli.caller_secret.as_ref() {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim()
                .to_owned(),
        ),
        None => {
            warn!("no --caller-secret: anybody who can reach this can spend somebody's battery");
            None
        }
    };

    let public = BASE64.encode(&key.public().to_bytes());
    println!("notifier public key: {public}");

    let server = Arc::new(Server {
        key,
        pushers,
        caller_secret,
        max_per_request: cli.max_per_request,
    });

    let app = Router::new()
        .route("/key", get(public_key))
        .route("/wake", post(wake))
        .with_state(server);

    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;

    info!(bind = %cli.bind, "notifier listening. It holds no registry and writes nothing down");
    axum::serve(listener, app).await.context("serving")?;
    Ok(())
}
