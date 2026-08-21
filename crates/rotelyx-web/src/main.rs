//! A local browser UI for Rotelyx.
//!
//! Serves one page on loopback and drives a real Rotelyx session behind it: real
//! QUIC, real MLS, real admission control. It exists so the protocol can be
//! exercised by clicking rather than by reading test output.
//!
//! ## The browser is outside the encryption boundary
//!
//! Plaintext travels from the page to this process over a loopback WebSocket,
//! and encryption happens in this process. Anything with access to your
//! machine's loopback interface, or to the browser, sees plaintext.
//!
//! That is acceptable for a local harness and unacceptable for a product. A
//! real client puts the crypto in the same trust domain as the display. The
//! page says so, prominently, so nobody mistakes this for a secure web client.

mod handshake;
mod session;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use tokio::sync::mpsc;
use rotelyx_core::store;
use rotelyx_core::{epoch_at, Identity, Invitation};
use rotelyx_net::EndpointAddr;

use session::{Command, Driver, Event};

#[derive(Parser, Debug)]
#[command(name = "rotelyx-web", about = "Rotelyx browser harness")]
struct Cli {
    /// Identity key file.
    #[arg(long, default_value = "rotelyx-identity.key")]
    identity: PathBuf,

    /// Where to serve the UI.
    ///
    /// Loopback by default and it should stay that way: this page speaks
    /// plaintext to the process behind it.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
}

struct AppState {
    identity_path: PathBuf,
    identity: Identity,
}

fn invitations_path(identity: &std::path::Path) -> PathBuf {
    identity.with_extension("invites")
}

fn now_epoch() -> Result<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();
    Ok(epoch_at(secs))
}

fn load_identity(path: &PathBuf) -> Result<Identity> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("identity file is not 32 bytes")?;
        Ok(Identity::from_bytes(key))
    } else {
        let identity = Identity::generate();
        std::fs::write(path, &*identity.to_storage_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(identity)
    }
}

/// Invitations, in the format the rest of Rotelyx uses.
///
/// This file used to have a format of its own, `<secret> <expiry>`, with no
/// transport key in it. An invitation needs one: it is the address the holder
/// calls, and without it this client can only listen under its identity, which
/// gives every contact the same name to compare. Sharing the store also means
/// a code issued here is a code the terminal client accepts, and the other way
/// round, which was not true while the two wrote different things.
fn load_invitations(path: &PathBuf, epoch: u64) -> Result<Vec<store::StoredInvitation>> {
    Ok(store::load_invitations(path, epoch)?)
}

pub(crate) fn encode_addr(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr).context("encoding address")?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(&json))
}

pub(crate) fn decode_addr(s: &str) -> Result<EndpointAddr> {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .context("address is not valid base64")?;
    serde_json::from_slice(&bytes).context("address is not a valid Rotelyx address")
}

async fn index() -> impl IntoResponse {
    Html(include_str!("ui.html"))
}

#[derive(serde::Serialize)]
struct StateResponse {
    id: String,
    invitations: usize,
}

async fn api_state(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let epoch = now_epoch().unwrap_or(0);
    let live = load_invitations(&invitations_path(&state.identity_path), epoch)
        .unwrap_or_default()
        .len();

    Json(StateResponse {
        id: state.identity.id().to_string(),
        invitations: live,
    })
}

#[derive(serde::Deserialize)]
struct InviteRequest {
    hours: u64,
}

#[derive(serde::Serialize)]
struct InviteResponse {
    code: String,
}

async fn api_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InviteRequest>,
) -> std::result::Result<Json<InviteResponse>, (axum::http::StatusCode, String)> {
    let err = |e: anyhow::Error| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string());

    let epoch = now_epoch().map_err(err)?;
    let expires = epoch + req.hours.max(1);
    let invitation = Invitation::issue(expires);
    let stored = store::StoredInvitation {
        secret: *invitation.secret_bytes(),
        transport: *invitation.transport_bytes(),
        expires_at_epoch: expires,
    };
    // The whole code: the secret that authorises and the address to call. The
    // secret alone is what this used to hand out, and a holder of one cannot
    // reach the address it belongs to.
    let code = stored.code();

    let path = invitations_path(&state.identity_path);
    store::add_invitation(&path, stored, epoch).map_err(|e| err(e.into()))?;

    Ok(Json(InviteResponse { code }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| drive(socket, state))
}

/// One tab, one session.
async fn drive(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = {
        use futures_util::StreamExt;
        socket.split()
    };

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Command>();

    // Events out to the page.
    let pump = tokio::spawn(async move {
        use futures_util::SinkExt;
        while let Some(event) = event_rx.recv().await {
            let Ok(json) = serde_json::to_string(&event) else {
                continue;
            };
            if sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Commands in from the page.
    let inbound = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                if let Ok(cmd) = serde_json::from_str::<Command>(&text) {
                    if cmd_tx.send(cmd).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let epoch = now_epoch().unwrap_or(0);
    let identity = Identity::from_bytes(*state.identity.to_storage_bytes());
    let invitations =
        load_invitations(&invitations_path(&state.identity_path), epoch).unwrap_or_default();
    let mut driver = Driver::new(identity, invitations, epoch, event_tx.clone());

    // The first command decides the role for the whole session.
    let outcome = match cmd_rx.recv().await {
        Some(Command::Listen { open }) => driver.listen(open, &mut cmd_rx).await,
        Some(Command::Connect { addr, invite }) => {
            driver.connect(&addr, invite.as_deref(), &mut cmd_rx).await
        }
        _ => Ok(()),
    };

    if let Err(e) = outcome {
        let _ = event_tx.send(Event::Error {
            // `{:#}` prints the whole anyhow context chain, which is what makes
            // a refusal legible instead of just "connecting failed".
            text: format!("{e:#}"),
        });
    }

    drop(event_tx);
    let _ = pump.await;
    inbound.abort();
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx_web=info,warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let identity = load_identity(&cli.identity)?;

    let state = Arc::new(AppState {
        identity_path: cli.identity.clone(),
        identity,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/invite", post(api_invite))
        .route("/ws", get(ws_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;

    println!("Rotelyx UI on http://{}", cli.bind);
    println!("identity {}", state.identity.id());
    println!();
    println!("The browser is OUTSIDE the encryption boundary: plaintext travels");
    println!("from the page to this process over loopback. Fine for testing,");
    println!("wrong for a product.");

    axum::serve(listener, app).await.context("serving")?;
    Ok(())
}
