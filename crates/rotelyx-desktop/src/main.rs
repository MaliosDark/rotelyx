//! Rotelyx desktop.
//!
//! A native window over the same protocol stack the CLI drives: real QUIC, real
//! MLS, real admission control, sealed identity on disk.
//!
//! ## Trust boundary
//!
//! Tauri's IPC is in process, so plaintext never crosses a socket. That is the
//! meaningful difference from the browser harness, which speaks over loopback
//! and therefore admits anything on the machine that can reach that port.
//!
//! What remains outside the boundary is the operating system and anything with
//! code execution on the device. That is unavoidable in any client that renders
//! a message to a screen.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod handshake;
mod keyfile;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rotelyx_core::store::{self, Paths, StoredInvitation};
use rotelyx_core::{epoch_at, Identity, Invitation};
use rotelyx_net::EndpointAddr;
use tauri::{Emitter, Manager};
use tokio::sync::mpsc;

use engine::{Command, Engine, Event};

/// Process wide state. One identity, one session at a time.
struct App {
    identity: Identity,
    paths: Paths,
    /// Sender into the running session, if any.
    session: Mutex<Option<mpsc::UnboundedSender<Command>>>,
}

fn now_epoch() -> Result<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();
    Ok(epoch_at(secs))
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

// ---------------------------------------------------------------------------
// Commands the window can call
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Snapshot {
    id: String,
    invitations: usize,
}

/// One live invitation, as the window lists them.
#[derive(serde::Serialize)]
struct InvitationRow {
    code: String,
    expires_in_hours: u64,
}

#[tauri::command]
fn snapshot(app: tauri::State<'_, Arc<App>>) -> Result<Snapshot, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let invitations = store::load_invitations(&app.paths.invitations, epoch)
        .map_err(|e| e.to_string())?
        .len();
    Ok(Snapshot {
        id: app.identity.id().to_string(),
        invitations,
    })
}

#[tauri::command]
fn issue_invitation(app: tauri::State<'_, Arc<App>>, hours: u64) -> Result<String, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let expires = epoch + hours.max(1);
    let invitation = Invitation::issue(expires);
    let stored = StoredInvitation {
        secret: *invitation.secret_bytes(),
        // The address this invitation is answered on. See `Invitation`.
        transport: *invitation.transport_bytes(),
        expires_at_epoch: expires,
    };
    let code = stored.code();

    store::add_invitation(&app.paths.invitations, stored, epoch).map_err(|e| e.to_string())?;
    Ok(code)
}

#[tauri::command]
fn invitations(app: tauri::State<'_, Arc<App>>) -> Result<Vec<InvitationRow>, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let live = store::load_invitations(&app.paths.invitations, epoch).map_err(|e| e.to_string())?;
    Ok(live
        .iter()
        .map(|inv| InvitationRow {
            code: inv.code(),
            // An epoch is an hour, so this is already hours.
            expires_in_hours: inv.expires_at_epoch.saturating_sub(epoch),
        })
        .collect())
}

/// Withdraw an invitation, which is what blocking means here.
///
/// There is no identity to ban. A caller arrives on a key belonging to one
/// invitation and nothing else, so a list of identities to refuse is a list of
/// values that never arrive. What can be withdrawn is the invitation, and that
/// is checked against a secret this side holds rather than against something
/// the caller chose to say about itself.
#[tauri::command]
fn block(app: tauri::State<'_, Arc<App>>, code: String) -> Result<bool, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let code = code.trim();
    let live = store::load_invitations(&app.paths.invitations, epoch).map_err(|e| e.to_string())?;
    let target = live
        .iter()
        .find(|inv| inv.code() == code)
        .ok_or_else(|| "that is not a code this device issued".to_string())?;

    store::revoke_invitation(&app.paths.invitations, &target.secret, epoch)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn send_message(app: tauri::State<'_, Arc<App>>, text: String) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::Send { text }).map_err(|_| "session ended".to_string())
}

/// Start talking.
///
/// Refused by the engine, with a reason, on a session that may take a direct
/// path: audio over one is this machine's address handed to the other end. The
/// window learns that through an error event rather than here, because by the
/// time this returns the engine has not looked at it yet.
#[tauri::command]
fn start_call(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::StartCall).map_err(|_| "session ended".to_string())
}

/// Stop talking. The session stays up and text keeps working.
#[tauri::command]
fn end_call(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::EndCall).map_err(|_| "session ended".to_string())
}

#[tauri::command]
fn hangup(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    if let Some(tx) = guard.take() {
        let _ = tx.send(Command::Hangup);
    }
    Ok(())
}

/// Start a session. `mode` is either `listen` or `connect`.
#[tauri::command]
fn start(
    window: tauri::Window,
    app: tauri::State<'_, Arc<App>>,
    mode: String,
    open: Option<bool>,
    addr: Option<String>,
    invite: Option<String>,
    // A relay to route through, and what a call needs. Left out, the session is
    // direct only: fine for text, and a call is refused because a direct path
    // shows the other end this machine's address. Both sides need the same one.
    relay: Option<String>,
) -> Result<(), String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
    {
        let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
        if guard.is_some() {
            return Err("a session is already running".into());
        }
        *guard = Some(tx);
    }

    // Events reach the window through Tauri's IPC, which is in process. No
    // socket is involved and no plaintext leaves the address space.
    let emitter = window.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        let _ = emitter.emit("rotelyx", event);
    });

    // The identity is re-derived rather than shared, so the engine owns its own
    // copy and nothing has to be locked on the hot path.
    let identity = Identity::from_bytes(*app.identity.to_storage_bytes());
    let paths = app.paths.clone();
    let app_handle = app.inner().clone();
    let window_for_reset = window.clone();

    tauri::async_runtime::spawn(async move {
        let engine = match Engine::new(identity, paths, epoch, emit.clone(), relay.as_deref()) {
            Ok(e) => e,
            Err(e) => {
                emit(Event::Error { text: format!("{e:#}") });
                emit(Event::Disconnected { reason: "could not start".into() });
                return;
            }
        };

        let outcome = match mode.as_str() {
            "listen" => engine.listen(open.unwrap_or(false), &mut rx).await,
            "connect" => {
                let addr = addr.unwrap_or_default();
                engine.connect(&addr, invite.as_deref(), &mut rx).await
            }
            other => Err(anyhow::anyhow!("unknown mode {other}")),
        };

        if let Err(e) = outcome {
            // `{:#}` prints the whole context chain, which is what turns
            // "connecting failed" into a legible refusal.
            emit(Event::Error { text: format!("{e:#}") });
        }

        if let Ok(mut guard) = app_handle.session.lock() {
            *guard = None;
        }
        let _ = window_for_reset.emit(
            "rotelyx",
            Event::Status {
                text: "Session ended".into(),
            },
        );
    });

    Ok(())
}

fn identity_path() -> PathBuf {
    if let Ok(p) = std::env::var("ROTELYX_IDENTITY") {
        return PathBuf::from(p);
    }
    // Beside the executable's working directory keeps the harness predictable.
    // A shipped client would use the platform config directory.
    PathBuf::from("rotelyx-identity.key")
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx=info,warn".into()),
        )
        .init();

    let path = identity_path();
    let identity = match keyfile::load_or_create(&path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("could not open the identity at {}: {e:#}", path.display());
            std::process::exit(1);
        }
    };

    let app = Arc::new(App {
        paths: Paths::from_identity(&path),
        identity,
        session: Mutex::new(None),
    });

    tauri::Builder::default()
        .manage(app)
        .invoke_handler(tauri::generate_handler![
            snapshot,
            issue_invitation,
            block,
            invitations,
            start,
            start_call,
            end_call,
            send_message,
            hangup,
        ])
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Rotelyx");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("running the Rotelyx window");
}
