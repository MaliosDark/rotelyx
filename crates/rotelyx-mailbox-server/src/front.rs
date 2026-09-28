//! The front: a websocket multiplexer between phones and a mailbox.
//!
//! # What it is
//!
//! A phone opens one connection here and runs its conversations sealed inside
//! it, one session per conversation. The front holds a small pool of
//! connections to the mailbox's `/front` endpoint and forwards every phone's
//! sessions across them, so the mailbox sees sessions from the front with no
//! address and no way to tell which belong to one phone. The front reads
//! neither the phone's secret (it is sealed to the mailbox's key) nor the
//! mailbox's; it moves opaque frames and rewrites one number. See
//! `docs/FRONT.md`.
//!
//! # The one number it rewrites, and why that is the whole correctness story
//!
//! A phone names its own sessions with an eight-byte id it chose, and two
//! phones will choose the same one. If the front forwarded that id upstream as
//! it is, the mailbox would deliver one phone's envelopes to a session the
//! other phone opened under the same id: a privacy failure, not a glitch. So
//! the front gives every session a fresh upstream id from a counter that never
//! repeats, keeps the phone's own id beside it, rewrites the id to the
//! upstream one on the way to the mailbox and back to the phone's on the way
//! out. The phone's id is meaningful only within the phone's own connection;
//! the upstream id is unique across the whole front. That is the property
//! every test in this file exists to hold.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use data_encoding::BASE64;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as UpstreamMessage;
use tracing::{info, warn};

/// How many connections the front holds to the mailbox. Sessions are spread
/// across them, so this is the number of connections the mailbox counts from
/// the front's address, and it must be inside the allowance the mailbox gives
/// that address (`--exempt-address`, or a raised front allowance).
const UPSTREAM_POOL: usize = 8;

/// A frame on the multiplexed wire, phone-facing and upstream both: one of a
/// hello, a sealed body, or a close, tagged with a session.
#[derive(Deserialize)]
struct Frame {
    s: String,
    #[serde(default)]
    hello: Option<String>,
    #[serde(default)]
    b: Option<String>,
    #[serde(default)]
    close: bool,
}

/// Where an upstream session's replies go, and the id the phone knows it by.
#[derive(Clone)]
struct PhoneSlot {
    inbox: mpsc::Sender<Message>,
    phone_id: String,
}

/// One slot in the pool: a connection to the mailbox, the sessions riding on
/// it, and whether it is up.
///
/// A slot outlives its connection. The task behind it reconnects for as long as
/// the front runs, because a mailbox restart is ordinary and a front that gave
/// up on one would go on listening with nothing behind it.
struct Upstream {
    out: mpsc::Sender<String>,
    /// Upstream session id -> where its replies go. The reply from the mailbox
    /// names the upstream id; this is how it finds the phone and the id to
    /// rewrite back to.
    routes: Arc<Mutex<HashMap<u64, PhoneSlot>>>,
    /// Whether this slot has a connection right now.
    ///
    /// Read before a session is placed on it. Without this the front would
    /// accept a session onto a dead slot and drop every frame in silence, which
    /// is exactly how a front with a healthy landing page delivered nothing.
    alive: Arc<AtomicBool>,
}

/// The front's shared state: the pool, the id counter, the key it serves for
/// the mailbox.
pub struct Front {
    upstreams: Vec<Upstream>,
    next_id: AtomicU64,
    cursor: AtomicU64,
    front_key: String,
}

impl Front {
    /// Connect the pool and read the mailbox's front key. `mailbox` is the
    /// mailbox's base URL, for example `ws://127.0.0.1:3341`.
    pub async fn connect(mailbox: &str) -> Result<Arc<Self>> {
        Self::connect_with(mailbox, UPSTREAM_POOL).await
    }

    /// As [`connect`](Self::connect), with the pool size named, for a test that
    /// wants to prove two phones cross onto one upstream connection.
    pub async fn connect_with(mailbox: &str, pool: usize) -> Result<Arc<Self>> {
        let http = mailbox.replace("ws://", "http://").replace("wss://", "https://");
        let front_key = reqwest::get(format!("{http}/front-key"))
            .await
            .with_context(|| format!("asking {http}/front-key"))?
            .error_for_status()
            .context("the mailbox serves no front key: start it with --front-key")?
            .text()
            .await
            .context("reading the front key")?
            .trim()
            .to_string();

        let mut upstreams = Vec::with_capacity(pool);
        for _ in 0..pool.max(1) {
            upstreams.push(spawn_upstream(mailbox.to_string()));
        }
        let front = Arc::new(Self {
            upstreams,
            next_id: AtomicU64::new(1),
            cursor: AtomicU64::new(0),
            front_key,
        });

        // Starting is still allowed to fail loudly. The slots reconnect for
        // ever once the front is up, but a front that never reached the mailbox
        // at all is a misconfiguration, and saying so at startup is worth more
        // than a process that listens and serves nothing.
        for _ in 0..50 {
            if front.has_mailbox() {
                return Ok(front);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        anyhow::bail!("no connection to the mailbox at {mailbox} came up")
    }

    /// The router a phone reaches: the multiplexed endpoint and the key.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/front", get(phone_handler))
            .route("/front-key", get(key_handler))
            .with_state(Arc::clone(self))
    }

    /// The next slot with a connection, round robin, or `None` when the
    /// mailbox is unreachable.
    fn pick_upstream(&self) -> Option<usize> {
        let n = self.upstreams.len();
        if n == 0 {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize;
        (0..n)
            .map(|k| (start + k) % n)
            .find(|&i| self.upstreams[i].alive.load(Ordering::Relaxed))
    }

    /// Whether any slot has a connection to the mailbox.
    ///
    /// A front with none of them is not a front: it can take a session and
    /// never answer it. It says so instead, and the client goes to the mailbox
    /// directly, which is what every build did before fronts existed.
    pub fn has_mailbox(&self) -> bool {
        self.upstreams
            .iter()
            .any(|u| u.alive.load(Ordering::Relaxed))
    }

    fn fresh_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

async fn key_handler(State(front): State<Arc<Front>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        front.front_key.clone(),
    )
        .into_response()
}

async fn phone_handler(ws: WebSocketUpgrade, State(front): State<Arc<Front>>) -> Response {
    // Refused rather than accepted and swallowed. A phone that is told no falls
    // back to the mailbox itself; a phone that is accepted by a front with
    // nothing behind it waits for an answer that is never coming.
    if !front.has_mailbox() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "this front has no connection to its mailbox\n",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| async move { serve_phone(socket, front).await })
}

/// A phone connection's session: which upstream carries it, under which id.
struct Route {
    upstream: usize,
    upstream_id: u64,
}

/// One phone connection.
async fn serve_phone(mut socket: WebSocket, front: Arc<Front>) {
    let mut routes: HashMap<String, Route> = HashMap::new();
    // Replies from every upstream this phone uses, already rewritten to the
    // phone's own session ids, funnelled to the socket.
    let (to_phone, mut from_upstreams) = mpsc::channel::<Message>(256);

    loop {
        tokio::select! {
            reply = from_upstreams.recv() => {
                let Some(message) = reply else { continue };
                if socket.send(message).await.is_err() {
                    break;
                }
            }
            incoming = socket.next() => {
                let text = match incoming {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                };
                let Ok(frame) = serde_json::from_str::<Frame>(&text) else { continue };

                if frame.close {
                    if let Some(route) = routes.remove(&frame.s) {
                        let close = serde_json::json!({
                            "s": upstream_label(route.upstream_id), "close": true,
                        }).to_string();
                        let _ = front.upstreams[route.upstream].out.send(close).await;
                        deregister(&front, route.upstream, route.upstream_id).await;
                    }
                    continue;
                }

                if frame.hello.is_some() {
                    // A new session. A fresh upstream id, the phone's own id
                    // kept beside it for the reply, and the hello forwarded
                    // with the id rewritten. A repeat of an id the phone is
                    // already using is dropped rather than crossed.
                    if routes.contains_key(&frame.s) {
                        continue;
                    }
                    let Some(upstream) = front.pick_upstream() else {
                        // The mailbox went away between the upgrade and this
                        // hello. Closing is the answer for the same reason the
                        // upgrade is refused above.
                        break;
                    };
                    let upstream_id = front.fresh_id();
                    front.upstreams[upstream].routes.lock().await.insert(
                        upstream_id,
                        PhoneSlot { inbox: to_phone.clone(), phone_id: frame.s.clone() },
                    );
                    routes.insert(frame.s.clone(), Route { upstream, upstream_id });
                    forward(&front, upstream, upstream_id, &frame).await;
                    continue;
                }

                let Some(route) = routes.get(&frame.s) else { continue };
                forward(&front, route.upstream, route.upstream_id, &frame).await;
            }
        }
    }

    // Gone: every session closed upstream so the mailbox releases its tags,
    // and the routes dropped so a late reply reaches nobody.
    for (_, route) in routes.drain() {
        let close = serde_json::json!({
            "s": upstream_label(route.upstream_id), "close": true,
        }).to_string();
        let _ = front.upstreams[route.upstream].out.send(close).await;
        deregister(&front, route.upstream, route.upstream_id).await;
    }
}

/// Forward a phone frame to the mailbox with the upstream id in place of the
/// phone's. The phone's id never leaves this front.
async fn forward(front: &Front, upstream: usize, upstream_id: u64, frame: &Frame) {
    let mut out = serde_json::Map::new();
    out.insert("s".into(), upstream_label(upstream_id).into());
    if let Some(hello) = &frame.hello {
        out.insert("hello".into(), hello.clone().into());
    }
    if let Some(b) = &frame.b {
        out.insert("b".into(), b.clone().into());
    }
    let _ = front.upstreams[upstream]
        .out
        .send(serde_json::Value::Object(out).to_string())
        .await;
}

async fn deregister(front: &Front, upstream: usize, upstream_id: u64) {
    front.upstreams[upstream].routes.lock().await.remove(&upstream_id);
}

/// The eight bytes an upstream id travels as, encoded exactly like a phone's
/// own session id so the wire shape upstream is indistinguishable from a
/// direct connection's.
fn upstream_label(id: u64) -> String {
    BASE64.encode(&id.to_be_bytes())
}

fn upstream_id_of(label: &str) -> Option<u64> {
    let bytes = BASE64.decode(label.as_bytes()).ok()?;
    let array: [u8; 8] = bytes.as_slice().try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// One slot in the pool, and the task that keeps it connected.
///
/// The slot is returned before anything is connected, and the task behind it
/// connects, pumps frames both ways, and reconnects when the connection ends,
/// for as long as the front runs. A mailbox restart is ordinary: it used to
/// leave the front listening with a dead socket, accepting phones and dropping
/// everything they sent, because the pool was opened once at startup and never
/// again. Nothing announced it. That is what `alive` and this loop close.
fn spawn_upstream(mailbox: String) -> Upstream {
    let (out, mut out_rx) = mpsc::channel::<String>(256);
    let routes: Arc<Mutex<HashMap<u64, PhoneSlot>>> = Arc::new(Mutex::new(HashMap::new()));
    let alive = Arc::new(AtomicBool::new(false));

    let routes_task = Arc::clone(&routes);
    let alive_task = Arc::clone(&alive);
    tokio::spawn(async move {
        let url = format!("{}/front", mailbox.trim_end_matches('/'));
        let mut backoff = Duration::from_secs(1);
        loop {
            match tokio_tungstenite::connect_async(&url).await {
                Ok((stream, _)) => {
                    backoff = Duration::from_secs(1);
                    // Frames queued while this slot was down name sessions the
                    // mailbox never heard of, so they are dropped rather than
                    // sent to a connection that would ignore them anyway.
                    while out_rx.try_recv().is_ok() {}
                    alive_task.store(true, Ordering::Relaxed);
                    info!(%url, "front: upstream connected");

                    let (mut write, mut read) = stream.split();
                    loop {
                        tokio::select! {
                            outgoing = out_rx.recv() => {
                                let Some(text) = outgoing else { return };
                                if write.send(UpstreamMessage::Text(text.into())).await.is_err() {
                                    break;
                                }
                            }
                            incoming = read.next() => {
                                let Some(Ok(message)) = incoming else { break };
                                let text = match message {
                                    UpstreamMessage::Text(t) => t.to_string(),
                                    UpstreamMessage::Close(_) => break,
                                    _ => continue,
                                };
                                let Ok(frame) = serde_json::from_str::<Frame>(&text) else { continue };
                                let Some(id) = upstream_id_of(&frame.s) else { continue };
                                let slot = { routes_task.lock().await.get(&id).cloned() };
                                let Some(slot) = slot else { continue };

                                // The reply names the upstream id; the phone
                                // knows its own. Rewrite `s` back before it
                                // leaves the front, so the phone sees only the
                                // id it chose.
                                let Some(body) = frame.b else { continue };
                                let rewritten =
                                    serde_json::json!({ "s": slot.phone_id, "b": body }).to_string();
                                let _ = slot.inbox.send(Message::Text(rewritten.into())).await;
                            }
                        }
                    }

                    alive_task.store(false, Ordering::Relaxed);
                    // Every session on this connection died with it, and the
                    // phones holding them are told so they open new ones. A
                    // phone that is not told goes on sealing frames for a
                    // session the mailbox has forgotten.
                    let stranded: Vec<PhoneSlot> = {
                        let mut held = routes_task.lock().await;
                        held.drain().map(|(_, slot)| slot).collect()
                    };
                    let count = stranded.len();
                    for slot in stranded {
                        let _ = slot.inbox.send(Message::Close(None)).await;
                    }
                    warn!(%url, sessions = count, "front: upstream lost, reconnecting");
                }
                Err(error) => {
                    alive_task.store(false, Ordering::Relaxed);
                    warn!(%url, %error, "front: upstream will not connect");
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(15));
        }
    });

    Upstream { out, routes, alive }
}
