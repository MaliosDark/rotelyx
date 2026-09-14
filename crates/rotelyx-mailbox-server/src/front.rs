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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

/// One connection to the mailbox, and the sessions riding on it.
struct Upstream {
    out: mpsc::Sender<String>,
    /// Upstream session id -> where its replies go. The reply from the mailbox
    /// names the upstream id; this is how it finds the phone and the id to
    /// rewrite back to.
    routes: Arc<Mutex<HashMap<u64, PhoneSlot>>>,
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
            upstreams.push(spawn_upstream(mailbox).await?);
        }
        Ok(Arc::new(Self {
            upstreams,
            next_id: AtomicU64::new(1),
            cursor: AtomicU64::new(0),
            front_key,
        }))
    }

    /// The router a phone reaches: the multiplexed endpoint and the key.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/front", get(phone_handler))
            .route("/front-key", get(key_handler))
            .with_state(Arc::clone(self))
    }

    fn pick_upstream(&self) -> usize {
        (self.cursor.fetch_add(1, Ordering::Relaxed) as usize) % self.upstreams.len()
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
                    let upstream = front.pick_upstream();
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

/// Open one connection to the mailbox's `/front`, and a task that routes each
/// reply to the phone that owns the upstream id, with the id rewritten back to
/// the phone's own.
async fn spawn_upstream(mailbox: &str) -> Result<Upstream> {
    let url = format!("{}/front", mailbox.trim_end_matches('/'));
    let (stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    let (mut write, mut read) = stream.split();

    let (out, mut out_rx) = mpsc::channel::<String>(256);
    let routes: Arc<Mutex<HashMap<u64, PhoneSlot>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        while let Some(text) = out_rx.recv().await {
            if write.send(UpstreamMessage::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    let routes_in = Arc::clone(&routes);
    tokio::spawn(async move {
        while let Some(Ok(message)) = read.next().await {
            let text = match message {
                UpstreamMessage::Text(t) => t.to_string(),
                UpstreamMessage::Close(_) => break,
                _ => continue,
            };
            let Ok(frame) = serde_json::from_str::<Frame>(&text) else { continue };
            let Some(id) = upstream_id_of(&frame.s) else { continue };
            let slot = { routes_in.lock().await.get(&id).cloned() };
            let Some(slot) = slot else { continue };

            // The reply names the upstream id; the phone knows its own. Rewrite
            // `s` back before it leaves the front, so the phone sees only the
            // id it chose.
            let Some(body) = frame.b else { continue };
            let rewritten = serde_json::json!({ "s": slot.phone_id, "b": body }).to_string();
            let _ = slot.inbox.send(Message::Text(rewritten.into())).await;
        }
    });

    Ok(Upstream { out, routes })
}
