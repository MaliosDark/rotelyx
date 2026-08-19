//! The blind mailbox server.
//!
//! Stores sealed envelopes under rotating tags and hands them to whoever asks
//! for the right tag. It holds no key, learns no identity, and cannot read a
//! single byte it stores.
//!
//! # What the operator sees, and what it does not
//!
//! | Observable | Visible to the operator |
//! |---|---|
//! | Envelope contents | No. Encrypted by MLS, and this process holds no key |
//! | Message length | No. Padded to one of five fixed buckets before it arrives |
//! | Sender identity | No. Deposits carry nothing but the envelope |
//! | Recipient identity | No. A tag is an unlinkable 32 byte value |
//! | Which tags exist, and when they are busy | **Yes** |
//! | Which tags one connection asks for together | **Yes** |
//! | Source IP addresses | **Yes**, unless the client arrives over Tor or a VPN |
//!
//! The last two are the honest cost of a store and forward design and are
//! ADV-3 in the threat model. They are the reason a native client prefers a
//! direct path over any relayed one, and the reason this server exists only for
//! peers that have no direct path or are not online at the same time.
//!
//! # Delivery is exactly once
//!
//! Collection removes. Two devices polling the same tag race, and one of them
//! loses the message. That is a real limitation of multi-device use and is
//! preferred over the alternative, which is a mailbox that keeps copies of
//! everything it has already delivered.

mod vault;
mod wake;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use data_encoding::BASE64;
use futures_lite::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

use rotelyx_mailbox::{Envelope, Mailbox, Tag, DEFAULT_TTL_SECONDS};

use rotelyx_capability as access;
use rotelyx_capability::{Capability, Charge, Meter, Tier, Verifier};

/// How often expired envelopes are dropped. Expiry is also enforced on
/// collection, so a missed sweep can never cause an expired envelope to be
/// served; the sweep only reclaims memory.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// How often an idle connection is pinged.
///
/// Cloudflare drops an idle WebSocket at around 100 seconds and other proxies
/// have their own limits, none of them generous. A conversation where nobody
/// has typed for two minutes is completely normal, so without this the socket
/// dies during ordinary use and the client reports a dropped connection with no
/// cause. Well under the tightest limit we know of.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// A client that subscribes to more tags than this is either broken or
/// enumerating. A legitimate one asks for its current time bucket plus a small
/// lookback.
const MAX_TAGS_PER_SUBSCRIPTION: usize = 64;

/// The largest bucket is 8 MiB; the rest is envelope overhead and base64
/// expansion, with room to spare.
const MAX_FRAME_BYTES: usize = 12 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "rotelyx-mailbox-server", version, about = "Rotelyx blind mailbox")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Address to bind. Use 0.0.0.0 when a reverse proxy is on another machine.
    #[arg(long, default_value = "127.0.0.1:3341")]
    bind: SocketAddr,

    /// How long an uncollected envelope is kept, in seconds. Overridden per
    /// connection by the tier's own retention.
    #[arg(long, default_value_t = DEFAULT_TTL_SECONDS)]
    ttl: u64,

    /// Issuer public key, hex. Without it the server accepts no tokens and
    /// everyone gets the free tier.
    #[arg(long)]
    issuer: Option<String>,

    /// Public key for blindly issued plus++ tokens, a DER file.
    #[arg(long)]
    blind_plusplus: Option<PathBuf>,

    /// Public key for blindly issued plus tokens, a DER file.
    ///
    /// The tier a token grants is decided by which key verifies it, never by
    /// anything written inside the token, because the client chooses what gets
    /// blinded.
    #[arg(long)]
    blind_plus: Option<PathBuf>,

    /// Where to keep the consumption counters across restarts.
    ///
    /// Without this the meter lives only in memory, and every restart hands
    /// each token a fresh allowance. Holds a random id and a byte count per
    /// token: no address, no tag, no content.
    #[arg(long)]
    meter_state: Option<PathBuf>,

    /// Where to keep undelivered envelopes across restarts, encrypted.
    ///
    /// Requires ROTELYX_MAILBOX_PASSPHRASE. Without both, the mailbox lives in
    /// memory only and a restart drops everything nobody collected.
    #[arg(long)]
    mailbox_state: Option<PathBuf>,

    /// The APNs authentication key, a `.p8` downloaded once from the Apple
    /// Developer account.
    ///
    /// Without it this server wakes nobody and says so when asked, rather than
    /// accepting registrations it will never act on. Apple keeps no copy of
    /// this file, so losing it means minting a new one, and it belongs here and
    /// never in a repository.
    #[arg(long, value_name = "PATH")]
    apns_key: Option<PathBuf>,

    /// The ten character key identifier Apple shows beside the key.
    #[arg(long, value_name = "ID")]
    apns_key_id: Option<String>,

    /// The ten character team identifier from the developer account.
    #[arg(long, value_name = "ID")]
    apns_team_id: Option<String>,

    /// The application's bundle identifier, which Apple calls the topic.
    #[arg(long, value_name = "BUNDLE", default_value = "com.ideoalabs.rotelyx")]
    apns_topic: String,

    /// Use Apple's sandbox rather than production.
    ///
    /// A development build's tokens are valid only against the sandbox and a
    /// production build's only against production. Getting it wrong yields
    /// `BadDeviceToken` and no other clue.
    #[arg(long)]
    apns_sandbox: bool,

    /// How often to wake every registered device, in seconds.
    ///
    /// The one number that trades latency against battery, and deliberately not
    /// tunable per device: a device woken on its own schedule is a device
    /// distinguishable by its rhythm.
    #[arg(long, value_name = "SECONDS", default_value_t = wake::WAKE_EVERY_DEFAULT)]
    wake_every: u64,

    /// Where the wake registry is snapshotted, sealed under the mailbox
    /// passphrase.
    ///
    /// Without it every device stops being woken after a restart until it next
    /// connects, and a device that is asleep cannot connect. That circularity is
    /// why this is needed in practice, and it is still optional because an
    /// operator may prefer to hold nothing at rest.
    #[arg(long, value_name = "PATH")]
    wake_state: Option<PathBuf>,

    /// Where to record availability, for the status strip on the landing page.
    ///
    /// Without it the strip can only say "up since this process started", so
    /// every restart looks like the beginning of time and an outage is never
    /// visible: a mailbox that is down serves no page, so the only way it can
    /// report having been down is to have written it beforehand.
    ///
    /// The file holds half-hour bucket numbers and nothing else. No tags, no
    /// addresses, no counts.
    #[arg(long)]
    status: Option<PathBuf>,

    /// Show aggregate counters on the landing page.
    ///
    /// Off by default, and meant to be off in production. Even totals measure a
    /// community: somebody polling "envelopes delivered" every minute learns
    /// when a group is awake, roughly how large it is, and when something
    /// happened, without reading a byte. That is the tracking this project
    /// exists to prevent.
    ///
    /// It exists because while a thing is being built, being able to see that
    /// it is working matters more than a leak to an audience of one.
    #[arg(long)]
    stats: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Client side: blind a fresh id, ready to be paid for and signed.
    BlindRequest {
        /// The tier's public key, DER.
        #[arg(long)]
        public: PathBuf,

        /// Where to keep the in-flight state until the signature comes back.
        #[arg(long)]
        state: PathBuf,
    },

    /// Client side: turn a blind signature into a usable token.
    BlindRedeem {
        /// The tier's public key, DER.
        #[arg(long)]
        public: PathBuf,

        /// The state written by blind-request.
        #[arg(long)]
        state: PathBuf,

        /// The issuer's blind signature, base64url.
        #[arg(long)]
        signature: String,
    },
}

/// Shared server state.
///
/// One lock over the whole store. Collection is destructive and must be atomic
/// against a concurrent deposit under the same tag, and finer grained locking
/// would buy throughput this server does not need at the cost of a race that
/// loses messages.
/// Decrements the open-connection count however the connection ends.
struct OpenGuard(Arc<Server>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0
            .counters
            .connections_open
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Totals, and nothing that could be joined to a person.
#[derive(Debug, Default)]
struct Counters {
    /// Whether the landing page shows any of this at all.
    show: bool,
    connections_open: AtomicU64,
    connections_total: AtomicU64,
    deposits: AtomicU64,
    delivered: AtomicU64,
    expired: AtomicU64,
    refused: AtomicU64,
}

struct Server {
    mailbox: Mutex<Mailbox>,

    /// Announces that a tag has something waiting.
    ///
    /// Only the tag travels, never the envelope. Subscribers wake and collect
    /// from the store, so the store stays the single source of truth and two
    /// listeners on one tag cannot both be handed the same message.
    ///
    /// The connection that deposited travels with it so it can skip its own
    /// wake. Without that, a client subscribed to a tag it also deposits under
    /// races to collect its own message, and because collection removes, it
    /// wins sometimes and the real recipient never sees it. Both sides of a
    /// conversation share one tag, so this is the normal case, not an edge one.
    wake: broadcast::Sender<Wake>,

    /// Hands out connection ids. Never leaves the process and identifies a
    /// socket, not a person.
    next_connection: AtomicU64,

    /// How often to ping an idle connection. A field rather than a constant so
    /// a test can drive it in milliseconds instead of waiting half a minute.
    keepalive: Duration,

    /// Devices to wake on the schedule. Tokens and nothing else: see
    /// [`crate::wake`] for why there is no tag beside them.
    wake_registry: Mutex<wake::Registry>,

    /// The Apple connection. `None` when the server was started without a
    /// `.p8` key, in which case `registerWake` is refused with a reason rather
    /// than accepted and silently never acted on. A device that believes it
    /// will be woken and is not is worse than one that knows it will not be.
    apns: Option<Arc<wake::Apns>>,

    /// How often a registered device is woken.
    wake_every: Duration,

    /// Where the registry is snapshotted, and under which passphrase. `None`
    /// keeps it in memory, which means every device stops being woken after a
    /// restart until it next connects, and a device that is asleep cannot
    /// connect. That circularity is why persistence is not optional in
    /// practice, and it is still a flag because an operator may prefer to hold
    /// nothing at rest.
    wake_state: Option<(PathBuf, Zeroizing<String>)>,

    /// Checks capability tokens. `None` when the server was started without an
    /// issuer key, in which case everyone is on the free tier and no token is
    /// accepted at all. Refusing tokens outright is safer than ignoring them:
    /// a misconfigured server that silently downgrades paying clients looks
    /// exactly like one that is working.
    tokens: Option<Verifier>,

    /// Verifies blindly issued tokens. Empty when no blind key was configured.
    blind: rotelyx_capability::blind::BlindVerifier,

    /// Consumption per token. Holds a random id and a byte count, nothing else.
    meter: Mutex<Meter>,

    /// Aggregate counters, for the operator's own page.
    ///
    /// # What these are and are not
    ///
    /// Totals. Never a tag, never an address, never an identity, and never a
    /// breakdown that could be joined against one. A count of envelopes stored
    /// says nothing about who stored them; a list of tags would say everything.
    ///
    /// They are off unless `--stats` is passed, because even a total is a
    /// measurement of a community: somebody polling "envelopes delivered" every
    /// minute learns when a group is awake, how many people are in it, and when
    /// something happened, without ever reading a byte. That is precisely the
    /// tracking this project exists to prevent, so it is opt-in and meant to be
    /// switched off before anybody but the operator can reach the page.
    counters: Counters,

    /// Where the meter is snapshotted. `None` keeps it in memory only, which
    /// means every restart hands out a fresh allowance.
    meter_state: Option<PathBuf>,

    /// Where undelivered envelopes are kept, and the key they are sealed
    /// under. `None` keeps them in memory only.
    mailbox_state: Option<(PathBuf, Zeroizing<String>)>,
}

impl Server {
    /// Write the meter out, if a path was configured.
    ///
    /// Logged rather than propagated: a snapshot that cannot be written is
    /// worth an operator's attention and is not a reason to stop serving.
    /// Write the undelivered envelopes out, sealed.
    async fn save_mailbox(&self) {
        let Some((path, passphrase)) = self.mailbox_state.as_ref() else {
            return;
        };

        let entries = self.mailbox.lock().await.snapshot();
        let encoded = match postcard::to_allocvec(&entries) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "could not encode the mailbox");
                return;
            }
        };

        if let Err(e) = vault::Vault::seal(passphrase, path, &encoded) {
            warn!(error = %e, path = %path.display(), "could not write the mailbox");
        }
    }

    /// Write the wake registry out, under the same key as the mailbox.
    ///
    /// Logged rather than propagated, like the mailbox snapshot beside it: a
    /// registry that cannot be written is a device that will not be woken after
    /// the next restart, which is a degradation and not a reason to refuse the
    /// registration that is already in memory and already working.
    async fn save_wake(&self) {
        let Some((path, passphrase)) = self.wake_state.as_ref() else {
            return;
        };
        let registry = self.wake_registry.lock().await;
        if let Err(e) = wake::save_to(path, passphrase, &registry) {
            warn!(error = %e, path = %path.display(), "could not write the wake registry");
        }
    }

    async fn save_meter(&self) {
        let Some(path) = self.meter_state.as_deref() else {
            return;
        };
        if let Err(e) = self.meter.lock().await.save(path) {
            warn!(error = %e, path = %path.display(), "could not write the meter snapshot");
        }
    }
}

#[derive(Clone, Copy)]
struct Wake {
    tag: Tag,
    from: u64,
}

/// Report the tier in force and what is left of its allowance.
async fn tier_reply(cap: &Capability, server: &Arc<Server>) -> Reply {
    let remaining = match server
        .meter
        .lock()
        .await
        .charge(cap, 0, now_seconds() / 3600)
    {
        Charge::Allowed { remaining } => remaining,
        Charge::OverQuota { .. } => 0,
    };

    Reply::Tier {
        tier: cap.tier.name(),
        max_fanout: cap.limits.max_fanout,
        max_payload: cap.limits.max_payload,
        retention_days: cap.limits.ttl_seconds / 86_400,
        bytes_remaining: remaining,
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

/// Sent by the client.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    /// Ask for everything waiting under these tags, and for anything that
    /// arrives under them while the connection lives.
    Subscribe { tags: Vec<String> },

    /// Stop listening on these tags.
    ///
    /// Needed because collection removes. A client still listening on a tag it
    /// has finished with silently eats envelopes meant for whoever is still
    /// using it, and the sender has no way to tell.
    Unsubscribe { tags: Vec<String> },

    /// Leave an envelope. No tag field: the tag is inside the envelope, so
    /// there is nothing for a client to get wrong and nothing for the server to
    /// cross-check.
    Deposit { envelope: String },

    /// Present a capability token.
    ///
    /// Optional. A connection that never sends one stays on the free tier and
    /// works, which is what keeps the mailbox usable without an account.
    Auth { token: String },

    /// Present a blindly issued token.
    ///
    /// Separate from `auth` because the two are different credentials with
    /// different verification, and guessing which one arrived would mean trying
    /// both and reporting whichever error was less confusing.
    #[serde(rename = "authblind")]
    AuthBlind { token: String },

    /// Ask to be woken on the schedule.
    ///
    /// No tag field, and the absence is the design rather than an oversight.
    /// Binding a wake to a tag would put a stable device identifier beside a
    /// tag that rotates hourly, and this server could then follow the token
    /// across every rotation and re-link the sequence the rotation exists to
    /// separate. See [`crate::wake`].
    #[serde(rename = "registerWake")]
    RegisterWake {
        token: String,
        kind: String,
        /// What a later revocation must present. A token is an address, not a
        /// credential: without this, anybody who learned a token could silence
        /// that phone. See [`crate::wake::Device::revoke_hash`].
        #[serde(default)]
        secret: String,
    },

    /// Stop being woken.
    ///
    /// Carries the secret and **not** the token, which is one fewer place a
    /// device token travels and makes the credential the only thing that can
    /// act.
    #[serde(rename = "revokeWake")]
    RevokeWake { secret: String },

    /// Leave the same payload for many recipients at once.
    ///
    /// # What this changes, stated plainly
    ///
    /// Without it a sender uploads one envelope per recipient, and a group of
    /// two hundred costs two hundred uploads. With it the sender uploads once
    /// and the server makes the copies.
    ///
    /// The cost is that the group becomes **explicit**. Before, the operator
    /// saw a burst of deposits and had to correlate them with who subscribes to
    /// what; now the recipient set arrives written down in a single request.
    /// The operator could already reach the same conclusion, since it sees
    /// which connection listens on which tag, so this makes an existing
    /// inference cheap rather than creating a new one. It is still a real
    /// reduction, and it is the price of groups larger than a few dozen.
    ///
    /// `payload` must already be padded to a bucket by the sender. The server
    /// never sees an unpadded length.
    Fanout { tags: Vec<String>, payload: String },
}

/// Sent by the server.
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Reply {
    /// The subscription is active. `waiting` is how many envelopes were already
    /// held under those tags and are being delivered now.
    Ready { waiting: usize },

    /// One envelope, base64. Its tag is inside it.
    Envelope { envelope: String },

    /// The deposit was stored.
    Stored,

    /// The tags are no longer being listened on. `listening` is how many
    /// remain.
    Dropped { listening: usize },

    /// A fan-out finished. `stored` is below `asked` when a recipient's slot
    /// was full; reported rather than hidden, because a silently dropped
    /// recipient looks exactly like a person who stopped replying.
    #[serde(rename = "fannedout")]
    FannedOut { stored: usize, asked: usize },

    /// This device will be woken, and how often.
    ///
    /// The interval is reported rather than assumed so a client can tell its
    /// user the real number. A messenger that says "instant" and delivers in
    /// five minutes has lied about the one thing the user can check.
    #[serde(rename = "wakeRegistered")]
    WakeRegistered {
        #[serde(rename = "everySeconds")]
        every_seconds: u64,
    },

    /// The tier now in force, and what it allows. Sent after `auth` and
    /// whenever a limit refuses something, so a client can say why rather than
    /// appearing broken.
    Tier {
        tier: &'static str,
        #[serde(rename = "maxFanout")]
        max_fanout: usize,
        #[serde(rename = "maxPayload")]
        max_payload: usize,
        #[serde(rename = "retentionDays")]
        retention_days: u64,
        #[serde(rename = "bytesRemaining")]
        bytes_remaining: u64,
    },

    /// The period's allowance is spent.
    #[serde(rename = "overquota")]
    OverQuota { limit: u64, used: u64, tier: &'static str },

    /// Something was wrong with the request. The connection stays open: a
    /// malformed frame is a client bug, not grounds to drop a conversation.
    Error { message: String },
}

impl Reply {
    fn into_message(self) -> Message {
        // Serialising these cannot fail: every variant is a struct of owned
        // strings and integers.
        Message::Text(serde_json::to_string(&self).unwrap_or_default().into())
    }
}

fn parse_tag(hex: &str) -> Option<Tag> {
    if hex.len() != 64 {
        return None;
    }
    let bytes: Result<Vec<u8>, _> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    Tag::from_bytes(&bytes.ok()?).ok()
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

async fn handle_socket(mut socket: WebSocket, server: Arc<Server>) {
    let keepalive_every = server.keepalive;
    let mut wake = server.wake.subscribe();
    let mut subscribed: HashSet<Tag> = HashSet::new();
    let me = server.next_connection.fetch_add(1, Ordering::Relaxed);
    server.counters.connections_total.fetch_add(1, Ordering::Relaxed);
    server.counters.connections_open.fetch_add(1, Ordering::Relaxed);
    // Decremented on the way out, whichever way out that is: a guard rather
    // than a line at the end, because a socket can leave through an error path
    // and an open count that only ever rises is not a count.
    let _open = OpenGuard(Arc::clone(&server));
    let mut cap = Capability::free();

    let mut keepalive = tokio::time::interval(keepalive_every);
    keepalive.tick().await; // the first tick is immediate

    loop {
        tokio::select! {
            // Keep the connection alive through proxies that cut idle sockets.
            // The browser answers a ping itself, so this costs the client
            // nothing and never reaches the page.
            _ = keepalive.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            }

            // Something arrived under a tag. Collect it, which removes it, so
            // exactly one listener gets it.
            Ok(event) = wake.recv() => {
                // Never hand a client back its own deposit.
                if event.from == me || !subscribed.contains(&event.tag) {
                    continue;
                }
                let envelopes = server.mailbox.lock().await.collect(event.tag, now_seconds());
                server
                    .counters
                    .delivered
                    .fetch_add(envelopes.len() as u64, Ordering::Relaxed);
                for envelope in envelopes {
                    let reply = Reply::Envelope {
                        envelope: BASE64.encode(&envelope.to_bytes()),
                    };
                    if socket.send(reply.into_message()).await.is_err() {
                        return;
                    }
                }
            }

            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { return };

                let text = match message {
                    Message::Text(t) => t,
                    Message::Close(_) => return,
                    // Ping and Pong are handled by axum. Binary frames are not
                    // part of this protocol.
                    _ => continue,
                };

                if text.len() > MAX_FRAME_BYTES {
                    let _ = socket.send(Reply::Error {
                        message: "frame too large".into(),
                    }.into_message()).await;
                    continue;
                }

                let reply = match serde_json::from_str::<Request>(&text) {
                    Ok(request) => {
                        handle_request(request, &server, &mut subscribed, &mut socket, me, &mut cap)
                            .await
                    }
                    Err(e) => Some(Reply::Error {
                        message: format!("malformed request: {e}"),
                    }),
                };

                if let Some(reply) = reply {
                    if socket.send(reply.into_message()).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Returns the reply to send, or `None` when the handler already wrote to the
/// socket itself (the backlog delivery does).
async fn handle_request(
    request: Request,
    server: &Arc<Server>,
    subscribed: &mut HashSet<Tag>,
    socket: &mut WebSocket,
    connection: u64,
    cap: &mut Capability,
) -> Option<Reply> {
    match request {
        Request::Auth { token } => {
            let Some(verifier) = server.tokens.as_ref() else {
                return Some(Reply::Error {
                    message: access::TokenError::NoIssuer.to_string(),
                });
            };

            match verifier.verify(&token, now_seconds() / 3600) {
                Ok(granted) => {
                    debug!(tier = granted.tier.name(), "capability accepted");
                    *cap = granted;
                    Some(tier_reply(cap, server).await)
                }
                Err(e) => Some(Reply::Error {
                    message: e.to_string(),
                }),
            }
        }

        Request::AuthBlind { token } => {
            if server.blind.is_empty() {
                return Some(Reply::Error {
                    message: "this server accepts no blind tokens: it was started without \
                              a blind issuance key"
                        .into(),
                });
            }

            match server.blind.verify(&token) {
                Ok(granted) => {
                    debug!(tier = granted.tier.name(), "blind capability accepted");
                    *cap = granted;
                    Some(tier_reply(cap, server).await)
                }
                Err(e) => Some(Reply::Error {
                    message: e.to_string(),
                }),
            }
        }

        Request::RegisterWake { token, kind, secret } => {
            let Some(_) = server.apns.as_ref() else {
                return Some(Reply::Error {
                    message: "this server cannot wake anyone: it was started without an \
                              APNs key"
                        .into(),
                });
            };

            let device = wake::Device::registering(token, kind, &secret);
            let accepted = server.wake_registry.lock().await.register(device);

            if !accepted {
                // One message for two different refusals: a token this server
                // will not store, and a token already registered under a secret
                // the caller could not produce. Naming which would tell whoever
                // holds a token whether this mailbox has a row for it, and a
                // token is not a secret. The refusal itself still reveals that
                // much, which is recorded on `wake::Registry::register`.
                return Some(Reply::Error {
                    message: "that is not a push token this server will accept".into(),
                });
            }

            server.save_wake().await;
            Some(Reply::WakeRegistered {
                every_seconds: server.wake_every.as_secs(),
            })
        }

        Request::RevokeWake { secret } => {
            // The answer is the same whether or not anything was removed. A
            // reply that distinguished them would turn this into an oracle for
            // testing guessed secrets.
            server.wake_registry.lock().await.revoke(&secret);
            server.save_wake().await;
            Some(Reply::WakeRegistered {
                every_seconds: server.wake_every.as_secs(),
            })
        }

        Request::Subscribe { tags } => {
            if tags.len() > MAX_TAGS_PER_SUBSCRIPTION {
                return Some(Reply::Error {
                    message: format!("at most {MAX_TAGS_PER_SUBSCRIPTION} tags per subscription"),
                });
            }

            let mut parsed = Vec::with_capacity(tags.len());
            for tag in &tags {
                match parse_tag(tag) {
                    Some(t) => parsed.push(t),
                    None => {
                        return Some(Reply::Error {
                            message: "a tag must be 64 hex characters".into(),
                        })
                    }
                }
            }

            subscribed.extend(parsed.iter().copied());

            // Deliver the backlog before reporting ready, so a client that
            // starts sending immediately cannot interleave with it.
            let waiting = server
                .mailbox
                .lock()
                .await
                .collect_many(&parsed, now_seconds());

            let count = waiting.len();
            server
                .counters
                .delivered
                .fetch_add(count as u64, Ordering::Relaxed);
            debug!(tags = parsed.len(), waiting = count, "subscription");

            for envelope in waiting {
                let reply = Reply::Envelope {
                    envelope: BASE64.encode(&envelope.to_bytes()),
                };
                if socket.send(reply.into_message()).await.is_err() {
                    return None;
                }
            }

            Some(Reply::Ready { waiting: count })
        }

        Request::Unsubscribe { tags } => {
            for tag in &tags {
                if let Some(parsed) = parse_tag(tag) {
                    subscribed.remove(&parsed);
                }
            }
            server.counters.deposits.fetch_add(1, Ordering::Relaxed);
            Some(Reply::Dropped {
                listening: subscribed.len(),
            })
        }

        Request::Fanout { tags, payload } => {
            if tags.is_empty() {
                return Some(Reply::Error {
                    message: "a fan-out with no recipients".into(),
                });
            }
            if tags.len() > cap.limits.max_fanout {
                return Some(Reply::Error {
                    message: format!(
                        "the {} tier allows at most {} recipients per fan-out, and {} were named",
                        cap.tier.name(),
                        cap.limits.max_fanout,
                        tags.len()
                    ),
                });
            }

            let mut parsed = Vec::with_capacity(tags.len());
            for tag in &tags {
                match parse_tag(tag) {
                    Some(t) => parsed.push(t),
                    None => {
                        return Some(Reply::Error {
                            message: "a tag must be 64 hex characters".into(),
                        })
                    }
                }
            }

            let bytes = match BASE64.decode(payload.trim().as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    return Some(Reply::Error {
                        message: "payload is not valid base64".into(),
                    })
                }
            };

            // Refuse anything that is not already a bucket. Accepting a short
            // payload and padding it here would mean the true length reached
            // the server, which is the one thing the buckets exist to prevent.
            if rotelyx_mailbox::Bucket::from_size(bytes.len()).is_none() {
                return Some(Reply::Error {
                    message: "payload must already be padded to a bucket size".into(),
                });
            }
            if bytes.len() > cap.limits.max_payload {
                return Some(Reply::Error {
                    message: format!(
                        "the {} tier allows at most {} bytes per envelope",
                        cap.tier.name(),
                        cap.limits.max_payload
                    ),
                });
            }

            // Charge for what actually leaves the server: one copy per
            // recipient. Refused before storing, because a quota checked
            // afterwards is not a quota.
            let cost = (bytes.len() as u64).saturating_mul(parsed.len() as u64);
            if let Charge::OverQuota { limit, used } = server
                .meter
                .lock()
                .await
                .charge(cap, cost, now_seconds() / 3600)
            {
                server.counters.refused.fetch_add(1, Ordering::Relaxed);
                return Some(Reply::OverQuota {
                    limit,
                    used,
                    tier: cap.tier.name(),
                });
            }

            let now = now_seconds();
            let mut stored = 0usize;
            {
                let mut mailbox = server.mailbox.lock().await;
                for tag in &parsed {
                    let envelope = match Envelope::seal(*tag, &bytes) {
                        Ok(e) => e,
                        Err(e) => {
                            return Some(Reply::Error {
                                message: format!("{e}"),
                            })
                        }
                    };
                    // A full slot for one recipient must not lose the message
                    // for all the others.
                    if mailbox
                        .deposit_with(envelope, now, cap.limits.ttl_seconds, cap.limits.max_per_tag)
                        .is_ok()
                    {
                        stored += 1;
                    }
                }
            }

            for tag in &parsed {
                let _ = server.wake.send(Wake {
                    tag: *tag,
                    from: connection,
                });
            }

            server.counters.deposits.fetch_add(1, Ordering::Relaxed);
            Some(Reply::FannedOut {
                stored,
                asked: parsed.len(),
            })
        }

        Request::Deposit { envelope } => {
            let bytes = match BASE64.decode(envelope.trim().as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    return Some(Reply::Error {
                        message: "envelope is not valid base64".into(),
                    })
                }
            };

            let envelope = match Envelope::from_bytes(&bytes) {
                Ok(e) => e,
                Err(e) => {
                    return Some(Reply::Error {
                        message: format!("not a well formed envelope: {e}"),
                    })
                }
            };

            if envelope.payload().len() > cap.limits.max_payload {
                return Some(Reply::Error {
                    message: format!(
                        "the {} tier allows at most {} bytes per envelope",
                        cap.tier.name(),
                        cap.limits.max_payload
                    ),
                });
            }

            if let Charge::OverQuota { limit, used } = server
                .meter
                .lock()
                .await
                .charge(cap, envelope.payload().len() as u64, now_seconds() / 3600)
            {
                server.counters.refused.fetch_add(1, Ordering::Relaxed);
                return Some(Reply::OverQuota {
                    limit,
                    used,
                    tier: cap.tier.name(),
                });
            }

            let tag = envelope.tag();

            if let Err(e) = server.mailbox.lock().await.deposit_with(
                envelope,
                now_seconds(),
                cap.limits.ttl_seconds,
                cap.limits.max_per_tag,
            ) {
                return Some(Reply::Error {
                    message: format!("{e}"),
                });
            }

            // A send error means nobody is subscribed, which is the normal case
            // for a recipient who is offline. The envelope is already stored
            // and will be delivered when they subscribe.
            let _ = server.wake.send(Wake { tag, from: connection });

            server.counters.deposits.fetch_add(1, Ordering::Relaxed);
            Some(Reply::Stored)
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn ws_handler(ws: WebSocketUpgrade, State(server): State<Arc<Server>>) -> Response {
    ws.max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, server))
}

/// Health probe. Deliberately reports nothing about contents: an operator
/// needs to know the process is alive, and a passer-by should learn no more
/// than that.
async fn ping() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// This mailbox's availability, from the same crate the relay uses.
///
/// Shared rather than reimplemented: two status strips whose colours mean
/// subtly different things are worse than one.
static STATUS: rotelyx_status::Status = rotelyx_status::Status::new();

async fn landing(State(server): State<Arc<Server>>) -> impl IntoResponse {
    let recorded = STATUS.recorded_count();
    let history = if recorded > 0 {
        format!(
            "{recorded} half {} recorded",
            if recorded == 1 { "hour" } else { "hours" }
        )
    } else {
        "no history before this process".into()
    };

    let block = format!(
        "<div class=\"status\"><span class=\"dot\"></span><b>Operational</b>\
         <span>up {}</span></div>{}\
         <div class=\"scale\"><span>48h</span><span>now</span></div>{}\
         <p class=\"note\">{}.</p>",
        STATUS.uptime_text(),
        STATUS.strip(),
        rotelyx_status::LEGEND,
        history,
    );

    // Counters only when the operator asked for them. Off by default, because
    // a total is still a measurement of a community: polling "envelopes
    // delivered" every minute says when a group is awake and roughly how large
    // it is, without reading a byte.
    // Counters only when the operator asked for them. Off by default, because
    // a total is still a measurement of a community: polling "envelopes
    // delivered" every minute says when a group is awake and roughly how large
    // it is, without reading a byte.
    //
    // Rendered as a row of stat tiles rather than a bar chart, because these
    // are five headline numbers in four different units. A chart comparing
    // "connections accepted" against "envelopes held" would put incommensurable
    // quantities on one scale, which is the classic way to make a graph that
    // looks informative and means nothing.
    //
    // And with no explanatory note. The first version carried one saying the
    // stats were on because a debug flag had been passed, which announces to a
    // visitor that the operator left something switched on.
    let counters = if server.counters.show {
        let c = &server.counters;
        let stored = server.mailbox.lock().await.len();
        let tile = |label: &str, value: u64| {
            format!("<div class=\"tile\"><b>{value}</b><span>{label}</span></div>")
        };
        format!(
            "<div class=\"tiles\">{}{}{}{}{}{}{}</div>",
            tile("Open", c.connections_open.load(Ordering::Relaxed)),
            tile("Accepted", c.connections_total.load(Ordering::Relaxed)),
            tile("Deposits", c.deposits.load(Ordering::Relaxed)),
            tile("Delivered", c.delivered.load(Ordering::Relaxed)),
            tile("Held", stored as u64),
            tile("Expired", c.expired.load(Ordering::Relaxed)),
            tile("Refused", c.refused.load(Ordering::Relaxed)),
        )
    } else {
        String::new()
    };

    let page = include_str!("landing.html")
        .replace("/*STATUS-STYLE*/", rotelyx_status::STYLE)
        .replace("<!--STATUS-->", &block)
        .replace("<!--COUNTERS-->", &counters);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                // `img-src data:` permits only bytes already inside this
                // response, which is where the mark and the favicon live.
                // Nothing may be fetched from anywhere, which is the property
                // that matters for a server that must not phone out.
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
                 frame-ancestors 'none'; form-action 'none'; base-uri 'self'",
            ),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // A status page a proxy caches is a status page that lies.
            (header::CACHE_CONTROL, "no-store"),
        ],
        page,
    )
}

/// Build the router and its state.
///
/// Separate from `main` so tests can bind an ephemeral port and drive the real
/// server over a real socket, rather than testing a reimplementation of it.
#[cfg(test)]
fn router(ttl_seconds: u64, keepalive: Duration) -> Router {
    router_with(ttl_seconds, keepalive, None)
}

#[cfg(test)]
fn router_with(ttl_seconds: u64, keepalive: Duration, tokens: Option<Verifier>) -> Router {
    router_full(ttl_seconds, keepalive, tokens, Meter::default(), None).0
}

#[cfg(test)]
fn router_full(
    ttl_seconds: u64,
    keepalive: Duration,
    tokens: Option<Verifier>,
    meter: Meter,
    meter_state: Option<PathBuf>,
) -> (Router, Arc<Server>) {
    router_stateful(
        ttl_seconds,
        keepalive,
        tokens,
        meter,
        meter_state,
        Mailbox::new(ttl_seconds),
        None,
        rotelyx_capability::blind::BlindVerifier::new(),
        // Tests do not need the counters, and leaving them off here means a
        // test never accidentally asserts on a page that production hides.
        false,
        Waking::default(),
    )
}

#[allow(clippy::too_many_arguments)]
/// Everything the wake schedule needs, bundled so `router_stateful` does not
/// grow four more positional parameters that are easy to pass in the wrong
/// order.
struct Waking {
    registry: wake::Registry,
    apns: Option<Arc<wake::Apns>>,
    every: Duration,
    state: Option<(PathBuf, Zeroizing<String>)>,
}

impl Default for Waking {
    /// No Apple key, so nothing is woken and `registerWake` says so.
    fn default() -> Self {
        Self {
            registry: wake::Registry::new(),
            apns: None,
            every: Duration::from_secs(wake::WAKE_EVERY_DEFAULT),
            state: None,
        }
    }
}

fn router_stateful(
    ttl_seconds: u64,
    keepalive: Duration,
    tokens: Option<Verifier>,
    meter: Meter,
    meter_state: Option<PathBuf>,
    mailbox: Mailbox,
    mailbox_state: Option<(PathBuf, Zeroizing<String>)>,
    blind: rotelyx_capability::blind::BlindVerifier,
    stats: bool,
    waking: Waking,
) -> (Router, Arc<Server>) {
    let _ = ttl_seconds;
    let (wake, _) = broadcast::channel(1024);
    let server = Arc::new(Server {
        mailbox: Mutex::new(mailbox),
        wake,
        next_connection: AtomicU64::new(0),
        keepalive,
        wake_registry: Mutex::new(waking.registry),
        apns: waking.apns,
        wake_every: waking.every,
        wake_state: waking.state,
        tokens,
        meter: Mutex::new(meter),
        meter_state,
        mailbox_state,
        blind,
        counters: Counters {
            show: stats,
            ..Default::default()
        },
    });

    // Reclaim memory from envelopes nobody collected.
    let sweeper = Arc::clone(&server);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let dropped = sweeper.mailbox.lock().await.sweep(now_seconds());
            sweeper
                .counters
                .expired
                .fetch_add(dropped as u64, Ordering::Relaxed);
            let forgotten = sweeper.meter.lock().await.sweep(now_seconds() / 3600);
            if dropped > 0 || forgotten > 0 {
                debug!(dropped, forgotten, "swept");
            }
            sweeper.save_meter().await;
            sweeper.save_mailbox().await;
        }
    });

    // Wake every registered device, on a fixed schedule and regardless of
    // whether anything arrived for it.
    //
    // The schedule is the privacy property, not a simplification. Waking on
    // arrival would mean this server knows which device to wake for which tag,
    // and would mean Apple learns the timing of every conversation. A fixed
    // rhythm identical for every device carries neither. See `wake.rs`.
    if let Some(apns) = server.apns.clone() {
        let waker = Arc::clone(&server);
        let every = server.wake_every;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            // The first tick fires immediately, which would wake every device
            // at startup for no reason and would make a restart visible to
            // Apple as a burst.
            ticker.tick().await;
            loop {
                ticker.tick().await;

                let devices = waker.wake_registry.lock().await.all();
                if devices.is_empty() {
                    continue;
                }

                let dead = wake::sweep(&apns, &devices).await;
                if dead.is_empty() {
                    continue;
                }

                // Apple said these are gone: uninstalled, or the device was
                // restored. Kept, they would be called forever, and Apple
                // counts that against the sender.
                let mut registry = waker.wake_registry.lock().await;
                for token in &dead {
                    registry.revoke(token);
                }
                drop(registry);
                info!(gone = dead.len(), "forgot devices Apple says no longer exist");
                waker.save_wake().await;
            }
        });
    }

    let router = Router::new()
        .route("/", get(landing))
        .route("/ping", get(ping))
        .route("/mailbox", get(ws_handler))
        .with_state(Arc::clone(&server));

    (router, server)
}

/// Client side: blind an id and keep the state until the signature returns.
fn blind_request(public: &Path, state: &Path) -> Result<()> {
    let der = std::fs::read(public).with_context(|| format!("reading {}", public.display()))?;
    let (redeemer, blinded) = rotelyx_capability::blind::Redeemer::begin(&der)?;

    std::fs::write(state, redeemer.to_bytes())
        .with_context(|| format!("writing {}", state.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("{blinded}");
    eprintln!();
    eprintln!("Send that to the issuer once payment clears. Keep {} until the", state.display());
    eprintln!("signature comes back: whoever holds it can finish the token.");
    Ok(())
}

/// Client side: unblind into a usable token.
fn blind_redeem(public: &Path, state: &Path, signature: &str) -> Result<()> {
    let der = std::fs::read(public).with_context(|| format!("reading {}", public.display()))?;
    let saved = std::fs::read(state).with_context(|| format!("reading {}", state.display()))?;

    let redeemer = rotelyx_capability::blind::Redeemer::from_bytes(&saved)?;
    let token = redeemer.finish(&der, signature)?;

    // The state is spent. Leaving it lying around is a second copy of
    // something that was only ever needed once.
    let _ = std::fs::remove_file(state);

    println!("{token}");
    Ok(())
}



#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx_mailbox_server=info".into()),
        )
        .init();

    let args = Args::parse();

    match args.command {
        Some(Command::BlindRequest { public, state }) => return blind_request(&public, &state),
        Some(Command::BlindRedeem { public, state, signature }) => {
            return blind_redeem(&public, &state, &signature)
        }
        None => {}
    }

    STATUS.started_now();
    if let Some(path) = args.status.clone() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        info!(path = %path.display(), "recording availability");
        STATUS.record_at(path);

        // Every minute rather than every half hour: a mailbox that dies four
        // minutes into a bucket has still served it, and recording only on the
        // boundary loses up to thirty minutes of history per restart.
        tokio::spawn(async {
            loop {
                STATUS.heartbeat();
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }

    let tokens = match args.issuer.as_deref() {
        Some(hex) => Some(
            Verifier::from_public_hex(hex)
                .context("--issuer must be a 64 character hex public key")?,
        ),
        None => {
            warn!("no --issuer key: every client is on the free tier and tokens are refused");
            None
        }
    };

    let meter = match args.meter_state.as_deref() {
        Some(path) => {
            let loaded = Meter::load(path, now_seconds() / 3600)
                .with_context(|| format!("reading the meter snapshot at {}", path.display()))?;
            info!(path = %path.display(), "meter restored");
            loaded
        }
        None => {
            warn!("no --meter-state: every restart hands each token a fresh allowance");
            Meter::default()
        }
    };

    // The passphrase arrives in the environment rather than on the command
    // line: an argument is visible in `ps` to every user on the machine.
    let mailbox_state = match args.mailbox_state.as_ref() {
        Some(path) => {
            let passphrase = Zeroizing::new(
                std::env::var("ROTELYX_MAILBOX_PASSPHRASE").context(
                    "--mailbox-state needs ROTELYX_MAILBOX_PASSPHRASE. Persisting \
                     undelivered envelopes in the clear would hand a seized disk the \
                     routing metadata the whole design exists to hide",
                )?,
            );
            Some((path.clone(), passphrase))
        }
        None => {
            warn!("no --mailbox-state: a restart drops every uncollected envelope");
            None
        }
    };

    let mailbox = match mailbox_state.as_ref() {
        Some((path, passphrase)) => match vault::Vault::open(passphrase, path)? {
            Some(bytes) => {
                let entries: Vec<(rotelyx_mailbox::Tag, Vec<u8>)> =
                    postcard::from_bytes(&bytes).context("decoding the mailbox snapshot")?;
                let restored = Mailbox::restore(args.ttl, entries, now_seconds());
                info!(path = %path.display(), held = restored.len(), "mailbox restored");
                restored
            }
            None => Mailbox::new(args.ttl),
        },
        None => Mailbox::new(args.ttl),
    };

    let mut blind_verifier = rotelyx_capability::blind::BlindVerifier::new();
    // Highest tier first, so the common paid case verifies in one operation.
    // A token verifies under exactly one key regardless of order.
    for (tier, path) in [
        (Tier::PlusPlus, args.blind_plusplus.as_deref()),
        (Tier::Plus, args.blind_plus.as_deref()),
    ] {
        let Some(path) = path else { continue };
        let der = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        blind_verifier = blind_verifier.with_tier(tier, &der)?;
        info!(tier = tier.name(), path = %path.display(), "blind key loaded");
    }

    // Apple, or nobody.
    //
    // All four pieces or none: a key without a team id produces a token Apple
    // rejects with `InvalidProviderToken`, and finding that out from a phone
    // that quietly stops receiving is far worse than finding it out here.
    let apns = match (
        args.apns_key.as_ref(),
        args.apns_key_id.as_ref(),
        args.apns_team_id.as_ref(),
    ) {
        (Some(path), Some(key_id), Some(team_id)) => {
            let pem = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?,
            );
            let apns = wake::Apns::new(
                &pem,
                key_id.clone(),
                team_id.clone(),
                args.apns_topic.clone(),
                args.apns_sandbox,
            )?;
            info!(
                topic = %args.apns_topic,
                sandbox = args.apns_sandbox,
                every_seconds = args.wake_every,
                "waking iPhones on a schedule, through Apple and nobody else"
            );
            Some(Arc::new(apns))
        }
        (None, None, None) => {
            info!("no APNs key: iPhones receive when the application is opened");
            None
        }
        _ => bail!(
            "--apns-key, --apns-key-id and --apns-team-id are all needed together. \
             A partial configuration produces a token Apple rejects, and the first \
             sign of it is a phone that quietly stops receiving"
        ),
    };

    // The registry rides on the mailbox passphrase. A separate one would be a
    // second secret to hold for a file that lives beside the first.
    let wake_state = match (args.wake_state.as_ref(), mailbox_state.as_ref()) {
        (Some(path), Some((_, passphrase))) => Some((path.clone(), passphrase.clone())),
        (Some(_), None) => bail!(
            "--wake-state needs --mailbox-state and its passphrase. A list of push \
             tokens is the closest thing this server holds to a list of its users, \
             and it is not written in the clear"
        ),
        (None, _) => {
            if apns.is_some() {
                warn!(
                    "no --wake-state: after a restart no device is woken until it next \
                     connects, and a sleeping device cannot connect"
                );
            }
            None
        }
    };

    let registry = match wake_state.as_ref() {
        Some((path, passphrase)) => {
            let restored = wake::restore_from(path, passphrase)?;
            if !restored.is_empty() {
                info!(devices = restored.len(), "wake registry restored");
            }
            restored
        }
        None => wake::Registry::new(),
    };

    let waking = Waking {
        registry,
        apns,
        every: Duration::from_secs(args.wake_every.max(60)),
        state: wake_state,
    };

    let (app, server) = router_stateful(
        args.ttl,
        KEEPALIVE,
        tokens,
        meter,
        args.meter_state.clone(),
        mailbox,
        mailbox_state,
        blind_verifier,
        args.stats,
        waking,
    );

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("cannot bind {}", args.bind))?;

    info!(bind = %args.bind, ttl_seconds = args.ttl, "blind mailbox listening");
    warn!("this server sees tags and connection addresses. It cannot see content");

    // The meter is snapshotted on the sweep timer, so a hard kill loses at most
    // one interval of spending. A signalled shutdown writes it out below and
    // loses nothing.
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutting down");
        })
        .await
        .context("serving")?;

    server.save_meter().await;
    server.save_mailbox().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    type Client = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Read one frame as text.
    ///
    /// Written out rather than calling `.next()` inline because both
    /// `futures_lite` and `futures_util` are in scope in this crate and their
    /// `StreamExt` traits collide.
    async fn recv(client: &mut Client) -> String {
        loop {
            let frame = futures_util::StreamExt::next(client)
                .await
                .expect("a frame")
                .expect("a valid frame");

            // Skip control frames. The server pings idle connections, and a
            // ping decodes to an empty string, which fails JSON parsing with an
            // error that says nothing about what actually happened.
            match frame {
                WsMessage::Text(text) => return text.to_string(),
                WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    }

    /// Read one frame and parse it as JSON.
    async fn recv_json(client: &mut Client) -> serde_json::Value {
        serde_json::from_str(&recv(client).await).expect("valid json")
    }

    /// `recv_json` with a deadline, so a step that never completes names
    /// itself instead of hanging the whole suite.
    async fn recv_step(client: &mut Client, step: &str) -> serde_json::Value {
        match tokio::time::timeout(Duration::from_secs(3), recv(client)).await {
            Ok(text) => serde_json::from_str(&text).expect("valid json"),
            Err(_) => panic!("stalled waiting at step: {step}"),
        }
    }

    /// Start the real server on an ephemeral port and return its URL.
    /// A server with counters on, and a handle to read them.
    async fn spawn_counting_server() -> (String, Arc<Server>) {
        let (app, server) = router_stateful(
            DEFAULT_TTL_SECONDS,
            KEEPALIVE,
            None,
            Meter::default(),
            None,
            Mailbox::new(DEFAULT_TTL_SECONDS),
            None,
            rotelyx_capability::blind::BlindVerifier::new(),
            true,
            Waking::default(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("ws://{addr}/mailbox"), server)
    }

    /// A server that can wake, without an Apple key to do it with.
    ///
    /// The registry and the frames are exercised; the call to Apple is not, and
    /// deliberately: a test that reaches api.push.apple.com is a test that
    /// fails on a train.
    async fn spawn_waking_server() -> (String, Arc<Server>) {
        let (app, server) = router_stateful(
            DEFAULT_TTL_SECONDS,
            KEEPALIVE,
            None,
            Meter::default(),
            None,
            Mailbox::new(DEFAULT_TTL_SECONDS),
            None,
            rotelyx_capability::blind::BlindVerifier::new(),
            false,
            Waking {
                registry: wake::Registry::new(),
                // A key that is not Apple's. Enough to make the server say yes
                // to a registration, which is what is under test.
                apns: Some(Arc::new(
                    wake::Apns::new(TEST_P8, "K".repeat(10), "T".repeat(10), "x".into(), true)
                        .expect("a test key"),
                )),
                every: Duration::from_secs(300),
                state: None,
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("ws://{addr}/mailbox"), server)
    }

    /// A P-256 key in PKCS#8 PEM, the shape a `.p8` from Apple has. Generated
    /// for this test and valid for nothing.
    const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----";

    /// Registering says how often, and says nothing about any conversation.
    #[tokio::test]
    async fn a_device_registers_for_a_schedule() {
        let (url, server) = spawn_waking_server().await;
        let mut client = connect(&url).await;

        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake",
                    "token": "ab".repeat(32),
                    "kind": "apns",
                    "secret": "a-secret",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");

        let reply = recv_step(&mut client, "registerWake").await;
        assert_eq!(reply["op"], "wakeRegistered");
        assert_eq!(reply["everySeconds"], 300);

        assert_eq!(server.wake_registry.lock().await.len(), 1);
    }

    /// The property that matters is an absence: the server holds a token and
    /// nothing that says which conversation it belongs to.
    #[tokio::test]
    async fn what_is_stored_says_nothing_about_conversations() {
        let (url, server) = spawn_waking_server().await;
        let mut client = connect(&url).await;

        let tag = Tag::from_bytes(&[7u8; 32]).expect("tag");
        client
            .send(WsMessage::text(
                serde_json::json!({"op": "subscribe", "tags": [tag_hex(&tag)]}).to_string(),
            ))
            .await
            .expect("subscribe");
        recv_step(&mut client, "ready").await;

        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake",
                    "token": "cd".repeat(32),
                    "kind": "apns",
                    "secret": "a-secret",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");
        recv_step(&mut client, "wakeRegistered").await;

        // The same connection both subscribed to a tag and registered a token,
        // which is the situation an operator could exploit if the two were
        // recorded together. They are not: the registry holds the token and
        // has no field to put the tag in.
        let stored = server.wake_registry.lock().await.all();
        assert_eq!(stored.len(), 1);
        let json = serde_json::to_value(&stored[0]).expect("json");
        assert_eq!(json.as_object().expect("object").len(), 3);
        assert!(json.get("tag").is_none());
    }

    /// The takeover, attempted the way an attacker would: over the wire.
    ///
    /// Requiring a secret to revoke achieved nothing on its own, because
    /// registration replaced any row with a matching token without asking for
    /// anything. So the attack ran in two steps instead of one: register the
    /// victim's token with a secret of your own, then revoke it. This is the
    /// end to end check that the second step can no longer be reached, because
    /// the first is refused.
    #[tokio::test]
    async fn a_stolen_token_cannot_take_over_a_registration_over_the_wire() {
        let (url, server) = spawn_waking_server().await;
        let token = "ab".repeat(32);

        let mut owner = connect(&url).await;
        owner
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake", "token": token, "kind": "apns",
                    "secret": "the-owners-secret",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");
        assert_eq!(recv_step(&mut owner, "wakeRegistered").await["op"], "wakeRegistered");

        // An attacker who has learned the token, and nothing else.
        let mut attacker = connect(&url).await;
        attacker
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake", "token": token, "kind": "apns",
                    "secret": "the-attackers-secret",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");
        let reply = recv_step(&mut attacker, "registerWake").await;
        assert_eq!(reply["op"], "error", "the takeover was accepted: {reply}");

        attacker
            .send(WsMessage::text(
                serde_json::json!({"op": "revokeWake", "secret": "the-attackers-secret"})
                    .to_string(),
            ))
            .await
            .expect("revokeWake");
        recv_step(&mut attacker, "wakeRegistered").await;

        assert_eq!(
            server.wake_registry.lock().await.len(),
            1,
            "the device was silenced by somebody who only had its token"
        );
    }

    /// The owner can still revoke, which is the half a takeover also destroys.
    #[tokio::test]
    async fn the_owner_can_still_revoke_their_own_device() {
        let (url, server) = spawn_waking_server().await;
        let mut client = connect(&url).await;

        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake", "token": "ef".repeat(32), "kind": "apns",
                    "secret": "mine",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");
        recv_step(&mut client, "wakeRegistered").await;

        client
            .send(WsMessage::text(
                serde_json::json!({"op": "revokeWake", "secret": "mine"}).to_string(),
            ))
            .await
            .expect("revokeWake");
        recv_step(&mut client, "wakeRegistered").await;

        assert_eq!(server.wake_registry.lock().await.len(), 0);
    }

    /// A server with no Apple key refuses rather than accepting quietly.
    #[tokio::test]
    async fn a_server_that_cannot_wake_says_so() {
        // A device told it is registered, on a server that will never call
        // Apple, is a phone that silently stops receiving. Refusing is the only
        // answer that lets the client tell its user the truth.
        let url = spawn_server().await;
        let mut client = connect(&url).await;

        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake",
                    "token": "ab".repeat(32),
                    "kind": "apns",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");

        let reply = recv_step(&mut client, "registerWake").await;
        assert_eq!(reply["op"], "error");
        assert!(reply["message"]
            .as_str()
            .expect("a message")
            .contains("cannot wake anyone"));
    }

    /// A token that is not one is refused.
    #[tokio::test]
    async fn a_token_that_is_not_one_is_refused() {
        let (url, server) = spawn_waking_server().await;
        let mut client = connect(&url).await;

        // A slash would address a different path on Apple's server.
        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "registerWake",
                    "token": format!("{}/x", "ab".repeat(32)),
                    "kind": "apns",
                })
                .to_string(),
            ))
            .await
            .expect("registerWake");

        let reply = recv_step(&mut client, "registerWake").await;
        assert_eq!(reply["op"], "error");
        assert!(server.wake_registry.lock().await.is_empty());
    }

    /// Revoking removes it.
    #[tokio::test]
    async fn revoking_stops_the_waking() {
        let (url, server) = spawn_waking_server().await;
        let mut client = connect(&url).await;

        for frame in [
            serde_json::json!({
                "op": "registerWake",
                "token": "ab".repeat(32),
                "kind": "apns",
                "secret": "only-this-phone-knows-this",
            }),
            // Naming the token is not enough, and that is the point: a stranger
            // who learned it could otherwise silence this phone.
            serde_json::json!({"op": "revokeWake", "secret": "ab".repeat(32)}),
        ] {
            client
                .send(WsMessage::text(frame.to_string()))
                .await
                .expect("frame");
            recv_step(&mut client, "wake").await;
        }

        assert_eq!(
            server.wake_registry.lock().await.len(),
            1,
            "the token must not revoke"
        );

        client
            .send(WsMessage::text(
                serde_json::json!({
                    "op": "revokeWake",
                    "secret": "only-this-phone-knows-this",
                })
                .to_string(),
            ))
            .await
            .expect("revokeWake");
        recv_step(&mut client, "revokeWake").await;

        assert!(
            server.wake_registry.lock().await.is_empty(),
            "a token the server still holds is a device it still wakes"
        );
    }

    /// One GET, by hand.
    ///
    /// A HTTP client crate for a single request in a single test is a
    /// dependency that outlives the reason for it.
    async fn fetch(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = url.trim_start_matches("http://").trim_end_matches('/');
        let mut socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut out = Vec::new();
        socket.read_to_end(&mut out).await.expect("read");
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The counters must count, and must stay off unless asked for.
    ///
    /// Both halves matter. A counter that never moves is decoration, and a
    /// counter that appears without `--stats` is exactly the leak the flag
    /// exists to prevent.
    #[tokio::test]
    async fn counters_count_and_stay_off_by_default() {
        let (url, server) = spawn_counting_server().await;
        let page_url = url.replace("ws://", "http://").replace("/mailbox", "/");

        assert_eq!(server.counters.deposits.load(Ordering::Relaxed), 0);

        let tag = Tag::from_bytes(&[0x33; 32]).expect("tag");
        let mut client = connect(&url).await;
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": [tag_hex(&tag)]})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("subscribe");
        recv_json(&mut client).await;

        let envelope = Envelope::seal(tag, b"a plausible ciphertext").expect("seal");
        client
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "deposit",
                    "envelope": BASE64.encode(&envelope.to_bytes())
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("deposit");
        recv_json(&mut client).await;

        assert_eq!(
            server.counters.deposits.load(Ordering::Relaxed),
            1,
            "a deposit must be counted"
        );
        assert!(
            server.counters.connections_total.load(Ordering::Relaxed) >= 1,
            "the connection must be counted"
        );

        let page = fetch(&page_url).await;
        assert!(page.contains("class=\"tiles\""), "with --stats the tiles show");

        // The first version of this page carried a note saying the counters
        // were on because a debug flag had been passed, which tells a visitor
        // the operator left something switched on. Asserted so it cannot come
        // back in a hurry.
        // This page is served to the public. Anything on it addressed to the
        // operator rather than to a visitor is a note left where strangers
        // read it, and the first version carried two: one saying a debug flag
        // had been passed, and a caption claiming the page published
        // availability and nothing else, which stopped being true the moment
        // counters could appear below it.
        for leaked in [
            "not for production",
            "--stats",
            "Availability only",
            "TODO",
            "FIXME",
            "debug",
        ] {
            assert!(
                !page.contains(leaked),
                "the page says `{leaked}`, which is addressed to the operator \
                 or is no longer true"
            );
        }
        assert!(
            !page.contains(&tag_hex(&tag)),
            "no tag may ever appear on the page"
        );

        // And the default server, which is what production runs.
        let plain = spawn_server().await;
        let plain_url = plain.replace("ws://", "http://").replace("/mailbox", "/");
        let page = fetch(&plain_url).await;
        assert!(
            !page.contains("class=\"tiles\""),
            "counters must be absent unless --stats was passed"
        );
    }

    async fn spawn_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = router(DEFAULT_TTL_SECONDS, KEEPALIVE);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("ws://{addr}/mailbox")
    }

    async fn connect(url: &str) -> Client {
        let (socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("websocket connect");
        socket
    }

    fn tag_hex(tag: &Tag) -> String {
        tag.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Two Rotelyx members exchange a real encrypted message through the real
    /// server over a real socket. Nothing here is a stand-in.
    #[tokio::test]
    async fn a_message_crosses_the_mailbox_end_to_end() {
        use rotelyx_crypto::{Conversation, Member};
        use rotelyx_mailbox::TagKey;

        // Two members reach a shared conversation.
        let alice = Member::new(b"alice").expect("identity");
        let bob = Member::new(b"bob").expect("identity");
        let mut a = Conversation::create(&alice).expect("create");
        let kp = bob.key_package().expect("kp");
        let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");

        // Both derive the same tag key at the epoch they share.
        let tags = TagKey::new(a.mailbox_tag_key(&alice).expect("export"));
        let their_tags = TagKey::new(b.mailbox_tag_key(&bob).expect("export"));
        let bucket = 490_000u64;
        let tag = tags.tag_for_epoch(bucket);
        assert_eq!(tag, their_tags.tag_for_epoch(bucket));

        let url = spawn_server().await;

        // Bob subscribes first.
        let mut receiver = connect(&url).await;
        receiver
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": [tag_hex(&tag)]})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("subscribe");

        let ready = recv_json(&mut receiver).await;
        assert_eq!(ready["op"], "ready");
        assert_eq!(ready["waiting"], 0, "nothing should be waiting yet");

        // Alice encrypts, seals and deposits.
        let ciphertext = a.send(&alice, b"hello by way of the mailbox").expect("send");
        let envelope = Envelope::seal(tag, &ciphertext).expect("seal");

        let mut sender = connect(&url).await;
        sender
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "deposit",
                    "envelope": BASE64.encode(&envelope.to_bytes())
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("deposit");

        assert_eq!(recv_json(&mut sender).await["op"], "stored");

        // It reaches Bob without him asking again.
        let value = recv_json(&mut receiver).await;
        assert_eq!(value["op"], "envelope");

        let received = Envelope::from_bytes(
            &BASE64
                .decode(value["envelope"].as_str().expect("string").as_bytes())
                .expect("base64"),
        )
        .expect("envelope");

        assert_eq!(received.tag(), tag, "delivered under the tag asked for");

        let plaintext = b
            .receive(&bob, received.payload())
            .expect("decrypt")
            .expect("application message");
        assert_eq!(plaintext, b"hello by way of the mailbox");
    }

    async fn deposit(client: &mut Client, envelope: String) {
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "deposit", "envelope": envelope})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("deposit");
    }

    async fn client_unsubscribe(client: &mut Client, tags: Vec<String>) {
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "unsubscribe", "tags": tags})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("unsubscribe");
    }

    async fn subscribe(client: &mut Client, tags: Vec<String>) {
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": tags})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("subscribe");
    }

    /// The browser client's whole handshake, run against the real server.
    ///
    /// This is the exact sequence `site/chat.html` performs, in the same
    /// order, through the same protocol. It exists because the ordering
    /// constraints in that flow are not obvious and none of them fail loudly:
    /// a post-quantum secret staged too late, an envelope routed by phase
    /// rather than by tag, or a sender handed back its own deposit all end in
    /// a page that simply shows nothing.
    #[tokio::test]
    async fn the_browser_handshake_completes_over_the_real_server() {
        // Rust keeps the snake_case names; `js_name` only renames what the
        // browser sees. The sequence below is otherwise identical.
        use rotelyx_wasm::{open_under, rendezvous_tag, seal_under, Session};

        let url = spawn_server().await;
        let meeting = rendezvous_tag("see you at the blind mailbox").expect("meeting tag");

        let b64 = |v: &serde_json::Value| BASE64.encode(v.to_string().as_bytes());
        let unb64 = |s: &str| -> serde_json::Value {
            serde_json::from_slice(&BASE64.decode(s.as_bytes()).expect("base64")).expect("json")
        };

        // ---- both sides arrive at the meeting place ----
        let mut host_ws = connect(&url).await;
        let mut guest_ws = connect(&url).await;

        let mut host = Session::new("alice").expect("identity");
        let mut guest = Session::new("bob").expect("identity");

        host.found().expect("found");

        subscribe(&mut host_ws, vec![meeting.clone()]).await;
        assert_eq!(recv_json(&mut host_ws).await["op"], "ready");
        subscribe(&mut guest_ws, vec![meeting.clone()]).await;
        assert_eq!(recv_json(&mut guest_ws).await["op"], "ready");

        // ---- guest knocks ----
        let hello = b64(&serde_json::json!({
            "t": "hello",
            "name": "bob",
            "keyPackage": guest.key_package().expect("kp"),
            "hybridPublicKey": guest.hybrid_public_key(),
        }));
        deposit(&mut guest_ws, seal_under(&meeting, &hello).expect("seal")).await;
        assert_eq!(recv_json(&mut guest_ws).await["op"], "stored");

        // ---- host answers ----
        let pushed = recv_json(&mut host_ws).await;
        assert_eq!(pushed["op"], "envelope", "the host must see the knock");

        let payload = open_under(pushed["envelope"].as_str().expect("string"), &meeting)
            .expect("under the meeting tag");
        let hello = unb64(&payload);
        assert_eq!(hello["t"], "hello");

        let invitation = host
            .invite(hello["keyPackage"].as_str().expect("string"))
            .expect("invite");
        let pq_ciphertext = host
            .encapsulate_to(hello["hybridPublicKey"].as_str().expect("string"))
            .expect("encapsulate");

        let welcome = b64(&serde_json::json!({
            "t": "welcome",
            "name": "alice",
            "welcome": invitation.welcome,
            "ratchetTree": invitation.ratchet_tree,
            "pqCiphertext": pq_ciphertext,
        }));
        deposit(&mut host_ws, seal_under(&meeting, &welcome).expect("seal")).await;
        assert_eq!(recv_json(&mut host_ws).await["op"], "stored");

        let commit = b64(&serde_json::json!({
            "t": "commit",
            "commit": host.commit_pq().expect("commit"),
        }));
        deposit(&mut host_ws, seal_under(&meeting, &commit).expect("seal")).await;
        assert_eq!(recv_json(&mut host_ws).await["op"], "stored");

        // ---- guest joins, stages, then applies the commit ----
        let pushed = recv_json(&mut guest_ws).await;
        assert_eq!(pushed["op"], "envelope");
        let welcome = unb64(
            &open_under(pushed["envelope"].as_str().expect("string"), &meeting).expect("open"),
        );
        assert_eq!(welcome["t"], "welcome");

        guest
            .join(
                welcome["welcome"].as_str().expect("string"),
                welcome["ratchetTree"].as_str().expect("string"),
            )
            .expect("join");
        guest
            .open_pq(welcome["pqCiphertext"].as_str().expect("string"))
            .expect("stage the post-quantum secret");

        let pushed = recv_json(&mut guest_ws).await;
        assert_eq!(pushed["op"], "envelope");
        let commit = unb64(
            &open_under(pushed["envelope"].as_str().expect("string"), &meeting).expect("open"),
        );
        assert_eq!(commit["t"], "commit");

        assert!(
            guest
                .receive(commit["commit"].as_str().expect("string"))
                .expect("apply the commit")
                .is_none(),
            "a commit carries no plaintext"
        );

        // ---- both sides are now in one post-quantum protected conversation ----
        assert_eq!(host.epoch(), guest.epoch(), "same epoch");
        assert_eq!(
            host.safety_number().expect("fingerprint"),
            guest.safety_number().expect("fingerprint"),
            "both sides must read the same number aloud"
        );

        // ---- and messages flow under group derived tags ----
        let slot = 490_000u64;
        subscribe(&mut host_ws, host.polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_json(&mut host_ws).await["op"], "ready");
        subscribe(&mut guest_ws, guest.polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_json(&mut guest_ws).await["op"], "ready");

        let ciphertext = host.send("hello from the browser").expect("send");
        deposit(&mut host_ws, host.seal(&ciphertext, slot).expect("seal")).await;
        assert_eq!(recv_json(&mut host_ws).await["op"], "stored");

        let pushed = recv_json(&mut guest_ws).await;
        assert_eq!(pushed["op"], "envelope");
        let payload = guest
            .open(pushed["envelope"].as_str().expect("string"), slot, 2)
            .expect("addressed to us");
        assert_eq!(
            guest.receive(&payload).expect("decrypt").expect("plaintext"),
            "hello from the browser"
        );
    }

    /// Three people in one conversation, over the real server, in the order
    /// `site/chat.html` performs it.
    ///
    /// The two party test cannot catch what breaks here. A group needs one
    /// deposit per recipient, because collection removes and a shared tag hands
    /// each message to whoever collects first; and the commit announcing a new
    /// member has to be addressed at the epoch the existing members are still
    /// on, since that commit is what moves them off it.
    #[tokio::test]
    async fn three_people_hold_one_conversation_over_the_real_server() {
        use rotelyx_wasm::{open_under, rendezvous_tag, seal_under, Session};

        let url = spawn_server().await;
        let meeting = rendezvous_tag("all three in the same mailbox").expect("tag");
        let slot = 490_000u64;

        let b64 = |v: serde_json::Value| BASE64.encode(v.to_string().as_bytes());
        let unb64 = |s: &str| -> serde_json::Value {
            serde_json::from_slice(&BASE64.decode(s.as_bytes()).expect("b64")).expect("json")
        };

        let mut host_ws = connect(&url).await;
        let mut guest_ws = connect(&url).await;

        let mut host = Session::new("alice").expect("id");
        let mut guest = Session::new("bob").expect("id");
        host.found().expect("found");

        for c in [&mut host_ws, &mut guest_ws] {
            subscribe(c, vec![meeting.clone()]).await;
            assert_eq!(recv_json(c).await["op"], "ready");
        }

        // ---- the founding pair ----
        deposit(&mut guest_ws, seal_under(&meeting, &b64(serde_json::json!({
            "t": "hello",
            "keyPackage": guest.key_package().expect("kp"),
            "hybridPublicKey": guest.hybrid_public_key(),
        }))).expect("seal")).await;
        assert_eq!(recv_step(&mut guest_ws, "#1").await["op"], "stored");

        let knock = unb64(&open_under(
            recv_step(&mut host_ws, "#2").await["envelope"].as_str().unwrap(),
            &meeting,
        ).expect("open"));

        let inv = host.invite(knock["keyPackage"].as_str().unwrap()).expect("invite");
        let pq = host
            .encapsulate_to(knock["hybridPublicKey"].as_str().unwrap())
            .expect("encapsulate");

        deposit(&mut host_ws, seal_under(&meeting, &b64(serde_json::json!({
            "t": "welcome",
            "welcome": inv.welcome,
            "ratchetTree": inv.ratchet_tree,
            "pqCiphertext": pq,
        }))).expect("seal")).await;
        assert_eq!(recv_step(&mut host_ws, "#3").await["op"], "stored");

        deposit(&mut host_ws, seal_under(&meeting, &b64(serde_json::json!({
            "t": "commit", "commit": host.commit_pq().expect("commit"),
        }))).expect("seal")).await;
        assert_eq!(recv_step(&mut host_ws, "#4").await["op"], "stored");

        let welcome = unb64(&open_under(
            recv_step(&mut guest_ws, "#5").await["envelope"].as_str().unwrap(),
            &meeting,
        ).expect("open"));
        guest
            .join(welcome["welcome"].as_str().unwrap(), welcome["ratchetTree"].as_str().unwrap())
            .expect("join");
        guest.open_pq(welcome["pqCiphertext"].as_str().unwrap()).expect("stage");

        let commit = unb64(&open_under(
            recv_step(&mut guest_ws, "#6").await["envelope"].as_str().unwrap(),
            &meeting,
        ).expect("open"));
        assert!(guest.receive(commit["commit"].as_str().unwrap()).expect("apply").is_none());

        // The guest leaves the meeting place and listens on its own tags. The
        // host stays, so people can still arrive.
        client_unsubscribe(&mut guest_ws, vec![meeting.clone()]).await;
        assert_eq!(recv_step(&mut guest_ws, "#7").await["op"], "dropped");
        subscribe(&mut guest_ws, guest.my_polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_step(&mut guest_ws, "#8").await["op"], "ready");
        subscribe(&mut host_ws, host.my_polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_step(&mut host_ws, "#9").await["op"], "ready");

        // ---- a third person arrives ----
        let mut third_ws = connect(&url).await;
        let mut carol = Session::new("carol").expect("id");
        subscribe(&mut third_ws, vec![meeting.clone()]).await;
        assert_eq!(recv_step(&mut third_ws, "#10").await["op"], "ready");

        deposit(&mut third_ws, seal_under(&meeting, &b64(serde_json::json!({
            "t": "hello",
            "keyPackage": carol.key_package().expect("kp"),
            "hybridPublicKey": carol.hybrid_public_key(),
        }))).expect("seal")).await;
        assert_eq!(recv_step(&mut third_ws, "#11").await["op"], "stored");

        // The host must be the one who hears it, not the guest.
        let knock = unb64(&open_under(
            recv_step(&mut host_ws, "#12").await["envelope"].as_str().unwrap(),
            &meeting,
        ).expect("open"));

        let inv = host.invite(knock["keyPackage"].as_str().unwrap()).expect("invite");

        deposit(&mut host_ws, seal_under(&meeting, &b64(serde_json::json!({
            "t": "welcome",
            "welcome": inv.welcome,
            "ratchetTree": inv.ratchet_tree,
        }))).expect("seal")).await;
        assert_eq!(recv_step(&mut host_ws, "#13").await["op"], "stored");

        for envelope in host.seal_commit_for_group(&inv.commit, slot).expect("seal commit") {
            deposit(&mut host_ws, envelope).await;
            assert_eq!(recv_step(&mut host_ws, "#14").await["op"], "stored");
        }
        subscribe(&mut host_ws, host.my_polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_step(&mut host_ws, "#15").await["op"], "ready");

        let welcome = unb64(&open_under(
            recv_step(&mut third_ws, "#16").await["envelope"].as_str().unwrap(),
            &meeting,
        ).expect("open"));
        carol
            .join(welcome["welcome"].as_str().unwrap(), welcome["ratchetTree"].as_str().unwrap())
            .expect("join");
        subscribe(&mut third_ws, carol.my_polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_step(&mut third_ws, "#17").await["op"], "ready");

        // The guest, still an epoch behind, receives the commit on its own tag.
        let envelope = recv_step(&mut guest_ws, "#18").await;
        assert_eq!(envelope["op"], "envelope");
        let payload = guest
            .open_mine(envelope["envelope"].as_str().unwrap(), slot, 2)
            .expect("addressed to the guest at the epoch it is still on");
        assert!(guest.receive(&payload).expect("apply").is_none());

        // Applying a commit moves the epoch, and the tags move with it. A
        // client that does not re-subscribe here goes silent: it keeps
        // listening on the previous epoch's tags while everyone addresses it at
        // the new one, and no error is raised anywhere.
        subscribe(&mut guest_ws, guest.my_polling_tags(slot, 2).expect("tags")).await;
        assert_eq!(recv_step(&mut guest_ws, "guest resubscribe").await["op"], "ready");

        assert_eq!(host.member_count(), 3);
        assert_eq!(host.epoch(), guest.epoch(), "host and guest agree");
        assert_eq!(host.epoch(), carol.epoch(), "and so does the newcomer");

        // ---- and all three can talk ----
        let ciphertext = carol.send("hello to you both").expect("send");
        let envelopes = carol.seal_for_group(&ciphertext, slot).expect("seal");
        assert_eq!(envelopes.len(), 2, "one deposit per recipient");

        for envelope in envelopes {
            deposit(&mut third_ws, envelope).await;
            assert_eq!(recv_step(&mut third_ws, "#19").await["op"], "stored");
        }

        for (who, ws, session) in [
            ("host", &mut host_ws, &mut host),
            ("guest", &mut guest_ws, &mut guest),
        ] {
            let envelope = recv_step(ws, who).await;
            assert_eq!(envelope["op"], "envelope", "{who} received nothing");
            let payload = session
                .open_mine(envelope["envelope"].as_str().unwrap(), slot, 2)
                .expect("addressed to us");
            assert_eq!(
                session.receive(&payload).expect("decrypt").expect("plaintext"),
                "hello to you both",
                "{who} could not read it"
            );
        }
    }

    /// One upload must reach every recipient. This is what makes a group of
    /// hundreds possible on a phone.
    #[tokio::test]
    async fn a_fanout_reaches_every_recipient_from_one_upload() {
        use rotelyx_wasm::Session;

        let url = spawn_server().await;
        let slot = 490_000u64;

        // Four members of a real conversation.
        let mut sessions: Vec<Session> = (0..4)
            .map(|i| Session::new(&format!("m{i}")).expect("id"))
            .collect();
        sessions[0].found().expect("found");
        for i in 1..4 {
            let kp = sessions[i].key_package().expect("kp");
            let inv = sessions[0].invite(&kp).expect("invite");
            sessions[i].join(&inv.welcome, &inv.ratchet_tree).expect("join");
            for j in 1..i {
                sessions[j].receive(&inv.commit).expect("commit");
            }
        }

        // Each listens on its own tags.
        let mut clients = Vec::new();
        for session in sessions.iter().skip(1) {
            let mut ws = connect(&url).await;
            subscribe(&mut ws, session.my_polling_tags(slot, 2).expect("tags")).await;
            assert_eq!(recv_json(&mut ws).await["op"], "ready");
            clients.push(ws);
        }

        // One upload for all three.
        let mut sender = connect(&url).await;
        let ciphertext = sessions[0].send("one for everybody").expect("send");
        let tags = sessions[0].recipient_tags(slot).expect("tags");
        let payload = sessions[0].padded_payload(&ciphertext).expect("pad");
        assert_eq!(tags.len(), 3);

        sender
            .send(WsMessage::Text(
                serde_json::json!({"op": "fanout", "tags": tags, "payload": payload})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("fanout");

        let ack = recv_json(&mut sender).await;
        assert_eq!(ack["op"], "fannedout");
        assert_eq!(ack["stored"], 3);
        assert_eq!(ack["asked"], 3);

        // And every one of them can read it.
        for (ws, session) in clients.iter_mut().zip(sessions.iter_mut().skip(1)) {
            let envelope = recv_json(ws).await;
            assert_eq!(envelope["op"], "envelope");
            let mine = session
                .open_mine(envelope["envelope"].as_str().unwrap(), slot, 2)
                .expect("addressed to us");
            assert_eq!(
                session.receive(&mine).expect("decrypt").expect("plaintext"),
                "one for everybody"
            );
        }
    }

    /// A payload that has not been padded must be refused. Padding it on the
    /// server would hand the server the true length, which is the one thing
    /// the buckets exist to withhold.
    #[tokio::test]
    async fn a_fanout_refuses_an_unpadded_payload() {
        let url = spawn_server().await;
        let mut client = connect(&url).await;

        client
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "fanout",
                    "tags": ["aa".repeat(32)],
                    "payload": BASE64.encode(b"short and unpadded"),
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send");

        assert!(recv(&mut client).await.contains("padded"));
    }

    /// An unbounded fan-out would turn the mailbox into a spray tool.
    #[tokio::test]
    async fn an_oversized_fanout_is_refused() {
        let url = spawn_server().await;
        let mut client = connect(&url).await;

        // One past what the free tier allows, which is what an unauthenticated
        // connection gets.
        let over = access::Tier::Free.limits().max_fanout + 1;
        let tags: Vec<String> = (0..over).map(|i| format!("{i:064x}")).collect();
        client
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "fanout",
                    "tags": tags,
                    "payload": BASE64.encode(&vec![0u8; 1024]),
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send");

        assert!(recv(&mut client).await.contains("at most"));
    }

    /// The key the paid-tier tests mint with. Not an issuer: minting here is
    /// `rotelyx_capability::testing`, a test fixture. The issuer itself is a
    /// separate crate that is not in this repository. See docs/BILLING.md.
    const TEST_KEY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    /// Start a server that accepts tokens, and return its URL plus the key that
    /// server trusts.
    async fn spawn_paid_server() -> (String, &'static str) {
        let verifier = Verifier::from_public_hex(
            &rotelyx_capability::testing::public_hex(TEST_KEY),
        )
        .expect("verifier");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = router_with(DEFAULT_TTL_SECONDS, KEEPALIVE, Some(verifier));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("ws://{addr}/mailbox"), TEST_KEY)
    }

    async fn auth(client: &mut Client, token: &str) -> serde_json::Value {
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "auth", "token": token}).to_string().into(),
            ))
            .await
            .expect("auth");
        recv_json(client).await
    }

    async fn try_fanout(client: &mut Client, recipients: usize, payload_len: usize) -> serde_json::Value {
        let tags: Vec<String> = (0..recipients).map(|i| format!("{i:064x}")).collect();
        client
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "fanout",
                    "tags": tags,
                    "payload": BASE64.encode(&vec![0u8; payload_len]),
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("fanout");
        recv_json(client).await
    }

    /// The whole point of a paid tier: an unpaid client must not be able to do
    /// the things that are sold, and no amount of reconnecting changes that.
    #[tokio::test]
    async fn an_unpaid_client_cannot_reach_the_paid_limits() {
        let (url, key) = spawn_paid_server().await;
        let free = Tier::Free.limits();

        let mut client = connect(&url).await;

        // A group wider than the free tier allows.
        let refused = try_fanout(&mut client, free.max_fanout + 1, 1024).await;
        assert_eq!(refused["op"], "error");
        assert!(
            refused["message"].as_str().unwrap().contains("free"),
            "the refusal must name the tier, got {refused}"
        );

        // An envelope larger than the free tier allows.
        let refused = try_fanout(&mut client, 1, free.max_payload * 16).await;
        assert_eq!(refused["op"], "error");
        assert!(refused["message"].as_str().unwrap().contains("bytes per envelope"));

        // Reconnecting does not help: these are checked per request.
        let mut again = connect(&url).await;
        assert_eq!(try_fanout(&mut again, free.max_fanout + 1, 1024).await["op"], "error");

        // With a token, the same requests succeed.
        let token = rotelyx_capability::testing::mint(
            key,
            [1u8; 16],
            Tier::Plus,
            now_seconds() / 3600 + 24,
            0,
        );

        let mut paid = connect(&url).await;
        let granted = auth(&mut paid, &token).await;
        assert_eq!(granted["op"], "tier");
        assert_eq!(granted["tier"], "plus");
        assert_eq!(granted["maxFanout"], Tier::Plus.limits().max_fanout);

        let allowed = try_fanout(&mut paid, free.max_fanout + 1, 1024).await;
        assert_eq!(allowed["op"], "fannedout", "a paid client must be allowed, got {allowed}");
    }

    /// A forged or expired token must leave the client on the free tier rather
    /// than granting anything.
    #[tokio::test]
    async fn a_bad_token_grants_nothing() {
        let (url, _) = spawn_paid_server().await;
        const OTHER_KEY: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";
        let forged = rotelyx_capability::testing::mint(
            OTHER_KEY,
            [2u8; 16],
            Tier::Plus,
            now_seconds() / 3600 + 24,
            0,
        );

        let mut client = connect(&url).await;
        let reply = auth(&mut client, &forged).await;
        assert_eq!(reply["op"], "error");

        // Still free, so still refused.
        let refused = try_fanout(&mut client, Tier::Free.limits().max_fanout + 1, 1024).await;
        assert_eq!(refused["op"], "error");
    }

    /// A server with no issuer key must refuse tokens outright rather than
    /// ignore them. A misconfigured server that silently downgrades paying
    /// clients looks exactly like one that is working.
    #[tokio::test]
    async fn a_server_without_an_issuer_refuses_tokens() {
        let url = spawn_server().await;
        const SOME_KEY: &str =
            "7777777777777777777777777777777777777777777777777777777777777777";
        let token = rotelyx_capability::testing::mint(
            SOME_KEY,
            [3u8; 16],
            Tier::Plus,
            now_seconds() / 3600 + 24,
            0,
        );

        let mut client = connect(&url).await;
        let reply = auth(&mut client, &token).await;
        assert_eq!(reply["op"], "error");
        assert!(reply["message"].as_str().unwrap().contains("no tokens"));
    }

    /// Quota is charged per copy that leaves the server, and refused before
    /// anything is stored.
    #[tokio::test]
    async fn a_fanout_is_charged_per_recipient_and_refused_over_quota() {
        let (url, key) = spawn_paid_server().await;

        // Enough for exactly four 1 KiB copies.
        let token = rotelyx_capability::testing::mint(
            key,
            [4u8; 16],
            Tier::Plus,
            now_seconds() / 3600 + 24,
            4 * 1024,
        );

        let mut client = connect(&url).await;
        assert_eq!(auth(&mut client, &token).await["bytesRemaining"], 4 * 1024);

        // Four recipients, one KiB each: exactly the allowance.
        assert_eq!(try_fanout(&mut client, 4, 1024).await["op"], "fannedout");

        // One more copy is over.
        let refused = try_fanout(&mut client, 1, 1024).await;
        assert_eq!(refused["op"], "overquota", "got {refused}");
        assert_eq!(refused["limit"], 4 * 1024);
        assert_eq!(refused["tier"], "plus");
    }

    /// A client that unsubscribes must stop consuming envelopes.
    ///
    /// Collection removes, so a client still listening on a tag it has
    /// finished with silently eats what was meant for someone else. This is
    /// what a third person joining an established conversation hit: their
    /// knock was swallowed by whichever existing tab collected it first, and
    /// nothing appeared anywhere.
    #[tokio::test]
    async fn an_unsubscribed_client_stops_consuming() {
        let url = spawn_server().await;
        let tag = Tag::from_bytes(&[11u8; 32]).expect("tag");

        let mut leaver = connect(&url).await;
        let mut sender = connect(&url).await;

        subscribe(&mut leaver, vec![tag_hex(&tag)]).await;
        assert_eq!(recv_json(&mut leaver).await["op"], "ready");

        client_unsubscribe(&mut leaver, vec![tag_hex(&tag)]).await;
        let dropped = recv_json(&mut leaver).await;
        assert_eq!(dropped["op"], "dropped");
        assert_eq!(dropped["listening"], 0);

        let envelope = Envelope::seal(tag, b"for whoever is still there").expect("seal");
        deposit(&mut sender, BASE64.encode(&envelope.to_bytes())).await;
        assert_eq!(recv_json(&mut sender).await["op"], "stored");

        // The leaver must be handed nothing.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                futures_util::StreamExt::next(&mut leaver),
            )
            .await
            .is_err(),
            "an unsubscribed client must not be handed envelopes"
        );

        // And the envelope is still there for whoever comes for it.
        let mut arriving = connect(&url).await;
        subscribe(&mut arriving, vec![tag_hex(&tag)]).await;
        assert_eq!(
            recv_json(&mut arriving).await["op"],
            "envelope",
            "the envelope must still be waiting, not consumed by the leaver"
        );
    }

    /// An idle connection must be kept alive by the server.
    ///
    /// Cloudflare and other proxies cut an idle WebSocket after a minute or
    /// two. A conversation where nobody has typed for that long is completely
    /// ordinary, so without a heartbeat the socket dies during normal use and
    /// the page reports a dropped connection with no cause.
    #[tokio::test]
    async fn an_idle_connection_is_pinged() {
        // A short interval rather than the production 30 seconds, so the test
        // asserts the behaviour without waiting for it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = router(DEFAULT_TTL_SECONDS, Duration::from_millis(80));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut client = connect(&format!("ws://{addr}/mailbox")).await;

        subscribe(&mut client, vec![]).await;
        assert_eq!(recv_json(&mut client).await["op"], "ready");

        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            futures_util::StreamExt::next(&mut client),
        )
        .await
        .expect("a heartbeat must arrive well inside any proxy timeout")
        .expect("a frame")
        .expect("a valid frame");

        assert!(
            matches!(frame, WsMessage::Ping(_)),
            "expected a ping, got {frame:?}"
        );
    }

    /// A client subscribed to a tag it also deposits under must not receive
    /// its own envelope. Both sides of a conversation share one tag, so
    /// without this a sender races its recipient and sometimes wins, and
    /// because collection removes, the message is simply lost.
    #[tokio::test]
    async fn a_client_never_receives_its_own_deposit() {
        let url = spawn_server().await;
        let tag = Tag::from_bytes(&[3u8; 32]).expect("tag");

        let mut sender = connect(&url).await;
        let mut receiver = connect(&url).await;

        for client in [&mut sender, &mut receiver] {
            client
                .send(WsMessage::Text(
                    serde_json::json!({"op": "subscribe", "tags": [tag_hex(&tag)]})
                        .to_string()
                        .into(),
                ))
                .await
                .expect("subscribe");
            assert_eq!(recv_json(client).await["op"], "ready");
        }

        let envelope = Envelope::seal(tag, b"for the other side").expect("seal");
        sender
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "deposit",
                    "envelope": BASE64.encode(&envelope.to_bytes())
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("deposit");

        // The sender gets its acknowledgement and nothing else.
        assert_eq!(recv_json(&mut sender).await["op"], "stored");

        // The other side gets the envelope.
        assert_eq!(recv_json(&mut receiver).await["op"], "envelope");

        // And the sender still has nothing waiting.
        let stray = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            futures_util::StreamExt::next(&mut sender),
        )
        .await;
        assert!(
            stray.is_err(),
            "the sender must not be handed its own envelope"
        );
    }

    /// An envelope left while the recipient is offline must be waiting when
    /// they come back. This is the whole reason the mailbox exists.
    #[tokio::test]
    async fn an_envelope_survives_until_the_recipient_returns() {
        let url = spawn_server().await;
        let tag = Tag::from_bytes(&[9u8; 32]).expect("tag");
        let envelope = Envelope::seal(tag, b"waiting").expect("seal");

        let mut sender = connect(&url).await;
        sender
            .send(WsMessage::Text(
                serde_json::json!({
                    "op": "deposit",
                    "envelope": BASE64.encode(&envelope.to_bytes())
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("deposit");
        assert_eq!(recv_json(&mut sender).await["op"], "stored");

        // Nobody was listening. The recipient connects afterwards.
        let mut receiver = connect(&url).await;
        receiver
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": [tag_hex(&tag)]})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("subscribe");

        let value = recv_json(&mut receiver).await;
        assert_eq!(
            value["op"], "envelope",
            "the backlog must arrive before ready, got {value}"
        );
    }

    /// A malformed frame must not drop the connection: it is a client bug, not
    /// grounds to end a conversation.
    #[tokio::test]
    async fn a_bad_request_is_answered_without_closing() {
        let url = spawn_server().await;
        let mut client = connect(&url).await;

        client
            .send(WsMessage::Text("this is not json".into()))
            .await
            .expect("send");
        assert!(recv(&mut client).await.contains("malformed"));

        // Still usable.
        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": []})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("send");
        assert_eq!(recv_json(&mut client).await["op"], "ready");
    }

    /// Subscribing to an unbounded tag list would let one connection enumerate
    /// the store.
    #[tokio::test]
    async fn an_oversized_subscription_is_refused() {
        let url = spawn_server().await;
        let mut client = connect(&url).await;

        let tags: Vec<String> = (0..MAX_TAGS_PER_SUBSCRIPTION + 1)
            .map(|i| format!("{i:064x}"))
            .collect();

        client
            .send(WsMessage::Text(
                serde_json::json!({"op": "subscribe", "tags": tags})
                    .to_string()
                    .into(),
            ))
            .await
            .expect("send");

        assert!(recv(&mut client).await.contains("at most"));
    }

    #[test]
    fn a_tag_must_be_exactly_sixty_four_hex_characters() {
        let valid = "a".repeat(64);
        assert!(parse_tag(&valid).is_some());

        assert!(parse_tag(&"a".repeat(63)).is_none(), "too short");
        assert!(parse_tag(&"a".repeat(65)).is_none(), "too long");
        assert!(parse_tag(&"z".repeat(64)).is_none(), "not hex");
        assert!(parse_tag("").is_none());
    }

    /// The server must reject anything that is not a well formed envelope,
    /// rather than storing arbitrary bytes under an attacker-chosen tag.
    #[test]
    fn a_malformed_envelope_is_not_stored() {
        assert!(Envelope::from_bytes(b"not an envelope").is_err());
        assert!(Envelope::from_bytes(&[]).is_err());
    }

    /// Collection removes, which is what makes delivery exactly once. If this
    /// ever became non-destructive the server would start keeping copies of
    /// delivered messages, which is the thing it exists not to do.
    #[test]
    fn collection_is_destructive() {
        let mut mailbox = Mailbox::with_default_ttl();
        let tag = Tag::from_bytes(&[7u8; 32]).expect("tag");

        mailbox
            .deposit(Envelope::seal(tag, b"payload").expect("seal"), 0)
            .expect("deposit");

        assert_eq!(mailbox.collect(tag, 0).len(), 1);
        assert_eq!(
            mailbox.collect(tag, 0).len(),
            0,
            "a second collection must find nothing"
        );
    }
}
