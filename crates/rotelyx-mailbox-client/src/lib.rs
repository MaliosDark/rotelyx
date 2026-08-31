//! Talking to a blind mailbox.
//!
//! # Why this exists
//!
//! The phone client speaks this protocol and the desktop did not, so the two
//! could not exchange a single message. They already share everything else: the
//! codec, the per-sender keys, the MLS group, the datagram transport. What they
//! did not share was **how two people find each other**, and that is the whole
//! of it.
//!
//! The client half lived only in the phone's Dart. This is the same protocol in
//! Rust, defined against the server in this repository rather than translated
//! from the Dart, so there is one authority and not two.
//!
//! # What the operator sees, said here because it is the trade
//!
//! A tag, a size bucket, an arrival time and an address. Not who, not what, and
//! not for how long: an envelope is removed when it is collected and the tag
//! rotates hourly. That is a weaker promise than a direct connection makes and a
//! far stronger one than an account, and it is the price of being reachable
//! while offline.
//!
//! # Why not just use the direct path
//!
//! Because both sides have to be awake at the same moment, and a phone is not.
//! The mailbox is what makes a conversation survive one of the two being asleep,
//! which is the ordinary case rather than the exception.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

/// What a client says.
///
/// Serialised exactly as the server's `Request` expects: a tagged enum with the
/// tag in `op` and the variants in lowercase.
///
/// **`lowercase`, not `camelCase`, and the difference is not cosmetic.** The
/// server declares both of its enums `rename_all = "lowercase"` and renames the
/// exceptions one at a time. These two said `camelCase`, which agrees with
/// lowercase for every variant of a single word and disagrees for every other,
/// and almost every variant here is one word. The one that was not cost a hang;
/// see [`Reply::OverQuota`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request<'a> {
    Subscribe {
        tags: Vec<&'a str>,
    },
    Collected {
        digests: Vec<String>,
    },
    Unsubscribe {
        tags: Vec<&'a str>,
    },
    Deposit {
        envelope: &'a str,
    },
    Auth {
        token: &'a str,
    },
    #[serde(rename = "authblind")]
    AuthBlind {
        token: &'a str,
    },
}

/// What the server says back.
///
/// `Other` catches everything this client does not act on. A wake registration
/// belongs to a phone rather than to a desktop, and a client that failed on a
/// reply it merely does not need would be brittle for no gain.
///
/// `overQuota` used to be in that set and does not belong there. An
/// unauthenticated caller is issued a free capability and metered like any
/// other, so the allowance is a desktop's concern too. Falling into `Other`
/// was worse than losing the message quietly: `deposit` went back to waiting
/// for a `Stored` that was never coming, so a deposit at the quota blocked
/// until something else arrived or the socket died. It is named now and
/// carries the numbers, so a caller can tell a refusal from a slow network.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Reply {
    Ready {
        waiting: usize,
    },
    Envelope {
        envelope: String,
    },
    Stored,
    Error {
        message: String,
    },
    /// The period's allowance is spent.
    ///
    /// **Spelled the way the server spells it, which is not what `rename_all`
    /// produces.** The server renames this variant explicitly to `overquota`,
    /// all lowercase, and the container attribute here would have made it
    /// `overQuota`. So this arrived as an unknown tag, fell into [`Reply::Other`]
    /// and was skipped, and `deposit` went on waiting for a `stored` the server
    /// had already decided not to send: a deposit at the quota hung until
    /// something else arrived or the socket died.
    ///
    /// That is the bug this variant was added to fix. It was added with the
    /// wrong name, and the test that was supposed to catch it fed the client a
    /// string in the client's own spelling rather than the server's, so it
    /// confirmed that this crate can parse what this crate would write.
    OverQuota {
        limit: u64,
        used: u64,
        tier: String,
    },
    /// What a capability grants. The answer to [`Mailbox::authenticate`].
    ///
    /// Every field is renamed, because the server renames every one of them and
    /// a container-level `rename_all` does not reach fields.
    Tier {
        tier: String,
        #[serde(rename = "maxFanout")]
        max_fanout: usize,
        #[serde(rename = "maxPayload")]
        max_payload: usize,
        #[serde(rename = "retentionDays")]
        retention_days: u64,
        #[serde(rename = "bytesRemaining")]
        bytes_remaining: u64,
    },
    #[serde(other)]
    Other,
}

/// Shortest a blindly issued token can be, and the line between the two auth
/// frames.
///
/// Measured rather than reasoned: an Ed25519 token is 119 characters and a
/// blind one is 406. This sits in the middle of that gap, and
/// `rotelyx_capability::tests` fails if the two formats ever grow close enough
/// that a length is no longer a reliable way to tell them apart. The same
/// threshold, for the same reason, is in `site/chat.html`.
pub const BLIND_TOKEN_MINIMUM: usize = 240;

/// The part of a size refusal that says a bigger tier would have taken it.
///
/// Matched rather than parsed, because the server sends this one as prose. The
/// exact message is pinned on that side by
/// `every_reply_is_spelled_the_way_a_client_reads_it`, which makes this a term
/// of the contract instead of a guess about somebody's wording.
const TIER_REFUSAL: &str = "tier allows at most";

/// What a token turned out to grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    /// The tier's name, as the server calls it: `free`, `plus`, `plus++`.
    pub tier: String,
    /// Recipients one fan-out may name.
    pub max_fanout: usize,
    /// Largest envelope payload accepted, in bytes.
    pub max_payload: usize,
    /// How long an uncollected envelope is kept.
    pub retention_days: u64,
    /// Payload bytes left in this metering period.
    pub bytes_remaining: u64,
}

/// How one attempt at a deposit ended.
///
/// The distinction that matters is whether a bigger tier would have taken it,
/// because that is the only refusal presenting a token can answer.
enum Deposited {
    Stored,
    /// Refused for a reason a tier decides: too large, or the allowance spent.
    RefusedByTier(String),
    /// Refused for a reason no token changes.
    Refused(String),
}

/// One connection to a mailbox.
pub struct Mailbox {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Envelopes that arrived while this side was waiting for an answer to
    /// something else.
    ///
    /// The socket carries envelopes and control replies on one stream, and a
    /// deposit has to read past whatever is in front of its `stored` to find
    /// it. Reading past it used to mean discarding it: an envelope pushed while
    /// a deposit was in flight was gone, with nothing anywhere saying so.
    ///
    /// Found by running two sides of a pairing against a real server. The host
    /// deposits a welcome and a commit back to back, and the guest's reply
    /// landed inside one of those deposits and was dropped. Both sides finished
    /// the handshake, agreed on a safety number, and then sat in silence, which
    /// is the failure that looks least like a bug.
    pending: VecDeque<String>,

    /// A capability token, held and not presented until something needs it.
    ///
    /// See [`Mailbox::hold_token`] for why it waits.
    token: Option<Zeroizing<String>>,

    /// Whether the token has been presented on this connection.
    ///
    /// Presented at most once. A second `auth` would tell the mailbox nothing
    /// it does not already know and would be one more thing to get wrong.
    presented: bool,
}

impl Mailbox {
    /// Open a connection. `url` is a websocket URL: `ws://host:3341/mailbox`.
    pub async fn connect(url: &str) -> Result<Self> {
        let (socket, _) = connect_async(url)
            .await
            .with_context(|| format!("connecting to {url}"))?;
        Ok(Self {
            socket,
            pending: VecDeque::new(),
            token: None,
            presented: false,
        })
    }

    /// Listen on these tags, and take everything already waiting under them.
    ///
    /// # Why this returns the envelopes rather than a count
    ///
    /// The server sends what is waiting **before** it says `ready`, and `ready`
    /// carries the count of what it just sent. A subscribe that read towards
    /// `ready` and discarded what came first would silently eat every envelope
    /// left while this side was away, which is the whole reason the mailbox
    /// exists. Written that way first, and both integration tests caught it.
    pub async fn subscribe(&mut self, tags: &[String]) -> Result<Vec<String>> {
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        self.send(&Request::Subscribe { tags: refs }).await?;

        let mut waiting = Vec::new();
        loop {
            match self.next_reply().await? {
                Reply::Envelope { envelope } => waiting.push(envelope),
                Reply::Ready { waiting: count } => {
                    if count != waiting.len() {
                        // Not fatal: the count is the server's own tally and the
                        // envelopes are the thing. Worth saying, because a gap
                        // means one of us is wrong about the protocol.
                        tracing::warn!(
                            said = count,
                            got = waiting.len(),
                            "the mailbox counted a different number of waiting envelopes"
                        );
                    }
                    return Ok(waiting);
                }
                Reply::Error { message } => bail!("mailbox refused the subscription: {message}"),
                _ => continue,
            }
        }
    }

    /// Stop listening on these tags.
    ///
    /// Sent and not waited on. The server's acknowledgement carries nothing a
    /// caller can act on, and waiting for it would mean reading past whatever
    /// is in front of it, which is where envelopes get lost. What matters is
    /// that unsubscribing does not recall what the server has already pushed:
    /// those envelopes are already on their way and are still delivered.
    /// Say which envelopes arrived, so the server can drop them.
    ///
    /// Delivery no longer removes: a tag is derivable by anybody in the group
    /// and by somebody recently removed from it, and removal on delivery let
    /// any of them drain another member's mailbox permanently and silently.
    /// Nothing goes now until the recipient says it has it.
    ///
    /// Not acknowledging is safe and costs re-delivery until the TTL runs out.
    /// Acknowledging something not yet processed is the unsafe direction, so
    /// this is called after the envelope has been opened and written down, not
    /// when it arrives.
    pub async fn collected(&mut self, envelopes_b64: &[String]) -> Result<()> {
        if envelopes_b64.is_empty() {
            return Ok(());
        }

        let digests: Vec<String> = envelopes_b64
            .iter()
            .filter_map(|b64| {
                let bytes = data_encoding::BASE64.decode(b64.as_bytes()).ok()?;
                let envelope = rotelyx_mailbox::Envelope::from_bytes(&bytes).ok()?;
                Some(data_encoding::HEXLOWER.encode(&envelope.digest()))
            })
            .collect();

        if digests.is_empty() {
            return Ok(());
        }

        self.send(&Request::Collected { digests }).await?;
        Ok(())
    }

    pub async fn unsubscribe(&mut self, tags: &[String]) -> Result<()> {
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        self.send(&Request::Unsubscribe { tags: refs }).await
    }

    /// Leave an envelope.
    ///
    /// # What this does not tell you, and why that is the point
    ///
    /// Whether anybody was listening. The server answers `stored` and nothing
    /// else, so a depositor cannot learn whether the person they are writing to
    /// is awake, and neither can anybody watching the depositor.
    ///
    /// That was not obvious from the outside: this was first written expecting a
    /// second answer meaning "handed straight over", on the strength of a
    /// `dropped` reply that turned out to be the answer to `unsubscribe`. The
    /// integration test caught it. Presence is not something this protocol
    /// carries, and a client that reported it would be inventing it.
    pub async fn deposit(&mut self, envelope: &str) -> Result<()> {
        // Twice at most: once as whoever this connection already is, and once
        // more after presenting a held token. See `hold_token` for why the
        // token is not presented before it is needed.
        for attempt in 0..2 {
            match self.deposit_once(envelope).await? {
                Deposited::Stored => return Ok(()),
                Deposited::RefusedByTier(why) => {
                    if attempt == 0 && self.present_held_token().await? {
                        continue;
                    }
                    bail!("{why}");
                }
                Deposited::Refused(why) => bail!("{why}"),
            }
        }
        unreachable!("the loop returns or bails on both attempts")
    }

    async fn deposit_once(&mut self, envelope: &str) -> Result<Deposited> {
        self.send(&Request::Deposit { envelope }).await?;

        loop {
            match self.next_reply().await? {
                Reply::Stored => return Ok(Deposited::Stored),
                Reply::Error { message } if message.contains(TIER_REFUSAL) => {
                    return Ok(Deposited::RefusedByTier(format!(
                        "mailbox refused the envelope: {message}"
                    )))
                }
                Reply::Error { message } => {
                    return Ok(Deposited::Refused(format!(
                        "mailbox refused the envelope: {message}"
                    )))
                }
                // The allowance is spent and the envelope was not stored.
                //
                // This used to fall into `Other` and be skipped, which did not
                // return success: it went back to waiting for a `Stored` that
                // was never coming, so a deposit at the quota **blocked** until
                // something else arrived or the socket died. Said plainly here
                // because a caller has to be able to tell a refusal from a slow
                // network, and because the numbers are what make the refusal
                // actionable.
                Reply::OverQuota { limit, used, tier } => {
                    return Ok(Deposited::RefusedByTier(format!(
                        "the {tier} allowance is spent: {used} of {limit} bytes used \
                         this period. The envelope was not stored."
                    )))
                }
                // Somebody else's envelope, in front of this deposit's answer.
                // Kept rather than skipped: see `pending`.
                Reply::Envelope { envelope } => self.pending.push_back(envelope),
                _ => continue,
            }
        }
    }

    /// Keep a capability token, and do not present it yet.
    ///
    /// # Why holding beats presenting
    ///
    /// A token carries a random id and the mailbox meters against it, so every
    /// deposit made under one token is tied to every other. `docs/THREAT-MODEL.md`
    /// says it plainly under ADV-4: the id names nobody, which is not the same
    /// as linking nothing, and it is **a stable pseudonym with a usage history**.
    ///
    /// Without one, an unauthenticated caller is given a fresh capability per
    /// connection, so one person's conversations are not tied to each other at
    /// the mailbox at all. Presenting a token at every connection throws that
    /// away, permanently, and throws it away **for nothing** on the traffic that
    /// would have fit in the free tier anyway, which is most of it.
    ///
    /// So the token waits here. [`Mailbox::deposit`] presents it when the free
    /// tier actually refuses something, and not before. The mailbox accepts an
    /// `auth` at any point on a connection and upgrades the capability in place,
    /// which is what makes waiting possible.
    ///
    /// **The safe behaviour is the one that happens by default.** A caller that
    /// wants the token presented immediately can call
    /// [`Mailbox::authenticate`]; a caller that does nothing gets the fewest
    /// links, rather than the other way round.
    pub fn hold_token(&mut self, token: impl Into<String>) {
        self.token = Some(Zeroizing::new(token.into()));
    }

    /// Present the held token, if there is one that has not been presented.
    ///
    /// `Ok(false)` when there is nothing to present, which is not a failure:
    /// it means this connection stays on the tier it already had.
    async fn present_held_token(&mut self) -> Result<bool> {
        if self.presented {
            return Ok(false);
        }
        let Some(token) = self.token.clone() else {
            return Ok(false);
        };
        self.authenticate(&token).await?;
        self.presented = true;
        Ok(true)
    }

    /// Present a capability token, and get back what it grants.
    ///
    /// # Why this did not exist, and what that cost
    ///
    /// Paid tiers were built end to end on the server: two token formats, blind
    /// issuance so the seller does not learn who bought, a meter that survives a
    /// restart, and a verifier for each. **No native client could present one.**
    /// This crate had no auth frame at all, so the desktop, which is what uses
    /// it, was permanently on the free tier with no way off. The browser could
    /// present the Ed25519 kind and not the blind one. The phone speaks this
    /// protocol from its own Dart and is not in this repository, so whether it
    /// can present one is a question for that app.
    ///
    /// So the tier could be sold and could not be used, and nothing failed:
    /// every client worked, on the free tier, exactly as it would have if the
    /// buyer had never paid.
    ///
    /// # Which frame this sends
    ///
    /// The mailbox has one for each format and **refuses to guess**, on purpose:
    /// guessing means trying both and reporting whichever error reads better,
    /// and a refusal then stops naming one thing. The holder is the side that
    /// knows, so the holder says.
    ///
    /// Told apart by length, which is what a caller holding a pasted string can
    /// see. An Ed25519 token is a postcard claim set and a 64 byte signature,
    /// about 119 characters; a blind one is a 16 byte id and an RSA signature at
    /// 2048 bits, 406. [`BLIND_TOKEN_MINIMUM`] sits in that gap, and
    /// `rotelyx_capability` has a test that fails if the two formats ever come
    /// close enough for it to be a guess.
    ///
    /// A token of the wrong kind is refused by the mailbox by name rather than
    /// quietly leaving the caller on the free tier.
    pub async fn authenticate(&mut self, token: &str) -> Result<Granted> {
        let token = token.trim();
        let request = if token.len() >= BLIND_TOKEN_MINIMUM {
            Request::AuthBlind { token }
        } else {
            Request::Auth { token }
        };
        self.send(&request).await?;

        loop {
            match self.next_reply().await? {
                Reply::Tier {
                    tier,
                    max_fanout,
                    max_payload,
                    retention_days,
                    bytes_remaining,
                } => {
                    return Ok(Granted {
                        tier,
                        max_fanout,
                        max_payload,
                        retention_days,
                        bytes_remaining,
                    })
                }
                Reply::Error { message } => bail!("the mailbox refused the token: {message}"),
                // An envelope can arrive at any moment and is not an answer to
                // this. Keeping it is the whole reason `pending` exists.
                Reply::Envelope { envelope } => self.pending.push_back(envelope),
                other => bail!("expected a tier, got {other:?}"),
            }
        }
    }

    /// Wait for the next envelope, up to `timeout`.
    ///
    /// `None` on timeout rather than an error: nothing arriving is the ordinary
    /// state of a mailbox and not a failure of it.
    pub async fn next_envelope(&mut self, timeout: Duration) -> Result<Option<String>> {
        // What arrived while this side was waiting on something else comes
        // first, and in the order it arrived.
        if let Some(envelope) = self.pending.pop_front() {
            return Ok(Some(envelope));
        }

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            match tokio::time::timeout(left, self.next_reply()).await {
                Err(_) => return Ok(None),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(Reply::Envelope { envelope })) => return Ok(Some(envelope)),
                Ok(Ok(Reply::Error { message })) => bail!("mailbox: {message}"),
                Ok(Ok(_)) => continue,
            }
        }
    }

    async fn send(&mut self, request: &Request<'_>) -> Result<()> {
        let text = serde_json::to_string(request).context("encoding a request")?;
        self.socket
            .send(Message::Text(text.into()))
            .await
            .context("sending to the mailbox")
    }

    async fn next_reply(&mut self) -> Result<Reply> {
        loop {
            let Some(message) = self.socket.next().await else {
                bail!("the mailbox closed the connection");
            };
            match message.context("reading from the mailbox")? {
                Message::Text(text) => {
                    return serde_json::from_str(&text)
                        .with_context(|| format!("mailbox said something unexpected: {text}"))
                }
                // Pings are answered by the library; anything else is not ours.
                Message::Close(_) => bail!("the mailbox closed the connection"),
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form has to match the server's, and the server is in this
    /// repository, so this is checkable rather than a matter of belief.
    #[test]
    fn requests_serialise_the_way_the_server_reads_them() {
        let subscribe = serde_json::to_string(&Request::Subscribe {
            tags: vec!["aabb", "ccdd"],
        })
        .expect("encode");
        assert_eq!(subscribe, r#"{"op":"subscribe","tags":["aabb","ccdd"]}"#);

        let deposit =
            serde_json::to_string(&Request::Deposit { envelope: "AAAA" }).expect("encode");
        assert_eq!(deposit, r#"{"op":"deposit","envelope":"AAAA"}"#);

        let unsubscribe =
            serde_json::to_string(&Request::Unsubscribe { tags: vec!["aabb"] }).expect("encode");
        assert_eq!(unsubscribe, r#"{"op":"unsubscribe","tags":["aabb"]}"#);
    }

    #[test]
    fn replies_parse() {
        let ready: Reply = serde_json::from_str(r#"{"op":"ready","waiting":3}"#).expect("ready");
        assert!(matches!(ready, Reply::Ready { waiting: 3 }));

        let envelope: Reply =
            serde_json::from_str(r#"{"op":"envelope","envelope":"AAAA"}"#).expect("envelope");
        assert!(matches!(envelope, Reply::Envelope { .. }));

        // `dropped` answers `unsubscribe`, not `deposit`. It is not acted on
        // here and must therefore be ignored rather than fatal.
        let dropped: Reply =
            serde_json::from_str(r#"{"op":"dropped","listening":2}"#).expect("dropped");
        assert!(matches!(dropped, Reply::Other));
    }

    /// A spent allowance has to be a reply this client can see.
    ///
    /// It parsed as `Other` once, which sent `deposit` back to waiting for a
    /// `Stored` that the server had already decided not to send. The failure
    /// was a hang rather than an error, and the envelope was not stored either
    /// way.
    ///
    /// # This test said the field names came from the server, and they did
    ///
    /// **The tag did not.** It read `"op":"overQuota"`, which is what
    /// `rename_all = "camelCase"` produces from `OverQuota`, and the server
    /// renames that variant explicitly to `overquota`. So the fix for the hang
    /// went in with a name the server never sends, the hang stayed, and this
    /// test passed the whole time: it fed the client a string in the client's
    /// own spelling and confirmed the client could read it.
    ///
    /// The string below is now the server's, pinned on that side by
    /// `every_reply_is_spelled_the_way_this_client_reads_it` in the mailbox
    /// server. Two halves of a wire in two crates need one of them to be
    /// authoritative and the other to copy, not both to describe.
    #[test]
    fn a_spent_allowance_is_not_mistaken_for_a_reply_to_ignore() {
        let spent: Reply = serde_json::from_str(
            r#"{"op":"overquota","limit":67108864,"used":67108900,"tier":"free"}"#,
        )
        .expect("overquota");

        assert!(
            matches!(spent, Reply::OverQuota { .. }),
            "a refused deposit must not fall into the set this client ignores: \
             ignoring it is what made `deposit` wait for an answer that was \
             never coming"
        );

        let Reply::OverQuota { limit, used, tier } = spent else {
            unreachable!()
        };
        assert_eq!(
            (limit, used, tier.as_str()),
            (67_108_864, 67_108_900, "free")
        );
    }

    /// A reply this client does not act on must not be an error.
    ///
    /// A tier grant and a wake registration belong to a phone. A desktop that
    /// fell over on one of them would be brittle for nothing, and the server is
    /// free to add more.
    ///
    /// **`overQuota` was in this list and that was the defect.** The test
    /// asserted the belief rather than checking it, so the belief could not be
    /// contradicted by anything: a refused deposit was classified as a reply
    /// worth ignoring, and `deposit` waited for an answer the server had
    /// decided not to send. A quota is not a phone's concern, because an
    /// unauthenticated caller is metered too. It is checked by the test above
    /// this one now, and this list is for replies that say nothing about
    /// whether a request succeeded.
    ///
    /// **`tier` has left this list too**, for the same shape of reason. It was
    /// here carrying a field the server does not send, `{"op":"tier","name":...}`
    /// against the real `{"op":"tier","tier":...,"maxFanout":...}`, which is
    /// what a sample invented rather than captured looks like. Nothing noticed,
    /// because a reply nobody reads can have any shape at all. It is the answer
    /// to [`Mailbox::authenticate`] now and is parsed.
    #[test]
    fn replies_this_client_does_not_need_are_ignored_rather_than_fatal() {
        for text in [
            r#"{"op":"wakeRegistered","secret":"aa"}"#,
            r#"{"op":"somethingFromAFutureServer"}"#,
        ] {
            let reply: Reply = serde_json::from_str(text).expect(text);
            assert!(matches!(reply, Reply::Other), "{text} was not ignored");
        }
    }

    /// The tier reply parses in the shape the server actually sends.
    ///
    /// Taken from `Reply::Tier` in the mailbox server rather than from memory,
    /// which is the mistake the entry above records.
    #[test]
    fn a_tier_reply_parses_as_the_server_writes_it() {
        let text = r#"{"op":"tier","tier":"plus","maxFanout":256,"maxPayload":8388608,
                       "retentionDays":30,"bytesRemaining":8589934592}"#;
        let reply: Reply = serde_json::from_str(text).expect("the server's own shape");
        match reply {
            Reply::Tier {
                tier,
                max_fanout,
                retention_days,
                ..
            } => {
                assert_eq!(tier, "plus");
                assert_eq!(max_fanout, 256);
                assert_eq!(retention_days, 30);
            }
            other => panic!("a tier reply parsed as {other:?}"),
        }
    }

    /// Which frame a token is presented in, either side of the threshold.
    #[test]
    fn the_frame_follows_the_token_length() {
        let short = "a".repeat(BLIND_TOKEN_MINIMUM - 1);
        let long = "a".repeat(BLIND_TOKEN_MINIMUM);

        let as_signed = serde_json::to_string(&Request::Auth { token: &short }).expect("json");
        assert!(as_signed.contains(r#""op":"auth""#), "{as_signed}");

        let as_blind = serde_json::to_string(&Request::AuthBlind { token: &long }).expect("json");
        assert!(
            as_blind.contains(r#""op":"authblind""#),
            "the blind frame is not named the way the server reads it: {as_blind}"
        );
    }
}
