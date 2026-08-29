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

/// What a client says.
///
/// Serialised exactly as the server's `Request` expects: a tagged enum with the
/// tag in `op` and the variants in lowercase.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "op", rename_all = "camelCase")]
enum Request<'a> {
    Subscribe { tags: Vec<&'a str> },
    Collected { digests: Vec<String> },
    Unsubscribe { tags: Vec<&'a str> },
    Deposit { envelope: &'a str },
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
#[serde(tag = "op", rename_all = "camelCase")]
enum Reply {
    Ready { waiting: usize },
    Envelope { envelope: String },
    Stored,
    Error { message: String },
    OverQuota { limit: u64, used: u64, tier: String },
    #[serde(other)]
    Other,
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
        self.send(&Request::Deposit { envelope }).await?;

        loop {
            match self.next_reply().await? {
                Reply::Stored => return Ok(()),
                Reply::Error { message } => bail!("mailbox refused the envelope: {message}"),
                // The allowance is spent and the envelope was not stored.
                //
                // This used to fall into `Other` and be skipped, which did not
                // return success: it went back to waiting for a `Stored` that
                // was never coming, so a deposit at the quota **blocked** until
                // something else arrived or the socket died. Said plainly here
                // because a caller has to be able to tell a refusal from a slow
                // network, and because the numbers are what make the refusal
                // actionable.
                Reply::OverQuota { limit, used, tier } => bail!(
                    "the {tier} allowance is spent: {used} of {limit} bytes used \
                     this period. The envelope was not stored."
                ),
                // Somebody else's envelope, in front of this deposit's answer.
                // Kept rather than skipped: see `pending`.
                Reply::Envelope { envelope } => self.pending.push_back(envelope),
                _ => continue,
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

        let deposit = serde_json::to_string(&Request::Deposit { envelope: "AAAA" }).expect("encode");
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
    /// way. The exact field names come from the server's `Reply::OverQuota`.
    #[test]
    fn a_spent_allowance_is_not_mistaken_for_a_reply_to_ignore() {
        let spent: Reply = serde_json::from_str(
            r#"{"op":"overQuota","limit":67108864,"used":67108900,"tier":"free"}"#,
        )
        .expect("overQuota");

        assert!(
            matches!(spent, Reply::OverQuota { .. }),
            "a refused deposit must not fall into the set this client ignores: \
             ignoring it is what made `deposit` wait for an answer that was \
             never coming"
        );

        let Reply::OverQuota { limit, used, tier } = spent else {
            unreachable!()
        };
        assert_eq!((limit, used, tier.as_str()), (67_108_864, 67_108_900, "free"));
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
    #[test]
    fn replies_this_client_does_not_need_are_ignored_rather_than_fatal() {
        for text in [
            r#"{"op":"tier","name":"free"}"#,
            r#"{"op":"wakeRegistered","secret":"aa"}"#,
            r#"{"op":"somethingFromAFutureServer"}"#,
        ] {
            let reply: Reply = serde_json::from_str(text).expect(text);
            assert!(matches!(reply, Reply::Other), "{text} was not ignored");
        }
    }
}
