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
    Unsubscribe { tags: Vec<&'a str> },
    Deposit { envelope: &'a str },
}

/// What the server says back.
///
/// `Other` catches everything this client does not act on: tiers, quotas and
/// wake registrations belong to a phone rather than to a desktop, and a client
/// that failed on a reply it merely does not need would be brittle for no gain.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
enum Reply {
    Ready { waiting: usize },
    Envelope { envelope: String },
    Stored,
    Error { message: String },
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

    /// A reply this client does not act on must not be an error.
    ///
    /// Tiers, quotas and wake registrations belong to a phone. A desktop that
    /// fell over on one of them would be brittle for nothing, and the server is
    /// free to add more.
    #[test]
    fn replies_this_client_does_not_need_are_ignored_rather_than_fatal() {
        for text in [
            r#"{"op":"tier","name":"free"}"#,
            r#"{"op":"overQuota","limit":1,"used":2,"tier":"free"}"#,
            r#"{"op":"wakeRegistered","secret":"aa"}"#,
            r#"{"op":"somethingFromAFutureServer"}"#,
        ] {
            let reply: Reply = serde_json::from_str(text).expect(text);
            assert!(matches!(reply, Reply::Other), "{text} was not ignored");
        }
    }
}
