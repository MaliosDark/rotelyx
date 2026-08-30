//! Meeting a phone at a place a QR code names.
//!
//! # Why this exists beside the engine
//!
//! [`engine`](crate::engine) speaks QUIC to an address, which is what makes a
//! call possible and what the desktop has always done. The phone client does
//! not do that. It has no listening socket, it moves between networks, and it
//! is asleep most of the time, so everything it does goes through a mailbox: a
//! server that holds sealed envelopes addressed to opaque tags and hands them
//! over to whoever asks for that tag.
//!
//! So a desktop and a phone had no way to reach each other. Both spoke MLS,
//! both derived the same safety numbers, and neither could deliver the first
//! byte to the other. This module is the second transport that closes that,
//! and it is deliberately the phone's transport rather than a third one.
//!
//! # What the QR carries, and what it does not
//!
//! Not an invitation. An X-Wing public key is 1216 bytes, and with the key
//! package and base64 around it an invitation runs to roughly three thousand
//! characters, well past what a QR holds at a correction level that leaves room
//! for a logo. It carries a meeting code: 120 random bits naming a place.
//!
//! Both sides derive the same mailbox tag from that code, meet there, and hand
//! each other the real keys where their size costs nothing. See
//! `rotelyx_wasm::new_meeting_code`, and `lib/rotelyx/meeting_code.dart` in the
//! phone client, which mints the same format.
//!
//! # What the mailbox operator sees
//!
//! Everything deposited at the meeting tag, which is acceptable only because
//! none of the handshake needs to be private: a key package is public, a
//! welcome is encrypted to the joiner's own key, and the hybrid ciphertext is
//! encapsulated to their public key. What the operator does not see is any
//! message, at the meeting place or after it.
//!
//! What a meeting code buys an attacker is one attempt at being first. Whoever
//! arrives before the intended person completes the handshake in their place.
//! Nothing here prevents that, and nothing can: a code is not proof of who
//! holds it. The safety number is the only check that detects it, which is why
//! it is on screen from the moment the conversation exists.
//!
//! # Why a call is refused here
//!
//! A mailbox is store and forward. It carries a message that arrives in a
//! second perfectly well and cannot carry twenty millisecond audio frames at
//! all. A session established this way says so rather than starting a call that
//! would never sound like one.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rotelyx_mailbox_client::Mailbox;
use rotelyx_wasm::{open_under, rendezvous_tag, seal_under, Session};
use tokio::sync::mpsc;

use rotelyx_core::{Identity, RotelyxEndpoint};
use rotelyx_net::{NetConfig, PathPolicy, RelayPolicy, RelayUrl};

use crate::chats::{self, Line};
use crate::engine::{Command, Event, Present};

/// Which side of the meeting this is.
///
/// Not a detail of presentation. The guest speaks first, because the host has
/// nothing to say until it knows who is asking, and the host stays listening at
/// the meeting place afterwards while the guest leaves it. Getting this the
/// wrong way round produces two clients waiting for each other in silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Showed the code. Founds the conversation and admits whoever knocks.
    Host,
    /// Read the code. Knocks, and joins what comes back.
    Guest,
}

/// What marks a message as something a client sent rather than a person.
///
/// The same two values `lib/rotelyx/signal.dart` uses in the phone client, and
/// they have to stay the same: a receipt written with a different marker is a
/// line of text in somebody's conversation, and one read with a different
/// marker is a receipt that never arrives.
const SIGNAL_MARKER: &str = "rx-signal";
const SIGNAL_SEP: char = '\x1f';

/// Whether a body is a client talking to a client rather than a person talking.
fn is_control(body: &str) -> bool {
    let mut prefix = String::from(SIGNAL_MARKER);
    prefix.push(SIGNAL_SEP);
    body.starts_with(&prefix)
}

/// How far back to look for envelopes when tags rotate.
///
/// Tags are derived per hour. A message deposited at 10:59 under the hour's tag
/// is collected at 11:00 by a client that has already moved on, so each side
/// listens on the previous windows as well. Two hours is slack over a boundary
/// that arrives once an hour.
const LOOKBACK: u64 = 2;

/// How long to wait on the socket before looking at the command channel.
///
/// The loop alternates rather than selecting over both, so an envelope cannot
/// be dropped by a cancelled branch. A quarter second is below what anybody
/// notices on a keystroke and is most of the time spent parked on a socket.
const TURN: Duration = Duration::from_millis(250);

/// A Fisher-Yates shuffle over whatever randomness the system has.
///
/// Refuses rather than falling back to an order, because the caller is using
/// this to remove an order and a silent no-op would leave it believing the
/// order was gone.
fn shuffle<T>(items: &mut [T]) -> Result<()> {
    if items.len() < 2 {
        return Ok(());
    }
    let mut bytes = vec![0u8; items.len() * 8];
    getrandom::fill(&mut bytes).context("no randomness to order deposits with")?;

    for i in (1..items.len()).rev() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        // Modulo bias over a 64 bit draw into a range this small is far below
        // anything an observer could measure.
        let j = (u64::from_le_bytes(word) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
    Ok(())
}

/// Hours since the Unix epoch, the same formula both clients use.
fn bucket() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs()
        / 3600)
}

/// Carry on a conversation that is already on disk.
///
/// # Why this cannot simply start receiving
///
/// A file is a copy, and a copy that starts sending is sending at generations
/// the other side has already seen. The core knows this: `reopen` sets
/// `restored_needs_rekey` and refuses to send until a fresh epoch has been
/// committed. So the first thing that goes out is that commit, addressed one
/// epoch back, which is where everybody else still is.
///
/// Until they apply it they are addressing a leaf whose generations have moved,
/// so a message sent in that window is lost. That is the price of resuming from
/// a file and it is paid once, at the start.
pub async fn resume(
    identity: &std::path::Path,
    key: rotelyx_wasm::SessionKey,
    id: &str,
    calls_as: Identity,
    relay: Option<String>,
    events: Arc<dyn Fn(Event) + Send + Sync>,
    rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    let (mut session, label, lines, mailbox_url) = chats::reopen(identity, &key, id)?;

    events(Event::Status {
        text: format!("opening the conversation with {label}"),
    });

    let mut mailbox = Mailbox::connect(&mailbox_url)
        .await
        .with_context(|| format!("the mailbox at {mailbox_url} did not answer"))?;

    // The commit first, before anything is listened for. Sending anything else
    // before it is refused by the core, and the other side cannot read a word
    // of this copy until they have applied it.
    let commit = session.rekey_after_restore().map_err(to_anyhow)?;
    let bucket_now = bucket()?;
    match session.seal_commit_for_group(&commit, bucket_now) {
        Ok(envelopes) => {
            for envelope in envelopes {
                mailbox.deposit(&envelope).await?;
            }
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "this conversation cannot be carried on: {}",
                error_text(&e)
            ))
        }
    }

    let mut meeting = Meeting {
        // No meeting place: that code was spent when the conversation began, and
        // both sides left it. Nothing will ever open under this tag, which is
        // what makes every envelope fall through to the conversation.
        tag: String::new(),
        role: Role::Host,
        session,
        joined: true,
        receipts: false,
        keeping: Some((identity.to_path_buf(), key)),
        identity: calls_as,
        relay,
        endpoint: None,
        call_id: String::new(),
        call_stop: None,
        mailbox_url,
        label: label.clone(),
        lines,
        admitted: Vec::new(),
        listening: Vec::new(),
        queued: Vec::new(),
        subscribed_bucket: bucket()?,
        events,
    };

    meeting.resubscribe(&mut mailbox).await?;
    (meeting.events)(Event::Connected {
        peer: label,
        safety_number: meeting.session.safety_number().map_err(to_anyhow)?,
        direct: false,
    });
    meeting.say_who_is_here();

    turn(&mut meeting, &mut mailbox, rx).await
}

/// Run one meeting, and the conversation that comes out of it, until it ends.
///
/// Returns when the command channel closes, which is the window asking for the
/// session to stop.
pub async fn run(
    code: &str,
    display_name: &str,
    mailbox_url: &str,
    role: Role,
    receipts: bool,
    // The identity a call binds an endpoint with, and the relay it routes
    // through. Without a relay there is no call: see `Meeting::endpoint`.
    calls_as: Identity,
    relay: Option<String>,
    // Where this identity keeps its conversations, and the key they are sealed
    // with. Absent means this one is not written down.
    keeping: Option<(std::path::PathBuf, rotelyx_wasm::SessionKey)>,
    events: Arc<dyn Fn(Event) + Send + Sync>,
    rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    let code = rotelyx_wasm::read_meeting_code(code)
        .map_err(|e| anyhow::anyhow!("{}", error_text(&e)))?;

    // Derived from the canonical form and never from what was displayed, so the
    // grouping used to read a code aloud cannot move the meeting place.
    let tag = rendezvous_tag(&code).map_err(|e| anyhow::anyhow!("{}", error_text(&e)))?;

    let mut session =
        Session::new(display_name).map_err(|e| anyhow::anyhow!("{}", error_text(&e)))?;
    if role == Role::Host {
        session
            .found()
            .map_err(|e| anyhow::anyhow!("{}", error_text(&e)))?;
    }

    events(Event::Status {
        text: format!("connecting to the mailbox at {mailbox_url}"),
    });
    let mut mailbox = Mailbox::connect(mailbox_url)
        .await
        .with_context(|| format!("the mailbox at {mailbox_url} did not answer"))?;

    // Whatever was already waiting comes back from `subscribe` rather than
    // arriving afterwards, so it is handled here or not at all.
    let waiting = mailbox.subscribe(&[tag.clone()]).await?;

    events(Event::Status {
        text: match role {
            Role::Host => "waiting at the meeting place".into(),
            Role::Guest => "knocking at the meeting place".into(),
        },
    });

    let mut meeting = Meeting {
        tag,
        role,
        session,
        joined: false,
        receipts,
        keeping,
        identity: calls_as,
        relay,
        endpoint: None,
        call_id: String::new(),
        call_stop: None,
        mailbox_url: mailbox_url.to_string(),
        label: String::new(),
        lines: Vec::new(),
        admitted: Vec::new(),
        listening: Vec::new(),
        queued: Vec::new(),
        subscribed_bucket: bucket()?,
        events,
    };

    // The guest speaks first: the host has nothing to say until it knows who is
    // asking.
    if role == Role::Guest {
        let hello = serde_json::json!({
            "t": "hello",
            "name": display_name,
            "keyPackage": meeting.session.key_package().map_err(to_anyhow)?,
            "hybridPublicKey": meeting.session.hybrid_public_key(),
        });
        meeting.deposit_rendezvous(&mut mailbox, &hello).await?;
    }

    for envelope in waiting {
        meeting.incoming(&mut mailbox, &envelope).await?;
    }


    turn(&mut meeting, &mut mailbox, rx).await
}

/// Take turns between the window and the socket until one of them stops.
///
/// Alternating rather than selecting over both, so an envelope cannot be lost to
/// a cancelled branch. Shared by a conversation that is being met and one that
/// is being carried on from disk: past the handshake they are the same thing.
async fn turn(
    meeting: &mut Meeting,
    mailbox: &mut Mailbox,
    rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    loop {
        // Commands first, so a message typed while an envelope was in flight
        // does not wait another turn.
        loop {
            match rx.try_recv() {
                Ok(command) => meeting.command(mailbox, command).await?,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // Anything a subscribe handed back, before parking on the socket.
        while !meeting.queued.is_empty() {
            for envelope in std::mem::take(&mut meeting.queued) {
                meeting.incoming(mailbox, &envelope).await?;
            }
        }

        if let Some(envelope) = mailbox.next_envelope(TURN).await? {
            meeting.incoming(mailbox, &envelope).await?;
        }

        // Tags are derived per hour, so the set subscribed to at pairing time
        // stops matching what the other side deposits under as soon as the hour
        // rolls over. Without this the conversation goes quiet at the top of the
        // hour and stays quiet, which reads as the other person having left.
        if meeting.joined && bucket()? != meeting.subscribed_bucket {
            meeting.resubscribe(mailbox).await?;
        }
    }
}

struct Meeting {
    tag: String,
    role: Role,
    session: Session,
    joined: bool,
    /// Where this conversation is written down, and the key it is sealed with.
    keeping: Option<(std::path::PathBuf, rotelyx_wasm::SessionKey)>,
    /// The mailbox this conversation lives on, kept so reopening it knows where
    /// to go back to.
    mailbox_url: String,
    /// What the other side called themselves, for the list.
    label: String,
    /// The transcript. The one thing here that is readable text at rest.
    lines: Vec<Line>,
    /// What a call needs: an identity to bind an endpoint with, and a relay to
    /// route it through.
    ///
    /// A call never takes a direct path. On a direct path the other party learns
    /// this machine's address, and `rotelyx_media` refuses any policy that
    /// permits one rather than trusting a caller to get it right. So without a
    /// relay there is no call, and saying so is better than a call that opens
    /// and discloses something.
    identity: Identity,
    relay: Option<String>,
    /// Bound lazily, the first time a call is placed or answered.
    endpoint: Option<RotelyxEndpoint>,
    /// Which call is in progress. Two people pressing call at the same moment
    /// produce two, and without this the answer to one ends the other.
    call_id: String,
    /// Stops the task carrying the audio. Dropping it ends the call.
    call_stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// Whether to tell the other side their messages were read.
    ///
    /// Off unless asked for. A receipt is one more envelope per read, which is
    /// something the operator of a mailbox counts, and the phone client makes
    /// the same trade with the same default.
    receipts: bool,
    /// Tags already subscribed to, so a rotation sends only what is new.
    ///
    /// Re-sending the whole set every commit is harmless on the wire and is
    /// exactly the burst an operator would most like to see.
    listening: Vec<String>,
    /// Key packages already admitted, so one guest is one member.
    ///
    /// A key package is single use, so this is an identity for exactly as long
    /// as it needs to be: the same guest knocking twice presents the same one,
    /// and a second guest cannot.
    admitted: Vec<String>,
    /// Envelopes handed back by a subscribe, waiting to be handled.
    ///
    /// Not handled where they arrive: a subscribe happens part way through
    /// handling another envelope, and handling these there would mean a
    /// recursion whose depth is whatever the mailbox held. The loop drains
    /// them.
    queued: Vec<String>,
    subscribed_bucket: u64,
    events: Arc<dyn Fn(Event) + Send + Sync>,
}

impl Meeting {
    async fn deposit_rendezvous(
        &self,
        mailbox: &mut Mailbox,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let json = serde_json::to_vec(payload)?;
        let sealed = seal_under(&self.tag, &b64(&json)).map_err(to_anyhow)?;
        mailbox.deposit(&sealed).await
    }

    /// Route by tag, not by phase.
    ///
    /// The post-quantum commit is deposited at the meeting tag but lands after
    /// the conversation already exists. Deciding on state would drop it in
    /// silence and leave this side an epoch behind with nothing saying so.
    async fn incoming(&mut self, mailbox: &mut Mailbox, envelope: &str) -> Result<()> {
        if let Ok(payload) = open_under(envelope, &self.tag) {
            return self.rendezvous(mailbox, &payload).await;
        }
        self.conversation(mailbox, envelope).await
    }

    async fn rendezvous(&mut self, mailbox: &mut Mailbox, payload_b64: &str) -> Result<()> {
        let Ok(bytes) = unb64(payload_b64) else {
            return Ok(());
        };
        let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Ok(());
        };

        match msg["t"].as_str() {
            // The host answers a knock, and keeps answering for the life of the
            // conversation so somebody can arrive after it is established.
            Some("hello") if self.role == Role::Host => {
                let (Some(key_package), Some(hybrid)) = (
                    msg["keyPackage"].as_str(),
                    msg["hybridPublicKey"].as_str(),
                ) else {
                    return Ok(());
                };
                // A hello this side has already answered.
                //
                // Admitting it again adds the same person a second time, which
                // MLS is happy to do: it is a second member with a second leaf,
                // at a third epoch, and the phone that sent both hellos ends up
                // holding two conversations with the same name and receiving
                // messages in neither. Seen on a real phone, which showed two
                // identical entries and no messages in either.
                //
                // A repeated hello means the guest has not heard the welcome
                // yet. That welcome is already at the meeting tag and the
                // mailbox holds it, so the answer is to leave it there.
                if self.admitted.iter().any(|seen| seen == key_package) {
                    tracing::info!("a repeated hello, already admitted");
                    println!("  hello: repeated, ignored");
                    return Ok(());
                }
                self.admitted.push(key_package.to_string());
                tracing::info!(
                    admitted = self.admitted.len(),
                    "admitting a guest"
                );
                println!(
                    "  hello: new key package, admitting (that makes {})",
                    self.admitted.len()
                );

                let name = msg["name"].as_str().unwrap_or("anon").to_string();
                self.admit(mailbox, &name, key_package, hybrid).await
            }

            Some("welcome") if self.role == Role::Guest && !self.joined => {
                let (Some(welcome), Some(tree)) =
                    (msg["welcome"].as_str(), msg["ratchetTree"].as_str())
                else {
                    return Ok(());
                };

                self.session.join(welcome, tree).map_err(to_anyhow)?;

                // Staging must precede the commit: MLS looks the pre-shared key
                // up by id and refuses the commit outright if it is missing,
                // rather than quietly continuing without the post-quantum layer.
                if let Some(pq) = msg["pqCiphertext"].as_str() {
                    self.session.open_pq(pq).map_err(to_anyhow)?;
                }

                let peer = msg["name"].as_str().unwrap_or("anon").to_string();
                self.enter(mailbox, peer).await
            }

            Some("commit") if self.role == Role::Guest => {
                let Some(commit) = msg["commit"].as_str() else {
                    return Ok(());
                };
                // A commit that will not apply leaves this side an epoch behind,
                // and the safety number stops matching, which is the signal that
                // matters and is already on screen.
                if self.session.receive(commit).is_ok() {
                    self.resubscribe(mailbox).await?;
                }
                Ok(())
            }

            _ => Ok(()),
        }
    }

    /// Admit a member and hand them everything they need, in the order they
    /// need it.
    async fn admit(
        &mut self,
        mailbox: &mut Mailbox,
        name: &str,
        key_package: &str,
        hybrid_public_key: &str,
    ) -> Result<()> {
        let founding = !self.joined;
        let invitation = self.session.invite(key_package).map_err(to_anyhow)?;

        // Who arrived, and how many are in the conversation now.
        //
        // Said rather than counted silently: a commit can remove one member and
        // add another at once, so a number on its own can report "2 members"
        // while the person on the other side has been replaced. See ADV-7 in the
        // threat model. It is also the only thing that shows a guest arriving
        // twice, which is what a phone did while both ends looked healthy.
        (self.events)(Event::GroupChanged {
            members: self.session.member_count(),
            added: vec![name.to_string()],
            removed: Vec::new(),
        });

        if founding {
            // One encapsulation establishes the post-quantum secret, and the
            // welcome carries it so the joiner can stage it before the commit
            // lands.
            let pq = self
                .session
                .encapsulate_to(hybrid_public_key)
                .map_err(to_anyhow)?;

            self.deposit_rendezvous(
                mailbox,
                &serde_json::json!({
                    "t": "welcome",
                    "name": "desktop",
                    "welcome": invitation.welcome,
                    "ratchetTree": invitation.ratchet_tree,
                    "pqCiphertext": pq,
                }),
            )
            .await?;

            let commit = self.session.commit_pq().map_err(to_anyhow)?;
            self.deposit_rendezvous(mailbox, &serde_json::json!({"t": "commit", "commit": commit}))
                .await?;

            // And again, addressed to where the guest actually is.
            //
            // The line above is what the phone client expects and it is not
            // enough on its own. The guest stops listening at the meeting place
            // the moment it processes the welcome, and this commit was
            // deposited a few milliseconds earlier: whether it arrives before
            // that unsubscribe takes effect is a race with the server, not
            // something either side controls.
            //
            // Losing it is close to invisible. The group id does not change, so
            // both sides show the same safety number and both say the
            // conversation is established. The guest is simply one epoch behind
            // for the rest of its life, and messages it sends are still read,
            // because the other side polls a window that reaches back. Messages
            // sent to it are addressed to an epoch it never reached and are
            // never collected by anyone. That is exactly what a real phone did:
            // paired, agreed the safety number, sent messages that arrived, and
            // received nothing.
            //
            // `seal_commit_for_group` addresses one epoch back, which is where
            // somebody who has not applied this commit still is, so this reaches
            // the guest through the conversation rather than the meeting place.
            // Arriving twice is harmless: the second one will not apply and is
            // dropped where every unusable commit is dropped.
            let bucket = bucket()?;
            match self.session.seal_commit_for_group(&commit, bucket) {
                Ok(envelopes) => {
                    for envelope in envelopes {
                        mailbox.deposit(&envelope).await?;
                    }
                }
                // Said rather than swallowed. This was written as an empty arm
                // on the reasoning that it could not happen, which is how a
                // belt-and-braces delivery came to do nothing at all while the
                // guest sat an epoch behind.
                Err(e) => tracing::warn!(
                    error = %error_text(&e),
                    "the commit could not be addressed to the guest through the conversation"
                ),
            }

            return self.enter(mailbox, name.to_string()).await;
        }

        // A later arrival. The members already present have not applied this
        // commit, so they are still an epoch behind and must be addressed
        // there. Addressing them at the new epoch would deposit under a tag
        // nobody listens on, and the group would split with this side one epoch
        // ahead and nothing saying so.
        self.deposit_rendezvous(
            mailbox,
            &serde_json::json!({
                "t": "welcome",
                "name": "desktop",
                "welcome": invitation.welcome,
                "ratchetTree": invitation.ratchet_tree,
            }),
        )
        .await?;

        let bucket = bucket()?;
        for envelope in self
            .session
            .seal_commit_for_group(&invitation.commit, bucket)
            .map_err(to_anyhow)?
        {
            mailbox.deposit(&envelope).await?;
        }
        self.resubscribe(mailbox).await
    }

    /// The conversation exists. Move off the meeting place and onto the group's
    /// own tags.
    async fn enter(&mut self, mailbox: &mut Mailbox, peer: String) -> Result<()> {
        // A guest stops listening at the meeting place; the host does not, so
        // somebody can arrive later. A guest still listening would read a knock
        // meant for the host, and acknowledging it would take it away from
        // them entirely.
        //
        // The tag itself is deliberately kept either way: the host deposits the
        // welcome and the commit back to back, so the commit is already in
        // flight when the guest lands here. Unsubscribing is a frame sent to the
        // server and does not recall what the server already pushed. Forgetting
        // the tag would leave that commit unrecognisable as rendezvous traffic,
        // dropped in silence, with the post-quantum secret never mixed in and
        // the only symptom a safety number that disagrees.
        if self.role == Role::Guest {
            mailbox.unsubscribe(&[self.tag.clone()]).await?;
        }

        self.joined = true;
        self.label = peer.clone();
        self.write_down();

        // Bound now rather than when a call is placed.
        //
        // Registering with a relay takes a moment, and the moment a call needs
        // it is the moment it is least able to wait: a ring arrives, an answer
        // goes out with an address in it, and the far side dials at once. Doing
        // it here spends that time while nobody is waiting.
        if self.relay.is_some() {
            if let Err(e) = self.endpoint().await {
                (self.events)(Event::Status {
                    text: format!("calls are not available: {e:#}"),
                });
            }
        }

        // Which epoch this side is at, and where it expects to be written to.
        //
        // Both are derived from the group, so two sides that disagree about
        // either will pair, agree a safety number, and never deliver anything.
        // Printed because the alternative is guessing at it from silence.
        tracing::debug!(
            epoch = self.session.epoch(),
            mine = ?self.session.my_polling_tags(bucket()?, LOOKBACK).map(|t| t.len()),
            theirs = ?self.session.recipient_tags(bucket()?).map(|t| t.len()),
            "the conversation exists"
        );
        (self.events)(Event::Connected {
            peer,
            safety_number: self.session.safety_number().map_err(to_anyhow)?,
            // Never direct. This is a mailbox, and a call is refused rather than
            // started over something that cannot carry one.
            direct: false,
        });

        self.resubscribe(mailbox).await
    }

    /// Listen on our own tags for the current window.
    ///
    /// Only the tags not already held are sent. Re-subscribing to one already
    /// held is harmless on the wire but makes every epoch change re-send the
    /// whole set, which is the burst an operator would most like to see.
    ///
    /// What was already waiting under those tags comes back from the subscribe
    /// itself, and is queued rather than dropped. This is where the first
    /// message of a conversation lives: the other side deposits it the moment
    /// it joins, which is before this side has finished subscribing to the tag
    /// it went to. Dropping it left the conversation silent with both ends
    /// believing they were in it.
    async fn resubscribe(&mut self, mailbox: &mut Mailbox) -> Result<()> {
        let bucket = bucket()?;
        let now = self
            .session
            .my_polling_tags(bucket, LOOKBACK)
            .map_err(to_anyhow)?;

        let fresh: Vec<String> = now
            .into_iter()
            .filter(|tag| !self.listening.contains(tag))
            .collect();

        if !fresh.is_empty() {
            let waiting = mailbox.subscribe(&fresh).await?;
            self.listening.extend(fresh);
            self.queued.extend(waiting);
        }
        self.subscribed_bucket = bucket;
        Ok(())
    }

    async fn conversation(&mut self, mailbox: &mut Mailbox, envelope: &str) -> Result<()> {
        if !self.joined {
            return Ok(());
        }

        let bucket = bucket()?;
        // Not addressed to us in this window. Ignored rather than reacted to,
        // because reacting is itself a signal.
        let Ok(payload) = self.session.open_mine(envelope, bucket, LOOKBACK) else {
            return Ok(());
        };

        let received = match self.session.receive(&payload) {
            Ok(json) => json,
            Err(e) => {
                (self.events)(Event::Error {
                    text: format!("a message failed to decrypt: {}", error_text(&e)),
                });
                return Ok(());
            }
        };

        // One unreadable answer is one lost message, not a dead session.
        //
        // This was `?`, which ended the whole conversation: a message the core
        // could not describe took the window with it, and the only sign was the
        // parser's complaint in the transcript and a compose box that no longer
        // did anything. Whatever is wrong with one message, the next one may be
        // fine, and the person is still in a conversation either way.
        let parsed: serde_json::Value = match serde_json::from_str(&received) {
            Ok(parsed) => parsed,
            Err(e) => {
                (self.events)(Event::Error {
                    text: format!("a message could not be read: {e}"),
                });
                return Ok(());
            }
        };
        match parsed["kind"].as_str() {
            Some("message") => {
                if let Some(text) = parsed["text"].as_str() {
                    // A control message is not something a person wrote.
                    //
                    // Read receipts, reactions and profile pictures travel as
                    // ordinary messages carrying a marker, so a client that does
                    // not know the marker shows them as a line of gibberish in
                    // the middle of a conversation. That is what this did.
                    if is_control(text) {
                        // Not shown, but not necessarily ignored. A ring is a
                        // control message: discarding every one of them is what
                        // made this side unable to answer a call at all.
                        let text = text.to_string();
                        return self.on_control(mailbox, &text).await;
                    }

                    (self.events)(Event::Message { text: text.into() });
                    self.remember(text, false);

                    // Say it was read, if this window says receipts at all.
                    //
                    // Off unless asked for, the same default the phone client
                    // keeps and for the same reason it states: a receipt is one
                    // more envelope per read, and envelopes are what an operator
                    // counts. Sent only in answer to something a person wrote,
                    // so two clients cannot acknowledge each other forever.
                    if self.receipts {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|since| since.as_millis())
                            .unwrap_or(0);
                        let receipt = format!("{SIGNAL_MARKER}{SIGNAL_SEP}read{SIGNAL_SEP}{now}");
                        if let Err(e) = self.deposit_message(mailbox, &receipt).await {
                            tracing::warn!(error = %e, "the read receipt did not go out");
                        }
                    }
                }
            }
            Some("membership") => {
                (self.events)(Event::GroupChanged {
                    members: parsed["members"].as_u64().unwrap_or(0) as usize,
                    added: strings(&parsed["added"]),
                    removed: strings(&parsed["removed"]),
                });
                // The epoch moved, so our tags moved with it.
                self.resubscribe(mailbox).await?;
                self.say_who_is_here();
            }
            _ => {
                // Nothing to show, but the epoch may still have moved under it.
                self.resubscribe(mailbox).await?;
            }
        }
        Ok(())
    }

    async fn command(&mut self, mailbox: &mut Mailbox, command: Command) -> Result<()> {
        match command {
            Command::Send { text } => {
                if !self.joined {
                    bail!("there is no conversation yet");
                }
                self.deposit_message(mailbox, &text).await
            }

            // Not yet, and the reason this used to give was wrong.
            //
            // It said a mailbox cannot carry a call, which is true and is not
            // the point: nobody was proposing to send audio through it. The
            // phone client rings by sending a `call` signal through MLS with a
            // relay address inside it, and the audio goes over that relay. The
            // mailbox carries one more envelope of the same padded size, which
            // is all it is being asked to do.
            //
            // So this is missing work, not an impossibility. What it takes is
            // this side binding an endpoint of its own, answering the ring with
            // its address, and handing the two to the media layer, which is
            // what `engine.rs` already does on the other transport.
            // The invitation goes through MLS and the audio goes over the
            // relay. The mailbox carries one more envelope of the same padded
            // size, which is all it is being asked to do.
            Command::StartCall => {
                if let Err(e) = self.place_call(mailbox).await {
                    (self.events)(Event::Error {
                        text: format!("cannot call: {e:#}"),
                    });
                }
                Ok(())
            }

            Command::EndCall => self.end_call(mailbox, true).await,

            // Hanging up ends the call and the session both. Telling them the
            // call is over first, because the conversation goes with it and
            // there will be nothing left to say it afterwards.
            Command::Hangup => self.end_call(mailbox, true).await,

            Command::WhoIsHere => {
                self.say_who_is_here();
                Ok(())
            }

            // Removal is a commit, not a local setting.
            //
            // A device that is gone is a leaf that can still decrypt, and
            // forgetting it here would change nothing about that: the key
            // schedule includes it until the group says otherwise. So this
            // moves the epoch, and the commit goes to the members who have not
            // applied it, which is all of them, one epoch back.
            Command::Remove { key } => {
                if !self.joined {
                    bail!("there is no conversation yet");
                }
                let commit = self.session.remove_member(&key).map_err(to_anyhow)?;

                let bucket = bucket()?;
                for envelope in self
                    .session
                    .seal_commit_for_group(&commit, bucket)
                    .map_err(to_anyhow)?
                {
                    mailbox.deposit(&envelope).await?;
                }

                self.resubscribe(mailbox).await?;
                self.say_who_is_here();
                Ok(())
            }
        }
    }

    /// Keep one line, and write the conversation down.
    ///
    /// After every message rather than on a timer or on exit. The ratchet turns
    /// on both sending and receiving, so a copy saved a message late cannot
    /// decrypt what comes next, and a window that is killed rather than closed
    /// is an ordinary way for a program to end.
    fn remember(&mut self, text: &str, mine: bool) {
        self.lines.push(Line {
            text: text.to_string(),
            mine,
            at: chats::now(),
        });
        self.write_down();
    }

    fn write_down(&mut self) {
        if !self.joined || self.keeping.is_none() {
            return;
        }

        let members = self.session.member_count();
        let saved = {
            let (identity, key) = self.keeping.as_ref().expect("checked above");
            chats::save(
                identity,
                key,
                &self.session,
                &self.label,
                &self.mailbox_url,
                members,
                &self.lines,
            )
        };

        if let Err(e) = saved {
            // Said rather than swallowed: a conversation that is not being
            // written down is one that will not be in the list after a restart,
            // and now is the only moment anybody could act on that.
            (self.events)(Event::Error {
                text: format!("this conversation is not being saved: {e:#}"),
            });
        }
    }

    /// A message from a client rather than from a person.
    ///
    /// The wire format is the phone client's: the marker, the kind, and the
    /// fields, joined by a unit separator. Only calls are acted on here. A read
    /// receipt has nowhere to go in this window, and a kind from a newer build
    /// is dropped rather than shown, which is what an unknown kind is for.
    async fn on_control(&mut self, mailbox: &mut Mailbox, body: &str) -> Result<()> {
        let mut parts = body.split(SIGNAL_SEP);
        let (Some(_marker), Some(kind)) = (parts.next(), parts.next()) else {
            return Ok(());
        };
        if kind != "call" {
            tracing::debug!(kind, "a control message this window does nothing with");
            return Ok(());
        }

        let what = parts.next().unwrap_or_default().to_string();
        let id = parts.next().unwrap_or_default().to_string();
        let address = parts.next().unwrap_or_default().to_string();

        let outcome = match what.as_str() {
            "ringing" => {
                if address.is_empty() {
                    // A ring with nowhere to connect is a ring from a build that
                    // does not carry addresses. Nothing to answer.
                    Ok(())
                } else {
                    (self.events)(Event::Status {
                        text: "they are calling".into(),
                    });
                    self.answer_call(mailbox, &id, &address).await
                }
            }
            "answered" => self.take_call(&id, &address).await,
            "declined" => {
                (self.events)(Event::Status {
                    text: "they declined".into(),
                });
                self.end_call(mailbox, false).await
            }
            "ended" => self.end_call(mailbox, false).await,
            // A heartbeat while it rings. Nothing to do with it here: this side
            // answers immediately or not at all.
            "stillRinging" => Ok(()),
            other => {
                tracing::debug!(other, "a call state from a newer build");
                Ok(())
            }
        };

        if let Err(e) = outcome {
            // A call that will not open is one error, not a dead conversation.
            (self.events)(Event::Error {
                text: format!("{e:#}"),
            });
            let _ = self.end_call(mailbox, false).await;
        }
        Ok(())
    }

    /// Bind this side's endpoint, once, for calls.
    ///
    /// Lazily rather than at startup: a conversation that never calls should
    /// never open a socket, and a window with no relay configured should fail
    /// when somebody asks for a call rather than when it starts.
    async fn endpoint(&mut self) -> Result<&RotelyxEndpoint> {
        if self.endpoint.is_none() {
            let relay = self
                .relay
                .as_deref()
                .map(str::trim)
                .filter(|relay| !relay.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "a call needs a relay. Without one the only path is direct, \
                         and a direct path hands the other party this machine's address"
                    )
                })?;

            let url: RelayUrl = relay
                .parse()
                .map_err(|_| anyhow::anyhow!("{relay} is not a relay address"))?;

            // Relay only, never "relay preferred". A call either goes through
            // the relay for its whole life or is refused at the start, rather
            // than depending on whether hole punching happened to succeed.
            let config = NetConfig::new(RelayPolicy::SelfHosted(vec![url]), PathPolicy::RelayOnly);
            let endpoint = RotelyxEndpoint::bind(&self.identity, config).await?;

            // Bound is not reachable.
            //
            // An address naming a relay is a promise until that relay has
            // completed its handshake and knows which connection belongs to this
            // endpoint id. Publishing before then hands the other side an
            // address the relay cannot route, and they dial it immediately,
            // because an answer is what they were waiting for. The dial fails
            // while both ends believe they agreed on a call.
            //
            // Ten seconds, and not fatal if it passes: the endpoint may still be
            // reachable and there is nothing better to publish either way. What
            // matters is that the common case waits.
            if !endpoint.online(Duration::from_secs(10)).await {
                (self.events)(Event::Status {
                    text: "the relay has not answered yet, so a call may not connect".into(),
                });
            }

            self.endpoint = Some(endpoint);
        }
        Ok(self.endpoint.as_ref().expect("just bound"))
    }

    /// Send one call signal, the way the phone client writes them.
    async fn signal_call(
        &mut self,
        mailbox: &mut Mailbox,
        what: &str,
        id: &str,
        address: &str,
    ) -> Result<()> {
        let body = format!(
            "{SIGNAL_MARKER}{SIGNAL_SEP}call{SIGNAL_SEP}{what}{SIGNAL_SEP}{id}{SIGNAL_SEP}{address}"
        );
        self.deposit_message(mailbox, &body).await
    }

    /// The key material a call is opened with, derived from the group.
    ///
    /// Both sides reach the same answer from state they already share, so no
    /// index is negotiated and the two cannot disagree about who is who.
    fn call_keys(&self) -> Result<([u8; 32], u8)> {
        let base = self.session.media_base_key().map_err(to_anyhow)?;
        let index = self.session.sender_index().map_err(to_anyhow)?;
        let index = u8::try_from(index).context("more members than a sender index can hold")?;
        Ok((base, index))
    }

    /// Ring somebody.
    async fn place_call(&mut self, mailbox: &mut Mailbox) -> Result<()> {
        if self.call_stop.is_some() {
            bail!("already on a call");
        }
        let address = {
            let endpoint = self.endpoint().await?;
            crate::encode_addr(&filtered(endpoint.addr(), self.relay.as_deref()))?
        };

        let id = call_id()?;
        self.call_id = id.clone();
        self.signal_call(mailbox, "ringing", &id, &address).await?;

        (self.events)(Event::Status {
            text: "ringing".into(),
        });
        Ok(())
    }

    /// Somebody is ringing us, and told us where to reach them.
    async fn answer_call(&mut self, mailbox: &mut Mailbox, id: &str, address: &str) -> Result<()> {
        if self.call_stop.is_some() {
            // Busy. Said rather than ignored, or their phone rings until it
            // gives up and neither person knows why.
            self.signal_call(mailbox, "declined", id, "").await?;
            return Ok(());
        }

        let (base, index) = self.call_keys()?;

        // The answer carries this side's address, and then this side waits.
        //
        // The caller connects and the receiver waits, which is the phone
        // client's rule and is written down in its `calls.dart`. This was built
        // the other way round at first: answering with nothing and then dialling
        // the address that came on the ring. Both ends then sat waiting for a
        // connection neither was making, and it showed up as `connecting to
        // 624f...: timed out`.
        //
        // The address on the ring is still worth having, because it is what says
        // the far side can be reached at all, but it is not what this side
        // dials.
        let _ = address;

        let mine = {
            let endpoint = self.endpoint().await?;
            crate::encode_addr(&filtered(endpoint.addr(), self.relay.as_deref()))?
        };

        self.call_id = id.to_string();
        self.signal_call(mailbox, "answered", id, &mine).await?;

        // Waiting for the connection and not for a stream on it.
        //
        // A call is datagrams alone. Waiting for a stream means waiting for the
        // other side to write something it has no reason to write: the phone
        // client opens one and never does, so this sat here until it gave up
        // while the phone believed it was connected and sent audio nobody was
        // reading.
        let (_peer, conn) = {
            let endpoint = self.endpoint().await?;
            tokio::time::timeout(Duration::from_secs(25), endpoint.accept_media())
                .await
                .map_err(|_| anyhow::anyhow!("they rang and then never connected"))??
        };

        self.begin_call(base, index, conn)
    }

    /// They answered what this side placed. Connect to where they said.
    ///
    /// The caller connects and the receiver waits, so this is the dialling half.
    async fn take_call(&mut self, id: &str, address: &str) -> Result<()> {
        if self.call_stop.is_some() || self.call_id != id {
            return Ok(());
        }
        if address.is_empty() {
            bail!("they answered without saying where to reach them");
        }

        let (base, index) = self.call_keys()?;
        let target = crate::decode_addr(address)?;

        let conn = {
            let endpoint = self.endpoint().await?;
            let mut session = endpoint.connect(target).await?;

            // One frame, so the stream exists.
            //
            // `connect` opens a bidirectional stream and writes nothing, and in
            // QUIC a stream opened by the dialler does not exist for the peer
            // until its first byte arrives. So the far side sat in `accept_bi`
            // forever while this side believed it was connected and started
            // sending audio into a call nobody had opened. Every other caller of
            // this API uses `connect_with`, which sends admission evidence
            // immediately and never notices.
            //
            // Nothing is being said here. The frame is the byte.
            session
                .send(&rotelyx_core::wire::Frame::new(
                    rotelyx_core::wire::FrameKind::Hello,
                    Vec::new(),
                ))
                .await?;
            let (_send, _recv, conn) = session.split_for_chat();
            conn
        };

        self.begin_call(base, index, conn)
    }

    /// Hand the audio to a task of its own.
    ///
    /// The mailbox loop takes turns of a quarter second, which is fine for a
    /// message and is ten frames of audio. A call cannot wait its turn, so it
    /// gets a task that does nothing else.
    fn begin_call(
        &mut self,
        base: [u8; 32],
        index: u8,
        conn: rotelyx_net::Connection,
    ) -> Result<()> {
        // The identifier this call was rung with, which the other side echoed
        // back and both ends therefore hold. Without it the media keys would be
        // a function of the MLS epoch alone, and a second call inside one epoch
        // would repeat every nonce of the first.
        let binding = rotelyx_audio::Binding::new(self.call_id.as_bytes())
            .context("this call has no identifier to key it with")?;

        let call = rotelyx_audio::Call::start(base, index, binding, PathPolicy::RelayOnly)
            .context("opening the microphone")?;

        (self.events)(Event::CallStarted {
            kbit: call.kbit_per_second(),
            mono: call.microphone_is_mono(),
        });

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        self.call_stop = Some(stop_tx);
        tokio::spawn(carry_call(call, conn, self.events.clone(), stop_rx));
        Ok(())
    }

    /// End whatever is running, and say so on the wire if asked to.
    async fn end_call(&mut self, mailbox: &mut Mailbox, tell_them: bool) -> Result<()> {
        let was = self.call_stop.take();
        if was.is_none() {
            return Ok(());
        }
        // Dropping the sender is what the task waits on.
        drop(was);

        if tell_them && !self.call_id.is_empty() {
            let id = self.call_id.clone();
            self.signal_call(mailbox, "ended", &id, "").await?;
        }
        self.call_id.clear();
        Ok(())
    }

    /// Tell the window who is in the conversation.
    ///
    /// With the key each is removed by, not only the label: two members can
    /// choose the same label, and a label is not what removal takes.
    fn say_who_is_here(&self) {
        let detail = match self.session.roster_detail() {
            Ok(json) => json,
            Err(e) => {
                (self.events)(Event::Error {
                    text: format!("could not read the roster: {}", error_text(&e)),
                });
                return;
            }
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&detail).unwrap_or_default();
        let members = parsed
            .into_iter()
            .map(|entry| Present {
                label: entry["label"].as_str().unwrap_or("anon").to_string(),
                key: entry["key"].as_str().unwrap_or_default().to_string(),
            })
            .collect();

        (self.events)(Event::Members { members });
    }

    /// Encrypt one body and leave it for every other member.
    ///
    /// Shared by what a person typed and by the receipts this side sends back,
    /// because on the wire they are the same thing: an application message. The
    /// only difference is the marker at the front, which is what keeps a receipt
    /// out of the transcript.
    async fn deposit_message(&mut self, mailbox: &mut Mailbox, body: &str) -> Result<()> {
        let ciphertext = self.session.send(body).map_err(to_anyhow)?;
        if !is_control(body) {
            self.remember(body, true);
        }
                let bucket = bucket()?;

                // Said out loud, because a message that goes nowhere looks
                // exactly like a message that was never sent. These are the
                // tags the other members should be listening on, and asking the
                // mailbox for one of them afterwards says which of those two
                // happened. See `is_anything_waiting`.
                if let Ok(tags) = self.session.recipient_tags(bucket) {
                    tracing::info!(bucket, ?tags, "depositing a message");
                    println!("  deposited to {tags:?} at bucket {bucket}");
                }

        let mut envelopes = self
            .session
            .seal_for_group(&ciphertext, bucket)
            .map_err(to_anyhow)?;

        // Shuffled before they go.
        //
        // A sender index is this member's position in the sorted roster, and
        // `seal_for_group` returns the envelopes in that order. Depositing them
        // in it tells the operator each recipient's position, which is a stable
        // label for a member that survives every tag rotation. Shuffling costs
        // one pass over a short vector and takes that away.
        //
        // It does not hide that these deposits belong together. They still
        // arrive in a burst from one connection, which is the residual the
        // threat model names and this does not close.
        shuffle(&mut envelopes)?;

        for envelope in envelopes {
            mailbox.deposit(&envelope).await?;
        }
        Ok(())
    }
}

/// Carry one call until somebody ends it.
///
/// Sends whatever the microphone has ready every twenty milliseconds and reads
/// datagrams as they arrive. Reading happens whether or not there is anything to
/// do with them, because a datagram nobody reads is one the peer keeps retrying.
async fn carry_call(
    mut call: rotelyx_audio::Call,
    conn: rotelyx_net::Connection,
    events: Arc<dyn Fn(Event) + Send + Sync>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Reported while it runs because it is the one number that says what a
    // person is about to hear: a figure that keeps climbing is the call falling
    // behind, and after the call it is too late to know.
    let mut since_report = 0u32;

    let reason = loop {
        tokio::select! {
            _ = &mut stop => break None,

            _ = tick.tick() => {
                if let Err(e) = call.send_all_ready(&conn) {
                    break Some(format!("{e:#}"));
                }
                since_report += 1;
                if since_report >= 25 {
                    since_report = 0;
                    events(Event::CallLevel { queued_ms: call.queued_ms() });
                }
            }

            datagram = conn.read_datagram() => {
                match datagram {
                    Ok(bytes) => call.receive_one(bytes.as_ref()),
                    Err(e) => break Some(format!("the connection closed: {e}")),
                }
            }
        }
    };

    events(Event::CallEnded {
        sent: call.frames_sent(),
        received: call.frames_received(),
        concealed: call.frames_concealed(),
        queued_ms: call.queued_ms(),
        dropped_ms: call.dropped_ms(),
    });
    if let Some(reason) = reason {
        events(Event::Error {
            text: format!("call ended: {reason}"),
        });
    }
}

/// Sixteen characters of call name.
///
/// Two people pressing call at the same moment produce two calls, and without a
/// name the answer to one ends the other.
fn call_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    // No fallback. This used to return "unnamed" when the system had no
    // randomness, which was harmless while the identifier only told two
    // simultaneous calls apart. It is not harmless now: the identifier is what
    // keys the media, and a constant one puts every call back on the same key
    // and the same nonces. A call that cannot be named cannot be placed.
    getrandom::fill(&mut bytes).context("no randomness to name this call with")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// An address with the IP addresses taken out and the relay left in.
///
/// Not tidiness. An `EndpointAddr` carries whatever the endpoint knows about
/// reaching itself, which on an ordinary machine includes its address on the
/// local network. Publishing that to whoever is being called hands them a
/// location, on the one configuration whose whole purpose is not revealing it.
/// The phone client filters the same fields for the same reason.
fn filtered(mut addr: rotelyx_net::EndpointAddr, relay: Option<&str>) -> rotelyx_net::EndpointAddr {
    addr.addrs
        .retain(|a| !matches!(a, rotelyx_net::TransportAddr::Ip(_)));

    // Taking the IPs out leaves nothing to route on: the address is read the
    // moment the endpoint binds, and the relay connection is not established
    // yet. The relay from the configuration is the right thing to publish. It is
    // where this endpoint can be reached, it is already public, and it is what
    // the other side will use.
    if let Some(relay) = relay.and_then(|relay| relay.trim().parse::<RelayUrl>().ok()) {
        addr.addrs.insert(rotelyx_net::TransportAddr::Relay(relay));
    }
    addr
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The message inside a `wasm_bindgen` error, which is a `JsValue` in the
/// browser and a plain string everywhere else.
fn error_text(error: &rotelyx_wasm::Error) -> String {
    error.to_string()
}

fn to_anyhow(error: rotelyx_wasm::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", error_text(&error))
}

/// Standard base64 with padding, which is what the phone client's
/// `base64Encode` produces and what the core decodes. Not the URL alphabet the
/// rest of this crate uses for invitations: the two are not interchangeable and
/// a rendezvous payload written in the wrong one is refused at the far end with
/// nothing on screen to say which of the two clients was wrong.
fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    Ok(data_encoding::BASE64.decode(text.as_bytes())?)
}

#[cfg(test)]
mod tests {
    //! Two sides meeting through the mailbox server in this repository.
    //!
    //! # Why against the real server
    //!
    //! The whole point of this module is that two implementations could not
    //! talk. A mock would be a third implementation of the same guesses, and
    //! the guesses are exactly what needs checking: three of them were wrong
    //! when the mailbox client was written, and every one was caught by running
    //! it rather than by reading it.
    //!
    //! What these do not prove is agreement with the phone client, which is a
    //! separate implementation in Dart. Both sides here are this file. The
    //! shapes on the wire were taken from `lib/rotelyx/rotelyx_service.dart`,
    //! and the only thing that establishes they were taken correctly is a real
    //! phone meeting a real desktop.

    use super::*;
    use std::process::{Child, Stdio};

    struct Server {
        child: Child,
        url: String,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    async fn start(port: u16) -> Option<Server> {
        let binary = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/debug/rotelyx-mailbox-server"
        );
        if !std::path::Path::new(binary).exists() {
            println!("\n  no mailbox server built, skipping: cargo build -p rotelyx-mailbox-server");
            return None;
        }

        let child = std::process::Command::new(binary)
            .args(["--bind", &format!("127.0.0.1:{port}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let url = format!("ws://127.0.0.1:{port}/mailbox");
        for _ in 0..60 {
            if Mailbox::connect(&url).await.is_ok() {
                return Some(Server { child, url });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// Collect what one side told the window, so a test can assert on it.
    fn recorder() -> (Arc<dyn Fn(Event) + Send + Sync>, Arc<std::sync::Mutex<Vec<Event>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        (
            Arc::new(move |event| sink.lock().expect("not poisoned").push(event)),
            seen,
        )
    }

    fn safety_numbers(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Connected { safety_number, .. } => Some(safety_number.clone()),
                _ => None,
            })
            .collect()
    }

    fn messages(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Message { text } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    /// The shuffle actually moves things, and never loses one.
    ///
    /// A shuffle that quietly returned its input would be the worst kind of
    /// fix: the order it exists to remove would still be there and the comment
    /// would say otherwise.
    #[test]
    fn deposits_are_not_left_in_roster_order() {
        let mut moved = 0;
        for _ in 0..40 {
            let mut items: Vec<u8> = (0..16).collect();
            shuffle(&mut items).expect("randomness");

            let mut back = items.clone();
            back.sort_unstable();
            assert_eq!(back, (0..16).collect::<Vec<u8>>(), "the shuffle lost one");

            if items != (0..16).collect::<Vec<u8>>() {
                moved += 1;
            }
        }
        assert!(
            moved > 35,
            "40 shuffles of 16 items left the order alone {} times",
            40 - moved
        );

        // And the degenerate sizes do not panic.
        shuffle::<u8>(&mut []).expect("empty");
        shuffle(&mut [1u8]).expect("one");
    }

    /// A code shown on one side and read on the other becomes a conversation,
    /// and a message crosses it.
    ///
    /// This is the whole feature in one test. Everything else in this module is
    /// in service of these two assertions: that both sides arrive at the same
    /// safety number, and that what one types the other reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_code_shown_and_read_becomes_a_conversation() {
        let Some(server) = start(3394).await else {
            return;
        };

        let code = rotelyx_wasm::new_meeting_code().expect("entropy");

        let (host_events, host_seen) = recorder();
        let (guest_events, guest_seen) = recorder();

        let (host_tx, mut host_rx) = mpsc::unbounded_channel();
        let (guest_tx, mut guest_rx) = mpsc::unbounded_channel();

        let host_url = server.url.clone();
        let host_code = code.clone();
        let host = tokio::spawn(async move {
            run(
                &host_code,
                "desktop",
                &host_url,
                Role::Host,
                false,
                Identity::generate(),
                None,
                None,
                host_events,
                &mut host_rx,
            )
            .await
        });

        // The reader arrives after the shower is listening, which is the order
        // the window enforces: a code on screen with nothing behind it is a
        // code somebody scans into a silence.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let guest_url = server.url.clone();
        let guest_code = code.clone();
        let guest = tokio::spawn(async move {
            run(
                &guest_code,
                "phone",
                &guest_url,
                Role::Guest,
                false,
                Identity::generate(),
                None,
                None,
                guest_events,
                &mut guest_rx,
            )
            .await
        });

        // Wait for both to say they are in, rather than sleeping a guess at how
        // long a handshake takes on a loaded machine.
        let joined = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let host_in = !safety_numbers(&host_seen.lock().expect("not poisoned")).is_empty();
                let guest_in = !safety_numbers(&guest_seen.lock().expect("not poisoned")).is_empty();
                if host_in && guest_in {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(joined.is_ok(), "the two sides never met");

        // The same conversation, seen from both ends.
        //
        // Not a formality: two sides can each believe they are in a group and
        // be in different ones, and a safety number is the only thing that says
        // so. If these ever disagree the pairing is broken in the way that
        // matters most and everything else still looks fine.
        let host_number = safety_numbers(&host_seen.lock().expect("not poisoned"))[0].clone();
        let guest_number = safety_numbers(&guest_seen.lock().expect("not poisoned"))[0].clone();
        assert_eq!(
            host_number, guest_number,
            "the two sides are not in the same conversation"
        );

        // And it carries a message. The commit is deposited immediately after
        // the welcome, so the epoch may still be moving when the guest lands:
        // send until it arrives or the time is up, rather than once into a race.
        let arrived = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                host_tx
                    .send(Command::Send {
                        text: "from the desktop".into(),
                    })
                    .expect("the host is running");

                for _ in 0..20 {
                    if messages(&guest_seen.lock().expect("not poisoned"))
                        .iter()
                        .any(|text| text == "from the desktop")
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await;
        assert!(
            arrived.is_ok(),
            "the message never crossed\n  host saw: {:?}\n  guest saw: {:?}",
            host_seen.lock().expect("not poisoned"),
            guest_seen.lock().expect("not poisoned"),
        );

        drop(host_tx);
        drop(guest_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), host).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
    }

    /// Is anything still waiting at a tag?
    ///
    /// Delivery peeks and removal waits for an acknowledgement, so an envelope
    /// that comes back here is one nobody has acknowledged: either nobody is
    /// listening on this tag, or somebody is and could not read what arrived.
    /// It used to mean the first of those on its own, when collection removed
    /// on delivery, and it does not any more. Reading it does not consume it,
    /// which is what makes this safe to run against a live conversation.
    ///
    ///   ROTELYX_MAILBOX=wss://... ROTELYX_TAG=<64 hex> cargo test \
    ///     -p rotelyx-desktop --bin rotelyx-desktop is_anything_waiting \
    ///     -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a live mailbox: set ROTELYX_MAILBOX and ROTELYX_TAG"]
    async fn is_anything_waiting() {
        let mailbox = std::env::var("ROTELYX_MAILBOX").expect("set ROTELYX_MAILBOX");
        let tag = std::env::var("ROTELYX_TAG").expect("set ROTELYX_TAG");

        let mut probe = Mailbox::connect(&mailbox).await.expect("connect");
        let waiting = probe.subscribe(&[tag.clone()]).await.expect("subscribe");

        println!("\n  tag {tag}");
        println!("  waiting: {}", waiting.len());
        for envelope in &waiting {
            println!("    {} bytes of base64", envelope.len());
        }
        let _ = probe.unsubscribe(&[tag]).await;
    }

    /// Two of these calling each other, to see whether audio crosses at all.
    ///
    /// Against a real relay, because a call is relay only by construction: on a
    /// direct path the other party learns this machine's address, and
    /// `rotelyx_media` refuses any policy that permits one. So there is nothing
    /// to test locally.
    ///
    /// What this answers is the question a real call left open. A phone and a
    /// desktop opened one, the desktop sent 2865 frames and received 2, and
    /// neither person heard anything. That is either the two implementations
    /// disagreeing or this side's own path being wrong, and one of those can be
    /// ruled out here without a phone in it.
    ///
    ///   ROTELYX_MAILBOX=wss://... ROTELYX_RELAY=https://... cargo test \
    ///     -p rotelyx-desktop --bin rotelyx-desktop two_desktops_calling \
    ///     -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a live mailbox and relay: set ROTELYX_MAILBOX and ROTELYX_RELAY"]
    async fn two_desktops_calling() {
        let mailbox = std::env::var("ROTELYX_MAILBOX").expect("set ROTELYX_MAILBOX");
        let relay = std::env::var("ROTELYX_RELAY").expect("set ROTELYX_RELAY");
        let code = rotelyx_wasm::new_meeting_code().expect("entropy");

        let (host_events, host_seen) = recorder();
        let (guest_events, guest_seen) = recorder();
        let (host_tx, mut host_rx) = mpsc::unbounded_channel();
        let (guest_tx, mut guest_rx) = mpsc::unbounded_channel();

        let (a, b) = (mailbox.clone(), mailbox.clone());
        let (ra, rb) = (relay.clone(), relay.clone());
        let (ca, cb) = (code.clone(), code.clone());

        let host = tokio::spawn(async move {
            run(&ca, "one", &a, Role::Host, false, Identity::generate(), Some(ra), None,
                host_events, &mut host_rx)
                .await
        });
        tokio::time::sleep(Duration::from_millis(600)).await;
        let guest = tokio::spawn(async move {
            run(&cb, "two", &b, Role::Guest, false, Identity::generate(), Some(rb), None,
                guest_events, &mut guest_rx)
                .await
        });

        let met = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let both = !safety_numbers(&host_seen.lock().expect("not poisoned")).is_empty()
                    && !safety_numbers(&guest_seen.lock().expect("not poisoned")).is_empty();
                if both {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(met.is_ok(), "the two sides never met");

        host_tx.send(Command::StartCall).expect("the host is running");

        let talking = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let both = host_seen
                    .lock()
                    .expect("not poisoned")
                    .iter()
                    .any(|e| matches!(e, Event::CallStarted { .. }))
                    && guest_seen
                        .lock()
                        .expect("not poisoned")
                        .iter()
                        .any(|e| matches!(e, Event::CallStarted { .. }));
                if both {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            talking.is_ok(),
            "the call never opened on both sides\n  one: {:?}\n  two: {:?}",
            host_seen.lock().expect("not poisoned"),
            guest_seen.lock().expect("not poisoned"),
        );

        println!("  talking. listening for twelve seconds.");
        tokio::time::sleep(Duration::from_secs(12)).await;

        host_tx.send(Command::EndCall).expect("the host is running");
        guest_tx.send(Command::EndCall).expect("the guest is running");
        tokio::time::sleep(Duration::from_secs(2)).await;

        for (who, seen) in [("one", &host_seen), ("two", &guest_seen)] {
            let ended = seen
                .lock()
                .expect("not poisoned")
                .iter()
                .rev()
                .find_map(|e| match e {
                    Event::CallEnded {
                    sent,
                    received,
                    concealed,
                    ..
                } => Some((*sent, *received, *concealed)),
                    _ => None,
                });
            match ended {
                Some((sent, received, concealed)) => {
                    println!("  {who}: sent {sent}, received {received}, concealed {concealed}");

                    // Sending proves nothing. A call that sends and receives
                    // nothing is what this test was written to catch: both ends
                    // said they were talking, one had opened a stream the other
                    // could not see, and the audio went into a connection nobody
                    // was reading. It looked like a working call from either
                    // side and neither person heard anything.
                    //
                    // Twelve seconds at fifty frames a second is six hundred.
                    // A quarter of that is loose enough for a loaded machine and
                    // far above the two frames the broken version delivered.
                    assert!(
                        sent > 100,
                        "{who} sent almost nothing: {sent}"
                    );
                    assert!(
                        received > 150,
                        "{who} received almost nothing: {received} of {sent} sent the other way"
                    );
                }
                None => panic!("{who}: the call never ended"),
            }
        }

        drop(host_tx);
        drop(guest_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), host).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
    }

    /// Meet an actual phone, at the mailbox an actual phone uses.
    ///
    /// Ignored, because it needs a person holding a phone and a network. This
    /// is the only test that says anything about the other implementation: run
    /// it, read the code it prints, type that into the phone's scanner under
    /// "or type it", and watch both ends.
    ///
    ///   ROTELYX_MAILBOX=wss://... cargo test -p rotelyx-desktop \
    ///     --bin rotelyx-desktop meet_a_real_phone -- --ignored --nocapture
    ///
    /// It prints every event as it happens and sends a message once there is
    /// somebody to send one to, so a silent pairing and a working one look
    /// different from the terminal.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a live mailbox and a phone: set ROTELYX_MAILBOX"]
    async fn meet_a_real_phone() {
        let mailbox = std::env::var("ROTELYX_MAILBOX").expect("set ROTELYX_MAILBOX");

        // Given a code, this side reads one the phone is showing. Given none, it
        // mints one for the phone to read. Both directions are worth running:
        // the two roles are not symmetric, and a fault in one of them looks
        // exactly like a fault in the transport until the other is tried.
        let (code, role) = match std::env::var("ROTELYX_MEET_CODE") {
            Ok(shown) => (
                rotelyx_wasm::read_meeting_code(&shown).expect("that is not a meeting code"),
                Role::Guest,
            ),
            Err(_) => (rotelyx_wasm::new_meeting_code().expect("entropy"), Role::Host),
        };
        println!("\n  role: {role:?}");
        tracing_subscriber::fmt()
            .with_env_filter("rotelyx_desktop=debug")
            .with_test_writer()
            .try_init()
            .ok();

        println!("\n  meeting at {mailbox}");
        println!("  code: {}", rotelyx_wasm::pretty_meeting_code(&code));
        println!("  canonical: {code}\n");

        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let events: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event| {
            println!("  event: {event:?}");
            sink.lock().expect("not poisoned").push(event);
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let running = tokio::spawn({
            let code = code.clone();
            // Receipts on, because this harness exists to watch what crosses.
            // With the identity and relay a call needs, because watching one
            // cross is what this harness is for.
            async move {
                run(&code, "desktop", &mailbox, role, true, Identity::generate(),
                    std::env::var("ROTELYX_RELAY").ok(), None, events, &mut rx)
                    .await
            }
        });

        // Send once there is somebody to send to, then keep the session up long
        // enough to type a reply on the phone and see it arrive.
        // Long enough to walk to the phone, and settable for when it is not.
        let seconds: u64 = std::env::var("ROTELYX_MEET_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(90);

        let mut sent = 0usize;
        for _ in 0..(seconds * 2) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let joined = {
                let events = seen.lock().expect("not poisoned");
                events
                    .iter()
                    .any(|event| matches!(event, Event::Connected { .. }))
            };
            if joined {
                // Every few seconds rather than once, and numbered.
                //
                // The first one, sent the instant the guest was admitted, did
                // not arrive on a real phone while a later one did. Numbering
                // them is what tells those two apart from the terminal: one
                // missing message is a race at the moment of joining, and all
                // of them missing is a direction that does not work.
                sent += 1;
                if sent % 20 == 1 {
                    tx.send(Command::Send {
                        text: format!("desktop message {}", sent / 20 + 1),
                    })
                    .expect("the session is running");
                    println!("  sent message {}", sent / 20 + 1);
                }
            }
        }

        drop(tx);
        // Reported rather than dropped. This ran for ninety seconds against the
        // production mailbox printing nothing but "connecting", because the
        // client had no TLS feature and could not open a `wss://` at all, and
        // the error was sitting in this join handle unread the whole time.
        match tokio::time::timeout(Duration::from_secs(5), running).await {
            Ok(Ok(Err(e))) => panic!("the meeting failed: {e:#}"),
            Ok(Err(e)) => panic!("the session panicked: {e}"),
            _ => {}
        }
    }

    /// A receipt is written the way the phone client reads one.
    ///
    /// Two implementations of one marker, and neither can see the other's. A
    /// receipt written with a different marker does not fail: it arrives as a
    /// line of `rx-signal` and a number in the middle of somebody's
    /// conversation, which is worse than not sending one.
    #[test]
    fn a_control_message_is_recognised_and_a_receipt_looks_like_one() {
        // The exact bytes `Signal.encode` produces in `lib/rotelyx/signal.dart`:
        // the marker, the kind, and the fields, joined by a unit separator.
        let receipt = format!("{SIGNAL_MARKER}{SIGNAL_SEP}read{SIGNAL_SEP}1787519663000");
        assert_eq!(receipt, "rx-signal\u{1f}read\u{1f}1787519663000");
        assert!(is_control(&receipt));

        for control in [
            "rx-signal\u{1f}read\u{1f}0",
            "rx-signal\u{1f}reaction\u{1f}a\u{1f}b",
            // An unknown kind is a newer build talking to an older one. Still
            // control, still not shown.
            "rx-signal\u{1f}something-later\u{1f}x",
        ] {
            assert!(is_control(control), "not recognised: {control:?}");
        }

        for written_by_a_person in [
            "",
            "hola",
            "rx-signal",
            "rx-signal is a strange thing to type but it is not a signal",
            " rx-signal\u{1f}read\u{1f}0",
        ] {
            assert!(
                !is_control(written_by_a_person),
                "a person's message was taken for a control: {written_by_a_person:?}"
            );
        }
    }

    /// A conversation survives the window closing, and can still speak.
    ///
    /// The assertion that matters is the second half. Writing a file and
    /// reading it back proves nothing: a copy resumed from disk is at
    /// generations the other side has already seen, so the test is whether a
    /// message sent after the reopen is one the other side can actually read.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_conversation_survives_being_closed() {
        let Some(server) = start(3397).await else {
            return;
        };

        let home = std::env::temp_dir().join(format!("rotelyx-chats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("a place to keep things");
        let identity = home.join("identity.key");

        let passphrase = "a passphrase long enough";
        let key = chats::key(&identity, passphrase).expect("a key");

        let code = rotelyx_wasm::new_meeting_code().expect("entropy");

        let (host_events, host_seen) = recorder();
        let (guest_events, guest_seen) = recorder();
        let (host_tx, mut host_rx) = mpsc::unbounded_channel();
        let (guest_tx, mut guest_rx) = mpsc::unbounded_channel();

        let host_url = server.url.clone();
        let host_code = code.clone();
        let host_keeping = Some((identity.clone(), key.clone()));
        let host = tokio::spawn(async move {
            run(&host_code, "desktop", &host_url, Role::Host, false, Identity::generate(), None,
                host_keeping, host_events, &mut host_rx)
                .await
        });

        tokio::time::sleep(Duration::from_millis(400)).await;

        let guest_url = server.url.clone();
        let guest_code = code.clone();
        let guest = tokio::spawn(async move {
            run(&guest_code, "phone", &guest_url, Role::Guest, false, Identity::generate(), None,
                None, guest_events, &mut guest_rx)
                .await
        });

        let met = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let both = !safety_numbers(&host_seen.lock().expect("not poisoned")).is_empty()
                    && !safety_numbers(&guest_seen.lock().expect("not poisoned")).is_empty();
                if both {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(met.is_ok(), "the two sides never met");

        host_tx
            .send(Command::Send { text: "before".into() })
            .expect("the host is running");
        tokio::time::sleep(Duration::from_secs(2)).await;

        // The window closes.
        drop(host_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), host).await;

        // And it is on the list, with what was said.
        let rows = chats::list(&identity, &key);
        assert_eq!(rows.len(), 1, "the conversation was not kept: {rows:?}");
        assert_eq!(rows[0].label, "phone");
        assert_eq!(rows[0].last, "before", "the transcript was not kept");

        // Opened again, it carries on.
        let (again_events, again_seen) = recorder();
        let (again_tx, mut again_rx) = mpsc::unbounded_channel();
        let id = rows[0].id.clone();
        let again_identity = identity.clone();
        let again_key = key.clone();
        let again = tokio::spawn(async move {
            resume(&again_identity, again_key, &id, Identity::generate(), None, again_events,
                &mut again_rx)
                .await
        });

        let back = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if !safety_numbers(&again_seen.lock().expect("not poisoned")).is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(back.is_ok(), "the conversation would not open again");

        // The part that matters: what it says now is readable over there.
        let heard = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                again_tx
                    .send(Command::Send { text: "after".into() })
                    .expect("the reopened session is running");

                for _ in 0..20 {
                    if messages(&guest_seen.lock().expect("not poisoned"))
                        .iter()
                        .any(|text| text == "after")
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await;
        assert!(
            heard.is_ok(),
            "a reopened conversation cannot be read by the other side: {:?}",
            guest_seen.lock().expect("not poisoned")
        );

        drop(again_tx);
        drop(guest_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), again).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Somebody removed is somebody who stops receiving.
    ///
    /// The assertion that matters is not that a list got shorter. A member is
    /// removed from a key schedule, so the test is whether what comes next is
    /// still readable by them, and it must not be. A removal that only changed
    /// a roster would pass a count and leave the device reading everything.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_removed_member_stops_receiving() {
        let Some(server) = start(3396).await else {
            return;
        };

        let code = rotelyx_wasm::new_meeting_code().expect("entropy");

        let (host_events, host_seen) = recorder();
        let (guest_events, guest_seen) = recorder();
        let (host_tx, mut host_rx) = mpsc::unbounded_channel();
        let (guest_tx, mut guest_rx) = mpsc::unbounded_channel();

        let host_url = server.url.clone();
        let host_code = code.clone();
        let host = tokio::spawn(async move {
            run(&host_code, "desktop", &host_url, Role::Host, false, Identity::generate(), None,
                None, host_events, &mut host_rx)
                .await
        });

        tokio::time::sleep(Duration::from_millis(400)).await;

        let guest_url = server.url.clone();
        let guest_code = code.clone();
        let guest = tokio::spawn(async move {
            run(&guest_code, "phone", &guest_url, Role::Guest, false, Identity::generate(), None,
                None, guest_events, &mut guest_rx)
                .await
        });

        let met = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let host_in = !safety_numbers(&host_seen.lock().expect("not poisoned")).is_empty();
                let guest_in = !safety_numbers(&guest_seen.lock().expect("not poisoned")).is_empty();
                if host_in && guest_in {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(met.is_ok(), "the two sides never met");

        // Who is here, and the key the guest is removed by.
        host_tx.send(Command::WhoIsHere).expect("the host is running");
        let key = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let found = host_seen
                    .lock()
                    .expect("not poisoned")
                    .iter()
                    .rev()
                    .find_map(|event| match event {
                        Event::Members { members } if members.len() == 2 => Some(
                            members
                                .iter()
                                .find(|m| m.label != "desktop")
                                .map(|m| m.key.clone()),
                        ),
                        _ => None,
                    })
                    .flatten();
                if let Some(key) = found {
                    return key;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the host never said who was here");

        assert!(!key.is_empty(), "a member with no key cannot be removed");

        // Everything the guest has heard so far, so what follows can be told
        // apart from what came before.
        let before = messages(&guest_seen.lock().expect("not poisoned")).len();

        host_tx
            .send(Command::Remove { key })
            .expect("the host is running");

        let gone = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let alone = host_seen
                    .lock()
                    .expect("not poisoned")
                    .iter()
                    .rev()
                    .any(|event| matches!(event, Event::Members { members } if members.len() == 1));
                if alone {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(gone.is_ok(), "the member was never removed");

        // And now the part that matters: what comes next does not reach them.
        for _ in 0..8 {
            host_tx
                .send(Command::Send {
                    text: "after the removal".into(),
                })
                .expect("the host is running");
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;

        let after = messages(&guest_seen.lock().expect("not poisoned"));
        assert_eq!(
            after.len(),
            before,
            "a removed member is still reading the conversation: {after:?}"
        );

        drop(host_tx);
        drop(guest_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), host).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
    }

    /// A code nobody is waiting at is not an error, it is a silence.
    ///
    /// Worth stating: the mailbox carries no presence information at all. A
    /// deposit succeeds whether or not anybody is listening, so a reader who
    /// mistypes a code sees exactly what a reader who arrived early sees. The
    /// window says "waiting", and that is the honest thing for it to say.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_code_nobody_is_waiting_at_simply_waits() {
        let Some(server) = start(3395).await else {
            return;
        };

        let code = rotelyx_wasm::new_meeting_code().expect("entropy");
        let (events, seen) = recorder();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let url = server.url.clone();
        let guest = tokio::spawn(async move {
            run(&code, "desktop", &url, Role::Guest, false, Identity::generate(), None, None, events,
                &mut rx)
                .await
        });

        tokio::time::sleep(Duration::from_secs(2)).await;

        let events = seen.lock().expect("not poisoned");
        assert!(
            safety_numbers(&events).is_empty(),
            "met somebody at a place nobody was"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Error { .. })),
            "an empty meeting place was reported as a failure: {events:?}"
        );
        drop(events);

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
    }

    /// What is not a meeting code is refused before anything connects.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_code_that_is_not_one_is_refused_before_the_socket() {
        let (events, _seen) = recorder();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        // The desktop's own transport invitation, which is what its QR carried
        // before this module existed.
        let outcome = run(
            "HqKKk-8fPRC7cTEaXLt1cxsKF3vOTkJKC1j6kmrZ3BJXxnFKQmifUbaqDsR3TWfYLKkImwQ2xWpR9sW9mr_UqA",
            "desktop",
            "ws://127.0.0.1:1/mailbox",
            Role::Host,
            false,
            Identity::generate(),
            None,
            None,
            events,
            &mut rx,
        )
        .await;

        let refusal = outcome.expect_err("that is not a meeting code").to_string();
        assert!(
            refusal.contains("meeting code"),
            "refused for the wrong reason: {refusal}"
        );
    }
}
