//! The Rotelyx session, driven from the UI thread by commands and reporting
//! back by events.
//!
//! ## Why this is a better trust boundary than the browser harness
//!
//! The browser harness carries plaintext from the page to a local process over
//! a loopback socket, which puts anything with access to that socket inside the
//! encryption boundary. Tauri's IPC is in process: the webview and the crypto
//! live in the same address space and plaintext never touches a socket.
//!
//! That closes the gap the harness documented. It does not close the other one:
//! a compromised device still sees everything, because it must, to draw the
//! message on a screen.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rotelyx_core::store::{self, Paths};
use rotelyx_core::{
    Admission, Frame, FrameKind, Gate, Identity, Invitation, ReachabilityPolicy, RotelyxEndpoint,
    Session,
};
use rotelyx_crypto::{Conversation, Member, Received};
use rotelyx_net::{NetConfig, PathPolicy, RelayPolicy, RelayUrl, SecretKey};
use rotelyx_audio::Call;
use tokio::sync::mpsc;

/// What the window asks a *running* session to do.
///
/// Starting a session is not here: that goes through the `start` IPC command,
/// which decides the role once and then owns the task. Only in-session
/// messages travel on this channel.
#[derive(Debug)]
pub enum Command {
    Send { text: String },
    /// Start talking. Refused, with a reason, on a session that may go direct.
    StartCall,
    /// Stop talking. The session stays up.
    EndCall,
    Hangup,
    /// Remove a member, by the key that identifies them.
    ///
    /// A key rather than a name: two members can choose the same label, and a
    /// position in the tree shifts as people come and go, so a caller holding
    /// one across an epoch would remove somebody else.
    Remove { key: String },
    /// Say who is here, so the window can offer to remove one of them.
    WhoIsHere,
}

/// A member's identity, short enough to read and long enough to mean something.
///
/// Eight bytes. Somebody comparing two of these is not relying on it for
/// authentication, which is what the safety number is for.
fn hex_id(identity: &[u8]) -> String {
    identity
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// What the engine tells the window. Serialised to the webview as JSON.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Status { text: String },
    Listening { addr: String, id: String },
    Connected { peer: String, safety_number: String, direct: bool },
    Message { text: String },
    CallStarted { kbit: usize, mono: bool },
    /// Milliseconds of audio waiting to be played.
    ///
    /// Sent while a call runs because it is the one number that tells a person
    /// what they are about to hear: a figure that keeps climbing is the call
    /// falling behind, and after the call it is too late to know.
    CallLevel { queued_ms: usize },
    /// `concealed` is frames that arrived and could not be turned into sound.
    ///
    /// Reported beside `received` because the two together are the difference
    /// between a call that is quiet and a call that is wrong. A frame the
    /// decoder cannot use is concealed rather than counted, which is right for
    /// packet loss and hides a format mismatch completely: a real call ran with
    /// eleven received frames out of three thousand and said nothing at all.
    CallEnded {
        sent: u64,
        received: u64,
        concealed: u64,
        queued_ms: usize,
        dropped_ms: usize,
    },
    /// The membership changed, with who rather than only how many.
    ///
    /// A commit can remove one member and add another at once, which leaves the
    /// count where it was. An event carrying only a number then reports "2
    /// members" while the person on the other side has been replaced. See ADV-7
    /// in the threat model: surfacing membership changes is a security control,
    /// and a change without names is not surfaced.
    GroupChanged {
        members: usize,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// Everybody in the conversation, with the key each is removed by.
    Members { members: Vec<Present> },
    Disconnected { reason: String },
    Error { text: String },
}

/// One member, as the window needs to show and act on them.
///
/// Not `rotelyx_crypto::Member`, which is this side's own signing identity. A
/// name collision worth keeping apart: one is who we are, the other is a row on
/// a list of who is here.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Present {
    /// What they called themselves. It proves nothing on its own.
    pub label: String,
    /// What removing them takes.
    pub key: String,
}

/// Everything one window needs to run a session.
pub struct Engine {
    identity: Identity,
    paths: Paths,
    /// Seals a conversation between runs. See `resume`.
    passphrase: zeroize::Zeroizing<String>,
    epoch: u64,
    events: Arc<dyn Fn(Event) + Send + Sync>,
    /// The network configuration for this session, and what decides whether a
    /// call is possible at all.
    ///
    /// Without a relay it is direct only, which is right for text and forbids a
    /// call: audio over a direct path is this machine's address handed to the
    /// other end, and `rotelyx_media` refuses rather than trusting a caller not
    /// to. With one it is relay only, never "relay preferred", so a call either
    /// works for a whole session or is refused at the start of it rather than
    /// depending on whether hole punching happened to succeed.
    net: NetConfig,
}

impl Engine {
    pub fn new(
        identity: Identity,
        paths: Paths,
        passphrase: zeroize::Zeroizing<String>,
        epoch: u64,
        events: Arc<dyn Fn(Event) + Send + Sync>,
        relay: Option<&str>,
    ) -> Result<Self> {
        let net = match relay {
            None => NetConfig::direct_only(),
            Some(url) => {
                let url: RelayUrl = url
                    .parse()
                    .with_context(|| format!("{url} is not a relay URL"))?;
                NetConfig::new(RelayPolicy::SelfHosted(vec![url]), PathPolicy::RelayOnly)
            }
        };
        Ok(Self {
            identity,
            paths,
            passphrase,
            epoch,
            events,
            net,
        })
    }

    fn emit(&self, event: Event) {
        (self.events)(event);
    }

    /// Build the admission gate from what is on disk.
    ///
    /// Invitations come from a file, so a restart does not hand access to somebody
    /// whose invitation expired.
    fn gate(&self, open: bool, invitations: &[store::StoredInvitation]) -> Result<Gate> {
        let gate = if open {
            Gate::new(ReachabilityPolicy::Open)
        } else {
            if invitations.is_empty() {
                bail!("No live invitations. Issue one first, or choose Open.");
            }
            let mut g = Gate::invitation_only();
            for inv in invitations {
                g.add_invitation(inv.to_invitation());
            }
            self.emit(Event::Status {
                text: format!("Admitting holders of {} invitation(s)", invitations.len()),
            });
            g
        };

        Ok(gate)
    }

    pub async fn listen(&self, open: bool, rx: &mut mpsc::UnboundedReceiver<Command>) -> Result<()> {
        let live = store::load_invitations(&self.paths.invitations, self.epoch)?;
        let gate = self.gate(open, &live)?;

        // Answer on the invitations' own addresses, not on this identity.
        //
        // An identity that listens under its own key is reachable at one address
        // for everybody, and every caller reaches the same one. That hands the
        // network a name shared by all of somebody's contacts, and it also means
        // this side cannot tell which invitation a caller used, so it has
        // nothing to derive a per-conversation name from. The terminal client
        // has answered per invitation for a while; this is the same arrangement.
        let newest = live.iter().max_by_key(|i| i.expires_at_epoch);
        let endpoint = match (newest, open) {
            (Some(inv), _) => RotelyxEndpoint::bind_as(
                &self.identity,
                SecretKey::from_bytes(&inv.transport),
                self.net.clone(),
            )
            .await
            .context("binding endpoint")?,
            // An open host publishes one address and keeps it. There is nobody
            // to hide it from.
            (None, true) => RotelyxEndpoint::bind(&self.identity, self.net.clone())
                .await
                .context("binding endpoint")?,
            (None, false) => bail!("No live invitations. Issue one first, or choose Open."),
        };

        let primary = newest.map(|i| i.transport);
        for inv in &live {
            if Some(inv.transport) == primary {
                continue;
            }
            if !endpoint.also_answer_as(&SecretKey::from_bytes(&inv.transport)) {
                self.emit(Event::Status {
                    text: "Could not ask the relay to answer one invitation's address"
                        .into(),
                });
            }
        }

        self.emit(Event::Listening {
            addr: crate::encode_addr(&endpoint.addr())?,
            id: endpoint.id().to_string(),
        });

        let mut session = endpoint
            .accept_with(&gate, self.epoch)
            .await
            .context("accepting")?;

        // The name this identity uses in this conversation, derived from the
        // invitation the caller actually used. Which one that is comes from the
        // address the call was answered at, which the caller does not choose.
        // Derived from the address the call arrived at, which both sides always
        // know. The invitation secret would work only when both have one, and
        // an open host with live invitations answers at an invitation's address
        // while a caller without a code has no secret to derive from.
        let shared = session
            .answered_at()
            .unwrap_or_else(|| self.identity.id())
            .as_bytes()
            .to_vec();
        let my_name = self.identity.in_conversation(&shared);
        let me = Member::new(my_name.as_bytes()).context("creating member")?;

        // The address is the name of the conversation, so it is also the name of
        // the file. See `resume`.
        let here = session.answered_at().unwrap_or_else(|| self.identity.id());
        let saved = crate::resume::reopen(&self.paths, &here, &self.passphrase)?;
        let opened = crate::handshake::host_resuming(&mut session, &me, saved)
            .await
            .context("MLS handshake")?;

        let (me, conversation) = match opened {
            crate::handshake::Opened::Fresh(conversation) => (me, conversation),
            crate::handshake::Opened::Resumed {
                member,
                conversation,
            } => {
                self.emit(Event::Status {
                    text: "Carried on from where this conversation left off".into(),
                });
                (member, conversation)
            }
        };

        // Written before a word is typed. A conversation only saved on a clean
        // exit is one people lose, and this side has just committed an epoch the
        // other has already processed.
        crate::resume::save(&self.paths, &here, &me, &conversation, &self.passphrase)?;

        self.announce(&endpoint, &conversation, my_name).await;

        let conversation = self.chat(session, conversation, &me, rx).await;
        if let Some(conversation) = conversation {
            crate::resume::save(&self.paths, &here, &me, &conversation, &self.passphrase)?;
        }
        endpoint.close().await;
        Ok(())
    }

    pub async fn connect(
        &self,
        addr: &str,
        invite: Option<&str>,
        rx: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Result<()> {
        let addr = crate::decode_addr(addr)?;

        // A transport key for this call and nothing else.
        //
        // The relay sees this and never the identity, and the proof commits to
        // it, because the proof has to name the caller the transport
        // authenticated. This used to bind the identity and prove as the
        // identity, which put a long-lived name on the wire for every call.
        let transport = RotelyxEndpoint::ephemeral_transport_key();
        let calling_as = rotelyx_core::RotelyxId::from(transport.public());

        let (evidence, addr) = match invite.map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(code.as_bytes())
                    .context("invitation is not valid base64")?;
                // A code is the secret and the address it is answered at. This
                // read thirty two bytes and refused anything else, so it could
                // not accept the code this application's own invite command
                // produces, which has been sixty four for a while.
                let (secret, host) = Invitation::read_code(&bytes)
                    .context("that is not an invitation code")?;
                // Expiry belongs to the issuer; we only prove possession.
                let invitation = Invitation::from_parts(secret, [0u8; 32], u64::MAX);
                // Call the address in the code, not one pasted beside it.
                //
                // Each invitation is answered at an address of its own, and a
                // permission is for one address: a holder dialling some other
                // address of the same host is refused. The id comes from the
                // code and the network addresses from what was pasted, because
                // one says which key to ask for and the other says where the
                // machine is.
                (
                    Admission::Invitation {
                        proof: invitation.prove(&calling_as, self.epoch),
                        epoch: self.epoch,
                    },
                    rotelyx_net::EndpointAddr::from_parts(
                        host.endpoint_id(),
                        addr.addrs.iter().cloned(),
                    ),
                )
            }
            None => (Admission::None, addr),
        };
        let dialled_id = rotelyx_core::RotelyxId::from(addr.id);

        let endpoint = RotelyxEndpoint::bind_as(&self.identity, transport, self.net.clone())
            .await
            .context("binding endpoint")?;

        self.emit(Event::Status {
            text: "Connecting".into(),
        });

        let mut session = endpoint
            .connect_with(addr, &evidence)
            .await
            .context("connecting")?;

        // The same derivation the listening side makes, from the address this
        // call was placed to.
        let shared = dialled_id.as_bytes().to_vec();
        let my_name = self.identity.in_conversation(&shared);
        let me = Member::new(my_name.as_bytes()).context("creating member")?;

        let saved = crate::resume::reopen(&self.paths, &dialled_id, &self.passphrase)?;
        let opened = crate::handshake::join_resuming(&mut session, &me, saved)
            .await
            .context("MLS handshake")?;

        let (me, conversation) = match opened {
            crate::handshake::Opened::Fresh(conversation) => (me, conversation),
            crate::handshake::Opened::Resumed {
                member,
                conversation,
            } => {
                self.emit(Event::Status {
                    text: "Carried on from where this conversation left off".into(),
                });
                (member, conversation)
            }
        };

        crate::resume::save(&self.paths, &dialled_id, &me, &conversation, &self.passphrase)?;

        self.announce(&endpoint, &conversation, my_name).await;

        let conversation = self.chat(session, conversation, &me, rx).await;
        if let Some(conversation) = conversation {
            crate::resume::save(&self.paths, &dialled_id, &me, &conversation, &self.passphrase)?;
        }
        endpoint.close().await;
        Ok(())
    }

    /// # Which value the safety number compares
    ///
    /// The identity the group authenticated, not the key the transport did.
    /// Those were the same value while an endpoint bound under its identity,
    /// and are not once it binds under an invitation's own key: that key
    /// belongs to one conversation and says nothing about who is behind it.
    ///
    /// Read after the handshake for the same reason. Before it there is no
    /// identity to compare, only an address.
    async fn announce(
        &self,
        endpoint: &RotelyxEndpoint,
        conversation: &Conversation,
        my_name: rotelyx_core::RotelyxId,
    ) {
        let roster: Vec<Vec<u8>> = conversation.roster().into_iter().map(|p| p.identity).collect();
        // Both halves must be names that are in the roster. Passing the
        // long-lived identity as "me" was consistent only while it was also
        // what went into the credential; a conversation carries a name derived
        // for it now, and the two sides would combine different pairs and read
        // out digits that cannot match.
        let peer = match rotelyx_core::peer_identity(&roster, my_name) {
            Some(id) => id,
            None => {
                self.emit(Event::Error {
                    text: "no peer identity in the group. Do not trust this session.".into(),
                });
                return;
            }
        };
        // Whether a third party is carrying this session. Shown in the window,
        // because a user deserves to know when a relay is in the path even
        // though it can read nothing.
        let direct = endpoint.is_direct(peer).await.unwrap_or(false);

        self.emit(Event::Connected {
            peer: peer.to_string(),
            safety_number: rotelyx_core::safety_number(&my_name, &peer),
            direct,
        });
    }

    /// Start a call from what this session has.
    ///
    /// The audio crate takes a key and a sender index rather than a group,
    /// because it has no business knowing what a conversation is. This is where
    /// that translation happens, and it is the same translation the terminal
    /// client does.
    fn start_call(&self, conversation: &Conversation, me: &Member) -> Result<Call> {
        let base = conversation
            .media_base_key(me)
            .context("deriving the call key from the group")?;

        // Sorting the roster gives both ends the same answer from state they
        // already share, so no index has to be negotiated and the two sides
        // cannot disagree about who is who.
        let mine = me.signature_key();
        let mut keys: Vec<Vec<u8>> =
            conversation.roster().into_iter().map(|p| p.signature_key).collect();
        keys.sort();
        let index = keys
            .iter()
            .position(|k| *k == mine)
            .context("this member is not in the roster it belongs to")?;

        // Refused, rather than started on keys that repeat.
        //
        // A call needs a value both ends agree on and neither reuses, and this
        // path has nowhere to put one: two people press the button and audio
        // starts, with no ringing and no exchange. Deriving from the group alone
        // is what produced the defect this argument exists to close, so the
        // honest state until `FrameKind::CallControl` carries a binding is a
        // refusal that says why.
        let _ = (base, index);
        bail!(
            "calling over a direct invitation is disabled: it has no way to agree \
             a per-call key, and without one a second call reuses the first call's \
             nonces. Meet through a code, which does agree one."
        );
    }

    /// Returns the conversation as it ended, so the caller can save it.
    ///
    /// `None` when the session fell over rather than closing, in which case what
    /// is already on disk is the last thing both sides agreed on and is better
    /// than whatever half state this one is in.
    async fn chat(
        &self,
        session: Session,
        mut conversation: Conversation,
        me: &Member,
        rx: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Option<Conversation> {
        let (mut send, mut recv, conn) = session.split_for_chat();

        // No call until somebody asks for one, so a window that only types opens
        // no microphone.
        let mut call: Option<Call> = None;

        // Ticks regardless. One every 20 ms on an idle session costs nothing,
        // and creating the interval when a call starts would mean the select
        // changing shape.
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // The window is told the queued figure about once a second. Every tick
        // would be fifty IPC messages a second to say almost the same thing.
        let mut since_report = 0u32;

        loop {
            tokio::select! {
                command = rx.recv() => {
                    match command {
                        // Both belong to a conversation met through a code,
                        // which is the other transport. A session on this one
                        // has exactly two members and no roster to act on.
                        Some(Command::Remove { .. }) | Some(Command::WhoIsHere) => {}
                        Some(Command::Send { text }) => {
                            match conversation.send(&me, text.as_bytes()) {
                                Ok(ciphertext) => {
                                    if let Err(e) = Frame::new(FrameKind::Message, ciphertext)
                                        .write(&mut send).await
                                    {
                                        self.emit(Event::Error { text: format!("send failed: {e}") });
                                        break;
                                    }
                                }
                                Err(e) => self.emit(Event::Error {
                                    text: format!("encrypt failed: {e}"),
                                }),
                            }
                        }
                        Some(Command::StartCall) => {
                            if call.is_some() {
                                self.emit(Event::Error { text: "already on a call".into() });
                            } else {
                                match self.start_call(&conversation, &me) {
                                    Ok(c) => {
                                        self.emit(Event::CallStarted {
                                            kbit: c.kbit_per_second(),
                                            mono: c.microphone_is_mono(),
                                        });
                                        call = Some(c);
                                    }
                                    Err(e) => self.emit(Event::Error {
                                        text: format!("cannot call: {e:#}"),
                                    }),
                                }
                            }
                        }
                        Some(Command::EndCall) => match call.take() {
                            Some(c) => self.emit(Event::CallEnded {
                                sent: c.frames_sent(),
                                received: c.frames_received(),
                                concealed: c.frames_concealed(),
                                queued_ms: c.queued_ms(),
                                dropped_ms: c.dropped_ms(),
                            }),
                            None => self.emit(Event::Error { text: "not on a call".into() }),
                        },
                        Some(Command::Hangup) | None => break,
                    }
                }
                // One tick of microphone, encoded and sent.
                _ = tick.tick() => {
                    if let Some(c) = call.as_mut() {
                        if let Err(e) = c.send_all_ready(&conn) {
                            self.emit(Event::CallEnded {
                                sent: c.frames_sent(),
                                received: c.frames_received(),
                                concealed: c.frames_concealed(),
                                queued_ms: c.queued_ms(),
                                dropped_ms: c.dropped_ms(),
                            });
                            self.emit(Event::Error { text: format!("call ended: {e:#}") });
                            call = None;
                        }
                    }
                    since_report += 1;
                    if since_report >= 50 {
                        since_report = 0;
                        if let Some(c) = call.as_ref() {
                            self.emit(Event::CallLevel { queued_ms: c.queued_ms() });
                        }
                    }
                }

                // Audio in. Read whether or not a call is running here, because
                // a datagram nobody reads is one the peer keeps retrying.
                datagram = conn.read_datagram() => {
                    if let Ok(bytes) = datagram {
                        if let Some(c) = call.as_mut() {
                            c.receive_one(&bytes);
                        }
                    }
                }

                frame = Frame::read(&mut recv) => {
                    let frame = match frame {
                        Ok(f) => f,
                        Err(e) => {
                            self.emit(Event::Disconnected { reason: e.to_string() });
                            break;
                        }
                    };

                    if frame.kind != FrameKind::Message {
                        continue;
                    }

                    match conversation.receive(&me, &frame.payload) {
                        Ok(Received::Message { bytes: plaintext, .. }) => self.emit(Event::Message {
                            text: String::from_utf8_lossy(&plaintext).into_owned(),
                        }),
                        // A commit. Surfacing it is a security control: MLS makes
                        // membership changes visible and a silent UI discards
                        // that guarantee.
                        Ok(Received::MembershipChanged(change)) => {
                            self.emit(Event::GroupChanged {
                                members: conversation.member_count(),
                                added: change.added.iter().map(|p| hex_id(&p.identity)).collect(),
                                removed: change
                                    .removed
                                    .iter()
                                    .map(|p| hex_id(&p.identity))
                                    .collect(),
                            })
                        }
                        Ok(Received::Nothing) => {}
                        Err(e) => self.emit(Event::Error {
                            text: format!("decrypt failed: {e}"),
                        }),
                    }
                }
            }
        }

        // Finish before closing: a dropped QUIC send stream resets and discards
        // anything still in flight.
        let _ = send.finish();
        let _ = send.stopped().await;
        conn.close(0u32.into(), b"bye");
        Some(conversation)
    }
}
