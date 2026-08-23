//! Driving one Rotelyx session from the browser.
//!
//! The browser is a terminal, not a participant. Plaintext travels from the
//! page to this process over a loopback WebSocket, and encryption happens
//! **here**, so the encryption boundary starts at this process, not at the
//! browser tab.
//!
//! That is fine for a local test UI and would be wrong for a product. A real
//! client puts the crypto in the same trust domain as the display; see the
//! warning the page shows.

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use rotelyx_core::store;
use rotelyx_core::{
    Admission, Frame, FrameKind, Gate, Identity, Invitation, ReachabilityPolicy, Session,
    RotelyxEndpoint,
};
use rotelyx_crypto::{Received, Conversation, Member};
use rotelyx_net::NetConfig;

/// What the page can ask for.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Wait for a peer holding one of our invitations.
    Listen { open: bool },
    /// Dial a peer.
    Connect {
        addr: String,
        invite: Option<String>,
    },
    /// Send a chat line.
    Send { text: String },
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

/// What the page is told.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Progress worth showing in the status line.
    Status { text: String },
    /// We are listening; this is the address to hand out.
    Listening { addr: String, id: String },
    /// A session is up.
    Connected {
        peer: String,
        safety_number: String,
        direct: bool,
    },
    /// A message arrived from the peer.
    Message { text: String },
    /// The group changed: membership must never change silently.
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
    /// Something failed. Shown to the user as-is.
    Error { text: String },
    /// The peer went away.
    Disconnected { reason: String },
}

/// Everything one browser tab drives.
pub struct Driver {
    identity: Identity,
    paths: store::Paths,
    /// What a saved conversation is sealed under.
    ///
    /// # Why this is derived and not asked for
    ///
    /// This binary keeps its identity **unsealed**, 32 bytes on disk, so there is
    /// no passphrase to reuse and inventing a prompt would put one secret behind
    /// a door while its key lay next to it.
    ///
    /// Derived from the identity instead, which is worth saying plainly: against
    /// somebody who can read the identity file this protects nothing, because
    /// they can derive it too. What it does is keep a conversation out of a
    /// backup that caught the conversation file and not the key, and stop the
    /// group state sitting in the clear where a stray `cat` will print it. It is
    /// exactly as strong as the identity file beside it and no stronger.
    conversation_key: zeroize::Zeroizing<String>,
    invitations: Vec<store::StoredInvitation>,
    epoch: u64,
    tx: mpsc::UnboundedSender<Event>,
}

impl Driver {
    pub fn new(
        identity: Identity,
        paths: store::Paths,
        invitations: Vec<store::StoredInvitation>,
        epoch: u64,
        tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        let conversation_key = zeroize::Zeroizing::new(data_encoding::HEXLOWER.encode(
            blake3::derive_key(
                "rotelyx web conversation-at-rest v1",
                &*identity.to_storage_bytes(),
            )
            .as_slice(),
        ));

        Self {
            identity,
            paths,
            conversation_key,
            invitations,
            epoch,
            tx,
        }
    }

    fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    /// Listen for one peer, then chat until either side goes away.
    pub async fn listen(&mut self, open: bool, rx: &mut mpsc::UnboundedReceiver<Command>) -> Result<()> {
        let gate = if open {
            self.emit(Event::Status {
                text: "Accepting anyone: no invitation required".into(),
            });
            Gate::new(ReachabilityPolicy::Open)
        } else {
            let live: Vec<_> = self
                .invitations
                .iter()
                .filter(|i| i.expires_at_epoch >= self.epoch)
                .collect();

            if live.is_empty() {
                bail!("No live invitations. Issue one first, or choose Open.");
            }

            let mut gate = Gate::invitation_only();
            let count = live.len();
            for inv in &live {
                // Rebuilt with its own transport key. This used to go through
                // `Invitation::from_secret`, which generates a fresh one, so
                // every invitation in the gate had an address unrelated to the
                // address its holder was told to call.
                gate.add_invitation(inv.to_invitation());
            }
            self.emit(Event::Status {
                text: format!("Admitting holders of {count} invitation(s)"),
            });
            gate
        };

        // Answer on the invitations' own addresses, not on this identity.
        //
        // Listening under the identity means every caller reaches one address,
        // so the network sees a name shared by all of somebody's contacts, and
        // this side cannot tell which invitation a caller used and so has
        // nothing to derive a per-conversation name from.
        let all: Vec<store::StoredInvitation> = self
            .invitations
            .iter()
            .filter(|i| i.expires_at_epoch >= self.epoch)
            .cloned()
            .collect();
        let newest = all.iter().max_by_key(|i| i.expires_at_epoch);

        let endpoint = match (newest, open) {
            (Some(inv), _) => RotelyxEndpoint::bind_as(
                &self.identity,
                rotelyx_net::SecretKey::from_bytes(&inv.transport),
                NetConfig::direct_only(),
            )
            .await
            .context("binding endpoint")?,
            _ => RotelyxEndpoint::bind(&self.identity, NetConfig::direct_only())
                .await
                .context("binding endpoint")?,
        };

        let primary = newest.map(|i| i.transport);
        for inv in &all {
            if Some(inv.transport) == primary {
                continue;
            }
            if !endpoint.also_answer_as(&rotelyx_net::SecretKey::from_bytes(&inv.transport)) {
                self.emit(Event::Status {
                    text: "Could not ask the relay to answer one invitation's address".into(),
                });
            }
        }

        self.emit(Event::Listening {
            addr: super::encode_addr(&endpoint.addr())?,
            id: endpoint.id().to_string(),
        });

        let mut session = endpoint
            .accept_with(&gate, self.epoch)
            .await
            .context("accepting")?;

        // Derived from the invitation the caller actually used, which comes from
        // the address the call was answered at rather than anything the caller
        // wrote.
        // Derived from the address the call arrived at, which both sides always
        // know, rather than from the invitation secret, which only both have
        // when the caller arrived with a code.
        let shared = session
            .answered_at()
            .unwrap_or_else(|| self.identity.id())
            .as_bytes()
            .to_vec();
        let my_name = self.identity.in_conversation(&shared);
        let me = Member::new(my_name.as_bytes()).context("creating member")?;

        let here = session.answered_at().unwrap_or_else(|| self.identity.id());
        let saved = super::resume::reopen(&self.paths, &here, &self.conversation_key)?;
        let opened = super::handshake::host_resuming(&mut session, &me, saved)
            .await
            .context("MLS handshake")?;

        let (me, conversation) = match opened {
            super::handshake::Opened::Fresh(conversation) => (me, conversation),
            super::handshake::Opened::Resumed {
                member,
                conversation,
            } => {
                self.emit(Event::Status {
                    text: "Carried on from where this conversation left off".into(),
                });
                (member, conversation)
            }
        };

        super::resume::save(&self.paths, &here, &me, &conversation, &self.conversation_key)?;

        self.announce(&endpoint, &conversation, my_name).await;

        if let Some(conversation) = self.chat(session, conversation, &me, rx).await {
            super::resume::save(&self.paths, &here, &me, &conversation, &self.conversation_key)?;
        }
        endpoint.close().await;
        Ok(())
    }

    /// Dial a peer, then chat.
    pub async fn connect(
        &mut self,
        addr: &str,
        invite: Option<&str>,
        rx: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Result<()> {
        let addr = super::decode_addr(addr)?;

        // A transport key for this call and nothing else, and the proof names
        // it: the proof has to commit to the caller the transport authenticated.
        let transport = RotelyxEndpoint::ephemeral_transport_key();
        let calling_as = rotelyx_core::RotelyxId::from(transport.public());

        let (evidence, _invitation_secret, addr) = match invite.map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(code.as_bytes())
                    .context("invitation is not valid base64")?;
                // The secret and the address it is answered at. Reading only
                // thirty two bytes meant refusing the code this application's
                // own invite produces.
                let (secret, host) =
                    Invitation::read_code(&bytes).context("that is not an invitation code")?;
                // Expiry is the issuer's to enforce; we only prove possession.
                let invitation = Invitation::from_parts(secret, [0u8; 32], u64::MAX);
                // Call the address in the code, not one pasted beside it.
                //
                // Each invitation is answered at an address of its own, so a
                // holder who dials some other address of the same host is
                // refused: a permission is for one address. The code carries
                // the right one, which is the whole reason it is in there.
                (
                    Admission::Invitation {
                        proof: invitation.prove(&calling_as, self.epoch),
                        epoch: self.epoch,
                    },
                    Some(secret.to_vec()),
                    // The id comes from the code and the network addresses
                    // from what was pasted: one says which key to ask for, the
                    // other says where the machine is.
                    rotelyx_net::EndpointAddr::from_parts(
                        host.endpoint_id(),
                        addr.addrs.iter().cloned(),
                    ),
                )
            }
            None => (Admission::None, None, addr),
        };
        let dialled_id = rotelyx_core::RotelyxId::from(addr.id);

        let endpoint = RotelyxEndpoint::bind_as(&self.identity, transport, NetConfig::direct_only())
            .await
            .context("binding endpoint")?;

        self.emit(Event::Status {
            text: "Connecting…".into(),
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

        let saved = super::resume::reopen(&self.paths, &dialled_id, &self.conversation_key)?;
        let opened = super::handshake::join_resuming(&mut session, &me, saved)
            .await
            .context("MLS handshake")?;

        let (me, conversation) = match opened {
            super::handshake::Opened::Fresh(conversation) => (me, conversation),
            super::handshake::Opened::Resumed {
                member,
                conversation,
            } => {
                self.emit(Event::Status {
                    text: "Carried on from where this conversation left off".into(),
                });
                (member, conversation)
            }
        };

        super::resume::save(
            &self.paths,
            &dialled_id,
            &me,
            &conversation,
            &self.conversation_key,
        )?;

        self.announce(&endpoint, &conversation, my_name).await;

        if let Some(conversation) = self.chat(session, conversation, &me, rx).await {
            super::resume::save(
                &self.paths,
                &dialled_id,
                &me,
                &conversation,
                &self.conversation_key,
            )?;
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
        // Both halves must be names that are in the roster: a conversation
        // carries a name derived for it, and the long-lived identity is in
        // neither entry, so combining it with a roster entry gives each side a
        // different pair and digits that cannot match.
        let peer = match rotelyx_core::peer_identity(&roster, my_name) {
            Some(id) => id,
            None => {
                self.emit(Event::Error {
                    text: "no peer identity in the group. Do not trust this session.".into(),
                });
                return;
            }
        };
        // Whether a third party is carrying this session. Users deserve to know,
        // even when that party is blind.
        let direct = endpoint.is_direct(peer).await.unwrap_or(false);

        self.emit(Event::Connected {
            peer: peer.to_string(),
            safety_number: rotelyx_core::safety_number(&my_name, &peer),
            direct,
        });
    }

    /// Pump messages between the browser and the peer until one side stops.
    /// Returns the conversation as it ended, so the caller can save it.
    ///
    /// `None` when the session fell over rather than closing: what is already on
    /// disk is the last thing both sides agreed on, and better than half of this.
    async fn chat(
        &self,
        session: Session,
        mut conversation: Conversation,
        me: &Member,
        rx: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Option<Conversation> {
        let (mut send, mut recv, conn) = session.split_for_chat();

        loop {
            tokio::select! {
                command = rx.recv() => {
                    match command {
                        Some(Command::Send { text }) => {
                            match conversation.send(&me, text.as_bytes()) {
                                Ok(ciphertext) => {
                                    if let Err(e) = Frame::new(FrameKind::Message, ciphertext)
                                        .write(&mut send)
                                        .await
                                    {
                                        self.emit(Event::Error { text: format!("send failed: {e}") });
                                        break;
                                    }
                                }
                                Err(e) => self.emit(Event::Error { text: format!("encrypt failed: {e}") }),
                            }
                        }
                        // The tab closed, or asked for something else entirely.
                        _ => break,
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
                        Ok(Received::Message(plaintext)) => self.emit(Event::Message {
                            text: String::from_utf8_lossy(&plaintext).into_owned(),
                        }),
                        // A commit. Surfacing this is a security control: MLS
                        // makes membership changes visible, and that is worth
                        // nothing if the UI stays quiet.
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
                        Err(e) => self.emit(Event::Error { text: format!("decrypt failed: {e}") }),
                    }
                }
            }
        }

        // Finish before closing: dropping a QUIC send stream resets it and
        // discards anything still in flight.
        let _ = send.finish();
        let _ = send.stopped().await;
        conn.close(0u32.into(), b"bye");
        Some(conversation)
    }
}
