//! Driving one Rotelyx session from the browser.
//!
//! The browser is a terminal, not a participant. Plaintext travels from the
//! page to this process over a loopback WebSocket, and encryption happens
//! **here** — so the encryption boundary starts at this process, not at the
//! browser tab.
//!
//! That is fine for a local test UI and would be wrong for a product. A real
//! client puts the crypto in the same trust domain as the display; see the
//! warning the page shows.

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use rotelyx_core::{
    Admission, Frame, FrameKind, Gate, Identity, Invitation, ReachabilityPolicy, Session,
    RotelyxEndpoint,
};
use rotelyx_crypto::{Conversation, Member};
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
    /// The group changed — membership must never change silently.
    GroupChanged { members: usize },
    /// Something failed. Shown to the user as-is.
    Error { text: String },
    /// The peer went away.
    Disconnected { reason: String },
}

/// Everything one browser tab drives.
pub struct Driver {
    identity: Identity,
    invitations: Vec<Invitation>,
    epoch: u64,
    tx: mpsc::UnboundedSender<Event>,
}

impl Driver {
    pub fn new(
        identity: Identity,
        invitations: Vec<Invitation>,
        epoch: u64,
        tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            identity,
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
                text: "Accepting anyone — no invitation required".into(),
            });
            Gate::new(ReachabilityPolicy::Open)
        } else {
            let live: Vec<_> = self
                .invitations
                .iter()
                .filter(|i| i.expires_at_epoch() >= self.epoch)
                .map(|i| Invitation::from_secret(*i.secret_bytes(), i.expires_at_epoch()))
                .collect();

            if live.is_empty() {
                bail!("No live invitations. Issue one first, or choose Open.");
            }

            let mut gate = Gate::invitation_only();
            let count = live.len();
            for inv in live {
                gate.add_invitation(inv);
            }
            self.emit(Event::Status {
                text: format!("Admitting holders of {count} invitation(s)"),
            });
            gate
        };

        let endpoint = RotelyxEndpoint::bind(&self.identity, NetConfig::direct_only())
            .await
            .context("binding endpoint")?;

        self.emit(Event::Listening {
            addr: super::encode_addr(&endpoint.addr())?,
            id: endpoint.id().to_string(),
        });

        let mut session = endpoint
            .accept_with(&gate, self.epoch)
            .await
            .context("accepting")?;

        let me = Member::new(self.identity.id().as_bytes()).context("creating member")?;
        self.announce(&session, &endpoint).await;

        let conversation = super::handshake::host(&mut session, &me)
            .await
            .context("MLS handshake")?;

        self.chat(session, conversation, me, rx).await;
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

        let evidence = match invite.map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(code.as_bytes())
                    .context("invitation is not valid base64")?;
                let secret: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .context("invitation secret is not 32 bytes")?;
                // Expiry is the issuer's to enforce; we only prove possession.
                let invitation = Invitation::from_secret(secret, u64::MAX);
                Admission::Invitation {
                    proof: invitation.prove(&self.identity.id(), self.epoch),
                    epoch: self.epoch,
                }
            }
            None => Admission::None,
        };

        let endpoint = RotelyxEndpoint::bind(&self.identity, NetConfig::direct_only())
            .await
            .context("binding endpoint")?;

        self.emit(Event::Status {
            text: "Connecting…".into(),
        });

        let mut session = endpoint
            .connect_with(addr, &evidence)
            .await
            .context("connecting")?;

        let me = Member::new(self.identity.id().as_bytes()).context("creating member")?;
        self.announce(&session, &endpoint).await;

        let conversation = super::handshake::join(&mut session, &me)
            .await
            .context("MLS handshake")?;

        self.chat(session, conversation, me, rx).await;
        endpoint.close().await;
        Ok(())
    }

    async fn announce(&self, session: &Session, endpoint: &RotelyxEndpoint) {
        let peer = session.peer();
        // Whether a third party is carrying this session. Users deserve to know,
        // even when that party is blind.
        let direct = endpoint.is_direct(peer).await.unwrap_or(false);

        self.emit(Event::Connected {
            peer: peer.to_string(),
            safety_number: self.identity.safety_number(&peer),
            direct,
        });
    }

    /// Pump messages between the browser and the peer until one side stops.
    async fn chat(
        &self,
        session: Session,
        mut conversation: Conversation,
        me: Member,
        rx: &mut mpsc::UnboundedReceiver<Command>,
    ) {
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
                        Ok(Some(plaintext)) => self.emit(Event::Message {
                            text: String::from_utf8_lossy(&plaintext).into_owned(),
                        }),
                        // A commit. Surfacing this is a security control: MLS
                        // makes membership changes visible, and that is worth
                        // nothing if the UI stays quiet.
                        Ok(None) => self.emit(Event::GroupChanged {
                            members: conversation.member_count(),
                        }),
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
    }
}
