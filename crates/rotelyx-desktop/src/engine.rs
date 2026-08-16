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
use rotelyx_core::store::{self, Blocklist, Paths};
use rotelyx_core::{
    Admission, Frame, FrameKind, Gate, Identity, Invitation, ReachabilityPolicy, RotelyxEndpoint,
    Session,
};
use rotelyx_crypto::{Conversation, Member};
use rotelyx_net::NetConfig;
use tokio::sync::mpsc;

/// What the window asks a *running* session to do.
///
/// Starting a session is not here: that goes through the `start` IPC command,
/// which decides the role once and then owns the task. Only in-session
/// messages travel on this channel.
#[derive(Debug)]
pub enum Command {
    Send { text: String },
    Hangup,
}

/// What the engine tells the window. Serialised to the webview as JSON.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Status { text: String },
    Listening { addr: String, id: String },
    Connected { peer: String, safety_number: String, direct: bool },
    Message { text: String },
    GroupChanged { members: usize },
    Disconnected { reason: String },
    Error { text: String },
}

/// Everything one window needs to run a session.
pub struct Engine {
    identity: Identity,
    paths: Paths,
    epoch: u64,
    events: Arc<dyn Fn(Event) + Send + Sync>,
}

impl Engine {
    pub fn new(
        identity: Identity,
        paths: Paths,
        epoch: u64,
        events: Arc<dyn Fn(Event) + Send + Sync>,
    ) -> Self {
        Self {
            identity,
            paths,
            epoch,
            events,
        }
    }

    fn emit(&self, event: Event) {
        (self.events)(event);
    }

    /// Build the admission gate from what is on disk.
    ///
    /// Invitations and blocks both come from files, so a restart does not
    /// reopen the door to somebody who was blocked or hand access to somebody
    /// whose invitation expired.
    fn gate(&self, open: bool) -> Result<Gate> {
        let mut gate = if open {
            Gate::new(ReachabilityPolicy::Open)
        } else {
            let invitations = store::load_invitations(&self.paths.invitations, self.epoch)?;
            if invitations.is_empty() {
                bail!("No live invitations. Issue one first, or choose Open.");
            }
            let mut g = Gate::invitation_only();
            for inv in &invitations {
                g.add_invitation(inv.to_invitation());
            }
            self.emit(Event::Status {
                text: format!("Admitting holders of {} invitation(s)", invitations.len()),
            });
            g
        };

        let blocks = Blocklist::load(&self.paths.blocks)?;
        for id in blocks.iter() {
            gate.block(*id);
        }
        Ok(gate)
    }

    pub async fn listen(&self, open: bool, rx: &mut mpsc::UnboundedReceiver<Command>) -> Result<()> {
        let gate = self.gate(open)?;

        let endpoint = RotelyxEndpoint::bind(&self.identity, NetConfig::direct_only())
            .await
            .context("binding endpoint")?;

        self.emit(Event::Listening {
            addr: crate::encode_addr(&endpoint.addr())?,
            id: endpoint.id().to_string(),
        });

        let mut session = endpoint
            .accept_with(&gate, self.epoch)
            .await
            .context("accepting")?;

        let me = Member::new(self.identity.id().as_bytes()).context("creating member")?;
        self.announce(&session, &endpoint).await;

        let conversation = crate::handshake::host(&mut session, &me)
            .await
            .context("MLS handshake")?;

        self.chat(session, conversation, me, rx).await;
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

        let evidence = match invite.map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(code.as_bytes())
                    .context("invitation is not valid base64")?;
                let secret: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .context("invitation secret is not 32 bytes")?;
                // Expiry belongs to the issuer; we only prove possession.
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
            text: "Connecting".into(),
        });

        let mut session = endpoint
            .connect_with(addr, &evidence)
            .await
            .context("connecting")?;

        let me = Member::new(self.identity.id().as_bytes()).context("creating member")?;
        self.announce(&session, &endpoint).await;

        let conversation = crate::handshake::join(&mut session, &me)
            .await
            .context("MLS handshake")?;

        self.chat(session, conversation, me, rx).await;
        endpoint.close().await;
        Ok(())
    }

    async fn announce(&self, session: &Session, endpoint: &RotelyxEndpoint) {
        let peer = session.peer();
        // Whether a third party is carrying this session. Shown in the window,
        // because a user deserves to know when a relay is in the path even
        // though it can read nothing.
        let direct = endpoint.is_direct(peer).await.unwrap_or(false);

        self.emit(Event::Connected {
            peer: peer.to_string(),
            safety_number: self.identity.safety_number(&peer),
            direct,
        });
    }

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
                        Some(Command::Hangup) | None => break,
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
                        // A commit. Surfacing it is a security control: MLS makes
                        // membership changes visible and a silent UI discards
                        // that guarantee.
                        Ok(None) => self.emit(Event::GroupChanged {
                            members: conversation.member_count(),
                        }),
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
    }
}
