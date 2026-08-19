//! Rotelyx: a headless two-terminal chat, for exercising the protocol end to end.
//!
//! Not a product. It exists so the stack can be run rather than only tested:
//! two processes, a real QUIC connection, an MLS group of two, and messages
//! that are ciphertext everywhere except inside the two terminals.
//!
//! ```text
//!   terminal 1:  rotelyx listen
//!   terminal 2:  rotelyx connect <address printed by terminal 1>
//! ```

mod handshake;
mod keyfile;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};
use rotelyx_core::store::{self, Blocklist, Paths, StoredInvitation};
use rotelyx_core::{
    epoch_at, Admission, Frame, FrameKind, Gate, Identity, Invitation, ReachabilityPolicy, Session,
    RotelyxEndpoint, RotelyxId,
};
use rotelyx_crypto::{Conversation, Member};
use rotelyx_net::{EndpointAddr, NetConfig};

#[derive(Parser, Debug)]
#[command(name = "rotelyx", about = "Rotelyx protocol harness")]
struct Cli {
    /// Where the identity key is stored.
    ///
    /// Plaintext on disk. Acceptable for a harness, unacceptable for a client:
    /// a real one seals this with a key derived from the device keystore.
    #[arg(long, default_value = "rotelyx-identity.key", global = true)]
    identity: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print this identity, creating one if the key file does not exist.
    Id,

    /// Issue an invitation and print it.
    ///
    /// Hand the code to the person you want to reach you, over a channel you
    /// trust. Anyone holding it can open a session with you until it expires.
    Invite {
        /// Hours the invitation stays valid.
        #[arg(long, default_value_t = 24)]
        hours: u64,
    },

    /// Wait for a peer, then chat.
    Listen {
        /// Accept anyone who connects, with no invitation.
        ///
        /// Explicit on purpose. Rotelyx's default is that an identity is
        /// unreachable without a capability it issued: the whole answer to
        /// free identities being free to spam from.
        #[arg(long)]
        open: bool,
    },

    /// Refuse a specific identity from now on. Persists across restarts.
    Block {
        /// The identity to refuse.
        id: String,
    },

    /// Stop refusing an identity.
    Unblock {
        /// The identity to allow again.
        id: String,
    },

    /// List blocked identities.
    Blocks,

    /// Dial a peer, then chat.
    Connect {
        /// The address printed by the listening side.
        addr: String,

        /// The invitation code the peer issued.
        #[arg(long)]
        invite: Option<String>,
    },
}

/// Wall-clock epoch. The library takes time as a parameter so it stays
/// testable; somebody has to read a clock, and this is the somebody.
fn now_epoch() -> Result<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();
    Ok(epoch_at(secs))
}

/// Show what the user needs to compare out of band before trusting the session.
fn print_safety_number(me: &Identity, peer: RotelyxId) {
    println!();
    println!("  peer          {peer}");
    println!("  safety number {}", me.safety_number(&peer));
    println!();
    println!("  Read those digits to your peer over a channel Rotelyx does not");
    println!("  control. If they differ, someone is in the middle: the");
    println!("  transport authenticated a key, not a person.");
    println!();
}

/// Read lines from the terminal and send them; print what arrives.
async fn chat(session: Session, mut conversation: Conversation, me: Member) -> Result<()> {
    let (mut send, mut recv, conn) = session.split_for_chat();

    let reader = BufReader::new(tokio::io::stdin());
    let mut lines = reader.lines();

    println!("connected: type to send, Ctrl-D to quit");

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line.context("reading stdin")? {
                    Some(text) => {
                        let ciphertext = conversation
                            .send(&me, text.as_bytes())
                            .context("encrypting")?;
                        Frame::new(FrameKind::Message, ciphertext)
                            .write(&mut send)
                            .await
                            .context("sending")?;
                    }
                    None => break,
                }
            }
            frame = Frame::read(&mut recv) => {
                let frame = match frame {
                    Ok(f) => f,
                    // The peer hanging up ends a chat; it is not a failure and
                    // should not print a stack trace at somebody.
                    Err(e) => {
                        println!("[peer disconnected: {e}]");
                        break;
                    }
                };
                match frame.kind {
                    FrameKind::Message => {
                        match conversation.receive(&me, &frame.payload).context("decrypting")? {
                            Some(plaintext) => {
                                println!("peer: {}", String::from_utf8_lossy(&plaintext));
                            }
                            // A commit: the group changed. A real client must
                            // surface this: silent membership changes are how
                            // ghost-member attacks stay invisible.
                            None => println!("[the group changed: {} members]", conversation.member_count()),
                        }
                    }
                    other => println!("[ignoring {other:?} frame]"),
                }
            }
        }
    }

    // Finish before closing: a dropped QUIC send stream resets, discarding
    // anything still in flight: the last message would vanish silently.
    let _ = send.finish();
    let _ = send.stopped().await;
    conn.close(0u32.into(), b"bye");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx=info,warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let paths = Paths::from_identity(&cli.identity);
    let identity = keyfile::load_or_create(&paths.identity)?;

    match cli.command {
        Command::Id => {
            println!("{}", identity.id());
        }

        Command::Invite { hours } => {
            let epoch = now_epoch()?;
            let expires = epoch + hours.max(1);
            let invitation = Invitation::issue(expires);
            let stored = StoredInvitation {
                secret: *invitation.secret_bytes(),
                expires_at_epoch: expires,
            };
            let code = stored.code();

            store::add_invitation(&paths.invitations, stored, epoch)?;

            println!("invitation, valid {hours}h. Treat it like a password.");
            println!();
            println!("  {code}");
            println!();
            println!("The holder connects with:");
            println!("  rotelyx connect <address> --invite {code}");
        }

        Command::Block { id } => {
            let target: RotelyxId = id.parse().context("not a valid identity")?;
            let mut blocks = Blocklist::load(&paths.blocks)?;
            if blocks.insert(target) {
                blocks.save(&paths.blocks)?;
                println!("blocked {target}");
            } else {
                println!("{target} was already blocked");
            }
        }

        Command::Unblock { id } => {
            let target: RotelyxId = id.parse().context("not a valid identity")?;
            let mut blocks = Blocklist::load(&paths.blocks)?;
            if blocks.remove(&target) {
                blocks.save(&paths.blocks)?;
                println!("unblocked {target}");
            } else {
                println!("{target} was not blocked");
            }
        }

        Command::Blocks => {
            let blocks = Blocklist::load(&paths.blocks)?;
            if blocks.is_empty() {
                println!("no blocked identities");
            } else {
                let mut ids: Vec<_> = blocks.iter().map(ToString::to_string).collect();
                ids.sort();
                for id in ids {
                    println!("{id}");
                }
            }
        }

        Command::Listen { open } => {
            let epoch = now_epoch()?;
            let blocks = Blocklist::load(&paths.blocks)?;

            let mut gate = if open {
                eprintln!("WARNING: accepting anyone who connects");
                Gate::new(ReachabilityPolicy::Open)
            } else {
                let invitations = store::load_invitations(&paths.invitations, epoch)?;
                if invitations.is_empty() {
                    bail!(
                        "no live invitations in {}. Run `rotelyx invite` first, \
                         or pass --open to accept anyone.",
                        paths.invitations.display()
                    );
                }
                let mut gate = Gate::invitation_only();
                let count = invitations.len();
                for inv in &invitations {
                    gate.add_invitation(inv.to_invitation());
                }
                eprintln!("admitting holders of {count} live invitation(s)");
                gate
            };

            // Blocks are loaded from disk, so they survive a restart. A block
            // that does not is not a block.
            for id in blocks.iter() {
                gate.block(*id);
            }
            if !blocks.is_empty() {
                eprintln!("refusing {} blocked identity(ies)", blocks.len());
            }

            // Direct-only: no relay, no discovery. Both peers must be reachable
            // to each other, which on one machine or one LAN they are.
            let endpoint = RotelyxEndpoint::bind(&identity, NetConfig::direct_only()).await?;
            let addr = endpoint.addr();

            println!("listening as {}", endpoint.id());
            println!();
            println!("  rotelyx connect '{}'", encode_addr(&addr)?);
            println!();

            let mut session = endpoint
                .accept_with(&gate, epoch)
                .await
                .context("accepting")?;
            print_safety_number(&identity, session.peer());

            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::host(&mut session, &me).await?;
            chat(session, conversation, me).await?;
            endpoint.close().await;
        }

        Command::Connect { addr, invite } => {
            let addr = decode_addr(&addr)?;
            let epoch = now_epoch()?;

            let evidence = match invite {
                Some(code) => {
                    let bytes = data_encoding::BASE64URL_NOPAD
                        .decode(code.trim().as_bytes())
                        .context("invitation is not valid base64")?;
                    let secret: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .context("invitation secret is not 32 bytes")?;
                    // Expiry is the issuer's to enforce; we only prove holding.
                    let invitation = Invitation::from_secret(secret, u64::MAX);
                    Admission::Invitation {
                        proof: invitation.prove(&identity.id(), epoch),
                        epoch,
                    }
                }
                None => Admission::None,
            };

            let endpoint = RotelyxEndpoint::bind(&identity, NetConfig::direct_only()).await?;
            let mut session = endpoint
                .connect_with(addr, &evidence)
                .await
                .context("connecting")?;
            print_safety_number(&identity, session.peer());

            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::join(&mut session, &me).await?;
            chat(session, conversation, me).await?;
            endpoint.close().await;
        }
    }

    Ok(())
}

/// Addresses are exchanged out of band, so they need a form a person can paste.
fn encode_addr(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr).context("encoding address")?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(&json))
}

fn decode_addr(s: &str) -> Result<EndpointAddr> {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .context("address is not valid base64")?;
    serde_json::from_slice(&bytes).context("address is not a valid Rotelyx address")
}
