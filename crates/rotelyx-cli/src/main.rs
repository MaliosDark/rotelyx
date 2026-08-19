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
use rotelyx_net::{EndpointAddr, NetConfig, PathPolicy, RelayPolicy, RelayUrl};
use rotelyx_audio::Call;

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

        /// Route through this relay, and never take a direct path.
        ///
        /// Without it the session is direct only, which is fine for text and
        /// impossible for a call: audio over a direct path shows the other side
        /// your address, and `MediaOut` refuses to exist on a connection that
        /// permits one. So `/call` needs this and says so if it is missing.
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
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

        /// Route through this relay, and never take a direct path.
        ///
        /// Must match what the listening side used, and is what a call needs.
        /// See `Listen`.
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
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
/// Start a call from what a chat has: a group and a member.
///
/// The audio crate takes a key and an index rather than a conversation, because
/// it has no business knowing what a conversation is. This is the one place that
/// translation happens.
fn start_call(conversation: &Conversation, me: &Member, paths: PathPolicy) -> Result<Call> {
    let base = conversation
        .media_base_key(me)
        .context("deriving the call key from the group")?;
    Call::start(base, sender_index(conversation, me)?, paths)
}

/// This member's sender index, agreed without exchanging anything.
///
/// Every frame is keyed per sender, so the two sides must not pick the same
/// index and must each know the other's. Sorting the roster by signature key and
/// taking a position gives both sides the same answer from state they already
/// share, which beats adding a negotiation that could disagree.
fn sender_index(conversation: &Conversation, me: &Member) -> Result<u8> {
    let mine = me.signature_key();
    let mut keys: Vec<Vec<u8>> = conversation.roster().into_iter().map(|p| p.signature_key).collect();
    keys.sort();
    let position = keys
        .iter()
        .position(|k| *k == mine)
        .context("this member is not in the roster it belongs to")?;
    u8::try_from(position).context("more members than a sender index can hold")
}


async fn chat(
    session: Session,
    mut conversation: Conversation,
    me: Member,
    paths: PathPolicy,
) -> Result<()> {
    let (mut send, mut recv, conn) = session.split_for_chat();

    let reader = BufReader::new(tokio::io::stdin());
    let mut lines = reader.lines();

    // A call, once one is running. `None` the rest of the time, so a session
    // that never calls opens no device and allocates no codec.
    let mut call: Option<Call> = None;

    // Ticks whether or not a call is running. An interval that is created when a
    // call starts would need the select to change shape, and one tick every 20 ms
    // on an idle session costs nothing worth the complication.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    println!("connected: type to send, /call to talk, Ctrl-D to quit");

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line.context("reading stdin")? {
                    Some(text) if text.trim() == "/call" => {
                        match call {
                            Some(_) => println!("[already on a call: /hang to stop]"),
                            None => match start_call(&conversation, &me, paths) {
                                Ok(c) => {
                                    println!(
                                        "[call started: {} kbit/s, microphone is {}]",
                                        c.kbit_per_second(),
                                        if c.microphone_is_mono() { "mono" } else { "stereo, averaged" }
                                    );
                                    call = Some(c);
                                }
                                Err(e) => println!("[cannot call: {e:#}]"),
                            },
                        }
                    }
                    Some(text) if text.trim() == "/hang" => {
                        match call.take() {
                            Some(c) => println!(
                                "[call ended: {} sent, {} received, {} ms queued, {} ms of microphone dropped]",
                                c.frames_sent(),
                                c.frames_received(),
                                c.queued_ms(),
                                c.dropped_ms()
                            ),
                            None => println!("[not on a call]"),
                        }
                    }
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

            // One frame of microphone, encoded and sent. Nothing happens here
            // when no call is running, and nothing happens when the microphone
            // has not yet produced a whole window: a partial window padded with
            // zeros is an audible click every 20 ms.
            _ = tick.tick() => {
                if let Some(c) = call.as_mut() {
                    if let Err(e) = c.send_all_ready(&conn) {
                        println!("[call ended: {e:#}]");
                        call = None;
                    }
                }
            }

            // Audio in. Read even with no call running, because a datagram that
            // is never read is a datagram the peer keeps retrying.
            datagram = conn.read_datagram() => {
                match datagram {
                    Ok(bytes) => {
                        if let Some(c) = call.as_mut() {
                            c.receive_one(&bytes);
                        }
                    }
                    Err(e) => {
                        // The connection going away ends the chat too, and the
                        // stream branch below will say so. Nothing to add here.
                        let _ = e;
                    }
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

        Command::Listen { open, relay } => {
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

            // Without --relay this is direct only: no relay, no discovery, and
            // both peers must be reachable to each other, which on one machine
            // or one LAN they are. With it, relayed and never direct.
            let config = net_config(relay.as_deref())?;
            let endpoint = RotelyxEndpoint::bind(&identity, config.clone()).await?;
            let addr = endpoint.addr();

            println!("listening as {}", endpoint.id());
            println!();
            println!("  rotelyx connect '{}'", encode_addr(&addr, &config)?);
            println!();

            let mut session = endpoint
                .accept_with(&gate, epoch)
                .await
                .context("accepting")?;
            print_safety_number(&identity, session.peer());

            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::host(&mut session, &me).await?;
            chat(session, conversation, me, net_config(relay.as_deref())?.paths()).await?;
            endpoint.close().await;
        }

        Command::Connect { addr, invite, relay } => {
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

            let endpoint = RotelyxEndpoint::bind(&identity, net_config(relay.as_deref())?).await?;
            let mut session = endpoint
                .connect_with(addr, &evidence)
                .await
                .context("connecting")?;
            print_safety_number(&identity, session.peer());

            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::join(&mut session, &me).await?;
            chat(session, conversation, me, net_config(relay.as_deref())?.paths()).await?;
            endpoint.close().await;
        }
    }

    Ok(())
}

/// Addresses are exchanged out of band, so they need a form a person can paste.

/// The network configuration for a session, and why it is one of two.
///
/// Without `--relay` this is direct only: no relay is contacted at all, which is
/// the right default for text between two machines that can reach each other.
///
/// With `--relay` it is **relay only**, not "relay preferred". A call cannot run
/// on a connection that permits a direct path, because a direct path is your
/// address handed to whoever is on the other end, and `rotelyx_media` enforces
/// that rather than trusting a caller to. Choosing `PreferDirect` here would
/// produce a session that sometimes allows a call and sometimes does not,
/// depending on whether hole punching happened to work, which is worse than
/// either answer.
fn net_config(relay: Option<&str>) -> Result<NetConfig> {
    let Some(url) = relay else {
        return Ok(NetConfig::direct_only());
    };
    let url: RelayUrl = url
        .parse()
        .with_context(|| format!("{url} is not a relay URL"))?;
    Ok(NetConfig::new(
        RelayPolicy::SelfHosted(vec![url]),
        PathPolicy::RelayOnly,
    ))
}

/// Encode an address to hand to a peer, minus anything the policy will not use.
///
/// # Why this filters
///
/// An `EndpointAddr` carries whatever the endpoint knows about how to reach
/// itself, and on an ordinary machine that includes its IP and port. Handing
/// that to somebody is handing them your address, and on a session that will
/// never take a direct path they cannot use it for anything except knowing
/// where you are.
///
/// Observed rather than assumed: with `--relay` set, the address printed was
///
/// ```text
/// {"id":"3b427d3f...","addrs":[{"Ip":"192.168.68.46:56860"}]}
/// ```
///
/// which is the operator's LAN address published to whoever they send an
/// invitation to, on the one configuration whose entire purpose is not
/// revealing it.
///
/// The transport is not wrong to know its own addresses. What was wrong was
/// printing all of them regardless of what the session would do with them.
fn encode_addr(addr: &EndpointAddr, config: &NetConfig) -> Result<String> {
    let mut addr = addr.clone();

    if !config.paths().permits_direct() {
        addr.addrs
            .retain(|a| !matches!(a, rotelyx_net::TransportAddr::Ip(_)));

        // Removing the IPs leaves nothing to route on, because `addr()` is read
        // the moment the endpoint binds and the relay is not established yet.
        // Measured: with the IPs stripped and nothing put back, the peer failed
        // with "connecting" and never reached anything.
        //
        // The relay from the configuration is the right thing to publish anyway.
        // It is where this endpoint can be reached, it is already public, and it
        // is what the peer will use.
        for url in config.relays().urls() {
            addr.addrs
                .insert(rotelyx_net::TransportAddr::Relay(url.clone()));
        }
    }

    let json = serde_json::to_vec(&addr).context("encoding address")?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(&json))
}

fn decode_addr(s: &str) -> Result<EndpointAddr> {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .context("address is not valid base64")?;
    serde_json::from_slice(&bytes).context("address is not a valid Rotelyx address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rotelyx_net::TransportAddr;

    fn addr_with_ip() -> EndpointAddr {
        let id = rotelyx_net::SecretKey::generate().public();
        let mut addr = EndpointAddr::from(id);
        addr.addrs.insert(TransportAddr::Ip(
            "192.168.68.46:56860".parse().expect("a socket address"),
        ));
        addr
    }

    fn decoded(encoded: &str) -> EndpointAddr {
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .expect("base64");
        serde_json::from_slice(&bytes).expect("json")
    }

    /// A relayed session must not publish where the machine is.
    ///
    /// This is the check on a claim, not a unit test of a helper: the address a
    /// user pastes into a chat window is the one place their IP would travel,
    /// and it did travel, on the configuration whose whole purpose is that it
    /// does not.
    #[test]
    fn a_relayed_address_carries_no_ip() {
        let config = net_config(Some("http://relay.example.internal")).expect("config");
        let encoded = encode_addr(&addr_with_ip(), &config).expect("encode");
        let out = decoded(&encoded);

        assert!(
            !out.addrs.iter().any(|a| matches!(a, TransportAddr::Ip(_))),
            "a relay-only address published an IP: {:?}",
            out.addrs
        );
    }

    /// And it must still say where to find them, or the peer cannot connect.
    ///
    /// Removing the IPs and putting nothing back was tried, and the peer failed
    /// with "connecting" against a live relay. Both halves are the property.
    #[test]
    fn a_relayed_address_still_says_where_to_connect() {
        let config = net_config(Some("http://relay.example.internal")).expect("config");
        let encoded = encode_addr(&addr_with_ip(), &config).expect("encode");
        let out = decoded(&encoded);

        assert!(
            out.addrs.iter().any(|a| matches!(a, TransportAddr::Relay(_))),
            "a relay-only address named no relay, so nothing can reach it"
        );
    }

    /// A direct session needs the IP, and must keep it.
    ///
    /// The filter is not "always strip": stripping here would break the default
    /// configuration, which has no relay to fall back to.
    #[test]
    fn a_direct_address_keeps_its_ip() {
        let config = net_config(None).expect("config");
        let encoded = encode_addr(&addr_with_ip(), &config).expect("encode");
        let out = decoded(&encoded);

        assert!(
            out.addrs.iter().any(|a| matches!(a, TransportAddr::Ip(_))),
            "a direct-only address lost the address it needs"
        );
    }
}
