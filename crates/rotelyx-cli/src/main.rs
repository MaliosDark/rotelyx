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
use rotelyx_net::{EndpointAddr, NetConfig, PathPolicy, RelayPolicy, RelayUrl, SecretKey};
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
/// Refuse a session whose peer is blocked.
///
/// The transport check in `Gate::admit` cannot do this any more: an endpoint
/// bound under an invitation's key authenticates that key, and a blocklist
/// holds identities. Without this, blocking would report success and do
/// nothing, which is the one outcome worse than not having it.
fn refuse_if_blocked(gate: &Gate, conversation: &Conversation) -> Result<()> {
    let identities: Vec<Vec<u8>> = conversation.roster().into_iter().map(|p| p.identity).collect();
    if let Some(id) = gate.blocked_member(&identities) {
        bail!("{id} is blocked. Closing.");
    }
    Ok(())
}

/// The safety number, over the identity the group authenticated.
///
/// # Why not over the transport peer
///
/// It used to be, and that was correct while the transport key was the identity
/// key. It is not any more: an invitation is answered on a key of its own, so
/// the peer a handshake authenticates is a value that belongs to one
/// conversation and says nothing about who is behind it. A safety number over
/// that verifies that nobody swapped the key, which is not what anybody reads
/// it out loud for.
///
/// The identity is inside, where MLS put it, and that is what this compares.
/// Read after the handshake rather than before it, which is later than a user
/// might like and is the only point at which the number means anything.
fn print_safety_number(me: &Identity, conversation: &Conversation) {
    let roster: Vec<Vec<u8>> = conversation.roster().into_iter().map(|p| p.identity).collect();

    println!();
    match rotelyx_core::peer_identity(&roster, me.id()) {
        Some(peer) => {
            println!("  peer          {peer}");
            println!("  safety number {}", me.safety_number(&peer));
            println!();
            println!("  Read those digits to your peer over a channel Rotelyx does not");
            println!("  control. If they differ, somebody is in the middle.");
            println!();
            println!("  This is their identity, not the address you called. Those are");
            println!("  different values now, and only this one is the person.");
        }
        None => {
            println!("  no peer identity in the group, which should not happen.");
            println!("  Do not trust this session.");
        }
    }
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
                transport: *invitation.transport_bytes(),
                expires_at_epoch: expires,
            };
            let code = stored.code();

            store::add_invitation(&paths.invitations, stored, epoch)?;

            println!("invitation, valid {hours}h. Treat it like a password.");
            println!();
            println!("  {code}");
            println!();
            println!("The holder connects with just that:");
            println!("  rotelyx connect {code}");
            println!();
            println!("It carries the address as well as the permission, and that");
            println!("address belongs to this invitation alone. It is not your");
            println!("identity, and a relay carrying the traffic never sees one.");
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

            // Loaded before the gate, because they decide two things now: who is
            // admitted, and which key this endpoint answers on.
            let live = store::load_invitations(&paths.invitations, epoch)?;

            let mut gate = if open {
                eprintln!("WARNING: accepting anyone who connects");
                Gate::new(ReachabilityPolicy::Open)
            } else {
                let invitations = &live;
                if invitations.is_empty() {
                    bail!(
                        "no live invitations in {}. Run `rotelyx invite` first, \
                         or pass --open to accept anyone.",
                        paths.invitations.display()
                    );
                }
                let mut gate = Gate::invitation_only();
                let count = invitations.len();
                for inv in invitations {
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

            // Which key to answer on.
            //
            // An invitation now carries an address of its own, so answering
            // means binding that invitation's key rather than the identity's.
            // The identity never reaches the wire and a relay carrying this
            // sees a value that belongs to one conversation.
            //
            // **Every live invitation, on one connection.** A relay connection
            // is opened under one key, so the newest invitation is bound first
            // and the rest are added as aliases: the relay is asked to route
            // their addresses to this same connection, and the TLS resolver is
            // given their keys so it can answer there. Each holder still sees
            // only the address it was given, and nothing on the wire ties them
            // to each other.
            let newest = live.iter().max_by_key(|i| i.expires_at_epoch);
            let endpoint = match (newest, open) {
                (Some(inv), _) => {
                    let key = SecretKey::from_bytes(&inv.transport);
                    RotelyxEndpoint::bind_as(&identity, key, config.clone()).await?
                }
                // An open host publishes one address and keeps it, so it answers
                // on the identity. There is nobody to hide it from: it is
                // already telling strangers where it is.
                (None, true) => RotelyxEndpoint::bind(&identity, config.clone()).await?,
                (None, false) => bail!(
                    "no live invitation to answer on. Issue one with `rotelyx invite`, \
                     or pass --open to answer on this identity"
                ),
            };
            // The rest of the live invitations, answered on the same connection.
            let primary = newest.map(|i| i.transport);
            for inv in &live {
                if Some(inv.transport) == primary {
                    continue;
                }
                if !endpoint.also_answer_as(&SecretKey::from_bytes(&inv.transport)) {
                    eprintln!(
                        "warning: could not ask the relay to answer one invitation's \
                         address. Its holder may not be able to reach you."
                    );
                }
            }

            let addr = endpoint.addr();

            match newest {
                Some(_) => {
                    let mut codes: Vec<_> = live.iter().collect();
                    codes.sort_by_key(|i| i.expires_at_epoch);
                    let n = codes.len();
                    if n == 1 {
                        println!("answering one invitation. Hand the holder its code:");
                    } else {
                        println!("answering {n} invitations. Each holder gets its own code:");
                    }
                    println!();
                    for inv in codes {
                        println!("  rotelyx connect {}", inv.code());
                    }
                    println!();
                    println!("A code is the address as well as the permission, and");
                    println!("the address is not this identity.");
                    if n > 1 {
                        println!();
                        println!("All {n} addresses are answered, and the first caller to");
                        println!("arrive is the one served: this is one conversation at a");
                        println!("time, not {n} at once.");
                    }
                }
                None => {
                    println!("listening as {}", endpoint.id());
                    println!();
                    println!("  rotelyx connect '{}'", encode_addr(&addr, &config)?);
                    println!();
                }
            }

            let mut session = endpoint
                .accept_with(&gate, epoch)
                .await
                .context("accepting")?;
            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::host(&mut session, &me).await?;
            refuse_if_blocked(&gate, &conversation)?;
            print_safety_number(&identity, &conversation);
            chat(session, conversation, me, net_config(relay.as_deref())?.paths()).await?;
            endpoint.close().await;
        }

        Command::Connect { addr, invite, relay } => {
            let epoch = now_epoch()?;

            // A transport key for this call and nothing else.
            //
            // The relay sees this and never the identity. It is generated here
            // rather than stored, so two calls to the same person are two
            // unrelated values to anybody carrying them. The identity is still
            // authenticated, inside, where an operator cannot look.
            let transport = RotelyxEndpoint::ephemeral_transport_key();
            let calling_as: RotelyxId = transport.public().into();

            // An invitation code carries where to call as well as permission to.
            // A bare address is still accepted, for a host running --open.
            let code = invite.as_deref().or(Some(addr.as_str()));
            let (evidence, addr) = match code {
                Some(text) => {
                    let bytes = data_encoding::BASE64URL_NOPAD
                        .decode(text.trim().as_bytes())
                        .context("invitation is not valid base64")?;

                    match Invitation::read_code(&bytes) {
                        Ok((secret, host)) => {
                            // Expiry is the issuer's to enforce; we prove holding.
                            let invitation = Invitation::from_parts(secret, [0u8; 32], u64::MAX);
                            // The code names who to call and not where. A bare
                            // id is not routable: the transport reports "no
                            // addressing information" and stops, because
                            // address lookup is deliberately not configured
                            // and never will be.
                            //
                            // The relay is where. Which is also why an
                            // invitation address is only reachable through
                            // one: it is a key belonging to nobody, and
                            // nothing on the network knows where it lives.
                            let mut to = EndpointAddr::from(host.endpoint_id());
                            let cfg = net_config(relay.as_deref())?;
                            for url in cfg.relays().urls() {
                                to.addrs
                                    .insert(rotelyx_net::TransportAddr::Relay(url.clone()));
                            }
                            if to.addrs.is_empty() {
                                bail!(
                                    "an invitation address is reachable only through a relay, \
                                     and none was given. Pass --relay <url>, the same one the \
                                     other side is answering on"
                                );
                            }

                            (
                                Admission::Invitation {
                                    proof: invitation.prove(&calling_as, epoch),
                                    epoch,
                                },
                                to,
                            )
                        }
                        // Not an invitation code, so it is a plain address.
                        Err(_) => (Admission::None, decode_addr(&addr)?),
                    }
                }
                None => (Admission::None, decode_addr(&addr)?),
            };

            let endpoint =
                RotelyxEndpoint::bind_as(&identity, transport, net_config(relay.as_deref())?)
                    .await?;
            let mut session = endpoint
                .connect_with(addr, &evidence)
                .await
                .context("connecting")?;
            let me = Member::new(identity.id().as_bytes()).context("creating member")?;
            let conversation = handshake::join(&mut session, &me).await?;

            // The caller checks too. Blocking somebody and then dialling them
            // and talking is not blocking, and the person on the other end has
            // no way to know you meant to refuse.
            {
                let mut gate = Gate::invitation_only();
                for id in Blocklist::load(&paths.blocks)?.iter() {
                    gate.block(*id);
                }
                refuse_if_blocked(&gate, &conversation)?;
            }

            print_safety_number(&identity, &conversation);
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
