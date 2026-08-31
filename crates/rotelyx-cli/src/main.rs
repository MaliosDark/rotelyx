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
mod resume;

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rotelyx_audio::Call;
use rotelyx_core::store::{self, Paths, StoredInvitation};
use rotelyx_core::{
    epoch_at, Admission, Frame, FrameKind, Gate, Invitation, ReachabilityPolicy, RotelyxEndpoint,
    RotelyxId, Session,
};
use rotelyx_crypto::{Conversation, Member, Received};
use rotelyx_net::{EndpointAddr, NetConfig, PathPolicy, RelayPolicy, RelayUrl, SecretKey};
use tokio::io::{AsyncBufReadExt, BufReader};

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

        /// Name this relay as the far end of a chain, so the caller reaches you
        /// through two relays rather than one.
        ///
        /// # What it buys and what it does not
        ///
        /// One relay learns who is talking to whom. Two split that: the
        /// caller's relay learns the caller and that a circuit was opened
        /// through this one; this one learns you and that traffic arrives from
        /// theirs. Neither alone holds the pair.
        ///
        /// **Two relays run by one operator buy nothing.** Colluding operators
        /// hold exactly what one holds today, and nothing here can check
        /// whether two relays are run by the same person: they are two
        /// addresses and two keys, and that is all anybody can see.
        ///
        /// The invitation carries this relay's name and a hash of its circuit
        /// key, which is fetched from it now. It has to be a relay started with
        /// `--circuit-key`, or it has no key to give.
        #[arg(long, value_name = "URL")]
        through: Option<String>,
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

    /// Withdraw an invitation, so its holder cannot connect again.
    ///
    /// This is what blocking means here. There is no identity to ban: a caller
    /// arrives on a key belonging to one invitation and nothing else, and the
    /// name anybody sees is derived per conversation. What can be withdrawn is
    /// the invitation, which is a thing this side issued and holds the secret
    /// for.
    Block {
        /// The invitation code, or its number from `rotelyx invitations`.
        which: String,
    },

    /// List the invitations this device has issued and not withdrawn.
    Invitations,

    /// Dial a peer, then chat.
    Connect {
        /// The address printed by the listening side.
        ///
        /// A code is base64url, whose alphabet includes `-`, so roughly one code
        /// in sixty four begins with one and would otherwise be read as a flag.
        /// The holder was told to paste what they were given, so it has to be
        /// taken as a value whatever it starts with.
        #[arg(allow_hyphen_values = true)]
        addr: String,

        /// The invitation code the peer issued.
        #[arg(long, allow_hyphen_values = true)]
        invite: Option<String>,

        /// Route through this relay, and never take a direct path.
        ///
        /// Must match what the listening side used, and is what a call needs.
        /// See `Listen`.
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
    },

    /// Dial a peer and report whether a direct path is ever established.
    ///
    /// # What this is for
    ///
    /// The reason a relay exists is that two NATs sometimes cannot be punched
    /// through, and **that has never been measured here**. Every test so far
    /// runs on loopback, which needs no hole punching at all, so the failure
    /// rate this whole design is built around is a number nobody has.
    ///
    /// This is the instrument, not the measurement. The measurement needs two
    /// machines on **different** networks: run `listen` on one, this on the
    /// other, and collect the last line from many runs. One run says nothing.
    ///
    /// The last line is one record, so a shell loop can append them to a file:
    ///
    /// ```text
    /// direct=yes after=1.42s relayed_first=yes peer=a1b2c3d4e5f6a7b8
    /// direct=no  after=-     relayed_first=yes peer=a1b2c3d4e5f6a7b8
    /// ```
    Probe {
        /// The address printed by the listening side.
        #[arg(allow_hyphen_values = true)]
        addr: String,

        /// The invitation code the peer issued.
        #[arg(long, allow_hyphen_values = true)]
        invite: Option<String>,

        /// Relays to use while hole punching is attempted.
        #[arg(long, value_name = "URL")]
        relay: Option<String>,

        /// How long to wait for a direct path before calling it relayed.
        ///
        /// Thirty seconds because hole punching is not instant and a probe that
        /// gave up in two would report failures that were not failures.
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        wait: u64,
    },
}

/// A member's identity, short enough to read aloud and long enough to mean
/// something. Eight bytes: a person comparing two of these is not relying on it
/// for authentication, which the safety number is for.
fn short_id(identity: &[u8]) -> String {
    identity
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
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
/// Refuse a peer on the blocklist.
///
/// # This does not work against anybody who does not want it to
///
/// It reads the roster, and a roster entry is an MLS credential: a byte string
/// the member chose. Nothing proves it corresponds to any identity. Measured: a
/// peer that puts its real identity there is refused, and the same peer putting
/// anything else is admitted.
///
/// It did not work before per-conversation names either, and they make it plain
/// rather than worse: a name is derived per conversation now, so a blocklist of
/// identities cannot match one by construction.
///
/// The check that does work is revocation. An invitation proof is verified
/// against a secret the issuer holds, so retiring the invitation refuses the
/// holder and there is nothing for them to rename. Blocking a person is not a
/// thing this design can do; ending a conversation is.
/// Resolve what somebody typed into one of the invitations they have issued.
///
/// A number, because that is what the list prints and what a person can retype
/// without pasting; or the code itself, for the case where they kept it and the
/// list has since renumbered. Nothing else: guessing at a prefix would make
/// `block` ambiguous, and this is the command that takes something away.
fn pick_invitation<'a>(
    live: &'a [store::StoredInvitation],
    which: &str,
) -> Result<&'a store::StoredInvitation> {
    if live.is_empty() {
        bail!("no live invitations to withdraw. `rotelyx invitations` lists them.");
    }

    if let Ok(n) = which.parse::<usize>() {
        return live
            .get(n.wrapping_sub(1))
            .filter(|_| n >= 1)
            .ok_or_else(|| match live.len() {
                1 => anyhow!("there is no invitation {n}. There is one."),
                many => anyhow!("there is no invitation {n}. There are {many}."),
            });
    }

    live.iter().find(|inv| inv.code() == which).ok_or_else(|| {
        anyhow!("that is neither a number from `rotelyx invitations` nor a code this device issued")
    })
}

/// The safety number, over the names the two sides use in this conversation.
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
fn print_safety_number(my_name: RotelyxId, conversation: &Conversation) {
    let roster: Vec<Vec<u8>> = conversation
        .roster()
        .into_iter()
        .map(|p| p.identity)
        .collect();

    println!();
    // Both halves must be the names that are actually in the roster.
    //
    // This used to pass the long-lived identity as "me" while reading the peer
    // out of the roster. That was consistent while the two were the same value.
    // They are not any more: a conversation carries a name derived for it, the
    // identity is in neither roster entry, so each side combined a different
    // pair and read out digits that could not match.
    match rotelyx_core::peer_identity(&roster, my_name) {
        Some(peer) => {
            println!("  peer          {peer}");
            println!(
                "  safety number {}",
                rotelyx_core::safety_number(&my_name, &peer)
            );
            println!();
            println!("  Read those digits to your peer over a channel Rotelyx does not");
            println!("  control. If they differ, somebody is in the middle.");
            println!();
            println!("  This is the name they use in this conversation, and nowhere");
            println!("  else. It is not the address you called and it is not an");
            println!("  identity you can look for elsewhere: the same person shows a");
            println!("  different one to everybody they talk to, so two of their");
            println!("  contacts cannot compare notes and find each other. What the");
            println!("  digits verify is this conversation, not a person in general.");
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
    // Refused rather than started on repeating keys. See the same refusal in
    // the desktop engine: this path has no call setup to carry a per-call value,
    // and without one every call in an epoch shares the first call's nonces.
    let _ = (base, paths, sender_index(conversation, me)?);
    anyhow::bail!(
        "calling over a direct invitation is disabled: it has no way to agree a \
         per-call key, and without one a second call reuses the first call's \
         nonces"
    );
}

/// This member's sender index, agreed without exchanging anything.
///
/// Every frame is keyed per sender, so the two sides must not pick the same
/// index and must each know the other's. Sorting the roster by signature key and
/// taking a position gives both sides the same answer from state they already
/// share, which beats adding a negotiation that could disagree.
fn sender_index(conversation: &Conversation, me: &Member) -> Result<u8> {
    let mine = me.signature_key();
    let mut keys: Vec<Vec<u8>> = conversation
        .roster()
        .into_iter()
        .map(|p| p.signature_key)
        .collect();
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
    me: &Member,
    paths: PathPolicy,
) -> Result<Conversation> {
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
                            None => match start_call(&conversation, me, paths) {
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
                            .send(me, text.as_bytes())
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
                        match conversation.receive(me, &frame.payload).context("decrypting")? {
                            Received::Message { bytes: plaintext, .. } => {
                                println!("peer: {}", String::from_utf8_lossy(&plaintext));
                            }
                            // Who, not how many. A commit can remove one member
                            // and add another at once, which leaves the count
                            // where it was: a client that reports only a number
                            // says "2 members" while you are talking to
                            // somebody else. Silent membership changes are how
                            // ghost-member attacks stay invisible, and so are
                            // membership changes announced without names.
                            Received::MembershipChanged(change) => {
                                for who in &change.added {
                                    println!("[joined: {}]", short_id(&who.identity));
                                }
                                for who in &change.removed {
                                    println!("[left: {}]", short_id(&who.identity));
                                }
                                println!("[the group is now {} members]", conversation.member_count());
                            }
                            Received::Nothing => {}
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
    Ok(conversation)
}

#[tokio::main]
async fn main() -> Result<()> {
    // One TLS provider for this process, before anything builds a client.
    //
    // The HTTP client that reads a relay's circuit key is built with no
    // provider of its own, and without this it does not fail, it **panics**,
    // with a message about a feature flag rather than about what the user
    // asked for.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rotelyx_relay_proto::tls::default_provider()
            .as_ref()
            .clone(),
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx=info,warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let paths = Paths::from_identity(&cli.identity);
    let (identity, passphrase) = keyfile::load_with_passphrase(&paths.identity)?;

    match cli.command {
        Command::Id => {
            println!("{}", identity.id());
        }

        Command::Invite { hours, through } => {
            let epoch = now_epoch()?;
            let expires = epoch + hours.max(1);
            let invitation = Invitation::issue(expires);
            let stored = StoredInvitation {
                secret: *invitation.secret_bytes(),
                transport: *invitation.transport_bytes(),
                expires_at_epoch: expires,
            };
            // Named after the code is minted, because the exit relay is
            // something added to an invitation rather than part of one.
            let code = match through.as_deref() {
                None => stored.code(),
                Some(url) => {
                    let exit = exit_relay_at(url).await?;
                    println!("  the caller will reach you through {url}");
                    println!("  and their own relay, which is theirs to pick.");
                    println!();
                    data_encoding::BASE64URL_NOPAD.encode(&invitation.code_with_exit(&exit)[..])
                }
            };

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

        Command::Block { which } => {
            let epoch = now_epoch()?;
            let live = store::load_invitations(&paths.invitations, epoch)?;
            let target = pick_invitation(&live, &which)?;
            let secret = target.secret;

            // The conversation that ran on it goes too. An invitation withdrawn
            // while its conversation stays on the disk is a person told they are
            // blocked and a file that still decrypts everything they said.
            let address = target.to_invitation().address();

            if store::revoke_invitation(&paths.invitations, &secret, epoch)? {
                resume::forget(&paths, &address)?;
                println!("withdrawn. That invitation admits nobody from now on,");
                println!("and the conversation it carried is off this disk.");
                println!();
                println!("A session already open stays open until it closes: this");
                println!("stops the next connection, it is not a hang-up. To let");
                println!("that person back in, issue a new invitation.");
            } else {
                println!("nothing to withdraw: that invitation is already gone.");
            }
        }

        Command::Invitations => {
            let epoch = now_epoch()?;
            let live = store::load_invitations(&paths.invitations, epoch)?;
            if live.is_empty() {
                println!("no live invitations. Run `rotelyx invite` to make one.");
            } else {
                println!(
                    "{} live. Withdraw one with `rotelyx block <n>`.",
                    live.len()
                );
                println!();
                for (n, inv) in live.iter().enumerate() {
                    // An epoch is an hour, so this is already hours.
                    let hours = inv.expires_at_epoch.saturating_sub(epoch);
                    println!("  {}. expires in {hours}h", n + 1);
                    println!("     {}", inv.code());
                }
            }
        }

        Command::Listen { open, relay } => {
            let epoch = now_epoch()?;

            // Loaded before the gate, because they decide two things now: who is
            // admitted, and which key this endpoint answers on.
            let live = store::load_invitations(&paths.invitations, epoch)?;

            let gate = if open {
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
            // The name this identity uses inside this conversation.
            //
            // Not the long-lived identity: every contact would be shown the same
            // value and two of them could compare it. The invitation the caller
            // actually used is something only the two of us know, so a name
            // derived from it is stable here and unrelated to the name any other
            // contact sees. Which invitation that is comes from the address the
            // call was answered at, which the caller does not choose.
            // Derived from the address the call arrived at, which both sides
            // know and neither can be mistaken about.
            //
            // The invitation secret would do as well and only when both sides
            // have one: an open host with live invitations answers at an
            // invitation's address, and a caller arriving without a code has no
            // secret to derive from, so the two would reach different names and
            // read out safety numbers that cannot match. The address is the
            // thing they always share.
            //
            // It is not secret from the relay, and does not need to be: what is
            // hashed with it is this identity's own key, which nobody else has.
            let shared = session
                .answered_at()
                .unwrap_or_else(|| identity.id())
                .as_bytes()
                .to_vec();
            let my_name = identity.in_conversation(&shared);
            let me = Member::new(my_name.as_bytes()).context("creating member")?;

            // The address is the name of the conversation, so it is also the
            // name of the file. See `resume`.
            let here = session.answered_at().unwrap_or_else(|| identity.id());
            let saved = resume::reopen(&paths, &here, &passphrase)?;
            let opened = handshake::host_resuming(&mut session, &me, saved).await?;

            let (me, conversation) = match opened {
                handshake::Opened::Fresh(conversation) => (me, conversation),
                handshake::Opened::Resumed {
                    member,
                    conversation,
                } => {
                    println!("carried on from where this conversation left off.");
                    (member, conversation)
                }
            };

            // Saved before a word is typed, and again on the way out.
            //
            // A conversation that is only written when the program exits
            // cleanly is one that people lose: terminals get closed, laptops
            // sleep, power goes. Worse, this side has just committed a fresh
            // epoch that the other side has already processed, so leaving
            // without recording it means coming back to an epoch they have
            // moved past.
            resume::save(&paths, &here, &me, &conversation, &passphrase)?;

            print_safety_number(my_name, &conversation);
            let conversation = chat(
                session,
                conversation,
                &me,
                net_config(relay.as_deref())?.paths(),
            )
            .await?;
            resume::save(&paths, &here, &me, &conversation, &passphrase)?;
            endpoint.close().await;
        }

        Command::Probe {
            addr,
            invite,
            relay,
            wait,
        } => {
            let epoch = now_epoch()?;
            let transport = RotelyxEndpoint::ephemeral_transport_key();
            let calling_as: RotelyxId = transport.public().into();
            let config = probing_config(relay.as_deref())?;

            let (evidence, to) = match invite.as_deref().or(Some(addr.as_str())) {
                Some(text) => {
                    let bytes = data_encoding::BASE64URL_NOPAD
                        .decode(text.trim().as_bytes())
                        .unwrap_or_default();
                    match Invitation::read_code(&bytes) {
                        Ok((secret, host)) => {
                            let invitation = Invitation::from_parts(secret, [0u8; 32], u64::MAX);
                            let mut to = EndpointAddr::from(host.endpoint_id());
                            for url in config.relays().urls() {
                                to.addrs
                                    .insert(rotelyx_net::TransportAddr::Relay(url.clone()));
                            }
                            if to.addrs.is_empty() {
                                bail!(
                                    "an invitation address is reachable only through a relay.                                      Pass --relay <url>, the same one the other side is on"
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
                        Err(_) => (Admission::None, decode_addr(&addr)?),
                    }
                }
                None => (Admission::None, decode_addr(&addr)?),
            };

            let peer = RotelyxId::from(to.id);
            let endpoint = RotelyxEndpoint::bind_as(&identity, transport, config).await?;
            let started = std::time::Instant::now();
            let _session = endpoint
                .connect_with(to, &evidence)
                .await
                .context("connecting")?;

            // Whether the session began relayed, which is the interesting case:
            // a direct path that was there from the start needed no punching.
            let relayed_first = endpoint
                .is_direct(peer)
                .await
                .map(|direct| !direct)
                .unwrap_or(true);

            println!(
                "  connected in {:.2}s, waiting up to {wait}s for a direct path",
                started.elapsed().as_secs_f32()
            );

            // Polled rather than notified: `is_direct` is what the interface
            // shows a user, so measuring the same thing they would see keeps
            // the number honest.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
            let mut became_direct = None;
            while std::time::Instant::now() < deadline {
                if endpoint.is_direct(peer).await == Some(true) {
                    became_direct = Some(started.elapsed());
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }

            match became_direct {
                Some(at) => println!("  a direct path came up after {:.2}s", at.as_secs_f32()),
                None => println!("  no direct path in {wait}s: this session stays relayed"),
            }

            // One line, one record. A shell loop appends these and the file is
            // the measurement; a single run is an anecdote.
            println!(
                "direct={} after={} relayed_first={} peer={}",
                if became_direct.is_some() { "yes" } else { "no" },
                became_direct
                    .map(|d| format!("{:.2}s", d.as_secs_f32()))
                    .unwrap_or_else(|| "-".into()),
                if relayed_first { "yes" } else { "no" },
                peer,
            );

            endpoint.close().await;
        }

        Command::Connect {
            addr,
            invite,
            relay,
        } => {
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
            // The exit relay, when the code names one. Read out here because
            // whether this call is chained decides what the endpoint is asked
            // to do after it connects, which is past where the code is parsed.
            let exit = code
                .and_then(|text| {
                    data_encoding::BASE64URL_NOPAD
                        .decode(text.trim().as_bytes())
                        .ok()
                })
                .and_then(|bytes| Invitation::read_code_full(&bytes).ok())
                .and_then(|read| read.exit);

            let (evidence, addr, _invitation_secret) = match code {
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
                                Some(secret.to_vec()),
                            )
                        }
                        // Not an invitation code, so it is a plain address.
                        Err(_) => (Admission::None, decode_addr(&addr)?, None),
                    }
                }
                None => (Admission::None, decode_addr(&addr)?, None),
            };
            // What an open host derives from when there is no invitation: the
            // address that was dialled, which both sides know and which is the
            // identity itself in that case.
            let dialled_id = RotelyxId::from(addr.id);

            let endpoint =
                RotelyxEndpoint::bind_as(&identity, transport, net_config(relay.as_deref())?)
                    .await?;

            // A chain is built before the session, because a session that
            // started addressed and became chained would have already told the
            // first relay who this call is for.
            if let Some(exit) = exit.as_ref() {
                let Some(first) = relay.as_deref() else {
                    bail!(
                        "this invitation names an exit relay, so the call goes through two. \
                         Pass --relay <url> for your own, which is the first of the two and \
                         is yours to pick"
                    );
                };
                chain_through(&endpoint, first, exit, dialled_id, &calling_as).await?;
            }

            let mut session = endpoint
                .connect_with(addr, &evidence)
                .await
                .context("connecting")?;
            // The same derivation the listening side makes, from the address
            // this call was placed to.
            let shared = dialled_id.as_bytes().to_vec();
            let my_name = identity.in_conversation(&shared);
            let me = Member::new(my_name.as_bytes()).context("creating member")?;

            let saved = resume::reopen(&paths, &dialled_id, &passphrase)?;
            let opened = handshake::join_resuming(&mut session, &me, saved).await?;

            let (me, conversation) = match opened {
                handshake::Opened::Fresh(conversation) => (me, conversation),
                handshake::Opened::Resumed {
                    member,
                    conversation,
                } => {
                    println!("carried on from where this conversation left off.");
                    (member, conversation)
                }
            };

            // Saved before a word is typed, and again on the way out.
            //
            // A conversation that is only written when the program exits
            // cleanly is one that people lose: terminals get closed, laptops
            // sleep, power goes. Worse, this side has just committed a fresh
            // epoch that the other side has already processed, so leaving
            // without recording it means coming back to an epoch they have
            // moved past.
            resume::save(&paths, &dialled_id, &me, &conversation, &passphrase)?;

            print_safety_number(my_name, &conversation);
            let conversation = chat(
                session,
                conversation,
                &me,
                net_config(relay.as_deref())?.paths(),
            )
            .await?;
            resume::save(&paths, &dialled_id, &me, &conversation, &passphrase)?;
            endpoint.close().await;
        }
    }

    Ok(())
}

// Addresses are exchanged out of band, so they need a form a person can paste.

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

/// Build the circuit this call goes through, before the call.
///
/// # The order of these steps is the whole security of it
///
/// The exit relay's key is not in the invitation, so it is fetched, and it is
/// fetched **through this caller's own relay**. Asking the exit relay directly
/// would hand it this caller's address before any circuit exists, which is the
/// thing a chain is for.
///
/// That relay could answer with a key of its own and read every circuit sealed
/// to it. It cannot, because the invitation carried a fingerprint of the real
/// one and this refuses anything that does not match. **A caller that skipped
/// that check would have a chain that protects nothing**, so it is not
/// skippable: there is no path here that seals to an unchecked key.
async fn chain_through(
    endpoint: &RotelyxEndpoint,
    first_relay: &str,
    exit: &rotelyx_core::access::ExitRelay,
    destination: RotelyxId,
    return_key: &RotelyxId,
) -> Result<()> {
    let first: rotelyx_net::RelayUrl = first_relay
        .parse()
        .with_context(|| format!("{first_relay} is not a relay URL"))?;

    // This relay's own name and key, which it publishes. Asking it about itself
    // tells it nothing it does not already know.
    let (mine_id, mine_key) = relay_identity_at(first_relay).await?;

    // And the exit relay's, asked of this one rather than of it.
    //
    // Retried, because an endpoint that has just bound has not necessarily
    // opened its relay connection yet, and asking a relay this endpoint is not
    // connected to answers the same as a relay that refused. Ten seconds is far
    // longer than a connection takes and short enough to fail while somebody is
    // still watching.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let theirs = loop {
        if let Some(key) = endpoint
            .transport()
            .fetch_relay_key(first.clone(), exit.url.clone())
            .await
        {
            break key;
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "{first_relay} did not hand back a circuit key for {}. Either this \
                 endpoint never reached {first_relay}, or that relay terminates no \
                 circuits, or it cannot be reached from there, or it will not talk to \
                 it. Those look alike on purpose, so that the shape of a failure does \
                 not say which relays are reachable",
                exit.url
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    // Base64url on the wire, because that is how a relay publishes it. The
    // fingerprint in the invitation is over the key's bytes, so that two
    // spellings of one key give one answer, which means this has to decode
    // before it compares.
    let theirs = data_encoding::BASE64URL_NOPAD
        .decode(String::from_utf8_lossy(&theirs).trim().as_bytes())
        .context("that relay's key did not come back as base64url")?;

    if !exit.accepts(&theirs) {
        bail!(
            "the key {} handed back for {} is not the one the invitation names. \
             Either that relay changed its key, or the one carrying this call \
             answered with a key of its own, which is the case this check exists \
             for. Refusing rather than sealing a circuit to it",
            first_relay,
            exit.url
        );
    }

    let theirs = rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(&theirs)
        .map_err(|_| anyhow::anyhow!("that key is not a key"))?;
    let ours = rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(&mine_key)
        .map_err(|_| anyhow::anyhow!("this relay's own key is not a key"))?;

    let hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("before the epoch")?
        .as_secs()
        / 3600;

    let (sealed, inner) = exit
        .seal_circuit(&mine_id, &ours, &theirs, &destination, return_key, hour)
        .map_err(|e| anyhow::anyhow!("sealing the circuit: {e}"))?;

    if !endpoint.transport().route_through_circuit(
        first,
        destination.endpoint_id(),
        sealed.into(),
        inner.into(),
    ) {
        bail!("this endpoint would not take the circuit request");
    }

    println!("  through {} and then {}", first_relay, exit.url);
    Ok(())
}

/// A relay's own name and circuit key, read from the relay itself.
///
/// Returns the key's bytes rather than a parsed key, because one caller hashes
/// them and the other seals with them.
async fn relay_identity_at(url: &str) -> Result<(RotelyxId, Vec<u8>)> {
    let at = format!(
        "{}{}",
        url.trim_end_matches('/'),
        rotelyx_relay_proto::http::CIRCUIT_KEY_PATH
    );
    let body = reqwest::get(&at)
        .await
        .with_context(|| format!("asking {url} for its circuit key"))?
        .error_for_status()
        .with_context(|| format!("{url} has no circuit key: it was started without --circuit-key"))?
        .text()
        .await
        .context("reading the circuit key")?;

    // `<endpoint id> <key>`, because a descriptor is sealed to the one and with
    // the other, and either alone names nothing.
    let (id, key) = body
        .trim()
        .split_once(' ')
        .context("that relay did not name itself alongside its key")?;

    let key = data_encoding::BASE64URL_NOPAD
        .decode(key.as_bytes())
        .context("that relay's circuit key is not base64url")?;
    // Checked here rather than trusted onward: a hash of something that is not
    // a key names nothing anybody can ever match.
    rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(&key)
        .map_err(|_| anyhow::anyhow!("that relay's circuit key is not a key"))?;

    let relay: RotelyxId = id
        .parse()
        .with_context(|| format!("{url} named itself {id}, which is not an endpoint id"))?;

    Ok((relay, key))
}

/// Name a relay as the far end of a chain.
///
/// # Why the issuer may ask this relay directly and a caller may not
///
/// A caller must not: it would put their address in front of the one relay a
/// chain exists to keep it from, before any circuit exists. The issuer is
/// already talking to this relay, is already known to it, and is choosing it.
/// The hash that goes in the invitation is what lets the caller check what
/// their own relay fetches on their behalf.
async fn exit_relay_at(url: &str) -> Result<rotelyx_core::access::ExitRelay> {
    let (relay, key) = relay_identity_at(url).await?;
    Ok(rotelyx_core::access::ExitRelay {
        relay,
        key_hash: rotelyx_core::access::ExitRelay::fingerprint(&key),
        url: url.to_owned(),
    })
}

/// A relay to fall back on, and a direct path preferred over it.
///
/// # Why the probe cannot use `net_config`
///
/// That one gives `RelayOnly` whenever a relay is named, which is right for a
/// call and is the one policy that can never answer the question the probe
/// asks. A session that refuses direct paths establishes no direct path, and
/// measuring hole punching with it would measure nothing and report zero.
fn probing_config(relay: Option<&str>) -> Result<NetConfig> {
    let Some(url) = relay else {
        return Ok(NetConfig::direct_only());
    };
    let url: RelayUrl = url
        .parse()
        .with_context(|| format!("{url} is not a relay URL"))?;
    Ok(NetConfig::new(
        RelayPolicy::SelfHosted(vec![url]),
        PathPolicy::PreferDirect,
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
/// {"id":"3b427d3f...","addrs":[{"Ip":"192.0.2.17:56860"}]}
/// ```
///
/// which is the operator's LAN address published to whoever they send an
/// invitation to, on the one configuration whose entire purpose is not
/// revealing it. The address above is written from the documentation range
/// rather than the one that was actually seen, for the same reason this
/// function exists.
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
            // Documentation range, not a real network. This file is about not
            // publishing somebody's address and would be a poor place to
            // publish one.
            "192.0.2.17:56860".parse().expect("a socket address"),
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
            out.addrs
                .iter()
                .any(|a| matches!(a, TransportAddr::Relay(_))),
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
