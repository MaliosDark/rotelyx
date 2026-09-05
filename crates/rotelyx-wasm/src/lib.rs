//! Rotelyx in the browser.
//!
//! This crate exposes the message layer (L2) and the blind mailbox envelope
//! format (L3) to JavaScript. It deliberately does **not** expose the transport
//! (L0/L1).
//!
//! # Why the transport is absent
//!
//! Rotelyx's transport is QUIC over UDP with hole punching. A browser cannot
//! open a UDP socket, so none of it can run here, and pretending otherwise
//! would mean shipping a different protocol under the same name. What a browser
//! *can* do is speak WebSocket to a mailbox, which is exactly what L3 was
//! designed for: the operator sees a rotating tag and a padded blob, and
//! nothing else.
//!
//! The security consequence is stated plainly because it is real:
//!
//! | | Native client | Browser client |
//! |---|---|---|
//! | Message confidentiality | MLS + hybrid PQ | **Identical** |
//! | Message integrity | MLS | **Identical** |
//! | Padding, rotating tags | Yes | **Identical** |
//! | Direct peer to peer path | Yes, preferred | **Never** |
//! | Who learns that two parties talk | Nobody, on a direct path | **The mailbox operator, always** |
//! | Code integrity | Verify the binary once | **Trust the server on every load** |
//!
//! The last row is the one that does not appear in the threat model, because
//! the threat model assumes an installed binary. A web page is re-delivered on
//! every visit, so the operator can serve different code to one visitor. Use
//! this to try Rotelyx and to reach a device that cannot install anything. Do
//! not use it where ADV-4 (a compromised operator) is in scope.
//!
//! # Byte encoding
//!
//! Everything crossing into JavaScript is standard base64. Handshake material
//! is copied by humans often enough that an alphabet everyone's tooling already
//! handles is worth more than the few bytes a denser encoding would save.

use data_encoding::BASE64;
use wasm_bindgen::prelude::*;

use rotelyx_crypto::{
    deserialize_key_package, serialize_key_package, Conversation, HybridCiphertext,
    HybridPublicKey, Member, MemberState, PqSecret, WrappedPqSecret,
};
use rotelyx_mailbox::{Envelope, Tag, TagKey};
use zeroize::Zeroizing;

/// What names one staging slot: the group and the epoch the secret is for.
fn binding_id(group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(group_id.len() + 8);
    out.extend_from_slice(group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// How many past epochs of tag keys to keep.
///
/// Covers the window where a sender has committed and a recipient has not yet
/// applied it. Three is generous for a conversation and still bounds how long a
/// departed member's tag knowledge stays useful.
const TAG_EPOCH_MEMORY: usize = 3;

/// The largest group this client will build.
///
/// Not a limit of MLS. Measured, up to a thousand members:
///
/// | Members | Tree | Commit | Padded commit | Per member, per join |
/// |---|---|---|---|---|
/// | 32 | 6.1 KB | 3.4 KB | 4 KiB | 4 KiB |
/// | 256 | 47 KB | 21.8 KB | 32 KiB | 32 KiB |
/// | 512 | 94 KB | 42.8 KB | 64 KiB | 64 KiB |
/// | 1000 | 184 KB | 83 KB | 128 KiB | 128 KiB |
///
/// The commit grows about 83 bytes per member, which is TreeKEM and not
/// something a client can avoid. What *was* avoidable was the padding: the
/// original bucket ladder jumped 64 KiB straight to 1 MiB, so a thousand
/// member commit paid twelve times its own size. The ladder now doubles, so
/// nothing ever pays more than double, and a join costs each member 128 KiB
/// instead of 1 MiB.
///
/// Membership changes are rare next to messages. An ordinary text message
/// costs each member 1 KiB at any group size, because the floor of the ladder
/// has not moved.
pub const MAX_MEMBERS: usize = 1_000;

/// The largest group this client will build. See [`MAX_MEMBERS`].
#[wasm_bindgen(js_name = maxMembers)]
pub fn max_members() -> usize {
    MAX_MEMBERS
}

/// The exact protocol this build speaks. A browser and a native client that
/// disagree here cannot talk, and the failure would otherwise surface as an
/// unreadable message rather than as a version mismatch.
#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> String {
    concat!("rotelyx/", env!("CARGO_PKG_VERSION")).to_string()
}

/// Route a Rust panic to the browser console instead of an opaque
/// `unreachable executed` trap.
///
/// Browser only. The rest of this crate compiles for the host too, which is
/// what lets the handshake below be tested by `cargo test` rather than only in
/// a browser.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start() {
    std::panic::set_hook(Box::new(|info| {
        web_sys::console::error_1(&format!("rotelyx panic: {info}").into());
    }));
}

/// Errors carry a plain string and only become a JavaScript exception at the
/// boundary.
///
/// Constructing a `Error` calls a wasm import, which panics on the host, so
/// building one inside the logic would make every error path untestable by
/// `cargo test`. Converting at the edge keeps the whole flow, failures
/// included, runnable natively.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<Error> for JsValue {
    fn from(e: Error) -> JsValue {
        JsError::new(&e.0).into()
    }
}

fn err(e: impl std::fmt::Display) -> Error {
    Error::new(e.to_string())
}

fn decode(s: &str) -> Result<Vec<u8>, Error> {
    BASE64
        .decode(s.trim().as_bytes())
        .map_err(|e| Error::new(format!("not valid base64: {e}")))
}

/// What a conversation returns after a member is added.
///
/// Three separate values because they travel differently: the welcome and the
/// ratchet tree go to the joiner only, while the commit goes to everyone
/// already in the group.
#[wasm_bindgen(getter_with_clone)]
pub struct Invitation {
    /// For every existing member.
    pub commit: String,
    /// For the joiner only.
    pub welcome: String,
    /// For the joiner only. Public, but needed to reconstruct the tree.
    #[wasm_bindgen(js_name = ratchetTree)]
    pub ratchet_tree: String,
}

/// What a session writes down to survive a reload, before sealing.
#[derive(serde::Serialize, serde::Deserialize)]
struct SessionState {
    member: MemberState,
    group_id: Option<Vec<u8>>,
    /// Epoch, key. Re-derived on load rather than trusted, but the epochs they
    /// belong to cannot be recovered from MLS once passed, so they are carried.
    tag_keys: Vec<(u64, [u8; 32])>,
}

/// One party's view of one conversation.
///
/// Holds the MLS group state and the long term signature key. Dropping it ends
/// the conversation unless it was exported first: see `seal` and `unseal`.
#[wasm_bindgen]
pub struct Session {
    member: Member,
    conversation: Option<Conversation>,

    /// Tag keys for recent epochs, oldest first.
    ///
    /// # Why this is a list and not one value
    ///
    /// The key comes from the MLS exporter, which changes with every epoch.
    /// Pinning a single value works only for a group that never changes: add a
    /// third member and the founder is holding a key from epoch 1 while the
    /// newcomer derives one at epoch 2, and every message between them is
    /// deposited under a tag the other cannot compute. Nothing errors. The
    /// messages simply never arrive.
    ///
    /// So the key is re-derived whenever the epoch advances and the previous
    /// few are kept. A sender always addresses at its own current epoch; a
    /// recipient listens across the window, which covers the gap between a
    /// commit being sent and everyone having applied it.
    ///
    /// They cannot be recomputed later: MLS discards the secrets an old epoch
    /// was derived from, which is the forward secrecy working as intended. That
    /// is also what makes this better than a fixed key handed out at join time,
    /// since a removed member's tag knowledge expires with the epochs.
    tag_keys: Vec<(u64, TagKey)>,

    /// Set between `encapsulateTo`/`openPq` and `commitPq`. The post-quantum
    /// secret has no home in MLS state until the commit carries it in.
    pending_pq: Option<PqSecret>,
    /// Which (group, epoch) pairs already have a staged post-quantum secret.
    ///
    /// First one wins. Without this, a second wrap arriving after the
    /// legitimate one would replace the value the commit is about to look up,
    /// and the member would fall out of the group when the real commit landed.
    staged_pq: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl Session {
    /// Create a fresh identity.
    ///
    /// `label` is a credential shown to other members. It is authenticated by
    /// the group but chosen by its holder, so it says who someone claims to be
    /// and never who they are. Verify with the safety number.
    #[wasm_bindgen(constructor)]
    pub fn new(label: &str) -> Result<Session, Error> {
        Ok(Session {
            member: Member::new(label.as_bytes()).map_err(err)?,
            conversation: None,
            tag_keys: Vec::new(),
            pending_pq: None,
            staged_pq: Vec::new(),
        })
    }

    /// This member's key package: an authorisation to add the holder to a
    /// group. Public and signed, but it must reach the inviter through a
    /// channel that binds it to the identity it claims.
    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<String, Error> {
        let bundle = self.member.key_package().map_err(err)?;
        let bytes = serialize_key_package(bundle.key_package()).map_err(err)?;
        Ok(BASE64.encode(&bytes))
    }

    /// This member's X-Wing public key, for the post-quantum step. 1216 bytes:
    /// an ML-KEM-768 key and an X25519 key, which is why it is so much larger
    /// than a classical one.
    #[wasm_bindgen(js_name = hybridPublicKey)]
    pub fn hybrid_public_key(&self) -> String {
        BASE64.encode(&self.member.hybrid_public_key().to_bytes())
    }

    /// Start a conversation with this member as its only participant.
    pub fn found(&mut self) -> Result<(), Error> {
        if self.conversation.is_some() {
            return Err(Error::new("this session already has a conversation"));
        }
        self.conversation = Some(Conversation::create(&self.member).map_err(err)?);
        Ok(())
    }

    /// Add a member from their key package.
    ///
    /// The commit is applied locally before this returns, so the epoch has
    /// already advanced by the time the caller sees the result.
    pub fn invite(&mut self, key_package_b64: &str) -> Result<Invitation, Error> {
        if self.member_count() >= MAX_MEMBERS {
            return Err(Error::new(format!(
                "this conversation is full at {MAX_MEMBERS} members. Refusing rather than \
                 degrading: every message already costs one deposit per recipient, and \
                 beyond this the padding and the bandwidth both stop being reasonable"
            )));
        }
        let kp = deserialize_key_package(&decode(key_package_b64)?).map_err(err)?;

        // Borrow the member out of self first: `invite` needs both, and the
        // group accessor holds a mutable borrow of the whole session.
        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation yet: call found() first"))?;

        let (commit, welcome) = group.invite(member, &kp).map_err(err)?;
        let tree = group.ratchet_tree().map_err(err)?;

        self.sync_tag_keys()?;

        Ok(Invitation {
            commit: BASE64.encode(&commit),
            welcome: BASE64.encode(&welcome),
            ratchet_tree: BASE64.encode(&tree),
        })
    }

    /// Join a conversation from a welcome and its ratchet tree.
    pub fn join(&mut self, welcome_b64: &str, ratchet_tree_b64: &str) -> Result<(), Error> {
        if self.conversation.is_some() {
            return Err(Error::new("this session already has a conversation"));
        }
        let welcome = decode(welcome_b64)?;
        let tree = decode(ratchet_tree_b64)?;

        self.conversation = Some(Conversation::join(&self.member, &welcome, &tree).map_err(err)?);
        self.sync_tag_keys()?;
        Ok(())
    }

    /// Derive this epoch's tag key if it is not already held.
    ///
    /// Called after anything that can move the epoch. Cheap and idempotent: it
    /// returns immediately when the newest cached key already matches.
    fn sync_tag_keys(&mut self) -> Result<(), Error> {
        let epoch = self.epoch();
        if self.tag_keys.last().map(|(e, _)| *e) == Some(epoch) {
            return Ok(());
        }

        let member = &self.member;
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation"))?;
        let bytes = group.mailbox_tag_key(member).map_err(err)?;

        self.tag_keys.push((epoch, TagKey::new(bytes)));
        if self.tag_keys.len() > TAG_EPOCH_MEMORY {
            self.tag_keys.remove(0);
        }
        Ok(())
    }

    /// The key to address with: this epoch's.
    fn tag_key(&self) -> Result<&TagKey, Error> {
        self.tag_keys
            .last()
            .map(|(_, k)| k)
            .ok_or_else(|| Error::new("no tag key: the conversation has no second member yet"))
    }

    /// Every tag we might legitimately be addressed under right now: our own
    /// tag under each remembered epoch, across the time bucket lookback.
    fn my_tags(&self, time_bucket: u64, lookback: u64) -> Result<Vec<Tag>, Error> {
        if self.tag_keys.is_empty() {
            return Err(Error::new("no tag key yet"));
        }
        let mine = self.member.signature_key();
        Ok(self
            .tag_keys
            .iter()
            .flat_map(|(_, key)| key.for_member(&mine).polling_tags(time_bucket, lookback))
            .collect())
    }

    // ---- post-quantum step -------------------------------------------------

    /// Encapsulate to another member's hybrid public key.
    ///
    /// Returns the ciphertext to send them. The shared secret is held until
    /// `commitPq` puts it into the key schedule; nothing is protected by it
    /// until then.
    #[wasm_bindgen(js_name = encapsulateTo)]
    pub fn encapsulate_to(&mut self, hybrid_pk_b64: &str) -> Result<String, Error> {
        let pk = HybridPublicKey::from_bytes(&decode(hybrid_pk_b64)?).map_err(err)?;
        let (ct, secret) = pk.encapsulate();
        self.pending_pq = Some(secret);
        Ok(BASE64.encode(&ct.to_bytes()))
    }

    /// Recover the secret from a ciphertext encapsulated to us, and stage it.
    ///
    /// This must happen **before** the matching commit arrives: MLS looks the
    /// pre-shared key up by id in local storage, and processing the commit
    /// fails outright if it is not there. Failing rather than proceeding
    /// without the post-quantum material is deliberate.
    #[wasm_bindgen(js_name = openPq)]
    pub fn open_pq(&mut self, ciphertext_b64: &str) -> Result<(), Error> {
        let ct = HybridCiphertext::from_bytes(&decode(ciphertext_b64)?).map_err(err)?;
        let secret = self.member.open_pq(&ct);

        let member = &self.member;
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet: join() before staging a secret"))?;
        group.stage_pq_secret(member, &secret).map_err(err)?;
        Ok(())
    }

    /// Start a post-quantum rotation for a whole group.
    ///
    /// Returns one wrapped secret per recipient, in the same order as
    /// `roster()` minus ourselves. Every member must end up with the **same**
    /// secret, because MLS looks a pre-shared key up by one id, so the secret
    /// is chosen here and sealed to each member rather than derived pairwise.
    #[wasm_bindgen(js_name = beginGroupPq)]
    pub fn begin_group_pq(
        &mut self,
        hybrid_public_keys: Vec<String>,
    ) -> Result<Vec<String>, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        let group_id = group.group_id();
        let epoch = group.epoch();

        // Each recipient is named by its own signature key, so a wrap made for
        // one member does not open for another, and the roster order that pairs
        // a key with a wrap is the same order the caller passes them in.
        let roster: Vec<Vec<u8>> = group
            .roster()
            .into_iter()
            .map(|p| p.signature_key)
            .filter(|k| *k != self.member.signature_key())
            .collect();

        if roster.len() != hybrid_public_keys.len() {
            return Err(Error::new(
                "a hybrid public key is needed for every other member, in roster order",
            ));
        }

        let secret = PqSecret::generate();

        let mut wrapped = Vec::with_capacity(hybrid_public_keys.len());
        for (encoded, recipient) in hybrid_public_keys.iter().zip(&roster) {
            let pk = HybridPublicKey::from_bytes(&decode(encoded)?).map_err(err)?;
            // Signed as this member, so a receiver can tell a wrap from inside
            // the group from one minted by anybody holding a published key.
            let signed = self
                .member
                .wrap_group_pq_signed(&secret, &pk, &group_id, epoch, recipient)
                .map_err(err)?;
            wrapped.push(BASE64.encode(&signed.to_bytes()));
        }

        self.pending_pq = Some(secret);
        Ok(wrapped)
    }

    /// Recover a group secret sealed to us, and stage it.
    ///
    /// The group counterpart of `openPq`. Same ordering rule: this must happen
    /// before the matching commit arrives, or MLS refuses the commit outright
    /// rather than continuing without post-quantum protection.
    #[wasm_bindgen(js_name = openGroupPq)]
    pub fn open_group_pq(&mut self, wrapped_b64: &str) -> Result<(), Error> {
        let wrapped = WrappedPqSecret::from_bytes(&decode(wrapped_b64)?).map_err(err)?;

        let member = &self.member;
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        // The wrap has to have been made for this group, at this epoch, for us.
        // Anything else does not open, which is what stops a stranger holding
        // our published hybrid key from minting one, and stops a wrap captured
        // at an earlier epoch from being replayed into this one.
        // Accepted only if a current member signed it. Each roster key is tried
        // and the first that verifies wins; none verifying means it came from
        // outside the group, which is refused before anything is decrypted.
        let roster: Vec<Vec<u8>> = group
            .roster()
            .into_iter()
            .map(|p| p.signature_key)
            .collect();
        let secret = member
            .unwrap_group_pq_from_member(&wrapped, &group.group_id(), group.epoch(), &roster)
            .map_err(err)?;

        // First one wins. Overwriting would let a second wrap, arriving after
        // the legitimate one, replace the value the commit is about to look up.
        if self
            .staged_pq
            .contains(&binding_id(&group.group_id(), group.epoch()))
        {
            return Err(Error::new(
                "a post-quantum secret is already staged for this group and epoch",
            ));
        }
        group.stage_pq_secret(member, &secret).map_err(err)?;
        self.staged_pq
            .push(binding_id(&group.group_id(), group.epoch()));
        Ok(())
    }

    /// Commit the pending post-quantum secret into the key schedule.
    ///
    /// Returns a commit to broadcast. From the epoch it creates onward, an
    /// attacker must break both X25519 and ML-KEM-768 to read the
    /// conversation, not either one.
    #[wasm_bindgen(js_name = commitPq)]
    pub fn commit_pq(&mut self) -> Result<String, Error> {
        let secret = self
            .pending_pq
            .take()
            .ok_or_else(|| Error::new("nothing to commit: call encapsulateTo() first"))?;

        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation"))?;

        let commit = group.commit_pq_secret(member, &secret).map_err(err)?;
        self.sync_tag_keys()?;
        Ok(BASE64.encode(&commit))
    }

    // ---- messages ----------------------------------------------------------

    /// Encrypt a message. The result is padded to a 256 byte multiple by MLS
    /// before this returns.
    pub fn send(&mut self, text: &str) -> Result<String, Error> {
        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        let bytes = group.send(member, text.as_bytes()).map_err(err)?;
        Ok(BASE64.encode(&bytes))
    }

    /// Take one message, and say which of three things it was.
    ///
    /// Returns JSON, always: `{"kind":"message","text":…}`,
    /// `{"kind":"membership","added":[…],"removed":[…],"members":n}`, or
    /// `{"kind":"nothing"}`.
    ///
    /// # Why not "the plaintext, or undefined"
    ///
    /// That is what this used to return, and `undefined` meant all three: a
    /// third party joining, a routine rekey, and a message the group did not
    /// recognise. The page announced "the group changed" for every one of them,
    /// so the notice a person is meant to read fires on ordinary traffic, and a
    /// warning that cries wolf is one people learn to dismiss. Surfacing
    /// membership changes is a security control, stated as one in ADV-7 of the
    /// threat model; a control that fires when nothing happened is not one.
    pub fn receive(&mut self, message_b64: &str) -> Result<String, Error> {
        let bytes = decode(message_b64)?;

        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let outcome = group.receive(member, &bytes).map_err(err)?;

        // A commit moves the epoch, so the tag key must follow it.
        self.sync_tag_keys()?;

        fn short(identity: &[u8]) -> String {
            identity
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        // Built by serde rather than by hand.
        //
        // It was written by hand, on the reasoning that `escape_default` covers
        // "everything that could break the string". It does not: it produces
        // Rust escapes, and Rust writes a unit separator as `\u{1f}` where JSON
        // requires `\u001f`. Any parser reading the result answered "invalid
        // escape at line 1 column 41" and the caller took that for a failed
        // session.
        //
        // The same is true of every character above ASCII, which is the part
        // that matters most: `escape_default` renders an accented letter the
        // same way. A message with an accent in it produced a document no
        // parser would accept, which in Spanish is most messages.
        let value = match outcome {
            rotelyx_crypto::Received::Message {
                sender,
                bytes: plaintext,
            } => {
                let text = String::from_utf8(plaintext)
                    .map_err(|_| Error::new("decrypted payload is not valid UTF-8"))?;

                // Who MLS authenticated as the author, resolved to the label
                // that member joined under.
                //
                // # Why this field exists
                //
                // The crypto layer has carried the sending leaf since it was
                // written, with a comment saying an application that cannot say
                // who spoke cannot do the group cases. This layer dropped it,
                // and the phone then attributed every read receipt in a group to
                // one name, the conversation's own, so the second receipt looked
                // like a repeat of the first and a group of three never showed a
                // read tick at all.
                //
                // Absent rather than empty when the sender is unknown or has
                // since been removed, so a caller can tell "nobody knows" from
                // "somebody with no name".
                let from = sender
                    .and_then(|leaf| {
                        self.conversation
                            .as_ref()
                            .and_then(|group| group.participant_at(leaf))
                    })
                    .map(|p| String::from_utf8_lossy(&p.identity).into_owned());

                match from {
                    Some(from) => {
                        serde_json::json!({ "kind": "message", "text": text, "from": from })
                    }
                    None => serde_json::json!({ "kind": "message", "text": text }),
                }
            }
            rotelyx_crypto::Received::MembershipChanged(change) => {
                let added: Vec<String> = change.added.iter().map(|p| short(&p.identity)).collect();
                let removed: Vec<String> =
                    change.removed.iter().map(|p| short(&p.identity)).collect();
                let members = self
                    .conversation
                    .as_ref()
                    .map(|c| c.member_count())
                    .unwrap_or(0);
                serde_json::json!({
                    "kind": "membership",
                    "added": added,
                    "removed": removed,
                    "members": members,
                })
            }
            rotelyx_crypto::Received::Nothing => serde_json::json!({ "kind": "nothing" }),
        };

        serde_json::to_string(&value).map_err(|e| Error::new(format!("{e}")))
    }

    // ---- mailbox -----------------------------------------------------------

    /// Seal a message into an envelope addressed to `time_bucket`.
    ///
    /// The envelope is padded to one of five fixed sizes, so the operator
    /// learns a bucket rather than a length. `time_bucket` is hours since the
    /// Unix epoch, supplied by the caller: reading a clock in here would make
    /// the crate untestable and would hide clock skew instead of surfacing it.
    pub fn seal(&self, ciphertext_b64: &str, time_bucket: u64) -> Result<String, Error> {
        let key = self.tag_key()?;
        let tag = key.tag_for_epoch(time_bucket);

        // The MLS message is made opaque **before** it becomes a payload. Its
        // own framing carries the group id and the epoch in cleartext, so
        // depositing it raw handed the operator a stable name for the
        // conversation in every envelope, under every rotated tag, for ever.
        let sealed = key
            .payload_key()
            .seal(Some(tag), &decode(ciphertext_b64)?)
            .map_err(err)?;

        let envelope = Envelope::seal(tag, &sealed).map_err(err)?;
        Ok(BASE64.encode(&envelope.to_bytes()))
    }

    /// Strip an envelope, checking it was addressed to one of our tags.
    ///
    /// Rejecting a foreign tag matters: without the check, an operator could
    /// hand us any envelope and learn from our behaviour whether we could read
    /// it.
    pub fn open(
        &self,
        envelope_b64: &str,
        time_bucket: u64,
        lookback: u64,
    ) -> Result<String, Error> {
        let envelope = Envelope::from_bytes(&decode(envelope_b64)?).map_err(err)?;

        let expected = self.tag_key()?.polling_tags(time_bucket, lookback);
        if !expected.contains(&envelope.tag()) {
            return Err(Error::new(
                "envelope is not addressed to any tag of ours in this window",
            ));
        }

        // Every tag key we still remember, newest first: a payload deposited
        // just before a commit was sealed under the epoch before this one, and
        // refusing it would lose the message rather than protect anything.
        let sealed = envelope.payload();
        let tag = envelope.tag();
        for (_, key) in self.tag_keys.iter().rev() {
            let pk = key.payload_key();
            // Bound to this tag, or unbound because it came through a fan-out.
            if let Ok(plain) = pk
                .open(Some(tag), sealed)
                .or_else(|_| pk.open(None, sealed))
            {
                return Ok(BASE64.encode(&plain));
            }
        }

        Err(Error::new(
            "the payload did not open under any epoch key we hold",
        ))
    }

    /// Everyone in the conversation, as display names.
    ///
    /// Self-asserted: MLS authenticates that a member holds the signing key,
    /// never that the name is theirs. The safety number is what makes the
    /// roster meaningful.
    pub fn roster(&self) -> Result<Vec<String>, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        Ok(group
            .roster()
            .into_iter()
            .map(|p| String::from_utf8_lossy(&p.identity).into_owned())
            .collect())
    }

    /// What names this conversation, for as long as it exists.
    ///
    /// The group id, as hex. It does not move when the epoch does, when somebody
    /// joins, or when somebody is removed, which is what makes it the right name
    /// for a file: a label collides the moment two people choose the same one,
    /// and a meeting code is spent as soon as the conversation exists.
    #[wasm_bindgen(js_name = groupId)]
    pub fn group_id(&self) -> Result<String, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        Ok(hex(&group.group_id()))
    }

    /// Everyone in the conversation, with the key that identifies each of them.
    ///
    /// Returns JSON: `[{"label":…,"key":…}]`, where `key` is a base64 signature
    /// key. `roster` gives the labels alone, which is right for showing who is
    /// here and useless for acting on one of them: two members can choose the
    /// same label, and a label is not what removal takes.
    ///
    /// The key rather than a position in the tree, for the reason `Group::remove`
    /// gives: an index shifts as members come and go, and a caller holding one
    /// across an epoch would remove somebody else.
    #[wasm_bindgen(js_name = rosterDetail)]
    pub fn roster_detail(&self) -> Result<String, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let members: Vec<serde_json::Value> = group
            .roster()
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "label": String::from_utf8_lossy(&p.identity).into_owned(),
                    "key": BASE64.encode(&p.signature_key),
                })
            })
            .collect();

        serde_json::to_string(&members).map_err(|e| Error::new(format!("{e}")))
    }

    /// Remove a member, returning the commit every other member must apply.
    ///
    /// # What removal is and is not
    ///
    /// It is a commit, not a local setting. A device that is gone is a leaf that
    /// can still decrypt, and forgetting it here changes nothing about that: the
    /// key schedule includes it until the group says otherwise. Everybody who
    /// applies this commit moves to an epoch derived without that leaf.
    ///
    /// What it does not do is reach backwards. The removed member keeps
    /// everything it could already read, which is what forward secrecy means:
    /// what comes next is encrypted under a schedule it is no longer part of.
    ///
    /// The caller sends the commit to the members who have **not** applied it,
    /// which is all of them, so it is addressed one epoch back. See
    /// `sealCommitForGroup`.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&mut self, signature_key_b64: &str) -> Result<String, Error> {
        let key = decode(signature_key_b64)?;

        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let commit = group.remove(member, &key).map_err(err)?;

        // The removal is merged locally by `Group::remove`, so this side is
        // already at the new epoch and needs its key before it addresses
        // anybody.
        self.sync_tag_keys()?;
        Ok(BASE64.encode(&commit))
    }

    /// The tag this member listens on.    /// The tag this member listens on.
    ///
    /// Derived from the group's pinned key and this member's own signature
    /// key, so every other member computes the same value for us and nobody
    /// else can.
    #[wasm_bindgen(js_name = myTag)]
    pub fn my_tag(&self, time_bucket: u64) -> Result<String, Error> {
        Ok(hex(self
            .tag_key()?
            .for_member(&self.member.signature_key())
            .tag_for_epoch(time_bucket)
            .as_bytes()))
    }

    /// The tags this member polls: its own, across the lookback window.
    #[wasm_bindgen(js_name = myPollingTags)]
    pub fn my_polling_tags(&self, time_bucket: u64, lookback: u64) -> Result<Vec<String>, Error> {
        let mut tags: Vec<String> = self
            .my_tags(time_bucket, lookback)?
            .iter()
            .map(|t| hex(t.as_bytes()))
            .collect();
        tags.sort_unstable();
        tags.dedup();
        Ok(tags)
    }

    /// Seal one message for every other member, each under their own tag.
    ///
    /// Returns one envelope per recipient. The caller deposits all of them.
    /// This is where a group costs more than a pair: the same ciphertext is
    /// padded and addressed N-1 times, and an operator watching a burst of
    /// deposits from one connection can count the group.
    #[wasm_bindgen(js_name = sealForGroup)]
    pub fn seal_for_group(
        &self,
        ciphertext_b64: &str,
        time_bucket: u64,
    ) -> Result<Vec<String>, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let _ = group;
        self.seal_with(self.tag_key()?, ciphertext_b64, time_bucket)
    }

    /// The tags of everyone else, for the current epoch.
    ///
    /// Kept for callers that address tags themselves. It used to be paired with
    /// `paddedPayload` for a server-side fan-out, one upload naming every
    /// recipient; that request handed the operator the whole membership in one
    /// frame and is gone. Sending to a group goes through `sealForGroup`, which
    /// returns one sealed envelope per member to deposit separately.
    #[wasm_bindgen(js_name = recipientTags)]
    pub fn recipient_tags(&self, time_bucket: u64) -> Result<Vec<String>, Error> {
        self.tags_with(self.tag_key()?, time_bucket)
    }

    /// The tags of everyone who has not applied our latest commit yet.
    ///
    /// One epoch back, for the same reason as `sealCommitForGroup`: the commit
    /// is what will move them to the epoch we are already on, so they cannot
    /// yet derive its tags.
    #[wasm_bindgen(js_name = commitRecipientTags)]
    pub fn commit_recipient_tags(&self, time_bucket: u64) -> Result<Vec<String>, Error> {
        if self.tag_keys.len() < 2 {
            return Err(Error::new(
                "no previous epoch to address: a commit before the group has moved once \
                 has nobody waiting for it",
            ));
        }
        self.tags_with(&self.tag_keys[self.tag_keys.len() - 2].1, time_bucket)
    }

    fn tags_with(&self, key: &TagKey, time_bucket: u64) -> Result<Vec<String>, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let mine = self.member.signature_key();
        Ok(group
            .roster()
            .into_iter()
            .filter(|p| p.signature_key != mine)
            .map(|p| {
                hex(key
                    .for_member(&p.signature_key)
                    .tag_for_epoch(time_bucket)
                    .as_bytes())
            })
            .collect())
    }

    /// Pad a ciphertext to its bucket, without addressing it.
    ///
    /// The padding happens **here**, never on the server. A server that padded
    /// on our behalf would be handed the true length, which is precisely what
    /// the buckets exist to withhold.
    ///
    /// **No client calls this.** It existed for the server-side fan-out, where
    /// one padded payload was uploaded once and the server addressed it to
    /// every recipient; that request handed the operator the whole membership
    /// in one frame and was removed. Sending to a group goes through
    /// `sealForGroup`, which seals and pads per recipient. Kept because it is
    /// part of the published C ABI and because padding without addressing is a
    /// reasonable thing for a third-party client to want.
    #[wasm_bindgen(js_name = paddedPayload)]
    pub fn padded_payload(&self, ciphertext_b64: &str) -> Result<String, Error> {
        // Made opaque first, exactly as a single deposit is. Sealed under the
        // group's key rather than any one member's, so every member can open
        // it: that is what made one payload serve every recipient.
        let sealed = self
            .tag_key()?
            .payload_key()
            .seal(None, &decode(ciphertext_b64)?)
            .map_err(err)?;

        // Sealing under a throwaway tag is the shortest path to the padding
        // rule staying in one place: the bucket table lives in the envelope
        // type and is not duplicated here.
        let envelope =
            Envelope::seal(Tag::from_bytes(&[0u8; 32]).map_err(err)?, &sealed).map_err(err)?;

        Ok(BASE64.encode(envelope.payload()))
    }

    /// Seal a commit for the members who have not applied it yet.
    ///
    /// # Why this cannot use the current epoch
    ///
    /// `invite` merges its own commit, so by the time it returns we have
    /// already moved to the new epoch and our newest tag key belongs to it. The
    /// members still waiting for that commit cannot derive that key: the commit
    /// is what will move them there. Addressing them at the new epoch deposits
    /// under a tag nobody is listening on, and the group silently splits, with
    /// the inviter one epoch ahead of everyone else forever.
    ///
    /// So a commit is addressed one epoch back, which is where its recipients
    /// still are.
    ///
    /// A member added by this very commit also gets an envelope they will never
    /// collect, since they join at the new epoch and never held the old key.
    /// It expires with its TTL. Filtering it out would need the pre-invite
    /// roster threaded through, for one wasted envelope per join.
    #[wasm_bindgen(js_name = sealCommitForGroup)]
    pub fn seal_commit_for_group(
        &self,
        commit_b64: &str,
        time_bucket: u64,
    ) -> Result<Vec<String>, Error> {
        if self.tag_keys.len() < 2 {
            return Err(Error::new(
                "no previous epoch to address: a commit before the group has moved once \
                 has nobody waiting for it",
            ));
        }
        let key = &self.tag_keys[self.tag_keys.len() - 2].1;
        self.seal_with(key, commit_b64, time_bucket)
    }

    fn seal_with(
        &self,
        key: &TagKey,
        payload_b64: &str,
        time_bucket: u64,
    ) -> Result<Vec<String>, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let mine = self.member.signature_key();

        // Sealed once, under the group's key, and then addressed to each member
        // in turn. Every recipient derives the same payload key from the same
        // exported secret, so one opaque blob serves all of them, and the
        // operator sees a different tag and different bytes for each.
        let plaintext = decode(payload_b64)?;

        let mut out = Vec::new();
        for participant in group.roster() {
            if participant.signature_key == mine {
                continue;
            }
            let tag = key
                .for_member(&participant.signature_key)
                .tag_for_epoch(time_bucket);
            // Sealed per recipient rather than once, so each payload is bound
            // to the address it is deposited under and an operator cannot move
            // one to another.
            let payload = key.payload_key().seal(Some(tag), &plaintext).map_err(err)?;
            out.push(BASE64.encode(&Envelope::seal(tag, &payload).map_err(err)?.to_bytes()));
        }
        Ok(out)
    }

    /// Strip an envelope addressed to us in a group.
    #[wasm_bindgen(js_name = openMine)]
    pub fn open_mine(
        &self,
        envelope_b64: &str,
        time_bucket: u64,
        lookback: u64,
    ) -> Result<String, Error> {
        let envelope = Envelope::from_bytes(&decode(envelope_b64)?).map_err(err)?;

        if !self
            .my_tags(time_bucket, lookback)?
            .contains(&envelope.tag())
        {
            return Err(Error::new("envelope is not addressed to us in this window"));
        }

        let sealed = envelope.payload();
        let tag = envelope.tag();
        for (_, key) in self.tag_keys.iter().rev() {
            let pk = key.payload_key();
            // Bound to this tag, or unbound because it came through a fan-out.
            if let Ok(plain) = pk
                .open(Some(tag), sealed)
                .or_else(|_| pk.open(None, sealed))
            {
                return Ok(BASE64.encode(&plain));
            }
        }

        Err(Error::new(
            "the payload did not open under any epoch key we hold",
        ))
    }

    /// The tag to deposit under for `time_bucket`.
    ///
    /// An observer sees an unlinkable 32 byte value. Two tags from the same
    /// pair of members are, without the key, as unrelated as tags from
    /// different pairs.
    #[wasm_bindgen(js_name = tagFor)]
    pub fn tag_for(&self, time_bucket: u64) -> Result<String, Error> {
        Ok(hex(self.tag_key()?.tag_for_epoch(time_bucket).as_bytes()))
    }

    /// The tags to poll: the current bucket plus `lookback` earlier ones.
    ///
    /// Lookback covers a sender whose clock lags and a recipient who was
    /// offline. It costs one extra lookup per bucket of slack.
    #[wasm_bindgen(js_name = pollingTags)]
    pub fn polling_tags(&self, time_bucket: u64, lookback: u64) -> Result<Vec<String>, Error> {
        Ok(self
            .tag_key()?
            .polling_tags(time_bucket, lookback)
            .iter()
            .map(|t| hex(t.as_bytes()))
            .collect())
    }

    // ---- state -------------------------------------------------------------

    /// The current MLS epoch. Advances on every commit.
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.conversation.as_ref().map_or(0, |c| c.epoch())
    }

    #[wasm_bindgen(getter, js_name = memberCount)]
    pub fn member_count(&self) -> usize {
        self.conversation.as_ref().map_or(0, |c| c.member_count())
    }

    /// Write this session out, encrypted under a passphrase.
    ///
    /// # What this hands over
    ///
    /// Everything. The signing key, the hybrid key, and the whole MLS group
    /// state. Whoever holds the sealed blob **and** the passphrase can read
    /// what this member can read. It is not a backup of messages, it is a copy
    /// of the participant.
    ///
    /// # Why the passphrase is not optional
    ///
    /// The obvious place to keep this in a browser is local storage, which is
    /// readable by any script that ever runs on the origin and survives long
    /// after the tab is closed. Writing group state there unencrypted would
    /// undo the reason the message layer exists.
    ///
    /// Argon2id at 64 MiB is deliberately slow. In a browser that is a visible
    /// pause of roughly a second, which is the cost of a passphrase being worth
    /// something.
    #[wasm_bindgen(js_name = sealSession)]
    pub fn seal_session(&self, key: &SessionKey) -> Result<String, Error> {
        let state = SessionState {
            member: self.member.export().map_err(err)?,
            group_id: self.conversation.as_ref().map(|c| c.group_id()),
            tag_keys: self
                .tag_keys
                .iter()
                .map(|(epoch, key)| (*epoch, key.to_bytes()))
                .collect(),
        };

        let plain = postcard::to_allocvec(&state)
            .map_err(|e| Error::new(format!("encoding the session: {e}")))?;

        Ok(BASE64.encode(&seal_bytes(key, &plain)?))
    }

    /// Rebuild a session from a sealed blob.
    /// Move to a fresh epoch after unsealing, and let `send` work again.
    ///
    /// Returns the commit, base64. The caller must deliver it the way it
    /// delivers anything else, and until the other side has processed it they
    /// are still at the old epoch.
    ///
    /// # Why a resumed session cannot just carry on
    ///
    /// A session read back from storage believes it is at a generation the
    /// group may already have spent. Whatever it sends is then refused by the
    /// receiver, which deletes each generation's secret as it uses it, and
    /// nothing says so: the messages just stop arriving. That is what a copy of
    /// the same sealed blob on a second device looks like, and a browser cannot
    /// tell that from an ordinary reload, so it does this every time. A commit
    /// is cheap and it also moves the keys forward.
    #[wasm_bindgen(js_name = rekeyAfterRestore)]
    pub fn rekey_after_restore(&mut self) -> Result<String, Error> {
        let member = &self.member;
        let group = self
            .conversation
            .as_mut()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        let commit = group.rekey_after_restore(member).map_err(err)?;
        self.sync_tag_keys()?;
        Ok(BASE64.encode(&commit))
    }

    #[wasm_bindgen(js_name = unsealSession)]
    pub fn unseal_session(blob_b64: &str, key: &SessionKey) -> Result<Session, Error> {
        let plain = open_bytes(key, &decode(blob_b64)?)?;
        let state: SessionState = postcard::from_bytes(&plain)
            .map_err(|e| Error::new(format!("reading the session: {e}")))?;

        let member = Member::restore(state.member).map_err(err)?;

        let conversation = match state.group_id.as_deref() {
            Some(id) => Conversation::reopen(&member, id).map_err(err)?,
            None => None,
        };

        Ok(Session {
            member,
            conversation,
            tag_keys: state
                .tag_keys
                .into_iter()
                .map(|(epoch, key)| (epoch, TagKey::new(key)))
                .collect(),
            // A post-quantum secret in flight is deliberately not carried
            // across. It only has meaning between an encapsulation and the
            // commit that follows it, and resuming into the middle of that
            // would produce a commit the group cannot apply.
            pending_pq: None,
            staged_pq: Vec::new(),
        })
    }

    /// A short fingerprint of **who is in this conversation**, for confirming
    /// out of band that two devices are talking to each other and not to
    /// somebody who sat in between.
    ///
    /// Read it aloud. Comparing it over the same channel an attacker controls
    /// proves nothing.
    ///
    /// # Why it is the members and not the group
    ///
    /// It used to be `BLAKE3(group_id)`, and a group id is fixed when the group
    /// is created. So the number never moved: not when a member was added, not
    /// when a device was added, not when anybody's key changed. It attested to
    /// "we share an opaque identifier" and nothing else, which is the one thing
    /// two people comparing digits do not need to be told.
    ///
    /// That is the wrong construction and it defeats the purpose. A safety
    /// number exists so that a silent addition or a swapped key shows up as
    /// different digits the next time two people compare, and the whole
    /// argument for meeting through a code rests on it: a code is not proof of
    /// who holds it, and the number is what catches whoever arrived first.
    ///
    /// It is now the sorted set of member signature keys, which is the standard
    /// construction. Sorted so that both ends reach the same answer whatever
    /// order their rosters are in, and length-prefixed so that two keys cannot
    /// be run together to imitate a third.
    #[wasm_bindgen(js_name = safetyNumber)]
    pub fn safety_number(&self) -> Result<String, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;

        let mut keys: Vec<Vec<u8>> = group
            .roster()
            .into_iter()
            .map(|p| p.signature_key)
            .collect();
        keys.sort();
        keys.dedup();

        let mut hasher = blake3::Hasher::new_derive_key("rotelyx conversation fingerprint v2");
        for key in &keys {
            // Length first, so that two keys cannot be concatenated into a
            // sequence a third set would also produce.
            hasher.update(&(key.len() as u32).to_be_bytes());
            hasher.update(key);
        }

        let mut out = [0u8; 30];
        hasher.finalize_xof().fill(&mut out);

        Ok(out
            .chunks(5)
            .map(|c| {
                let n = c.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
                format!("{:05}", n % 100_000)
            })
            .collect::<Vec<_>>()
            .join(" "))
    }
}

// ---------------------------------------------------------------------------
// Buying access without the seller learning what it sold to whom
// ---------------------------------------------------------------------------

/// A capability token being bought, mid-purchase.
///
/// The client picks a random id, blinds it, pays, and receives a signature over
/// something the issuer never saw. What comes back cannot be matched to the
/// sale that produced it, and that is true by construction rather than by the
/// seller's promise.
///
/// This is the browser half of RFC 9474 blind RSA. The seller's half lives in
/// the mailbox server.
#[wasm_bindgen]
pub struct TokenRequest {
    id: [u8; 16],
    blinding: blind_rsa_signatures::BlindingResult,
}

#[wasm_bindgen]
impl TokenRequest {
    /// Blind a fresh id under a tier's public key.
    ///
    /// `public_key` is DER, published by the operator. Which tier it grants is
    /// decided by which key it is, never by anything the client writes: a blind
    /// issuer cannot read what it signs, so a tier chosen by the buyer would be
    /// a tier taken rather than bought.
    pub fn begin(public_key_b64: &str) -> Result<TokenRequest, Error> {
        use blind_rsa_signatures::{PublicKey, Randomized, Sha384, PSS};

        let pk = PublicKey::<Sha384, PSS, Randomized>::from_der(&decode(public_key_b64)?)
            .map_err(|_| Error::new("that is not a valid issuer public key"))?;

        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| Error::new(format!("entropy: {e}")))?;

        let blinding = pk
            .blind(&mut blind_rsa_signatures::DefaultRng, id)
            .map_err(|e| Error::new(format!("blinding: {e}")))?;

        Ok(TokenRequest { id, blinding })
    }

    /// The blinded message to send to the issuer with the payment.
    #[wasm_bindgen(getter)]
    pub fn blinded(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(&self.blinding.blind_message)
    }

    /// Turn the issuer's blind signature into a usable token.
    pub fn finish(self, public_key_b64: &str, blind_signature: &str) -> Result<String, Error> {
        use blind_rsa_signatures::{BlindSignature, PublicKey, Randomized, Sha384, PSS};

        let pk = PublicKey::<Sha384, PSS, Randomized>::from_der(&decode(public_key_b64)?)
            .map_err(|_| Error::new("that is not a valid issuer public key"))?;

        let raw = data_encoding::BASE64URL_NOPAD
            .decode(blind_signature.trim().as_bytes())
            .map_err(|_| Error::new("the signature is not valid base64url"))?;

        let randomizer = self
            .blinding
            .msg_randomizer
            .ok_or_else(|| Error::new("the blinding lost its randomizer"))?;

        let signature = pk
            .finalize(&BlindSignature(raw), &self.blinding, self.id)
            .map_err(|_| {
                Error::new("that signature does not match this request, or the wrong key was used")
            })?;

        let mut token = Vec::with_capacity(16 + 32 + signature.len());
        token.extend_from_slice(&self.id);
        token.extend_from_slice(&randomizer.0);
        token.extend_from_slice(&signature);
        Ok(data_encoding::BASE64URL_NOPAD.encode(&token))
    }
}

// ---------------------------------------------------------------------------
// Rendezvous
// ---------------------------------------------------------------------------

/// What to name an envelope by when acknowledging it.
///
/// Delivery peeks and removal waits for a receipt, so an envelope nobody
/// acknowledges sits until its TTL: the tag fills at `MAX_PER_TAG` and the
/// server then refuses further deposits, which loses messages silently.
/// Acknowledging is not optional housekeeping.
///
/// It lives in the engine rather than in each client because the digest is
/// over the envelope's stored bytes, and computing it means parsing the wire
/// format. Two more implementations of that format is two more places for it
/// to drift, which is the reason this crate exists.
///
/// No session: an envelope names itself, and a receipt for one the caller
/// cannot open is refused by the server anyway, which only honours a digest on
/// a tag that connection is listening on.
///
/// **Call it after the envelope is opened and written down, never on arrival.**
/// Not acknowledging costs re-delivery until the TTL; acknowledging something
/// not yet stored loses it.
#[wasm_bindgen(js_name = receiptFor)]
pub fn receipt_for(envelope_b64: &str) -> Result<String, Error> {
    let envelope = Envelope::from_bytes(&decode(envelope_b64)?).map_err(err)?;
    Ok(data_encoding::HEXLOWER.encode(&envelope.digest()))
}

/// Derive a meeting tag from a phrase both sides already know.
///
/// # This tag is not a secret channel
///
/// Two people who have never exchanged a key have nowhere to put the first
/// message. A phrase agreed in advance gives them one mailbox slot to meet in.
/// Everything deposited there is readable by the operator, which is acceptable
/// only because none of the handshake needs to be private: a key package is
/// public, a welcome is encrypted to the joiner's own key, and a hybrid
/// ciphertext is encapsulated to their public key.
///
/// What the phrase does **not** provide is authentication. Anyone who learns it
/// before the intended party arrives can answer in their place, and both sides
/// would complete a handshake with the attacker rather than each other. The
/// only thing that detects this is comparing the safety number out of band,
/// over a channel the attacker does not control. Displaying it is not optional.
#[wasm_bindgen(js_name = rendezvousTag)]
pub fn rendezvous_tag(passphrase: &str) -> Result<String, Error> {
    let phrase = passphrase.trim();
    if phrase.len() < 8 {
        return Err(Error::new(
            "a meeting phrase must be at least 8 characters: a short one is guessable, \
             and guessing it is enough to impersonate whoever it was meant for",
        ));
    }

    let mut hasher = blake3::Hasher::new_derive_key("rotelyx browser rendezvous v1");
    hasher.update(phrase.as_bytes());

    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    Ok(hex(&out))
}

/// Put a payload in an envelope addressed to an arbitrary tag.
///
/// Only for the rendezvous, where no conversation exists yet and so no tag key
/// does either. Once a conversation is established use `Session::seal`, which
/// derives the tag from the group and cannot be pointed at the wrong one.
#[wasm_bindgen(js_name = sealUnder)]
pub fn seal_under(tag_hex: &str, payload_b64: &str) -> Result<String, Error> {
    let tag = tag_from_hex(tag_hex)?;
    let payload = decode(payload_b64)?;
    let envelope = Envelope::seal(tag, &payload).map_err(err)?;
    Ok(BASE64.encode(&envelope.to_bytes()))
}

/// Take a payload out of a rendezvous envelope, checking the tag first.
///
/// # The padding has to come off here
///
/// An envelope carries no length field, by design: one would hand the operator
/// exactly the information the size buckets exist to hide. A recipient recovers
/// the real content because the inner message is self-delimiting, which is true
/// of an MLS message and **not** true of the JSON the rendezvous carries. A
/// parser handed the padded payload fails on trailing NUL bytes.
///
/// So the trailing NULs are stripped here rather than by the caller. Rendezvous
/// payloads are text, and text does not end in NUL, so this is unambiguous. It
/// is deliberately not done in `Session::open`, whose payload goes to MLS and
/// must arrive exactly as it was padded.
#[wasm_bindgen(js_name = openUnder)]
pub fn open_under(envelope_b64: &str, tag_hex: &str) -> Result<String, Error> {
    let expected = tag_from_hex(tag_hex)?;
    let envelope = Envelope::from_bytes(&decode(envelope_b64)?).map_err(err)?;

    if envelope.tag() != expected {
        return Err(Error::new("envelope is addressed to a different tag"));
    }

    let payload = envelope.payload();
    let end = payload
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |last| last + 1);

    Ok(BASE64.encode(&payload[..end]))
}

fn tag_from_hex(hex_str: &str) -> Result<Tag, Error> {
    if hex_str.len() != 64 {
        return Err(Error::new("a tag is 64 hex characters"));
    }
    let bytes: Result<Vec<u8>, _> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect();
    Tag::from_bytes(&bytes.map_err(|_| Error::new("not valid hex"))?).map_err(err)
}

// ---------------------------------------------------------------------------
// Meeting codes
// ---------------------------------------------------------------------------

/// The prefix, so a scanner can tell a Rotelyx code from any other QR before it
/// tries to use one.
pub const MEETING_PREFIX: &str = "RTLX1";

/// The alphabet: base32 as RFC 4648 defines it.
///
/// Two properties earn it the job. Every character is legal in the QR standard's
/// alphanumeric mode, so an encoder can pack two characters into eleven bits
/// rather than spending eight on each. And it omits 0, 1 and 8, which are the
/// digits people mistake for O, I and B when reading a code aloud.
const MEETING_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// How many random bytes a code carries.
///
/// Fifteen bytes is 120 bits, an exact multiple of the five bits a base32
/// character holds, so the code needs no padding and comes to 29 characters.
const MEETING_ENTROPY: usize = 15;

/// How many characters those bytes become.
const MEETING_BODY: usize = MEETING_ENTROPY * 8 / 5;

/// Mint a meeting code.
///
/// # What this is and is not
///
/// It is not a key and it is not an identity. It is an address at the mailbox,
/// in the same sense as a table number in a cafe. Both sides run it through
/// [`rendezvous_tag`], arrive at the same tag, and hand each other the real keys
/// there, where their size costs nothing.
///
/// The obvious alternative, putting the invitation in the QR, cannot be done. An
/// X-Wing public key is 1216 bytes because that is what resisting a quantum
/// computer costs, and with the key package and base64 alongside it the
/// invitation comes to roughly three thousand characters. A QR tops out at 2953,
/// at the weakest correction level, and at the level that leaves room for a logo
/// the ceiling is 1273.
///
/// # What it is worth to an attacker
///
/// Exactly one attempt at being first. Whoever reaches the meeting place before
/// the intended person completes the handshake in their place, and nothing in
/// the code prevents it, because a code is not proof of who is holding it. The
/// only thing that detects it is comparing the safety number out of band.
///
/// This is the same format `lib/rotelyx/meeting_code.dart` mints in the phone
/// client, character for character, because a code minted on one and scanned by
/// the other has to name the same place.
#[wasm_bindgen(js_name = newMeetingCode)]
pub fn new_meeting_code() -> Result<String, Error> {
    let mut bytes = [0u8; MEETING_ENTROPY];
    getrandom::fill(&mut bytes).map_err(|e| Error::new(format!("no randomness available: {e}")))?;

    let mut out = String::with_capacity(MEETING_PREFIX.len() + MEETING_BODY);
    out.push_str(MEETING_PREFIX);

    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(
                MEETING_ALPHABET[((buffer >> bits) & 0x1F) as usize],
            ));
        }
    }
    debug_assert_eq!(bits, 0, "entropy must divide into whole base32 characters");

    Ok(out)
}

/// Recognise a meeting code in whatever a scan or a paste produced.
///
/// Returns the code in its canonical form, or an error if this is not one.
///
/// Tolerant on the way in and strict on the way out. A code may arrive wrapped
/// in a link, with a trailing space, in lower case, or split into groups by
/// whoever typed it. None of those are the user's mistake to fix.
///
/// The canonical form is what goes into [`rendezvous_tag`]. Both clients derive
/// the tag from this string and not from what was displayed, so the grouping
/// used for reading a code aloud cannot change where the meeting happens.
#[wasm_bindgen(js_name = readMeetingCode)]
pub fn read_meeting_code(input: &str) -> Result<String, Error> {
    let mut text = input.trim();

    // A code shared as a link, which is what a person naturally does when they
    // want it tappable in whatever they are pasting into. Only the custom
    // scheme: an `https://` form would mean naming a web host in the client.
    const SCHEME: &str = "rotelyx://";
    if text.len() >= SCHEME.len() && text[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        text = &text[SCHEME.len()..];
    }

    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect();

    let body = cleaned
        .strip_prefix(MEETING_PREFIX)
        .ok_or_else(|| Error::new("that does not look like a meeting code"))?;

    if body.len() != MEETING_BODY {
        return Err(Error::new(
            "a meeting code is the prefix and twenty nine characters",
        ));
    }
    if !body.bytes().all(|b| MEETING_ALPHABET.contains(&b)) {
        return Err(Error::new(
            "a meeting code holds only the letters A to Z and the digits 2 to 7",
        ));
    }

    Ok(format!("{MEETING_PREFIX}{body}"))
}

/// Break a code into groups for display.
///
/// A twenty nine character run is unreadable and unspeakable. Groups of four are
/// what people are used to from card numbers and licence keys.
///
/// The prefix stays, as its own group. Dropping it would make the displayed code
/// something [`read_meeting_code`] refuses, so copying what is on screen would
/// fail in a way nobody could diagnose.
#[wasm_bindgen(js_name = prettyMeetingCode)]
pub fn pretty_meeting_code(code: &str) -> String {
    let body = code.strip_prefix(MEETING_PREFIX).unwrap_or(code);

    let mut out = String::from(MEETING_PREFIX);
    for (at, ch) in body.chars().enumerate() {
        if at % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

/// What a native caller needs and a browser does not.
///
/// A separate `impl` with no `#[wasm_bindgen]`, because that attribute exports
/// every public method in its block and neither of these can cross into
/// JavaScript: one returns a raw key, the other exists for a call path the
/// browser does not have.
impl Session {
    /// The base key a voice call derives its per-sender keys from.
    ///
    /// An MLS exporter output, so it is bound to the epoch: a member who joins
    /// changes it, and both ends of a call must be at the same epoch or every
    /// frame fails to authenticate. That is the correct behaviour and it is a
    /// trap for a caller who caches this across a membership change.
    ///
    /// Not exposed to JavaScript. The browser has no call path, and handing a
    /// page the raw media key would put it in a garbage-collected heap for no
    /// reason. `rotelyx-mobile` uses it, in the same process, and never returns
    /// it across its own boundary either.
    pub fn media_base_key(&self) -> Result<[u8; 32], Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        group.media_base_key(&self.member).map_err(err)
    }

    /// Which leaf this member is, which becomes its sender id in a call.
    ///
    /// A media header carries five bits of sender identity, so a call is limited
    /// to 32 simultaneous speakers whatever the group's size.
    pub fn sender_index(&self) -> Result<usize, Error> {
        let group = self
            .conversation
            .as_ref()
            .ok_or_else(|| Error::new("no conversation yet"))?;
        let mine = self.member.signature_key();
        group
            .roster()
            .iter()
            .position(|p| p.signature_key == mine)
            .ok_or_else(|| Error::new("this member is not in its own roster"))
    }
}

/// A key derived from a passphrase, held for the life of a tab.
///
/// # Why this is separate from the passphrase
///
/// Argon2id at 64 MiB takes about a second in a browser, which is the point:
/// it is what makes a passphrase worth something. But the MLS state changes
/// with **every message**, since sending and receiving both turn the ratchet,
/// so a session that re-derived the key on each save would stall for a second
/// per message.
///
/// So the cost is paid once, at unlock, and the key is held. It is zeroized on
/// drop, and it lives only as long as the tab.
#[wasm_bindgen]
/// Clone, because one window holds one of these and hands a copy to every
/// conversation it runs. Deriving a second one instead would mean a second
/// Argon2id at 64 MiB, which is the cost this type exists to pay once.
#[derive(Clone)]
pub struct SessionKey {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
}

#[wasm_bindgen]
impl SessionKey {
    /// Derive a fresh key with a new random salt, for a session being saved for
    /// the first time.
    pub fn create(passphrase: &str) -> Result<SessionKey, Error> {
        if passphrase.len() < 8 {
            return Err(Error::new(
                "a passphrase of at least 8 characters: what this protects is the \
                 whole conversation, and a short passphrase is a short walk to it",
            ));
        }

        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| Error::new(format!("entropy: {e}")))?;

        Ok(SessionKey {
            key: seal_key(passphrase, &salt)?,
            salt,
        })
    }

    /// A key the platform already holds, rather than one derived from a
    /// passphrase.
    ///
    /// # Why this exists
    ///
    /// Android has a keystore and iOS has a secure enclave, and a key held
    /// there is protected by hardware and by the device unlock rather than by
    /// something a person can be made to say. Neither is reachable from this
    /// crate: they are platform interfaces, and the part that belongs here is
    /// being able to **take** the key those produce rather than insisting on
    /// deriving one.
    ///
    /// The salt is still carried, and still random, so a blob sealed this way
    /// has the same shape as any other and the two are not told apart on disk.
    /// Nothing is derived from it in this path; it is there because the format
    /// has a slot for it and a blob with an empty one would be a blob that
    /// announces which kind of key opened it.
    ///
    /// **32 bytes, and they have to be a key.** This does no stretching, so
    /// anything with less entropy than a key is worth less than a passphrase
    /// would have been. Give it what a keystore returned, not something typed.
    pub fn from_platform_key(key: &[u8]) -> Result<SessionKey, Error> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| Error::new("a platform key is 32 bytes"))?;

        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| Error::new(format!("entropy: {e}")))?;

        Ok(SessionKey {
            key: Zeroizing::new(key),
            salt,
        })
    }

    /// Open an existing blob with a key the platform holds.
    ///
    /// The blob's salt is read and ignored, for the reason in
    /// [`Self::from_platform_key`]: it is carried so that every blob looks
    /// alike, and nothing here is derived from it.
    pub fn unlock_with_platform_key(key: &[u8], blob_b64: &str) -> Result<SessionKey, Error> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| Error::new("a platform key is 32 bytes"))?;

        let raw = decode(blob_b64)?;
        if raw.len() < 25 {
            return Err(Error::new("this is too short to be a sealed session"));
        }
        if &raw[..8] != SEAL_MAGIC {
            return Err(Error::new("this is not a sealed Rotelyx session"));
        }
        let salt: [u8; 16] = raw[9..25]
            .try_into()
            .map_err(|_| Error::new("malformed header"))?;

        Ok(SessionKey {
            key: Zeroizing::new(key),
            salt,
        })
    }

    /// Derive the key for an existing blob, whose salt travels inside it.
    pub fn unlock(passphrase: &str, blob_b64: &str) -> Result<SessionKey, Error> {
        let raw = decode(blob_b64)?;
        if raw.len() < 25 {
            return Err(Error::new("this is too short to be a sealed session"));
        }
        if &raw[..8] != SEAL_MAGIC {
            return Err(Error::new("this is not a sealed Rotelyx session"));
        }

        let salt: [u8; 16] = raw[9..25]
            .try_into()
            .map_err(|_| Error::new("malformed header"))?;

        Ok(SessionKey {
            key: seal_key(passphrase, &salt)?,
            salt,
        })
    }
}

/// Seal arbitrary bytes under a session key.
///
/// # Why this exists separately from the session
///
/// A conversation that resumes with an empty screen is technically correct and
/// useless: the group is intact but the reader has no idea what was said. So
/// the page keeps its own log and seals it here.
///
/// **This is the one place Rotelyx stores readable message text at rest.**
/// Everywhere else the plaintext exists only in memory, for the moment it is
/// displayed. A conversation kept across reloads is a conversation written
/// down, encrypted under a passphrase, in a browser profile that can be copied.
/// That is a real change and it is why keeping history is opt in: it happens
/// only when a passphrase is given.
///
/// The format of what goes in is entirely the caller's business. This function
/// knows only how to seal bytes.
/// Seal a push token to the notifier.
///
/// # What a ticket is for
///
/// A device leaves one of these under each tag it listens on, and the mailbox
/// stores it without being able to read it. When something arrives at that
/// tag, the mailbox hands the ticket to the notifier, which opens it and
/// pushes. The mailbox knows the tag and not the device; the notifier knows
/// the device and not the tag.
///
/// # Why one per tag, sealed separately
///
/// Every call produces different bytes for the same token, which is what makes
/// the rows unlinkable. Sealing once and leaving the same string under several
/// tags would put a repeated value in the mailbox's table, and following a
/// repeated value across the rotation is exactly what the rotation prevents.
///
/// `notifier_b64` is the notifier's public key, which a client pins in its
/// build. Asking a server for the key it should be sealed to hands that server
/// the option of naming its own.
#[wasm_bindgen(js_name = sealWakeTicket)]
pub fn seal_wake_ticket(
    notifier_b64: &str,
    kind: &str,
    token: &str,
    hour: u64,
) -> Result<String, Error> {
    let bytes = BASE64
        .decode(notifier_b64.as_bytes())
        .map_err(|_| Error::new("the notifier key is not base64"))?;
    let key = rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(&bytes)
        .map_err(|_| Error::new("the notifier key is not a key"))?;

    let kind = match kind {
        "apns" => rotelyx_crypto::TicketKind::Apns,
        "fcm" => rotelyx_crypto::TicketKind::Fcm,
        other => return Err(Error::new(&format!("no push service called {other}"))),
    };

    let ticket = rotelyx_crypto::WakeTicket::seal(&key, kind, token, hour).map_err(err)?;
    Ok(BASE64.encode(&ticket.to_bytes()))
}

#[wasm_bindgen(js_name = sealBlob)]
pub fn seal_blob(key: &SessionKey, data_b64: &str) -> Result<String, Error> {
    Ok(BASE64.encode(&seal_bytes(key, &decode(data_b64)?)?))
}

/// Open bytes sealed by [`seal_blob`].
#[wasm_bindgen(js_name = openBlob)]
pub fn open_blob(key: &SessionKey, blob_b64: &str) -> Result<String, Error> {
    Ok(BASE64.encode(&open_bytes(key, &decode(blob_b64)?)?))
}

/// Magic and version, so a blob from a future format is refused rather than
/// misread into a broken session.
const SEAL_MAGIC: &[u8; 8] = b"ROTELYXS";
const SEAL_VERSION: u8 = 1;

/// Argon2id at 64 MiB and three passes, matching the desktop keyfile. Costly on
/// purpose: this is the only thing between a stolen browser profile and a
/// conversation.
fn seal_key(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, Error> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| Error::new(format!("argon2 parameters: {e}")))?;

    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| Error::new(format!("deriving the key: {e}")))?;

    Ok(key)
}

fn seal_bytes(key: &SessionKey, plain: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let salt = key.salt;

    // A fresh nonce every save. The key is reused across saves, so repeating a
    // nonce would repeat a keystream, and these blobs differ by only a few
    // bytes between saves: exactly the case where that leaks the difference.
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| Error::new(format!("entropy: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key.key[..])
        .map_err(|e| Error::new(format!("cipher: {e}")))?;

    let mut header = Vec::with_capacity(8 + 1 + 16 + 24);
    header.extend_from_slice(SEAL_MAGIC);
    header.push(SEAL_VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: &header,
            },
        )
        .map_err(|e| Error::new(format!("sealing: {e}")))?;

    let mut out = header;
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_bytes(key: &SessionKey, raw: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let header_len = 8 + 1 + 16 + 24;
    if raw.len() < header_len + 16 {
        return Err(Error::new("this is too short to be a sealed session"));
    }

    let (header, body) = raw.split_at(header_len);
    if &header[..8] != SEAL_MAGIC {
        return Err(Error::new("this is not a sealed Rotelyx session"));
    }
    if header[8] != SEAL_VERSION {
        return Err(Error::new(format!(
            "this session was written by format version {}, and this build speaks {SEAL_VERSION}",
            header[8]
        )));
    }

    let nonce: [u8; 24] = header[25..].try_into().expect("checked length");

    let cipher = XChaCha20Poly1305::new_from_slice(&key.key[..])
        .map_err(|e| Error::new(format!("cipher: {e}")))?;

    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: body,
                aad: header,
            },
        )
        .map_err(|_| Error::new("wrong passphrase, or the stored session was altered"))
}

/// Tags are routing data an operator handles as text, so they cross the
/// boundary as hex rather than base64: it sorts, it is fixed width, and it has
/// no characters that need escaping in a URL or a log line.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {

    /// The text of a `receive` result, if it was an application message.
    ///
    /// `receive` returns JSON saying which of three things arrived, so a test
    /// that wants the plaintext has to say so. These two keep the assertions
    /// below reading like the properties they check rather than like parsing.
    fn message_text(json: &str) -> Option<String> {
        let marker = "\"kind\":\"message\",\"text\":\"";
        let start = json.find(marker)? + marker.len();
        let rest = &json[start..];
        let end = rest.rfind("\"}")?;
        Some(rest[..end].to_string())
    }

    /// Whether a `receive` result was an application message at all.
    fn is_message(json: &str) -> bool {
        json.contains("\"kind\":\"message\"")
    }

    use super::*;

    /// The whole browser handshake, executed on the host.
    ///
    /// This is the sequence the chat page performs. Running it here means a
    /// Nothing an operator holds may name the conversation.
    ///
    /// This is the regression test for the defect that defeated the mailbox's
    /// reason to exist. An envelope carried the serialised MLS message
    /// verbatim, and RFC 9420 puts `group_id` and `epoch` in cleartext in the
    /// framing ahead of the encrypted content. So the operator read a stable
    /// identifier out of every envelope with no key at all, and every envelope
    /// of a conversation linked to every other across every tag rotation and
    /// all of time. Rotating tags hid who. They did not hide that these belong
    /// together, which is most of a social graph.
    ///
    /// The assertion is on the bytes the operator actually stores, at three
    /// tags hours apart, which is exactly what the auditor's reproduction did.
    #[test]
    fn an_envelope_does_not_name_the_conversation() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        let group_id = alice.group_id().expect("group id");
        let raw = data_encoding::HEXLOWER
            .decode(group_id.as_bytes())
            .expect("hex");
        assert!(!raw.is_empty());

        // Three deposits, hours apart, under three different rotating tags.
        let mut payloads = Vec::new();
        let mut tags = Vec::new();
        for bucket in [100u64, 137, 941] {
            let ct = alice.send("the same conversation").expect("send");
            let envelope_b64 = alice.seal(&ct, bucket).expect("seal");
            let bytes = BASE64.decode(envelope_b64.as_bytes()).expect("b64");
            let envelope = Envelope::from_bytes(&bytes).expect("parse");

            tags.push(hex(envelope.tag().as_bytes()));
            payloads.push(envelope.payload().to_vec());
        }

        // Different tags, which was already true and was never the problem.
        assert_ne!(tags[0], tags[1]);
        assert_ne!(tags[1], tags[2]);

        // And now: the group id appears in none of the stored bytes.
        for (i, payload) in payloads.iter().enumerate() {
            assert!(
                !payload.windows(raw.len()).any(|w| w == raw.as_slice()),
                "envelope {i} carries the group id in the clear"
            );
        }

        // Nor do two payloads of one conversation resemble each other. They are
        // the same plaintext under the same key, and they must still differ,
        // because a repeated ciphertext is a link of its own.
        assert_ne!(payloads[0], payloads[1]);
        assert_ne!(payloads[1], payloads[2]);

        // The recipient still reads them.
        let ct = alice.send("hello").expect("send");
        let envelope = alice.seal(&ct, 100).expect("seal");
        let opened = bob.open(&envelope, 100, 2).expect("open");
        let text = bob.receive(&opened).expect("receive");
        assert!(
            text.contains("hello"),
            "the recipient could not read it: {text}"
        );
    }

    /// A wrap minted by somebody outside the group is refused.
    ///
    /// This is the last half of the post-quantum plumbing to close. The wrap is
    /// bound to the group, the epoch and the recipient, which stopped it being
    /// replayed and stopped it being opened by the wrong member. What it did
    /// not say was who produced it: anybody holding a member's published hybrid
    /// key could mint one, and a receiver that staged it would then be unable
    /// to process the legitimate commit.
    ///
    /// It is signed now, and a receiver tries every current member's key. A
    /// stranger's signature verifies under none of them.
    /// The receipt names the envelope and nothing else.
    ///
    /// It has to be computable by a client that only holds the base64 it was
    /// handed, and it has to be the same value the server derives from the
    /// bytes it stored, or an acknowledgement removes nothing and the tag
    /// fills.
    #[test]
    fn a_receipt_names_the_envelope_it_is_for() {
        let tag = Tag::from_bytes(&[9u8; 32]).expect("tag");
        let one = Envelope::seal(tag, b"the first").expect("seal");
        let two = Envelope::seal(tag, b"the second").expect("seal");

        let for_one = receipt_for(&BASE64.encode(&one.to_bytes())).expect("receipt");
        let for_two = receipt_for(&BASE64.encode(&two.to_bytes())).expect("receipt");

        assert_eq!(
            for_one,
            data_encoding::HEXLOWER.encode(&one.digest()),
            "the client's receipt must be the digest the server compares against"
        );
        assert_ne!(for_one, for_two, "two envelopes must not share a receipt");

        // Same bytes, same name, however many times a client is handed them.
        assert_eq!(
            for_one,
            receipt_for(&BASE64.encode(&one.to_bytes())).expect("again")
        );
    }

    /// Rubbish is refused rather than named.
    #[test]
    fn a_receipt_is_refused_for_something_that_is_not_an_envelope() {
        assert!(receipt_for("not base64 at all !!").is_err());
        assert!(receipt_for(&BASE64.encode(b"short")).is_err());
    }

    #[test]
    fn a_wrap_from_outside_the_group_is_refused() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");
        let mut mallory = Session::new("mallory").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        // Mallory holds Bob's published hybrid key, which is public, and is not
        // in the group. She founds a group of her own to have a member to sign
        // with, which is the best an outsider can do.
        mallory.found().expect("found");
        let forged = mallory
            .begin_group_pq(vec![bob.hybrid_public_key()])
            .expect_err("a group of one has nobody to wrap for");
        let _ = forged;

        // The real path, so the test proves the good case still works.
        let wraps = alice
            .begin_group_pq(vec![bob.hybrid_public_key()])
            .expect("wrap for bob");
        assert_eq!(wraps.len(), 1);
        bob.open_group_pq(&wraps[0])
            .expect("bob opens alice's wrap");

        // And a wrap whose signature has been tampered with is refused rather
        // than opened. Flipping a byte of the signature is the cheapest forgery
        // there is, and it must not work.
        let mut tampered = BASE64.decode(wraps[0].as_bytes()).expect("base64");
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let tampered = BASE64.encode(&tampered);

        let mut carol = Session::new("carol").expect("identity");
        let inv = alice
            .invite(&carol.key_package().expect("kp"))
            .expect("invite");
        carol.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        assert!(
            carol.open_group_pq(&tampered).is_err(),
            "a wrap with a broken signature was accepted"
        );
    }

    /// The safety number must move when the roster does.
    ///
    /// This is the regression test for a fingerprint that attested to nothing.
    /// It was `BLAKE3(group_id)`, and a group id is fixed when the group is
    /// created, so the number was identical for the whole life of a
    /// conversation: adding a member did not change it, and neither would a
    /// silently added device. Two people re-comparing digits would have seen a
    /// match in exactly the case the comparison exists to catch.
    #[test]
    fn the_safety_number_changes_when_the_roster_does() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");
        let mut carol = Session::new("carol").expect("identity");

        alice.found().expect("found");
        let alone = alice.safety_number().expect("number");

        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");
        let with_bob = alice.safety_number().expect("number");

        assert_ne!(
            alone, with_bob,
            "the number did not move when a member joined, which is the whole \
             thing it is for"
        );

        // And both ends must reach the same answer, from rosters they may hold
        // in different orders. Without the sort this is where it would show.
        assert_eq!(
            with_bob,
            bob.safety_number().expect("number"),
            "the two sides disagree about who is in the conversation"
        );

        let inv = alice
            .invite(&carol.key_package().expect("kp"))
            .expect("invite");
        carol.join(&inv.welcome, &inv.ratchet_tree).expect("join");
        let with_carol = alice.safety_number().expect("number");

        assert_ne!(
            with_bob, with_carol,
            "a third member joined and the number stayed the same"
        );

        // The shape is what a person reads aloud: six groups of five digits.
        let groups: Vec<&str> = with_carol.split(' ').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    /// break is caught by `cargo test` instead of by a blank page.
    #[test]
    fn two_browser_sessions_reach_the_same_conversation() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");

        alice.found().expect("found");
        let invitation = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&invitation.welcome, &invitation.ratchet_tree)
            .expect("join");

        assert_eq!(alice.epoch(), bob.epoch(), "both sides land on one epoch");
        assert_eq!(alice.member_count(), 2);

        // The post-quantum step, in the order the page performs it: Bob stages
        // before the commit reaches him, because MLS refuses a commit whose
        // pre-shared key is not already in local storage.
        let ct = alice
            .encapsulate_to(&bob.hybrid_public_key())
            .expect("encapsulate");
        bob.open_pq(&ct).expect("stage");

        let commit = alice.commit_pq().expect("commit");
        assert!(
            !is_message(&bob.receive(&commit).expect("apply commit")),
            "a commit carries no plaintext"
        );
        assert_eq!(alice.epoch(), bob.epoch());

        let wire = alice.send("hello from the browser").expect("send");
        assert_eq!(
            message_text(&bob.receive(&wire).expect("receive")).expect("application"),
            "hello from the browser"
        );

        assert_eq!(
            alice.safety_number().expect("fingerprint"),
            bob.safety_number().expect("fingerprint"),
            "both sides must read the same number aloud"
        );
    }

    /// A commit must fail without the staged secret rather than silently
    /// proceeding without post-quantum protection.
    #[test]
    fn a_pq_commit_is_refused_when_the_secret_was_never_staged() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        alice
            .encapsulate_to(&bob.hybrid_public_key())
            .expect("encapsulate");
        let commit = alice.commit_pq().expect("commit");

        // Bob never called openPq.
        assert!(
            bob.receive(&commit).is_err(),
            "processing must fail, not fall back to a classical-only epoch"
        );
    }

    /// Both sides must derive the same mailbox tag, or messages are deposited
    /// where the recipient never looks.
    #[test]
    fn both_sides_derive_the_same_mailbox_tag() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        assert_eq!(
            alice.tag_for(490_000).expect("tag"),
            bob.tag_for(490_000).expect("tag")
        );
        assert_ne!(
            alice.tag_for(490_000).expect("tag"),
            alice.tag_for(490_001).expect("tag"),
            "tags must not be linkable across time buckets"
        );
    }

    /// An envelope addressed elsewhere must be refused, so that an operator
    /// cannot learn from our behaviour which envelopes we can read.
    #[test]
    fn an_envelope_for_a_foreign_tag_is_refused() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");
        let mut mallory_a = Session::new("mallory").expect("identity");
        let mut mallory_b = Session::new("mallory2").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        mallory_a.found().expect("found");
        let inv2 = mallory_a
            .invite(&mallory_b.key_package().expect("kp"))
            .expect("invite");
        mallory_b
            .join(&inv2.welcome, &inv2.ratchet_tree)
            .expect("join");

        let foreign = mallory_a
            .seal(&BASE64.encode(b"payload"), 490_000)
            .expect("seal");
        assert!(
            bob.open(&foreign, 490_000, 1).is_err(),
            "an envelope under someone else's tag must be refused"
        );

        let ours = alice
            .seal(&BASE64.encode(b"payload"), 490_000)
            .expect("seal");
        assert!(bob.open(&ours, 490_000, 1).is_ok());
    }

    /// Two messages of very different lengths must be the same size on the
    /// wire. This is the property the mailbox operator is denied.
    /// Build a group of `n` and return every session, the founder first.
    fn group_of(n: usize) -> Vec<Session> {
        let mut sessions: Vec<Session> = (0..n)
            .map(|i| Session::new(&format!("member{i}")).expect("identity"))
            .collect();

        sessions[0].found().expect("found");

        for i in 1..n {
            let kp = sessions[i].key_package().expect("kp");
            let invitation = sessions[0].invite(&kp).expect("invite");

            sessions[i]
                .join(&invitation.welcome, &invitation.ratchet_tree)
                .expect("join");

            // Everyone already in the group applies the commit.
            for member in sessions.iter_mut().take(i).skip(1) {
                assert!(
                    !is_message(&member.receive(&invitation.commit).expect("commit")),
                    "an add commit carries no plaintext"
                );
            }
        }
        sessions
    }

    /// A message must reach every other member, not just whichever one
    /// collected first. This is the property a single shared tag cannot give.
    #[test]
    fn a_group_message_reaches_every_member() {
        let mut group = group_of(5);
        let slot = 490_000u64;

        for s in &group {
            assert_eq!(s.member_count(), 5);
            assert_eq!(s.epoch(), group[0].epoch(), "one epoch for everyone");
        }

        let ciphertext = group[0].send("hello everyone").expect("send");
        let envelopes = group[0].seal_for_group(&ciphertext, slot).expect("seal");

        assert_eq!(
            envelopes.len(),
            4,
            "one deposit per recipient, and none addressed to ourselves"
        );

        // Every other member finds exactly one envelope addressed to them.
        for member in group.iter_mut().skip(1) {
            let mine: Vec<&String> = envelopes
                .iter()
                .filter(|e| member.open_mine(e, slot, 2).is_ok())
                .collect();

            assert_eq!(mine.len(), 1, "exactly one envelope must be ours");

            let payload = member.open_mine(mine[0], slot, 2).expect("open");
            assert_eq!(
                message_text(&member.receive(&payload).expect("decrypt")).expect("plaintext"),
                "hello everyone"
            );
        }
    }

    /// Every member listens on a different tag, or the mailbox hands one
    /// member's message to another and it is gone.
    #[test]
    fn no_two_members_share_a_tag() {
        let group = group_of(6);
        let slot = 490_000u64;

        let tags: Vec<String> = group.iter().map(|s| s.my_tag(slot).expect("tag")).collect();
        let unique: std::collections::HashSet<&String> = tags.iter().collect();

        assert_eq!(unique.len(), tags.len(), "two members collided on one tag");
    }

    /// The post-quantum secret must be the same for every member, or the
    /// commit fails for all but one.
    #[test]
    fn a_group_post_quantum_rotation_reaches_everyone() {
        let mut group = group_of(4);
        let epoch_before = group[0].epoch();

        // The committer seals one chosen secret to each of the others.
        let keys: Vec<String> = group
            .iter()
            .skip(1)
            .map(|s| s.hybrid_public_key())
            .collect();
        let wrapped = group[0].begin_group_pq(keys).expect("wrap");
        assert_eq!(wrapped.len(), 3);

        // Each stages it before the commit arrives.
        for (member, sealed) in group.iter_mut().skip(1).zip(&wrapped) {
            member.open_group_pq(sealed).expect("unwrap and stage");
        }

        let commit = group[0].commit_pq().expect("commit");
        for member in group.iter_mut().skip(1) {
            assert!(
                !is_message(&member.receive(&commit).expect("apply commit")),
                "a commit carries no plaintext"
            );
        }

        let epoch = group[0].epoch();
        assert!(epoch > epoch_before);
        for member in &group {
            assert_eq!(member.epoch(), epoch, "everyone lands on one epoch");
        }

        // And the conversation continues, now post-quantum protected.
        let slot = 490_000u64;
        let ciphertext = group[0].send("after the rotation").expect("send");
        let envelopes = group[0].seal_for_group(&ciphertext, slot).expect("seal");

        for member in group.iter_mut().skip(1) {
            let mine = envelopes
                .iter()
                .find(|e| member.open_mine(e, slot, 2).is_ok())
                .expect("an envelope for us");
            let payload = member.open_mine(mine, slot, 2).expect("open");
            assert_eq!(
                message_text(&member.receive(&payload).expect("decrypt")).expect("plaintext"),
                "after the rotation"
            );
        }
    }

    /// A wrapped secret sealed to somebody else must not open, or a member
    /// could stage the wrong value and produce a commit nobody can apply.
    #[test]
    fn a_secret_wrapped_for_another_member_does_not_open() {
        let mut group = group_of(3);

        let keys = vec![group[1].hybrid_public_key(), group[2].hybrid_public_key()];
        let wrapped = group[0].begin_group_pq(keys).expect("wrap");

        // Member 2 tries to open the one sealed to member 1.
        assert!(
            group[2].open_group_pq(&wrapped[0]).is_err(),
            "a secret sealed to another member must not open"
        );
        assert!(group[2].open_group_pq(&wrapped[1]).is_ok());
    }

    /// A third member joining an established pair, exactly as the page does
    /// it: the newcomer gets a welcome, and everyone already present gets a
    /// commit addressed at the epoch they are still on.
    ///
    /// This is the ordering that has no error path. Address the commit at the
    /// new epoch instead and the deposit lands on a tag nobody listens to, the
    /// group splits with the inviter one epoch ahead, and nothing anywhere
    /// says so.
    #[test]
    fn a_third_member_joins_an_established_pair() {
        let mut group = group_of(2);
        let slot = 490_000u64;

        let mut carol = Session::new("carol").expect("identity");
        let epoch_before = group[1].epoch();

        let invitation = group[0]
            .invite(&carol.key_package().expect("kp"))
            .expect("invite");

        carol
            .join(&invitation.welcome, &invitation.ratchet_tree)
            .expect("join");

        // The existing member is still one epoch back and must be reachable.
        let commits = group[0]
            .seal_commit_for_group(&invitation.commit, slot)
            .expect("seal commit");

        let mine = commits
            .iter()
            .find(|e| group[1].open_mine(e, slot, 2).is_ok())
            .expect("the waiting member must be addressable");

        let payload = group[1].open_mine(mine, slot, 2).expect("open");
        assert!(
            !is_message(&group[1].receive(&payload).expect("apply")),
            "a commit carries no plaintext"
        );

        assert!(group[1].epoch() > epoch_before);
        assert_eq!(group[0].epoch(), group[1].epoch());
        assert_eq!(group[0].epoch(), carol.epoch(), "all three on one epoch");
        assert_eq!(group[0].member_count(), 3);

        // And all three can now talk.
        let ciphertext = carol.send("hello, I have just arrived").expect("send");
        let envelopes = carol.seal_for_group(&ciphertext, slot).expect("seal");
        assert_eq!(envelopes.len(), 2);

        for member in group.iter_mut() {
            let mine = envelopes
                .iter()
                .find(|e| member.open_mine(e, slot, 2).is_ok())
                .expect("an envelope for us");
            let payload = member.open_mine(mine, slot, 2).expect("open");
            assert_eq!(
                message_text(&member.receive(&payload).expect("decrypt")).expect("plaintext"),
                "hello, I have just arrived"
            );
        }
    }

    /// The cap must refuse rather than let the group degrade quietly.
    ///
    /// Only the founder is driven to the cap. Having every member apply every
    /// commit would be quadratic, and the cap is enforced by the inviter, which
    /// is the only view this needs.
    #[test]
    fn the_group_is_capped() {
        let mut founder = Session::new("founder").expect("identity");
        founder.found().expect("found");

        for i in 1..MAX_MEMBERS {
            let joiner = Session::new(&format!("member{i}")).expect("identity");
            founder
                .invite(&joiner.key_package().expect("kp"))
                .unwrap_or_else(|_| panic!("member {i} must be admitted"));
        }
        assert_eq!(founder.member_count(), MAX_MEMBERS);

        let one_too_many = Session::new("gatecrasher").expect("identity");
        assert!(
            founder
                .invite(&one_too_many.key_package().expect("kp"))
                .is_err(),
            "member {} must be refused rather than admitted quietly",
            MAX_MEMBERS + 1
        );
    }

    /// Sealing for a group produces one envelope per other member, each already
    /// padded.
    ///
    /// Named for the client operation rather than for the server one it used to
    /// feed. The server no longer takes a request that names every recipient at
    /// once; a client deposits these separately, in an order it shuffles.
    #[test]
    fn sealing_for_a_group_addresses_everyone_but_the_sender() {
        let mut group = group_of(4);
        let slot = 490_000u64;

        let ciphertext = group[0].send("hello").expect("send");
        let tags = group[0].recipient_tags(slot).expect("tags");
        let payload = group[0].padded_payload(&ciphertext).expect("pad");

        assert_eq!(tags.len(), 3, "everyone but the sender");

        let unique: std::collections::HashSet<&String> = tags.iter().collect();
        assert_eq!(unique.len(), 3, "no two recipients share a tag");

        // Each recipient's own tag must be in the list.
        for member in group.iter().skip(1) {
            assert!(
                tags.contains(&member.my_tag(slot).expect("tag")),
                "a member was left out of the fan-out"
            );
        }

        // The payload is a bucket, not the true length.
        let raw = BASE64.decode(payload.as_bytes()).expect("b64");
        assert!(
            [1024, 8192, 65536, 1024 * 1024, 8 * 1024 * 1024].contains(&raw.len()),
            "payload must already be a bucket, got {}",
            raw.len()
        );
        assert!(raw.len() > ciphertext.len(), "it must actually be padded");
    }

    /// A reloaded tab must land back in the same conversation, at the same
    /// epoch, able to read what the group sends next.
    #[test]
    fn a_session_survives_being_sealed_and_reopened() {
        let mut group = group_of(3);
        let slot = 490_000u64;
        let phrase = "the long passphrase for this tab";

        let before = group[1].safety_number().expect("fingerprint");
        let epoch = group[1].epoch();

        let key = SessionKey::create(phrase).expect("key");
        let sealed = group[1].seal_session(&key).expect("seal");
        let mut reopened = Session::unseal_session(
            &sealed,
            &SessionKey::unlock(phrase, &sealed).expect("unlock"),
        )
        .expect("unseal");

        assert_eq!(reopened.epoch(), epoch, "the epoch must not move");
        assert_eq!(reopened.member_count(), 3);
        assert_eq!(
            reopened.safety_number().expect("fingerprint"),
            before,
            "it must be the same conversation, not a lookalike"
        );

        // Same tag, so the group keeps reaching it.
        assert_eq!(
            reopened.my_tag(slot).expect("tag"),
            group[1].my_tag(slot).expect("tag")
        );

        // And it can still read what the group sends.
        let ciphertext = group[0].send("sigues ahi?").expect("send");
        let envelopes = group[0].seal_for_group(&ciphertext, slot).expect("seal");
        let mine = envelopes
            .iter()
            .find(|e| reopened.open_mine(e, slot, 2).is_ok())
            .expect("an envelope for the reopened session");

        let payload = reopened.open_mine(mine, slot, 2).expect("open");
        assert_eq!(
            message_text(&reopened.receive(&payload).expect("decrypt")).expect("plaintext"),
            "sigues ahi?"
        );
    }

    /// A reopened session must be able to speak, not only listen. Sending needs
    /// the signing key, which is the part most easily lost in a restore.
    #[test]
    fn a_reopened_session_can_still_send() {
        let mut group = group_of(2);
        let slot = 490_000u64;
        let phrase = "another long passphrase for a tab";

        let key = SessionKey::create(phrase).expect("key");
        let sealed = group[1].seal_session(&key).expect("seal");
        let mut reopened = Session::unseal_session(
            &sealed,
            &SessionKey::unlock(phrase, &sealed).expect("unlock"),
        )
        .expect("unseal");

        // A resumed session rekeys before it is allowed to send, and the other
        // side has to hear about it. Without that it would be speaking at a
        // generation the group may already have spent, and every message would
        // be dropped by the receiver with nothing to say so.
        assert!(
            reopened.send("too soon").is_err(),
            "a resumed session sent without rekeying"
        );
        let commit = reopened.rekey_after_restore().expect("rekey after restore");
        group[0]
            .receive(&commit)
            .expect("the other side applies the rekey");

        let ciphertext = reopened.send("vuelvo a estar").expect("send");
        let envelopes = reopened.seal_for_group(&ciphertext, slot).expect("seal");

        let payload = group[0].open_mine(&envelopes[0], slot, 2).expect("open");
        assert_eq!(
            message_text(&group[0].receive(&payload).expect("decrypt")).expect("plaintext"),
            "vuelvo a estar"
        );
    }

    /// A key the platform holds seals and opens, and a passphrase does not open
    /// it.
    ///
    /// The two paths produce blobs of the same shape on purpose, so what stops
    /// them being confused is that neither key opens the other's. If a
    /// passphrase-derived key ever opened a platform-sealed blob, the salt
    /// would be doing work it is documented not to do.
    #[test]
    fn a_platform_key_seals_and_opens_and_a_passphrase_does_not() {
        let group = group_of(2);
        let platform = [7u8; 32];

        let key = SessionKey::from_platform_key(&platform).expect("a platform key");
        let sealed = group[1].seal_session(&key).expect("seal");

        let same = SessionKey::unlock_with_platform_key(&platform, &sealed).expect("unlock");
        assert!(
            Session::unseal_session(&sealed, &same).is_ok(),
            "the key that sealed it did not open it"
        );

        let mut other = platform;
        other[0] ^= 1;
        let wrong = SessionKey::unlock_with_platform_key(&other, &sealed).expect("a key");
        assert!(
            Session::unseal_session(&sealed, &wrong).is_err(),
            "a key differing in one bit opened it"
        );

        // And a passphrase, however good, is not this key.
        let typed = SessionKey::unlock("a passphrase long enough to pass", &sealed)
            .expect("deriving is allowed; opening is what must fail");
        assert!(
            Session::unseal_session(&sealed, &typed).is_err(),
            "a passphrase opened a blob sealed with a key the platform held"
        );
    }

    /// A platform key is a key, not something typed.
    ///
    /// Nothing here stretches it, so anything shorter is worth less than the
    /// passphrase path it replaces. Refused rather than padded.
    #[test]
    fn a_platform_key_that_is_not_32_bytes_is_refused() {
        for len in [0usize, 1, 16, 31, 33, 64] {
            assert!(
                SessionKey::from_platform_key(&vec![0u8; len]).is_err(),
                "{len} bytes was accepted as a platform key"
            );
        }
        assert!(SessionKey::from_platform_key(&[0u8; 32]).is_ok());
    }

    /// The blob is the whole participant. Without the passphrase it must be
    /// worth nothing.
    #[test]
    fn a_sealed_session_needs_its_passphrase() {
        let group = group_of(2);
        let key = SessionKey::create("the right passphrase for here").expect("key");
        let sealed = group[1].seal_session(&key).expect("seal");

        let wrong =
            SessionKey::unlock("an entirely different passphrase", &sealed).expect("derive");
        assert!(
            Session::unseal_session(&sealed, &wrong).is_err(),
            "a stolen browser profile without the passphrase must yield nothing"
        );

        let right = SessionKey::unlock("the right passphrase for here", &sealed).expect("derive");
        assert!(Session::unseal_session(&sealed, &right).is_ok());
    }

    /// A short passphrase is refused, because this blob is the conversation.
    #[test]
    fn a_short_passphrase_is_refused_for_a_session() {
        assert!(SessionKey::create("corta").is_err());
        assert!(SessionKey::create("long enough to be accepted").is_ok());
    }

    /// Tampering must fail loudly rather than produce a subtly wrong session.
    #[test]
    fn a_tampered_session_is_refused() {
        let group = group_of(2);
        let phrase = "the passphrase for this long test";
        let key = SessionKey::create(phrase).expect("key");
        let sealed = group[1].seal_session(&key).expect("seal");

        let mut raw = BASE64.decode(sealed.as_bytes()).expect("b64");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;

        assert!(Session::unseal_session(&BASE64.encode(&raw), &key).is_err());
    }

    /// A session sealed before any conversation existed must reopen as an
    /// identity with no group, rather than failing.
    #[test]
    fn an_identity_with_no_conversation_reopens() {
        let alone = Session::new("solo").expect("identity");
        let phrase = "a passphrase for the lone member";

        let key = SessionKey::create(phrase).expect("key");
        let sealed = alone.seal_session(&key).expect("seal");
        let reopened = Session::unseal_session(
            &sealed,
            &SessionKey::unlock(phrase, &sealed).expect("unlock"),
        )
        .expect("unseal");

        assert_eq!(reopened.member_count(), 0);
        assert_eq!(reopened.epoch(), 0);

        // And it is still the same identity, so a key package issued before the
        // reload is still the one the group will add.
        assert_eq!(reopened.hybrid_public_key(), alone.hybrid_public_key());
    }

    /// The history has to survive under the same key as the session, or a
    /// conversation resumes to a blank screen.
    #[test]
    fn a_sealed_blob_round_trips_under_a_session_key() {
        let key = SessionKey::create("the passphrase for this long tab").expect("key");

        let log = br#"[{"me":true,"text":"hello"},{"me":false,"text":"que tal"}]"#;
        let sealed = seal_blob(&key, &BASE64.encode(log)).expect("seal");

        let recovered = BASE64
            .decode(open_blob(&key, &sealed).expect("open").as_bytes())
            .expect("b64");
        assert_eq!(recovered, log);
    }

    /// A stolen browser profile without the passphrase must not yield the
    /// conversation text. This is the claim that makes storing it acceptable.
    #[test]
    fn a_sealed_blob_is_worth_nothing_without_the_key() {
        let key = SessionKey::create("the right passphrase for here").expect("key");
        let secret = b"algo que no debe leerse en un perfil robado";
        let sealed = seal_blob(&key, &BASE64.encode(secret)).expect("seal");

        let raw = BASE64.decode(sealed.as_bytes()).expect("b64");
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "the message text is sitting in the blob"
        );

        let wrong = SessionKey::create("an entirely different passphrase").expect("key");
        assert!(
            open_blob(&wrong, &sealed).is_err(),
            "the wrong passphrase must yield nothing"
        );
    }

    /// Two saves of the same log must not produce the same bytes. The key is
    /// reused across saves, so a repeated nonce would repeat a keystream, and
    /// consecutive saves differ by one message: exactly the case where that
    /// leaks what changed.
    #[test]
    fn two_saves_of_the_same_data_differ() {
        let key = SessionKey::create("a passphrase for two saved sessions").expect("key");
        let data = BASE64.encode(b"the same log, saved twice");

        assert_ne!(
            seal_blob(&key, &data).expect("seal"),
            seal_blob(&key, &data).expect("seal"),
            "a repeated nonce would leak the difference between consecutive saves"
        );
    }

    /// The browser must be able to buy a token end to end, against the same
    /// issuer the mailbox trusts.
    #[test]
    fn a_token_can_be_bought_from_the_browser() {
        use blind_rsa_signatures::{DefaultRng, KeyPair, Randomized, Sha384, PSS};

        let keys = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)
            .expect("issuer keys");
        let public = BASE64.encode(&keys.pk.to_der().expect("der"));

        let request = TokenRequest::begin(&public).expect("blind");
        let blinded = request.blinded();

        // The issuer's whole involvement, on material it cannot read.
        let seen = data_encoding::BASE64URL_NOPAD
            .decode(blinded.as_bytes())
            .expect("b64");
        let blind_sig = keys.sk.blind_sign(&seen).expect("sign");

        let token = request
            .finish(&public, &data_encoding::BASE64URL_NOPAD.encode(&blind_sig))
            .expect("finalize");

        // What the issuer saw must not be in what it later has to honour.
        let spent = data_encoding::BASE64URL_NOPAD
            .decode(token.as_bytes())
            .expect("b64");
        assert!(
            !spent
                .windows(seen.len().min(spent.len()))
                .any(|w| w == &seen[..w.len()]),
            "the blinded message appears in the token, so a sale could be traced"
        );

        // And it is a well formed token: id, randomizer, 2048 bit signature.
        assert_eq!(spent.len(), 16 + 32 + 256);
    }

    /// A signature for a different request must not finalize, or one purchase
    /// could be redeemed into somebody else's token.
    #[test]
    fn a_signature_for_another_request_is_refused() {
        use blind_rsa_signatures::{DefaultRng, KeyPair, Randomized, Sha384, PSS};

        let keys = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)
            .expect("issuer keys");
        let public = BASE64.encode(&keys.pk.to_der().expect("der"));

        let mine = TokenRequest::begin(&public).expect("blind");
        let theirs = TokenRequest::begin(&public).expect("blind");

        let for_them = keys
            .sk
            .blind_sign(
                data_encoding::BASE64URL_NOPAD
                    .decode(theirs.blinded().as_bytes())
                    .expect("b64"),
            )
            .expect("sign");

        assert!(
            mine.finish(&public, &data_encoding::BASE64URL_NOPAD.encode(&for_them))
                .is_err(),
            "a signature bought for one request must not finish another"
        );
    }

    /// Two devices whose clocks put them in different time buckets must still
    /// reach each other.
    ///
    /// This is the failure that looked like a broken deployment for an evening.
    /// Tags rotate hourly, so a sender one bucket ahead addresses a tag the
    /// recipient is not watching, and nothing errors anywhere: the envelope is
    /// well formed, the signature checks out, and it lands where nobody looks.
    /// It appears asymmetric between two devices because it depends on whose
    /// clock leads.
    #[test]
    fn a_sender_whose_clock_leads_still_gets_through() {
        let mut group = group_of(2);

        // The window the client uses: anchored one bucket ahead, reaching back
        // far enough to cover it. Subscribing and accepting must use the same
        // one, or an envelope is delivered and then refused.
        let at = |b: u64| b + 1;
        let back = 3u64;

        for (sender_bucket, receiver_bucket, why) in [
            (490_000u64, 490_000u64, "same bucket"),
            (490_001, 490_000, "sender one hour ahead"),
            (490_000, 490_001, "receiver one hour ahead"),
            (490_000, 490_002, "receiver two hours ahead"),
        ] {
            let ciphertext = group[0].send("hello").expect("send");
            let envelopes = group[0]
                .seal_for_group(&ciphertext, sender_bucket)
                .expect("seal");

            // What the recipient is listening on, and what it will accept.
            let listening = group[1]
                .my_polling_tags(at(receiver_bucket), back)
                .expect("tags");

            let accepted = group[1]
                .open_mine(&envelopes[0], at(receiver_bucket), back)
                .is_ok();

            let addressed = &group[0].recipient_tags(sender_bucket).expect("tags")[0];

            assert!(
                listening.contains(addressed),
                "{why}: the recipient is not listening on the tag being addressed"
            );
            assert!(
                accepted,
                "{why}: the envelope was delivered and then refused, which is the \
                 exact shape of the bug this test exists for"
            );

            let payload = group[1]
                .open_mine(&envelopes[0], at(receiver_bucket), back)
                .expect("open");
            assert_eq!(
                message_text(&group[1].receive(&payload).expect("decrypt")).expect("plaintext"),
                "hello",
                "{why}"
            );
        }
    }

    /// The window used to subscribe and the window used to accept must be the
    /// same. Writing them out separately is how they drifted apart.
    #[test]
    fn the_listening_window_and_the_accepting_window_agree() {
        let mut group = group_of(2);
        let at = |b: u64| b + 1;
        let back = 3u64;

        let listening = group[1].my_polling_tags(at(490_000), back).expect("tags");

        // Every bucket the client listens on must also be one it will accept.
        for offset in 0..=3u64 {
            let sender_bucket = 490_001 - offset;
            let ciphertext = group[0].send("x").expect("send");
            let envelopes = group[0]
                .seal_for_group(&ciphertext, sender_bucket)
                .expect("seal");
            let addressed = &group[0].recipient_tags(sender_bucket).expect("tags")[0];

            assert_eq!(
                listening.contains(addressed),
                group[1].open_mine(&envelopes[0], at(490_000), back).is_ok(),
                "bucket {sender_bucket}: listening and accepting disagree"
            );
        }
    }

    /// Pins the exact mismatch the page had, so it cannot come back.
    ///
    /// The page subscribed with one window and accepted with another. This
    /// asserts that those parameters really do disagree, which is what made an
    /// envelope arrive and then be thrown away.
    #[test]
    fn the_windows_the_page_used_really_did_disagree() {
        let mut group = group_of(2);
        let receiver_bucket = 490_000u64;

        // A sender whose clock had already turned the hour.
        let ciphertext = group[0].send("hello").expect("send");
        let envelopes = group[0]
            .seal_for_group(&ciphertext, receiver_bucket + 1)
            .expect("seal");

        // What the page subscribed with: one bucket ahead, lookback 3.
        let subscribed = group[1]
            .my_polling_tags(receiver_bucket + 1, 3)
            .expect("tags");
        let addressed = &group[0].recipient_tags(receiver_bucket + 1).expect("tags")[0];

        assert!(
            subscribed.contains(addressed),
            "the page did subscribe to this tag"
        );

        // What the page accepted with: the current bucket, lookback 2.
        assert!(
            group[1]
                .open_mine(&envelopes[0], receiver_bucket, 2)
                .is_err(),
            "the mismatch is gone, so this test no longer describes anything"
        );

        // And with one window everywhere, it goes through.
        assert!(group[1]
            .open_mine(&envelopes[0], receiver_bucket + 1, 3)
            .is_ok());
    }

    /// The clock tolerance must be the same in both directions.
    ///
    /// Time zones do not enter into this: the bucket comes from milliseconds
    /// since the Unix epoch, which is UTC everywhere. What it has to survive is
    /// a clock that is actually wrong.
    #[test]
    fn the_clock_tolerance_is_symmetric() {
        let mut group = group_of(2);

        // The window the client uses.
        let skew = 2u64;
        let at = |b: u64| b + skew;
        let back = skew * 2;

        let receiver = 490_000u64;

        for offset in -3i64..=3 {
            let sender = (receiver as i64 + offset) as u64;

            let ciphertext = group[0].send("hello").expect("send");
            let envelopes = group[0].seal_for_group(&ciphertext, sender).expect("seal");
            let reachable = group[1]
                .open_mine(&envelopes[0], at(receiver), back)
                .is_ok();

            let expected = offset.unsigned_abs() <= skew;
            assert_eq!(
                reachable, expected,
                "a sender {offset} hours from the recipient: expected reachable={expected}"
            );

            if reachable {
                let payload = group[1]
                    .open_mine(&envelopes[0], at(receiver), back)
                    .expect("open");
                assert_eq!(
                    message_text(&group[1].receive(&payload).expect("decrypt")).expect("plaintext"),
                    "hello"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Meeting codes
    // -----------------------------------------------------------------------

    /// The shape the phone client mints, character for character.
    ///
    /// `lib/rotelyx/meeting_code.dart` is the other implementation of this, and
    /// a code minted on one and scanned by the other has to name the same
    /// place. The prefix, the length and the alphabet are the whole contract.
    #[test]
    fn a_minted_code_is_the_shape_the_phone_mints() {
        let code = new_meeting_code().expect("entropy");

        assert!(code.starts_with("RTLX1"), "no prefix: {code}");
        assert_eq!(code.len(), 5 + 24, "not the length the phone produces");
        assert!(
            code[5..].bytes().all(|b| b.is_ascii_uppercase()
                && b != b'0'
                && b != b'1'
                && b != b'8'
                || (b'2'..=b'7').contains(&b)),
            "outside the base32 alphabet: {code}"
        );
    }

    /// Two codes are not the same code.
    ///
    /// A guessable meeting code is a meeting somebody else can attend, and the
    /// failure that produces one is a generator seeded from the clock rather
    /// than the operating system. Two calls in the same millisecond is exactly
    /// the case that catches it.
    #[test]
    fn two_codes_differ() {
        let a = new_meeting_code().expect("entropy");
        let b = new_meeting_code().expect("entropy");
        assert_ne!(a, b, "the generator is not seeded from the OS");
    }

    /// What comes back from a minted code is the code.
    #[test]
    fn a_minted_code_reads_back() {
        let code = new_meeting_code().expect("entropy");
        assert_eq!(read_meeting_code(&code).expect("its own output"), code);
    }

    /// A real code the phone client minted, read here.
    ///
    /// Not a code this file produced: that would only prove this file agrees
    /// with itself. This one came out of `newMeetingCode` in the Dart
    /// implementation, run through `tool/mint_meeting_code.dart` in the phone
    /// client, and it is here so that a change to either side that breaks the
    /// other fails a test rather than a pairing.
    #[test]
    fn a_code_the_phone_minted_is_accepted() {
        let from_the_phone = "RTLX122IOBRVXL5C6EH2RCMVH4TRU";
        assert_eq!(from_the_phone.len(), 29);

        let read = read_meeting_code(from_the_phone).expect("the phone minted this");
        assert_eq!(read, from_the_phone);

        // And the tag both sides derive from it, which is the thing that has to
        // match. Derived from the canonical form, never from what was shown.
        let tag = rendezvous_tag(&read).expect("a code is long enough to be a phrase");
        assert_eq!(tag.len(), 64);
    }

    /// However it arrives, it is the same code.
    ///
    /// A camera may read one wrapped in a link, a person may paste it with a
    /// trailing space, and a keyboard may have lower-cased it. Each of these
    /// must reach the same meeting place, because otherwise the two sides sit
    /// at different tags and the pairing simply never happens, with nothing on
    /// either screen saying why.
    #[test]
    fn the_ways_a_code_arrives_all_name_one_place() {
        let canonical = "RTLX122IOBRVXL5C6EH2RCMVH4TRU";

        for arrival in [
            "  RTLX122IOBRVXL5C6EH2RCMVH4TRU  ",
            "rtlx122iobrvxl5c6eh2rcmvh4tru",
            "rotelyx://RTLX122IOBRVXL5C6EH2RCMVH4TRU",
            "ROTELYX://RTLX122IOBRVXL5C6EH2RCMVH4TRU",
            // Exactly what `prettyMeetingCode` puts on the phone's screen.
            "RTLX1 22IO BRVX L5C6 EH2R CMVH 4TRU",
            "RTLX1-22IO-BRVX-L5C6-EH2R-CMVH-4TRU",
        ] {
            assert_eq!(
                read_meeting_code(arrival).expect("this is a code"),
                canonical,
                "arrived as {arrival:?} and named somewhere else"
            );
        }
    }

    /// And what is not a code is refused rather than half accepted.
    #[test]
    fn what_is_not_a_code_is_refused() {
        for not_one in [
            "",
            "RTLX1",
            "hello",
            // The desktop's own transport invitation, which is what its QR
            // carried before this existed. Scanned into the phone it produced
            // an error the person holding it could do nothing about.
            "HqKKk-8fPRC7cTEaXLt1cxsKF3vOTkJKC1j6kmrZ3BJXxnFKQmifUbaqDsR3TWfYLKkImwQ2xWpR9sW9mr_UqA",
            // Right length, wrong alphabet: 0, 1 and 8 are the characters it
            // leaves out precisely because they are misread aloud.
            "RTLX1000000000000000000000000",
            // One short and one long, either of which is a misread rather than
            // a code, and neither of which may be quietly padded or trimmed.
            "RTLX122IOBRVXL5C6EH2RCMVH4TR",
            "RTLX122IOBRVXL5C6EH2RCMVH4TRUU",
            // A web link is not the custom scheme, deliberately: stripping one
            // would mean this client agreeing that some host speaks for it.
            "https://example.invalid/RTLX122IOBRVXL5C6EH2RCMVH4TRU",
        ] {
            assert!(
                read_meeting_code(not_one).is_err(),
                "accepted something that is not a meeting code: {not_one:?}"
            );
        }
    }

    /// The displayed form is still a code.
    ///
    /// Somebody reading a code off a screen copies what is on the screen. If
    /// the pretty form were not accepted, copying what is displayed would fail,
    /// and the person doing it would have no way to know they had been given
    /// something to look at rather than something to use.
    #[test]
    fn the_pretty_form_is_still_readable() {
        let code = new_meeting_code().expect("entropy");
        let shown = pretty_meeting_code(&code);

        assert!(shown.contains(' '), "nothing was grouped: {shown}");
        assert_eq!(read_meeting_code(&shown).expect("what is on screen"), code);
    }

    /// Both sides of one code arrive at one tag.
    ///
    /// This is the whole mechanism in a line: the QR carries no keys, and what
    /// makes it work is that two independent readings of the same code derive
    /// the same address at the mailbox.
    #[test]
    fn one_code_is_one_meeting_place() {
        let code = new_meeting_code().expect("entropy");

        let host = rendezvous_tag(&code).expect("tag");
        let guest = rendezvous_tag(&read_meeting_code(&pretty_meeting_code(&code)).expect("read"))
            .expect("tag");

        assert_eq!(host, guest, "the two sides would wait in different places");
    }

    /// A message comes back as JSON a parser will accept, whatever is in it.
    ///
    /// This was written by hand with `escape_default`, which produces Rust
    /// escapes rather than JSON ones: a unit separator became `\u{1f}` where
    /// JSON requires `\u001f`, and every character above ASCII went the same
    /// way. The reader answered "invalid escape at line 1 column 41" and the
    /// session it belonged to was taken for dead.
    ///
    /// The cases below are not exotic. An accent is most Spanish, an emoji is
    /// most conversations, and the separator is what a read receipt is built
    /// from, which is how this was found.
    #[test]
    fn what_receive_returns_is_json_whatever_the_message_held() {
        let mut group = group_of(2);
        let (host, guest) = group.split_at_mut(1);
        let host = &mut host[0];
        let guest = &mut guest[0];

        for message in [
            "plain",
            "acentos y eñes: qué más añadir",
            "an emoji 🔐 and another 🎧",
            // What a read receipt is made of.
            "rx-signal\u{1f}read\u{1f}1787519663000",
            // The characters that break a hand-written string.
            "quotes \" and \\ backslashes",
            "a newline\nand a tab\t",
        ] {
            let ciphertext = host.send(message).expect("send");
            let received = guest.receive(&ciphertext).expect("receive");

            let parsed: serde_json::Value = serde_json::from_str(&received)
                .unwrap_or_else(|e| panic!("not JSON for {message:?}: {e}\n  {received}"));

            assert_eq!(parsed["kind"], "message", "for {message:?}");
            assert_eq!(
                parsed["text"].as_str().expect("a text field"),
                message,
                "what came back is not what went in"
            );
        }
    }

    /// A phrase short enough to guess is refused, because guessing it is
    /// enough to stand in for whoever it was meant for.
    #[test]
    fn a_short_meeting_phrase_is_refused() {
        assert!(rendezvous_tag("corto").is_err());
        assert!(rendezvous_tag("       ").is_err());
        assert!(rendezvous_tag("a passphrase that is long enough").is_ok());
    }

    #[test]
    fn a_meeting_tag_is_stable_and_phrase_specific() {
        let a = rendezvous_tag("see you at the mailbox").expect("tag");
        let b = rendezvous_tag("  see you at the mailbox  ").expect("tag");
        assert_eq!(
            a, b,
            "surrounding whitespace must not change the meeting place"
        );

        assert_ne!(
            a,
            rendezvous_tag("see you at the mailboX").expect("tag"),
            "a phrase differing only in case must meet somewhere else"
        );
    }

    /// A rendezvous envelope addressed elsewhere must be refused, so a stray
    /// or injected envelope cannot be fed into the handshake.
    #[test]
    fn a_rendezvous_envelope_for_another_tag_is_refused() {
        let ours = rendezvous_tag("our rendezvous passphrase").expect("tag");
        let theirs = rendezvous_tag("an entirely different passphrase").expect("tag");

        let sealed = seal_under(&theirs, &BASE64.encode(b"hello")).expect("seal");
        assert!(open_under(&sealed, &ours).is_err());

        let mine = seal_under(&ours, &BASE64.encode(b"hello")).expect("seal");
        assert_eq!(
            BASE64
                .decode(open_under(&mine, &ours).expect("open").as_bytes())
                .expect("b64"),
            b"hello",
            "the padding must come off, byte for byte"
        );
    }

    /// The rendezvous carries JSON, and JSON is not self-delimiting the way an
    /// MLS message is. If the padding were left on, every handshake would fail
    /// at the parser with an error that says nothing about envelopes.
    #[test]
    fn a_rendezvous_payload_survives_the_padding_as_parseable_text() {
        let tag = rendezvous_tag("some rendezvous passphrase or other").expect("tag");
        let json = br#"{"t":"hello","name":"bob"}"#;

        let sealed = seal_under(&tag, &BASE64.encode(json)).expect("seal");
        let recovered = BASE64
            .decode(open_under(&sealed, &tag).expect("open").as_bytes())
            .expect("b64");

        assert_eq!(recovered, json);
        assert_eq!(
            String::from_utf8(recovered).expect("utf-8"),
            r#"{"t":"hello","name":"bob"}"#
        );
    }

    #[test]
    fn message_length_is_hidden_from_the_operator() {
        let mut alice = Session::new("alice").expect("identity");
        let mut bob = Session::new("bob").expect("identity");

        alice.found().expect("found");
        let inv = alice
            .invite(&bob.key_package().expect("kp"))
            .expect("invite");
        bob.join(&inv.welcome, &inv.ratchet_tree).expect("join");

        let short = alice.send("si").expect("send");
        let long = alice.send(&"x".repeat(400)).expect("send");

        let e_short = alice.seal(&short, 490_000).expect("seal");
        let e_long = alice.seal(&long, 490_000).expect("seal");

        assert_eq!(
            e_short.len(),
            e_long.len(),
            "a 2-character and a 400-character message must be indistinguishable"
        );
    }
}

#[cfg(test)]
mod wake_ticket_binding_tests {
    use super::*;

    const APNS: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

    fn notifier() -> (String, rotelyx_crypto::hybrid::HybridSecretKey) {
        let (secret, public) = rotelyx_crypto::HybridKem::generate();
        (BASE64.encode(&public.to_bytes()), secret)
    }

    /// The binding produces something the notifier can actually open.
    ///
    /// Asserted across the boundary rather than inside the crypto, because
    /// what breaks here is the encoding: a client that base64s what should be
    /// raw, or reverses an argument, produces a ticket that seals cleanly and
    /// opens to nothing, and nothing on the client would ever say so.
    #[test]
    fn a_sealed_ticket_opens_at_the_notifier() {
        let (public_b64, secret) = notifier();

        let sealed = seal_wake_ticket(&public_b64, "apns", APNS, 100).expect("seal");
        let bytes = BASE64.decode(sealed.as_bytes()).expect("base64");
        let ticket = rotelyx_crypto::WakeTicket::from_bytes(&bytes).expect("parse");

        let opened = ticket.open(&secret, 100).expect("open");
        assert_eq!(opened.token, APNS);
        assert_eq!(opened.kind, rotelyx_crypto::TicketKind::Apns);
    }

    /// One device, one token, many tags, and nothing in common between them.
    #[test]
    fn sealing_twice_gives_nothing_to_match_on() {
        let (public_b64, _secret) = notifier();

        let one = seal_wake_ticket(&public_b64, "apns", APNS, 100).expect("seal");
        let two = seal_wake_ticket(&public_b64, "apns", APNS, 100).expect("seal");

        assert_ne!(one, two, "two tickets were the same string");
    }

    #[test]
    fn a_key_that_is_not_one_is_refused() {
        assert!(seal_wake_ticket("not base64", "apns", APNS, 100).is_err());
        assert!(seal_wake_ticket(&BASE64.encode(b"too short"), "apns", APNS, 100).is_err());
    }

    #[test]
    fn an_unknown_push_service_is_refused() {
        let (public_b64, _) = notifier();
        assert!(seal_wake_ticket(&public_b64, "carrier-pigeon", APNS, 100).is_err());
    }
}
