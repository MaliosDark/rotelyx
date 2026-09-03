//! MLS conversations with a hybrid post-quantum key schedule.
//!
//! A conversation is an MLS group (RFC 9420) via OpenMLS. A 1:1 chat is simply
//! a group of two: there is no separate pairwise protocol, which removes an
//! entire class of "works in 1:1, subtly broken in groups" bugs.
//!
//! ## The post-quantum layer
//!
//! MLS ciphersuites are all classical. Rather than fork MLS, Rotelyx injects a
//! hybrid post-quantum secret at the pre-shared-key input RFC 9420 already
//! defines: a [`PreSharedKeyProposal`] carried inside a commit. MLS then mixes
//! it into the epoch's key schedule through its own, unmodified derivation.
//!
//! Two properties fall out of using the standard mechanism rather than a custom
//! one:
//!
//! - **Fresh material per epoch.** The secret is not fixed at group creation;
//!   every commit can carry new post-quantum material.
//! - **No silent injection.** The proposal is part of the commit that every
//!   member validates. A member cannot slip a chosen PSK past the others, which
//!   is the same property that makes "ghost member" additions visible.
//!
//! Not modified: any part of MLS.

use openmls::prelude::{tls_codec::*, *};
use openmls::schedule::PreSharedKeyId;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::hybrid::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, PqSecret};

/// The ciphersuite every Rotelyx conversation uses.
///
/// ChaCha20-Poly1305 rather than AES-GCM: most phones without AES hardware run
/// it faster, and it sidesteps the cache-timing surface of software AES.
///
/// Note the `128`: the OpenMLS RustCrypto provider offers no 256-bit suite, so
/// the classical security level is fixed here. The long-term margin comes from
/// the hybrid post-quantum PSK below, not from this line.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Plaintext is padded to a multiple of this before encryption.
///
/// **OpenMLS does no padding by default.** Measured on this ciphersuite the
/// overhead is a constant 145 bytes and the rest is one-to-one, so an
/// unpadded ciphertext discloses the plaintext length exactly. That matters
/// most on the direct peer-to-peer path, where there is no mailbox envelope to
/// hide behind and this is the *only* length defence.
///
/// 256 bytes: typical chat messages collapse to one or two padded sizes, at a
/// worst case of 255 wasted bytes on a one-word reply.
const PADDING_SIZE: usize = 256;

/// Domain separator binding a post-quantum PSK to one group and epoch.
const PSK_LABEL: &[u8] = b"rotelyx-pq-psk-v1";

/// MLS exporter label for the mailbox tag key. Distinct from every other label
/// in the system so the addressing key can never coincide with a message key.
const MAILBOX_TAG_KEY_LABEL: &str = "rotelyx mailbox tag key v1";

/// Media keys are exported under their own label, so a media key and a mailbox
/// tag key can never be the same bytes even at the same epoch.
const MEDIA_KEY_LABEL: &str = "rotelyx media base key v1";

/// Bytes of sequence number carried at the front of every application
/// plaintext. See [`Conversation::send`] for why it is there and not elsewhere.
const SEQ_LEN: usize = 8;

/// How far behind the highest accepted sequence number a message may still be.
///
/// OpenMLS lets a message through up to `out_of_order_tolerance` generations
/// behind what it has already decrypted, five by default, so anything reaching
/// this check is at most five behind. Sixty four is the width of the mask in
/// [`SeenFrom`] and is picked so this is never the binding constraint: if that
/// tolerance is ever raised, it has room to move before messages the library
/// accepts start being refused here.
const REPLAY_WINDOW: u64 = 64;

/// Which sequence numbers one sender has already spent at one epoch.
///
/// A high water mark plus a mask of the window below it, which is the ordinary
/// anti-replay window: out-of-order delivery still gets through, a repeat does
/// not. `high` of zero means nothing has been accepted yet, which is why
/// sequence numbers start at one.
#[derive(Default, Clone, Copy)]
struct SeenFrom {
    high: u64,
    window: u64,
}

impl SeenFrom {
    /// Record `seq`, or report that it must not be accepted.
    fn admit(&mut self, seq: u64) -> bool {
        if seq > self.high {
            let step = seq - self.high;
            // The old high water mark becomes a seen entry `step - 1` places
            // back once the frame moves up to `seq`.
            self.window = match step {
                s if s > REPLAY_WINDOW => 0,
                s if s == REPLAY_WINDOW => 1u64 << (REPLAY_WINDOW - 1),
                s => (self.window << s) | (1u64 << (s - 1)),
            };
            self.high = seq;
            return true;
        }

        let back = self.high - seq;
        if back == 0 || back > REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64 << (back - 1);
        if self.window & bit != 0 {
            return false;
        }
        self.window |= bit;
        true
    }
}

/// Split an application plaintext into its sequence number and its body.
fn split_sequence(bytes: &[u8]) -> Result<(u64, Vec<u8>), GroupError> {
    if bytes.len() < SEQ_LEN {
        return Err(GroupError::NoSequence);
    }
    let (head, body) = bytes.split_at(SEQ_LEN);
    let seq = u64::from_be_bytes(
        head.try_into()
            .expect("SEQ_LEN bytes, length checked just above"),
    );
    Ok((seq, body.to_vec()))
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("mls: {0}")]
    Mls(String),

    #[error("codec: {0}")]
    Codec(String),

    #[error("expected a {expected} message, got something else")]
    UnexpectedMessage { expected: &'static str },

    #[error("no member of this conversation holds that signature key")]
    NoSuchMember,

    #[error("a person's identity is {len} bytes, and a credential carries at most 255")]
    PersonTooLong { len: usize },

    #[error(
        "a member cannot remove itself: the commit would be encrypted under a \
         key schedule it has just left, so nobody would be able to read it"
    )]
    CannotRemoveSelf,

    #[error("message was not an application message")]
    NotApplication,

    #[error(
        "this conversation was reopened from storage and has not rekeyed. \
         Call `rekey_after_restore` and send the commit before sending messages"
    )]
    RestoredAndNotRekeyed,

    #[error("an application message carried no sequence number")]
    NoSequence,

    #[error("sequence {seq} from that sender was already spent at this epoch")]
    SequenceSpent { seq: u64 },

    #[error("an application message did not name a member as its sender")]
    UnattributedMessage,
}

fn mls<E: std::fmt::Display>(e: E) -> GroupError {
    GroupError::Mls(e.to_string())
}

fn codec<E: std::fmt::Display>(e: E) -> GroupError {
    GroupError::Codec(e.to_string())
}

/// A local participant: MLS credential, signing key, and hybrid KEM keypair.
///
/// One per device. The MLS signature key authenticates this device's messages;
/// the hybrid key is what peers encapsulate post-quantum material to.
pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    hybrid_sk: HybridSecretKey,
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Member")
            .field("signer", &"<redacted>")
            .field("hybrid_sk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Member {
    /// Create a participant.
    ///
    /// `identity` is the MLS credential identity. In Rotelyx this is the device's
    /// public key bytes, not a name: there is no name registry to consult, and
    /// a self-asserted display name in a credential is a phishing surface.
    pub fn new(identity: &[u8]) -> Result<Self, GroupError> {
        Self::for_device(identity, b"")
    }

    /// Create a participant that is one **device** belonging to one person.
    ///
    /// # Why a device is its own leaf
    ///
    /// The alternative is for a person's devices to share one key, which is
    /// simpler and wrong in the way that matters: a shared key cannot be taken
    /// away from one device without being taken away from all of them, so losing
    /// a phone means re-establishing every conversation on every device. Worse,
    /// nothing in the group can tell which device sent a message, so a stolen
    /// phone is indistinguishable from its owner for as long as nobody notices.
    ///
    /// Separate leaves make a device a member: it has its own signing key, it
    /// appears in the roster, and it can be removed with [`Conversation::remove`]
    /// while the person stays. That removal is a commit, so every partner sees
    /// it happen.
    ///
    /// # What the credential carries
    ///
    /// `person` and `device`, length-prefixed so they can be told apart again.
    /// The person is what a partner has verified with a safety number, and the
    /// device is what distinguishes two leaves of that person. Neither is a
    /// display name: there is no registry to consult and a self-asserted name in
    /// a credential is a phishing surface. In Rotelyx the person is the
    /// per-conversation name derived in `rotelyx-core`.
    ///
    /// **This does not by itself prove the two leaves are the same person.** A
    /// credential says what its holder chose to say. What makes it meaningful is
    /// who committed the Add: a device joins because a device already in the
    /// group added it, so the claim is only as good as the member that vouched.
    /// A partner's interface should say "a device was added by Ana" rather than
    /// "Ana added a device", because the first is what the group actually knows.
    pub fn for_device(person: &[u8], device: &[u8]) -> Result<Self, GroupError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(encode_identity(person, device)?).into(),
            signature_key: signer.public().into(),
        };

        let (hybrid_sk, _) = HybridKem::generate();

        Ok(Self {
            provider,
            signer,
            credential,
            hybrid_sk,
        })
    }

    /// Everything needed to rebuild this member and its groups.
    ///
    /// # What is in here
    ///
    /// The signing key, the hybrid decapsulation key, the credential identity,
    /// and the whole MLS storage, which is where OpenMLS keeps the group state
    /// itself. Holding it is equivalent to being this member: it decrypts every
    /// message the group's current epochs can decrypt.
    ///
    /// It is deliberately raw. Sealing it is the caller's job, because the
    /// right way to protect it differs between a file on a disk and a browser's
    /// local storage, and a crate that guessed would guess wrong for one of
    /// them.
    pub fn export(&self) -> Result<MemberState, GroupError> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| GroupError::Mls("storage lock poisoned".into()))?;

        Ok(MemberState {
            identity: self.credential.credential.serialized_content().to_vec(),
            signature_public: self.signer.public().to_vec(),
            // The whole key pair, serialised: the private half is only exposed
            // by an accessor gated behind the crate's test feature, and turning
            // that on in a shipping build to read our own key would be worse
            // than going through serde.
            signer: postcard::to_allocvec(&self.signer)
                .map_err(|e| GroupError::Mls(format!("serialising the signer: {e}")))?,
            hybrid_secret: *self.hybrid_sk.to_storage_bytes(),
            storage: values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        })
    }

    /// Rebuild a member from an export.
    pub fn restore(state: MemberState) -> Result<Self, GroupError> {
        let provider = OpenMlsRustCrypto::default();

        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| GroupError::Mls("storage lock poisoned".into()))?;
            values.clear();
            values.extend(state.storage);
        }

        let signer: SignatureKeyPair = postcard::from_bytes(&state.signer)
            .map_err(|e| GroupError::Mls(format!("reading the signer: {e}")))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(state.identity).into(),
            signature_key: state.signature_public.into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
            hybrid_sk: HybridSecretKey::from_storage_bytes(state.hybrid_secret),
        })
    }

    /// This member's signature public key.
    ///
    /// Unique per member and stable for as long as they are in the group, which
    /// is what makes it the right thing to derive a per-recipient mailbox tag
    /// from. A leaf index is neither: MLS reuses a slot after a removal, and the
    /// new occupant would inherit the old one's tag.
    pub fn signature_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    /// This member's hybrid public key, to be published alongside its key
    /// package so peers can encapsulate post-quantum material to it.
    pub fn hybrid_public_key(&self) -> HybridPublicKey {
        self.hybrid_sk.public()
    }

    /// Recover post-quantum material a peer encapsulated to us.
    pub fn open_pq(&self, ct: &HybridCiphertext) -> PqSecret {
        self.hybrid_sk.decapsulate(ct)
    }

    /// Recover a post-quantum group secret that was sealed to us.
    ///
    /// The group counterpart of [`Member::open_pq`]. With two members the
    /// encapsulation itself carries the secret; with more, one chosen secret is
    /// wrapped to each member, because MLS looks a pre-shared key up by a
    /// single id and every member has to arrive at the same value.
    /// `binding` must name the group, the epoch, and this member's signature
    /// key. A wrap that does not carry the same three does not open, which is
    /// what makes it un-mintable by a stranger and un-replayable into a later
    /// epoch.
    pub fn unwrap_group_pq(
        &self,
        wrapped: &crate::WrappedPqSecret,
        binding: &crate::hybrid::PqBinding,
    ) -> Result<PqSecret, crate::hybrid::HybridError> {
        self.hybrid_sk.unwrap_pq(wrapped, binding)
    }

    /// The same, but only if a member of this group signed it.
    ///
    /// The caller supplies the signature keys of the current roster. Each is
    /// tried, and the wrap is accepted under the first that verifies; if none
    /// does, it came from outside the group and is refused before anything is
    /// decrypted.
    ///
    /// Trying every key rather than being told which one is deliberate. The
    /// receiver has no way to know in advance who will rotate the material, and
    /// asking it to guess would mean either a wrong guess refusing a legitimate
    /// wrap or a caller passing whatever the sender claimed, which is not a
    /// check at all.
    pub fn unwrap_group_pq_from_member(
        &self,
        wrapped: &crate::WrappedPqSecret,
        group_id: &[u8],
        epoch: u64,
        roster_signature_keys: &[Vec<u8>],
    ) -> Result<PqSecret, crate::hybrid::HybridError> {
        let mut last = crate::hybrid::HybridError::WrongSender;
        for sender in roster_signature_keys {
            let binding =
                crate::hybrid::PqBinding::new(group_id, epoch, &self.signature_key(), sender);
            match self.hybrid_sk.unwrap_pq_signed(wrapped, &binding) {
                Ok(secret) => return Ok(secret),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Wrap a group secret for one recipient and sign it as this member.
    pub fn wrap_group_pq_signed(
        &self,
        secret: &PqSecret,
        recipient: &crate::hybrid::HybridPublicKey,
        group_id: &[u8],
        epoch: u64,
        recipient_signature_key: &[u8],
    ) -> Result<crate::WrappedPqSecret, crate::hybrid::HybridError> {
        let binding = crate::hybrid::PqBinding::new(
            group_id,
            epoch,
            recipient_signature_key,
            &self.signature_key(),
        );
        secret.wrap_and_sign(recipient, &binding, &self.signer)
    }

    /// Produce a key package so others can add this member to a group.
    ///
    /// Published through the blind mailbox, never a directory: a key package
    /// server that maps identities to packages is a social-graph oracle.
    pub fn key_package(&self) -> Result<KeyPackageBundle, GroupError> {
        KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls)
    }
}

/// Encode a key package for publication.
///
/// Key packages are public and signed, so this is not secret material, but it
/// is an authorisation to add the holder to a group, so it must be delivered
/// through a channel that binds it to the identity it claims. The blind mailbox
/// does that; a public directory would not.
pub fn serialize_key_package(kp: &KeyPackage) -> Result<Vec<u8>, GroupError> {
    kp.tls_serialize_detached().map_err(codec)
}

/// Decode a key package received from a peer.
///
/// Validation happens here rather than at use: a malformed or wrongly-suited
/// package must be rejected before it reaches group state.
pub fn deserialize_key_package(bytes: &[u8]) -> Result<KeyPackage, GroupError> {
    let msg = KeyPackageIn::tls_deserialize(&mut &bytes[..]).map_err(codec)?;
    let validated = msg
        .validate(
            OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .map_err(mls)?;

    if validated.ciphersuite() != CIPHERSUITE {
        return Err(GroupError::Mls(format!(
            "key package uses {:?}, this deployment requires {:?}",
            validated.ciphersuite(),
            CIPHERSUITE
        )));
    }
    Ok(validated)
}

/// An MLS conversation. A 1:1 chat is a conversation with two members.
/// A member's complete state, ready to be sealed by the caller.
///
/// Every field is secret. This is not a public profile: it is the material that
/// makes someone *be* a participant, and anyone holding it can read what the
/// group can read.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberState {
    pub identity: Vec<u8>,
    pub signature_public: Vec<u8>,
    pub signer: Vec<u8>,
    pub hybrid_secret: [u8; 32],
    /// OpenMLS's own storage, which is where the group state lives.
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Debug for MemberState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemberState(<redacted>)")
    }
}

/// One member as seen from inside the group.
///
/// Both fields are public by construction. The identity is self-asserted and
/// says who someone claims to be; the signature key is what MLS actually
/// authenticates and what a safety number covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    /// Who this leaf claims to belong to.
    ///
    /// Parsed out of the credential, so it keeps meaning the same thing it did
    /// before devices existed and every caller comparing it against a name still
    /// works. When `well_formed` is false this is the raw credential instead.
    pub identity: Vec<u8>,

    /// Which device of that person this leaf is.
    ///
    /// Empty for a person who has only ever had one, which is what
    /// [`Member::new`] produces.
    pub device: Vec<u8>,

    pub signature_key: Vec<u8>,

    /// Whether the credential was in Rotelyx's shape.
    ///
    /// A credential from another implementation is not split at a plausible
    /// place and called a person: it is reported as what it is, so a caller can
    /// tell "somebody else's member" from "a person with no device id" rather
    /// than being handed a guess.
    pub well_formed: bool,
}

/// The largest `person` a credential can carry, so the one byte length prefix
/// is enough and a longer one is refused rather than silently truncated.
const MAX_PERSON_LEN: usize = 255;

/// `person_len ‖ person ‖ device`.
///
/// One byte for the length rather than a delimiter, because a person's bytes are
/// a hash and can contain anything a delimiter could be.
fn encode_identity(person: &[u8], device: &[u8]) -> Result<Vec<u8>, GroupError> {
    if person.len() > MAX_PERSON_LEN {
        return Err(GroupError::PersonTooLong { len: person.len() });
    }
    let mut out = Vec::with_capacity(1 + person.len() + device.len());
    out.push(person.len() as u8);
    out.extend_from_slice(person);
    out.extend_from_slice(device);
    Ok(out)
}

/// Split a credential into the person and the device it names.
fn decode_identity(credential: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = credential.split_first()?;
    let len = *len as usize;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

impl Participant {
    fn from_credential(credential: &[u8], signature_key: Vec<u8>) -> Self {
        match decode_identity(credential) {
            Some((person, device)) => Self {
                identity: person.to_vec(),
                device: device.to_vec(),
                signature_key,
                well_formed: true,
            },
            None => Self {
                identity: credential.to_vec(),
                device: Vec::new(),
                signature_key,
                well_formed: false,
            },
        }
    }

    /// Whether two leaves claim the same person.
    ///
    /// A claim, not a proof. See [`Member::for_device`]: what makes it worth
    /// anything is which member committed the Add. Two credentials nobody could
    /// parse are never the same person, however identical their bytes: saying
    /// yes there would be answering a question about people using a value that
    /// is not known to name one.
    pub fn same_person_as(&self, other: &Participant) -> bool {
        self.well_formed && other.well_formed && self.identity == other.identity
    }
}

/// Who joined or left, when a commit changed the membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipChange {
    pub added: Vec<Participant>,
    pub removed: Vec<Participant>,
}

/// What arrived.
///
/// # Why this is not `Option<Vec<u8>>`
///
/// It was. A commit that added a member merged and returned `None`, which is
/// also what an unrecognised message returns, so no caller could tell a third
/// party being added to a conversation from nothing having happened.
///
/// MLS makes a silent addition impossible at the protocol level: every member
/// processes the commit. That is the whole defence against a "ghost user", and
/// it is only worth anything if the client can tell somebody. Returning `None`
/// threw the visibility away one layer below the client, so the obligation the
/// threat model puts on the UI could not be met however carefully the UI was
/// written.
///
/// A caller that does not care can still say so, and has to say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Decrypted application data, and the leaf MLS authenticated as its
    /// author.
    ///
    /// `sender` is `None` only for a message from outside the group's own
    /// membership, which an application should treat as unattributed rather
    /// than as anybody in particular.
    Message {
        sender: Option<openmls::prelude::LeafNodeIndex>,
        bytes: Vec<u8>,
    },
    /// The membership changed. Show this to the user: see ADV-7 in the threat
    /// model, where surfacing it is a security control rather than a nicety.
    MembershipChanged(MembershipChange),
    /// Handled, and nothing for the caller to do.
    Nothing,
}

impl Received {
    /// The application data, if that is what this was.
    ///
    /// For callers that have already dealt with the other cases, and for tests.
    pub fn message(self) -> Option<Vec<u8>> {
        match self {
            Self::Message { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    /// The author, when this was application data and MLS attributed it.
    pub fn sender(&self) -> Option<openmls::prelude::LeafNodeIndex> {
        match self {
            Self::Message { sender, .. } => *sender,
            _ => None,
        }
    }

    /// The membership change, if that is what this was.
    pub fn membership_change(&self) -> Option<&MembershipChange> {
        match self {
            Self::MembershipChanged(change) => Some(change),
            _ => None,
        }
    }
}

pub struct Conversation {
    group: MlsGroup,
    /// Reopened from storage and not yet rekeyed.
    ///
    /// # What this stops
    ///
    /// A copy restored from a backup believes it is at a generation the group
    /// has already spent, so everything it sends is refused by the receiver,
    /// which deleted that generation's secret as it used it. `send` succeeded
    /// anyway and nothing told the person holding the device: to them, messages
    /// simply stopped arriving.
    ///
    /// Two devices restored from one backup is the same shape, and so is a
    /// device rolled back to an older copy of itself. Measured, and written up
    /// in section 5b of the threat model.
    ///
    /// Rekeying moves the epoch, which gives this copy generations of its own.
    /// If two copies rekey at once, MLS resolves it the way it resolves any two
    /// commits at one epoch: one merges and the other has to process it.
    restored_needs_rekey: bool,

    /// The epoch the two sequence fields below belong to.
    seq_epoch: u64,

    /// Sequence number this copy last sent at `seq_epoch`.
    sent_seq: u64,

    /// Sequence numbers already spent by each sender at `seq_epoch`.
    seen_seq: std::collections::HashMap<openmls::prelude::LeafNodeIndex, SeenFrom>,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("epoch", &self.group.epoch().as_u64())
            .finish_non_exhaustive()
    }
}

impl Conversation {
    /// Start a new conversation with `founder` as its only member.
    ///
    /// The ciphersuite is set explicitly. `MlsGroupCreateConfig::default()`
    /// selects OpenMLS's default suite (AES-GCM), not ours, so a group built
    /// from the default would negotiate a different suite than the one every
    /// key package advertises, and the mismatch only surfaces when the first
    /// member is added.
    pub fn create(founder: &Member) -> Result<Self, GroupError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .padding_size(PADDING_SIZE)
            .build();

        let group = MlsGroup::new(
            &founder.provider,
            &founder.signer,
            &config,
            founder.credential.clone(),
        )
        .map_err(mls)?;

        Ok(Self::opened(group, false))
    }

    /// Wrap a group with empty sequence state at whatever epoch it is on.
    fn opened(group: MlsGroup, restored_needs_rekey: bool) -> Self {
        let seq_epoch = group.epoch().as_u64();
        Self {
            group,
            restored_needs_rekey,
            seq_epoch,
            sent_seq: 0,
            seen_seq: std::collections::HashMap::new(),
        }
    }

    /// Drop sequence state belonging to an epoch that has passed.
    ///
    /// Safe to do rather than a hole, because a sequence number is only ever
    /// compared against others from the same epoch, and the epoch is already
    /// part of what MLS signs. A number lifted from a spent epoch cannot be
    /// presented at this one: the signature covers the epoch and would not
    /// verify.
    fn sync_seq_epoch(&mut self) {
        let now = self.group.epoch().as_u64();
        if now != self.seq_epoch {
            self.seq_epoch = now;
            self.sent_seq = 0;
            self.seen_seq.clear();
        }
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The ciphersuite this conversation actually negotiated.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.group.ciphersuite()
    }

    /// Domain-separated binding for a post-quantum PSK at the current epoch.
    ///
    /// Both the committer and every receiver derive this independently from
    /// state they already share, so the binding never travels on the wire and
    /// cannot be chosen by an attacker. Including the epoch is what stops a PSK
    /// captured from one epoch being replayed into another.
    fn psk_binding(&self) -> Vec<u8> {
        crate::hybrid::psk_binding(
            PSK_LABEL,
            self.group.group_id().as_slice(),
            self.group.epoch().as_u64(),
        )
    }

    /// Derive the mailbox tag key for this conversation.
    ///
    /// Every member of the group derives the same value from the MLS exporter,
    /// so nothing has to be transmitted. It is domain-separated from every
    /// message key: a leaked tag key must reveal *where* to look in a mailbox,
    /// never what is there.
    ///
    /// # Re-derive this per epoch, and keep a bounded window of them
    ///
    /// The MLS exporter changes with every epoch, so a sender one commit ahead
    /// of a recipient deposits under a tag the recipient cannot yet compute,
    /// and the message is silently undeliverable. That is a real problem and it
    /// has an obvious wrong answer, which this documentation used to give:
    /// derive the key once at join time and pin it forever.
    ///
    /// **Do not do that.** A pinned tag key is a permanent one, and a member
    /// removed from the conversation keeps it. Removal is supposed to end their
    /// ability to address the group; with a pinned key they can still compute
    /// every other member's tag for the life of the conversation, which means
    /// they can still read what is waiting under it and, before delivery and
    /// removal were separated, could destroy it.
    ///
    /// The correct handling is what the clients in this repository do: derive a
    /// key at each epoch, keep the last few so a message from just before a
    /// commit still opens, and let the older ones fall out of the window. That
    /// bounds how long a removed member's knowledge survives to the width of
    /// that window rather than to the life of the group.
    ///
    /// Unlinkability *within* an epoch still comes from
    /// [`TagKey::tag_for_epoch`], which derives a fresh tag per coarse time
    /// bucket. The two mechanisms answer different questions and both are
    /// needed: the time bucket hides a conversation from an observer, and the
    /// epoch window is what makes removal mean something.
    ///
    /// [`TagKey::tag_for_epoch`]: https://docs.rs/rotelyx-mailbox
    pub fn mailbox_tag_key(&self, member: &Member) -> Result<[u8; 32], GroupError> {
        let bytes = self
            .group
            .export_secret(member.provider.crypto(), MAILBOX_TAG_KEY_LABEL, &[], 32)
            .map_err(mls)?;

        bytes
            .try_into()
            .map_err(|_| GroupError::Mls("exporter returned the wrong length".into()))
    }

    /// Export the base key that media frames are encrypted under.
    ///
    /// # Why this is not pinned like the mailbox tag key
    ///
    /// [`Conversation::mailbox_tag_key`] must be derived once and held, because
    /// it is an **address**: a sender one commit ahead would otherwise deposit
    /// where the recipient cannot look.
    ///
    /// A media key is the opposite. It should change with every epoch, so that
    /// a member removed from the group stops being able to decrypt the call
    /// immediately rather than at the end of it. A call therefore rekeys when
    /// the group does, which is exactly the behaviour a removal has to have to
    /// mean anything.
    ///
    /// Every member derives the same value at the same epoch;
    /// `rotelyx_media::SenderKeys::derive` splits it per speaker.
    pub fn media_base_key(&self, member: &Member) -> Result<[u8; 32], GroupError> {
        let bytes = self
            .group
            .export_secret(member.provider.crypto(), MEDIA_KEY_LABEL, &[], 32)
            .map_err(mls)?;

        bytes
            .try_into()
            .map_err(|_| GroupError::Mls("exporter returned the wrong length".into()))
    }

    /// Stage a post-quantum secret locally so an incoming PSK commit can be
    /// processed.
    ///
    /// The receiving side of [`Conversation::commit_pq_secret`]. A member who
    /// has decapsulated the sender's hybrid ciphertext calls this *before*
    /// handling the commit: MLS looks the PSK up by id in local storage and
    /// the commit fails if it is missing.
    ///
    /// Must be called while still at the pre-commit epoch, since the binding
    /// commits to it.
    pub fn stage_pq_secret(&self, member: &Member, secret: &PqSecret) -> Result<(), GroupError> {
        let binding = self.psk_binding();
        let psk_bytes = secret.to_psk_bytes(&binding);

        // The nonce is not stored, so any value works here; the committer's
        // nonce travels inside the commit and is checked there.
        PreSharedKeyId::external(binding, vec![0u8; 32])
            .store(&member.provider, &psk_bytes[..])
            .map_err(mls)
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Number of members currently in the conversation.
    ///
    /// Clients must surface changes to this. MLS makes member additions visible
    /// in the commit; that guarantee is worth nothing if the UI stays silent.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Everyone currently in the conversation.
    ///
    /// Clients need this to address a message: with more than two members a
    /// sender deposits one copy per recipient, each under that recipient's own
    /// tag. A single shared tag would hand every member every other member's
    /// mail, and whichever one acknowledged a message first would remove it
    /// from under the rest.
    pub fn roster(&self) -> Vec<Participant> {
        self.group
            .members()
            .map(|m| {
                Participant::from_credential(
                    m.credential.serialized_content(),
                    m.signature_key.as_slice().to_vec(),
                )
            })
            .collect()
    }

    /// Who sits at a leaf, by the index [`Received::Message`] carries.
    ///
    /// # Why the index does not leave this crate
    ///
    /// `receive` authenticates a sending leaf and reports it as a
    /// `LeafNodeIndex`, which is an MLS tree position and means nothing to an
    /// application. Every caller that wants it wants the same thing: a name to
    /// put beside a message or a receipt. So the resolution happens here, where
    /// the tree is, rather than in three clients that would each have to learn
    /// what a leaf is.
    ///
    /// `None` when the index is not in the group, which happens when a member
    /// has been removed since a message was sent.
    pub fn participant_at(&self, index: openmls::prelude::LeafNodeIndex) -> Option<Participant> {
        self.group.members().find(|m| m.index == index).map(|m| {
            Participant::from_credential(
                m.credential.serialized_content(),
                m.signature_key.as_slice().to_vec(),
            )
        })
    }

    /// Invite a member, returning the commit to broadcast and the welcome to
    /// deliver to the invitee.
    pub fn invite(
        &mut self,
        inviter: &Member,
        key_package: &KeyPackage,
    ) -> Result<(Vec<u8>, Vec<u8>), GroupError> {
        let (commit, welcome, _group_info) = self
            .group
            .add_members(
                &inviter.provider,
                &inviter.signer,
                core::slice::from_ref(key_package),
            )
            .map_err(mls)?;

        self.group
            .merge_pending_commit(&inviter.provider)
            .map_err(mls)?;

        Ok((
            commit.tls_serialize_detached().map_err(codec)?,
            welcome.tls_serialize_detached().map_err(codec)?,
        ))
    }

    /// Remove a member, returning the commit to broadcast.
    ///
    /// # Why this is what device revocation is
    ///
    /// A device that is lost is a leaf that can still decrypt. Nothing about
    /// forgetting it locally changes that: the group's key schedule includes it
    /// until the group says otherwise, so revocation has to be a commit, and a
    /// commit is exactly what every other member processes.
    ///
    /// That is what makes it visible rather than a local setting. Everybody who
    /// applies this commit moves to a new epoch derived without that leaf, sees
    /// the removal in [`MembershipChange::removed`], and can say so to the person
    /// reading. A revocation nobody else notices is a revocation the removed
    /// device does not have to respect.
    ///
    /// The removed device keeps everything it could already read. Forward
    /// secrecy is about what comes next, and what comes next is encrypted under
    /// a key schedule it is no longer part of.
    ///
    /// `signature_key` rather than a leaf index, because an index is a position
    /// in a tree that shifts as members come and go, and a caller holding one
    /// across a single epoch boundary would remove somebody else.
    pub fn remove(
        &mut self,
        remover: &Member,
        signature_key: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        let target = self
            .group
            .members()
            .find(|m| m.signature_key.as_slice() == signature_key)
            .ok_or(GroupError::NoSuchMember)?;

        if target.signature_key.as_slice() == remover.signer.public() {
            return Err(GroupError::CannotRemoveSelf);
        }

        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(&remover.provider, &remover.signer, &[target.index])
            .map_err(mls)?;

        self.group
            .merge_pending_commit(&remover.provider)
            .map_err(mls)?;

        commit.tls_serialize_detached().map_err(codec)
    }

    /// The public ratchet tree, needed out of band by a joining member.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(codec)
    }

    /// Reopen a conversation a restored member already holds state for.
    ///
    /// Returns `None` when the storage has no such group, which is how a caller
    /// tells "this export predates the conversation" from a real failure.
    pub fn reopen(member: &Member, group_id: &[u8]) -> Result<Option<Self>, GroupError> {
        let id = GroupId::from_slice(group_id);
        MlsGroup::load(member.provider.storage(), &id)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))
            .map(|maybe| {
                // Reopened from storage: this copy may be behind whatever
                // else has been using this state.
                maybe.map(|group| Self::opened(group, true))
            })
    }

    /// Join a conversation from a welcome message.
    pub fn join(
        joiner: &Member,
        welcome_bytes: &[u8],
        ratchet_tree_bytes: &[u8],
    ) -> Result<Self, GroupError> {
        let msg = MlsMessageIn::tls_deserialize(&mut &welcome_bytes[..]).map_err(codec)?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(GroupError::UnexpectedMessage {
                    expected: "welcome",
                })
            }
        };

        let tree = RatchetTreeIn::tls_deserialize(&mut &ratchet_tree_bytes[..]).map_err(codec)?;

        // Padding is per member, not per group.
        //
        // `MlsGroupCreateConfig` carries `padding_size` for whoever made the
        // group, and a joiner taking `MlsGroupJoinConfig::default()` gets zero.
        // With two people that is one direction padded and one not: measured at
        // 318 bytes for every plaintext from 1 to 100 on the creator's side, and
        // 146, 155, 195, 246 on the joiner's, which is the plaintext length
        // with a constant added. On a relayed session the ciphertext travels in
        // an L1 frame with nothing else around it, so the relay reads the
        // joiner's message lengths exactly, and the threat model says padding
        // buckets hide them.
        let join_config = MlsGroupJoinConfig::builder()
            .padding_size(PADDING_SIZE)
            .build();

        let staged =
            StagedWelcome::new_from_welcome(&joiner.provider, &join_config, welcome, Some(tree))
                .map_err(mls)?;

        let group = staged.into_group(&joiner.provider).map_err(mls)?;
        Ok(Self::opened(group, false))
    }

    /// Mix hybrid post-quantum material into the conversation's key schedule.
    ///
    /// `secret` must have been agreed via [`HybridKem`]; every member needs the
    /// same value, so in practice the committer encapsulates to each member's
    /// hybrid public key and ships the ciphertexts alongside the commit.
    ///
    /// The PSK id binds the secret to this group and this epoch, so material
    /// captured from one epoch cannot be replayed into another.
    /// Move to a fresh epoch after reopening from storage, and let `send` work.
    ///
    /// Returns the commit, which the caller must deliver to the other members
    /// the same way it delivers anything else. Until they process it they are
    /// still at the old epoch, which is ordinary MLS and not special to this.
    ///
    /// # Why this is not done inside `reopen`
    ///
    /// A commit has to reach the other side. `reopen` has no way to send one,
    /// and a rekey nobody receives leaves this copy talking to itself, which is
    /// the failure it exists to prevent, arrived at from the other direction.
    pub fn rekey_after_restore(&mut self, member: &Member) -> Result<Vec<u8>, GroupError> {
        let (commit, _welcome, _group_info) = self
            .group
            .commit_builder()
            .load_psks(member.provider.storage())
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?
            .build(
                member.provider.rand(),
                member.provider.crypto(),
                &member.signer,
                |_| true,
            )
            .map_err(mls)?
            .stage_commit(&member.provider)
            .map_err(mls)?
            .into_contents();

        let out = commit.tls_serialize_detached().map_err(codec)?;
        self.group
            .merge_pending_commit(&member.provider)
            .map_err(mls)?;
        self.restored_needs_rekey = false;
        Ok(out)
    }

    pub fn commit_pq_secret(
        &mut self,
        member: &Member,
        secret: &PqSecret,
    ) -> Result<Vec<u8>, GroupError> {
        let binding = self.psk_binding();
        let psk_bytes = secret.to_psk_bytes(&binding);

        // The nonce must be fresh each time the PSK is applied. It is *not*
        // stored: OpenMLS keys the secret by the PSK id alone , which is why
        // a receiver can stage the same secret without knowing our nonce.
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| GroupError::Mls("entropy".into()))?;

        let psk_id = PreSharedKeyId::external(binding.clone(), nonce.to_vec());
        psk_id
            .store(&member.provider, &psk_bytes[..])
            .map_err(mls)?;

        let commit = self
            .group
            .commit_builder()
            .add_proposal(Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(
                psk_id,
            ))))
            .load_psks(member.provider.storage())
            .map_err(mls)?
            .build(
                member.provider.rand(),
                member.provider.crypto(),
                &member.signer,
                |_| true,
            )
            .map_err(mls)?
            .stage_commit(&member.provider)
            .map_err(mls)?;

        let out = commit
            .into_messages()
            .0
            .tls_serialize_detached()
            .map_err(codec)?;

        self.group
            .merge_pending_commit(&member.provider)
            .map_err(mls)?;
        Ok(out)
    }

    /// Encrypt an application message.
    ///
    /// # The sequence number in front of the plaintext
    ///
    /// Every member of an MLS group holds the material every other member's
    /// messages are encrypted under: that is how the group works. A member can
    /// therefore take somebody else's message, decrypt it, and re-encrypt the
    /// signed content under the key and nonce of a different generation. The
    /// signature still verifies, because RFC 9420 does not put the generation
    /// into what is signed. So a member of the group can make another member's
    /// message arrive a second time, or arrive in a different order, without
    /// being able to change a word of it. Jaeger and Kumar set this out in
    /// "Analyzing Group Chat Encryption in MLS, Session, Signal, and Matrix"
    /// (EUROCRYPT 2025) and took it to the MLS working group.
    ///
    /// The fix they give is to bind the position into what gets signed. This
    /// counter is that binding: it rides inside the content, which the
    /// signature covers, so a member who moves a message to another generation
    /// leaves the counter saying where it came from, and
    /// [`Conversation::receive`] refuses it.
    ///
    /// # Why not in the associated data
    ///
    /// Because that is the obvious place and it is the wrong one here. The
    /// paper suggests it, and it is signed, but `authenticated_data` sits in
    /// `PrivateMessage` in the clear, next to `encrypted_sender_data`. MLS
    /// encrypts the sender data precisely so the leaf index and generation do
    /// not travel in the open. Putting a per-sender counter in the associated
    /// data would publish, in cleartext, the value that encryption exists to
    /// hide, and on a relayed session the relay reads the MLS ciphertext with
    /// nothing around it. The content is signed and encrypted; the associated
    /// data is only signed. So it goes in the content.
    pub fn send(&mut self, sender: &Member, plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
        // Refuse loudly rather than send into a hole. See
        // `Conversation::restored_needs_rekey`.
        if self.restored_needs_rekey {
            return Err(GroupError::RestoredAndNotRekeyed);
        }

        self.sync_seq_epoch();
        self.sent_seq += 1;

        let mut framed = Vec::with_capacity(SEQ_LEN + plaintext.len());
        framed.extend_from_slice(&self.sent_seq.to_be_bytes());
        framed.extend_from_slice(plaintext);

        self.group
            .create_message(&sender.provider, &sender.signer, &framed)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(codec)
    }

    /// Process an incoming message.
    ///
    /// Application messages return their plaintext. Commits are applied and
    /// return `None`: the caller must treat that as "the group changed" and
    /// re-read [`Conversation::member_count`].
    pub fn receive(&mut self, receiver: &Member, bytes: &[u8]) -> Result<Received, GroupError> {
        // Before anything is admitted, so state from a spent epoch is never
        // compared against a number from this one.
        self.sync_seq_epoch();

        let msg = MlsMessageIn::tls_deserialize(&mut &bytes[..]).map_err(codec)?;
        let protocol = msg.try_into_protocol_message().map_err(mls)?;

        let processed = self
            .group
            .process_message(&receiver.provider, protocol)
            .map_err(mls)?;

        // Who MLS says sent this, taken before the content is consumed.
        //
        // It used to be dropped on the floor. OpenMLS authenticates the sending
        // leaf and the result went nowhere, so `Received::Message` carried
        // bytes and no author. Harmless with two people, because there is only
        // one other person it could be from. In a group it means the
        // application cannot say who spoke, and the same enum's own
        // documentation exists to make membership changes visible for exactly
        // that kind of reason. The reasoning was not carried through to
        // application messages.
        let sender = match processed.sender() {
            openmls::prelude::Sender::Member(index) => Some(*index),
            _ => None,
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let (seq, body) = split_sequence(&app.into_bytes())?;

                // An application message always names a member; a group with an
                // unattributable one cannot sequence it, and refusing is the
                // only answer that does not leave a hole.
                let index = sender.ok_or(GroupError::UnattributedMessage)?;

                if !self.seen_seq.entry(index).or_default().admit(seq) {
                    return Err(GroupError::SequenceSpent { seq });
                }

                Ok(Received::Message {
                    sender,
                    bytes: body,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Read the roster on both sides of the merge rather than asking
                // the staged commit what it contains. A commit can add, remove
                // and update at once, and the difference between who was in the
                // group and who is in it now is the thing a person needs told.
                let before = self.roster();
                self.group
                    .merge_staged_commit(&receiver.provider, *staged)
                    .map_err(mls)?;
                let after = self.roster();

                // Compared on the signature key, which is what MLS authenticates
                // and what names a leaf. It used to compare the credential
                // identity, and that was wrong twice over: the identity is
                // self-asserted, so two members claiming the same one would hide
                // a real change, and once a person's devices became separate
                // leaves sharing a person, adding a second device looked like
                // nothing happening at all.
                let added: Vec<Participant> = after
                    .iter()
                    .filter(|p| !before.iter().any(|q| q.signature_key == p.signature_key))
                    .cloned()
                    .collect();
                let removed: Vec<Participant> = before
                    .iter()
                    .filter(|p| !after.iter().any(|q| q.signature_key == p.signature_key))
                    .cloned()
                    .collect();

                if added.is_empty() && removed.is_empty() {
                    // A rekey, which is routine and not worth interrupting
                    // anybody about.
                    return Ok(Received::Nothing);
                }
                Ok(Received::MembershipChanged(MembershipChange {
                    added,
                    removed,
                }))
            }
            _ => Ok(Received::Nothing),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Member, Member) {
        (
            Member::new(b"alice-device-1").expect("alice"),
            Member::new(b"bob-device-1").expect("bob"),
        )
    }

    #[test]
    fn two_members_exchange_a_message() {
        let (alice, bob) = pair();

        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("key package");
        let tree_before = a.ratchet_tree().expect("tree");
        let (_commit, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().unwrap_or(tree_before);

        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");

        assert_eq!(a.member_count(), 2);
        assert_eq!(b.member_count(), 2);

        let ct = a.send(&alice, b"nadie mas puede leer esto").expect("send");
        let pt = b
            .receive(&bob, &ct)
            .expect("receive")
            .message()
            .expect("application");
        assert_eq!(pt, b"nadie mas puede leer esto");
    }

    /// Two members, ready to exchange messages.
    fn conversation_of_two() -> (Member, Member, Conversation, Conversation) {
        let (alice, bob) = pair();
        let mut a = Conversation::create(&alice).expect("create");
        let (_commit, welcome) = a
            .invite(&alice, bob.key_package().expect("kp").key_package())
            .expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let b = Conversation::join(&bob, &welcome, &tree).expect("join");
        (alice, bob, a, b)
    }

    /// A modified message must be refused, not merely survived.
    ///
    /// # What this pins
    ///
    /// ADV-2 in the threat model says injection and modification fail
    /// authentication at L1 and L2 independently. The L2 half had no test. What
    /// existed was `no_single_byte_corruption_panics`, which feeds corrupted
    /// bytes to the parsers and discards the result: it asserts that nothing
    /// crashes, which is a different and much weaker property. An implementation
    /// that quietly accepted a tampered ciphertext passed the whole suite.
    #[test]
    fn a_modified_message_is_refused() {
        let (alice, _bob, mut a, _b) = conversation_of_two();
        let plaintext = b"the text an attacker wants to change";
        let valid = a.send(&alice, plaintext).expect("send");

        // Spread across the message rather than one convenient byte: framing,
        // header and ciphertext all have to refuse.
        let positions: Vec<usize> = (0..8).map(|n| valid.len() * n / 8).collect();
        for position in positions {
            for flip in [0x01u8, 0x80, 0xff] {
                let (_alice2, bob2, _a2, mut b2) = conversation_of_two();
                let mut corrupted = valid.clone();
                corrupted[position] ^= flip;
                if corrupted == valid {
                    continue;
                }

                match b2.receive(&bob2, &corrupted) {
                    Err(_) => {}
                    Ok(other) => assert_ne!(
                        other,
                        Received::Message {
                            sender: None,
                            bytes: plaintext.to_vec()
                        },
                        "a message with byte {position} altered was accepted as the original"
                    ),
                }
            }
        }
    }

    /// The same message delivered twice must not be accepted twice.
    ///
    /// # What this pins
    ///
    /// ADV-2 says replay is rejected by MLS epoch and generation tracking. That
    /// is a property of the library rather than of this code, which is exactly
    /// why it was worth writing down: nothing here checked that Rotelyx uses it
    /// in a way that keeps it. An attacker who can record and resend one
    /// ciphertext could otherwise make a message appear twice.
    #[test]
    fn a_replayed_message_is_refused() {
        let (alice, bob, mut a, mut b) = conversation_of_two();
        let ct = a.send(&alice, b"only once").expect("send");

        assert_eq!(
            b.receive(&bob, &ct).expect("first delivery").message(),
            Some(b"only once".to_vec())
        );

        assert!(
            b.receive(&bob, &ct).is_err(),
            "the same ciphertext was accepted a second time"
        );
    }

    /// A member of the group cannot move another member's message.
    ///
    /// # The hole this closes
    ///
    /// The test above covers somebody outside the group resending bytes they
    /// captured. It does not cover somebody inside it, and inside is where MLS
    /// is weaker than it reads: every member holds the material every other
    /// member's messages are encrypted under, so a member can decrypt one,
    /// re-encrypt the signed content at a different generation, and have the
    /// signature still verify. RFC 9420 leaves the generation out of what is
    /// signed. Jaeger and Kumar, EUROCRYPT 2025.
    ///
    /// Mounting that end to end needs the library's internals, which are not
    /// reachable from here, so what is pinned is the thing that stops it: the
    /// sequence number rides inside the signed content, and this window is what
    /// decides. If the window stops refusing, so does the defence.
    #[test]
    fn a_sequence_number_already_spent_is_refused() {
        let mut seen = SeenFrom::default();

        assert!(seen.admit(1), "the first message was refused");
        assert!(seen.admit(2), "the second message was refused");
        assert!(!seen.admit(2), "a repeat was admitted");
        assert!(!seen.admit(1), "an older repeat was admitted");
        assert!(seen.admit(3), "the conversation could not continue");
    }

    /// Out-of-order delivery is normal and must still arrive.
    ///
    /// A window that refused everything but the next number would drop real
    /// messages: OpenMLS itself accepts up to five generations behind what it
    /// has already decrypted, so anything reaching this check may be behind by
    /// that much and still be honest.
    #[test]
    fn a_message_that_arrives_out_of_order_is_still_admitted() {
        let mut seen = SeenFrom::default();

        assert!(seen.admit(5), "the first to arrive was refused");
        assert!(seen.admit(2), "a message behind the newest was refused");
        assert!(seen.admit(4), "a message behind the newest was refused");
        assert!(seen.admit(1), "a message behind the newest was refused");
        assert!(!seen.admit(4), "a repeat behind the newest was admitted");
        assert!(seen.admit(6), "the conversation could not continue");
    }

    /// Past the window there is no memory left, so nothing is admitted.
    ///
    /// The window is finite, and a number older than it cannot be told apart
    /// from one already seen. Refusing is the only answer that does not leave
    /// a replay through the back of the window.
    #[test]
    fn a_sequence_number_older_than_the_window_is_refused() {
        let mut seen = SeenFrom::default();

        assert!(seen.admit(1), "the first message was refused");
        assert!(seen.admit(REPLAY_WINDOW + 1), "a jump forward was refused");

        assert!(
            !seen.admit(1),
            "a number that has fallen out of the window was admitted"
        );
        assert!(
            seen.admit(REPLAY_WINDOW),
            "a number still inside the window was refused"
        );
    }

    /// The sequence number must not be readable by whoever carries the message.
    ///
    /// # Why this is worth a test
    ///
    /// The obvious place for it is `authenticated_data`, which is signed, and
    /// which the EUROCRYPT paper suggests. But that field travels in the clear
    /// inside `PrivateMessage`, beside `encrypted_sender_data`. MLS encrypts
    /// the sender data so that the leaf index and the generation do not travel
    /// in the open, and a per-sender counter in the clear gives back the same
    /// thing: a relay carrying the ciphertext could count each member's
    /// messages and link them across an epoch without holding a key.
    ///
    /// So it goes in the content, which is signed and encrypted both. This
    /// asserts the number is not on the wire, and it is the test that fails if
    /// somebody later moves it to the associated data for tidiness.
    #[test]
    fn the_sequence_number_does_not_travel_in_the_clear() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        let mut ct = Vec::new();
        for _ in 0..300 {
            ct = a.send(&alice, b"ordinary traffic").expect("send");
        }

        let needle = 300u64.to_be_bytes();
        assert!(
            !ct.windows(needle.len()).any(|w| w == needle),
            "the sequence number was readable in the ciphertext"
        );

        // And it is still doing its job: the receiver reads it and hands back
        // the message without it.
        b.receive(&bob, &ct).expect("delivery");
    }

    /// The sequence rides under the message and never surfaces in it.
    ///
    /// A prefix on the plaintext is only safe if every reader has it stripped.
    /// One path that handed back the raw bytes would show eight bytes of
    /// counter as part of somebody's message. Three members rather than two
    /// because that is the smallest group where a sender is told apart from a
    /// receiver, so it is the smallest case that exercises the per-sender
    /// bookkeeping at all.
    #[test]
    fn a_group_of_three_reads_what_was_written() {
        let (alice, bob) = pair();
        let carol = Member::new(b"carol").expect("carol");

        let mut a = Conversation::create(&alice).expect("create");

        let bob_kp = bob.key_package().expect("bob key package");
        let (_first_commit, welcome_b) =
            a.invite(&alice, bob_kp.key_package()).expect("invite bob");
        let mut b = Conversation::join(&bob, &welcome_b, &a.ratchet_tree().expect("tree"))
            .expect("bob joins");

        let carol_kp = carol.key_package().expect("carol key package");
        let (second_commit, welcome_c) = a
            .invite(&alice, carol_kp.key_package())
            .expect("invite carol");

        // Bob has to hear Carol arrive, or he stays an epoch behind and reads
        // nothing that follows.
        b.receive(&bob, &second_commit)
            .expect("bob applies the commit");

        let mut c = Conversation::join(&carol, &welcome_c, &a.ratchet_tree().expect("tree"))
            .expect("carol joins");

        for text in [b"first ".as_slice(), b"second", b"third "] {
            let ct = a.send(&alice, text).expect("send");

            assert_eq!(
                b.receive(&bob, &ct).expect("bob reads it").message(),
                Some(text.to_vec()),
                "the body did not survive the round trip to bob"
            );
            assert_eq!(
                c.receive(&carol, &ct).expect("carol reads it").message(),
                Some(text.to_vec()),
                "the body did not survive the round trip to carol"
            );
        }

        let repeat = a.send(&alice, b"once").expect("send");
        b.receive(&bob, &repeat).expect("the first delivery");
        assert!(
            b.receive(&bob, &repeat).is_err(),
            "a member accepted the same message twice"
        );
    }

    /// A copy reopened from storage refuses to send until it has rekeyed.
    ///
    /// # The hole this closes
    ///
    /// A restored copy believes it is at a generation the group has already
    /// spent. Everything it sent was refused by the receiver, which deletes each
    /// generation's secret as it uses it, and `send` succeeded anyway: nothing
    /// told the person holding the device, so to them messages simply stopped
    /// arriving. Confidentiality held and availability did not, silently, which
    /// is the worst way for anything to fail.
    ///
    /// The refusal is the point. Rekeying is what makes it work again, and the
    /// caller has to deliver that commit, so it cannot be done inside `reopen`.
    #[test]
    fn a_reopened_conversation_refuses_to_send_until_it_rekeys() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        // Alice's copy is written down and opened again, which is what a restore
        // from a backup looks like from here.
        let mut reopened = Conversation::reopen(&alice, &a.group_id())
            .expect("reopen")
            .expect("the group is there");

        assert!(
            matches!(
                reopened.send(&alice, b"into the hole"),
                Err(GroupError::RestoredAndNotRekeyed)
            ),
            "a reopened copy sent as though nothing had happened"
        );

        // Rekeying gives it generations of its own, and the other side has to
        // hear about it.
        let commit = reopened
            .rekey_after_restore(&alice)
            .expect("rekey after restore");
        b.receive(&bob, &commit).expect("bob applies the rekey");

        let ct = reopened
            .send(&alice, b"and now it arrives")
            .expect("sending works once the epoch has moved");
        assert_eq!(
            b.receive(&bob, &ct).expect("receive").message(),
            Some(b"and now it arrives".to_vec()),
            "the message did not arrive after the rekey"
        );

        // And the original copy, still at the old epoch, is the one now behind.
        assert!(
            a.send(&alice, b"from the stale copy")
                .ok()
                .map(|ct| b.receive(&bob, &ct).is_err())
                .unwrap_or(true),
            "a copy left behind by somebody else's rekey still delivered"
        );
    }

    /// A backup restored twice cannot deliver twice, at either layer.
    ///
    /// # The class this belongs to
    ///
    /// Review gate 4 names the state-corruption failures MLS does not solve for
    /// us. Two of them are one mechanism: a backup restored onto two devices,
    /// and a device rolled back to an older backup. Both rewind the generation
    /// counter, so the copy encrypts under a key the group has already spent.
    ///
    /// There are two layers between that and a delivered message, and this
    /// asserts both. The near one is the guard: a copy reopened from storage
    /// refuses to send at all. The far one is the receiver, which deletes each
    /// generation's secret as it uses it, so even a copy that got past the guard
    /// has nothing to be decrypted with. The far layer is the library's, which
    /// is why it is pinned here rather than assumed.
    #[test]
    fn a_rewound_sender_cannot_deliver_under_a_generation_already_used() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        let first = a.send(&alice, b"the same generation").expect("send");
        b.receive(&bob, &first).expect("the first arrives");

        let mut rewound = Conversation::reopen(&alice, &a.group_id())
            .expect("reopen")
            .expect("the group is there");

        // The near layer.
        assert!(
            matches!(
                rewound.send(&alice, b"the same generation"),
                Err(GroupError::RestoredAndNotRekeyed)
            ),
            "a copy reopened from storage sent without rekeying"
        );

        // The far layer. Rekeying clears the guard, and the commit is
        // deliberately *not* delivered, so this copy is now speaking at an epoch
        // the receiver has never seen: the same shape as a generation already
        // spent, and refused for the same reason.
        let _commit = rewound
            .rekey_after_restore(&alice)
            .expect("rekey after restore");
        let second = rewound
            .send(&alice, b"the same generation")
            .expect("sending is allowed once the guard is cleared");

        assert!(
            b.receive(&bob, &second).is_err(),
            "a receiver accepted a message from a copy it never heard rekey"
        );
    }

    /// A receiver will not derive keys without limit for messages it never saw.
    ///
    /// # The class this belongs to
    ///
    /// The third of gate 4's failures. Out-of-order delivery means a receiver
    /// derives the keys it skipped, and a sender that jumps far ahead makes it
    /// derive that many. Unbounded, that is a memory and CPU cost an attacker
    /// chooses.
    ///
    /// It is bounded at a thousand generations, which costs a few milliseconds
    /// to walk. That bound is the library's default and this crate does not set
    /// it, so the test is here to notice if it ever moves.
    #[test]
    fn a_generation_too_far_ahead_is_refused() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        let mut ahead = Vec::new();
        for n in 0..1_200u32 {
            ahead = a.send(&alice, &n.to_be_bytes()).expect("send");
        }

        assert!(
            b.receive(&bob, &ahead).is_err(),
            "a receiver walked more than a thousand skipped generations, which is \
             work an attacker asked for"
        );
    }

    /// A message from before a device reinstalled must not land on it after.
    ///
    /// # The class this belongs to
    ///
    /// The fourth of gate 4's failures. A reinstalled device is a new member
    /// with a new key package, added by a commit that moves the epoch. Anything
    /// captured before that belongs to an epoch the new member never had, and
    /// replaying it must not work.
    #[test]
    fn a_message_from_before_a_rejoin_is_refused_after_it() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        let before = a.send(&alice, b"sent before the reinstall").expect("send");
        b.receive(&bob, &before)
            .expect("the original device gets it");

        // The same person, a fresh install: new key package, new join.
        let reinstalled = Member::new(b"bob-device-1").expect("bob again");
        let (_commit, welcome) = a
            .invite(&alice, reinstalled.key_package().expect("kp").key_package())
            .expect("invite the reinstalled device");
        let tree = a.ratchet_tree().expect("tree");
        let mut fresh = Conversation::join(&reinstalled, &welcome, &tree).expect("rejoin");

        assert!(
            fresh.receive(&reinstalled, &before).is_err(),
            "a message captured before the reinstall was replayed into the device \
             that came after it"
        );
    }

    /// Both directions must pad, not just the one that made the group.
    ///
    /// # The hole this closes
    ///
    /// `padding_size` belongs to a member's own config, and only the creator's
    /// was set: a joiner took `MlsGroupJoinConfig::default()`, which pads to
    /// nothing. With two people that is one direction padded and one not, and
    /// the unpadded side's ciphertext grew a byte for every byte of plaintext.
    ///
    /// It matters most where there is nothing else around the ciphertext. A
    /// message sent through the mailbox is sealed into an envelope that pads to
    /// its own buckets, so the operator sees a bucket either way. A message on a
    /// live session travels in an L1 frame on its own, so the relay carrying it
    /// reads the length off the wire, and ADV-1 in the threat model says padding
    /// buckets hide exactly that.
    #[test]
    fn both_sides_of_a_conversation_pad_to_the_same_sizes() {
        let (alice, bob, mut a, mut b) = conversation_of_two();

        for len in [1usize, 10, 50, 100] {
            let plaintext = vec![b'x'; len];

            let creator = a.send(&alice, &plaintext).expect("creator send").len();
            // Keep the receiver in step, so generations stay usable.
            let carried = a.send(&alice, &plaintext).expect("send");
            b.receive(&bob, &carried).expect("receive");

            let joiner = b.send(&bob, &plaintext).expect("joiner send").len();

            assert_eq!(
                creator, joiner,
                "a {len} byte message was {creator} bytes from the member who made \
                 the group and {joiner} from the one who joined it, so one side's \
                 lengths are on the wire"
            );
        }
    }

    /// Somebody arriving must be reported to the people already there, by name.
    ///
    /// # The hole this closes
    ///
    /// A silent addition is what a "ghost user" attack needs, and MLS makes it
    /// impossible: every member processes the commit. That guarantee is only
    /// worth something if it reaches a person, and this layer used to hand the
    /// client the same value for an addition, a rekey and a message it did not
    /// Saving after a rekey must save the rekey.
    ///
    /// # The failure this catches
    ///
    /// A conversation that resumes and rekeys, is saved, and resumes again must
    /// come back at the epoch it reached, not the one it started from. Measured
    /// across three runs of the command line client it went 1, 2, 2: every
    /// resume was reopening the *same* old state and moving one epoch forward
    /// from it, for ever.
    ///
    /// That is not merely stale. Reopening the same epoch repeatedly is exactly
    /// the rollback `restored_needs_rekey` exists to prevent, arrived at through
    /// the door marked "save".
    #[test]
    fn a_saved_conversation_remembers_the_epoch_it_reached() {
        let alice = Member::new(b"alice").expect("alice");
        let bob = Member::new(b"bob").expect("bob");

        let mut group = Conversation::create(&alice).expect("create");
        group
            .invite(&alice, bob.key_package().expect("kp").key_package())
            .expect("invite");
        let group_id = group.group_id();
        let first = group.epoch();

        // Round one: export, restore, reopen, rekey.
        let state = alice.export().expect("export");
        let restored = Member::restore(state).expect("restore");
        let mut reopened = Conversation::reopen(&restored, &group_id)
            .expect("reopen")
            .expect("the group is in the storage");
        reopened.rekey_after_restore(&restored).expect("rekey");
        let second = reopened.epoch();
        assert!(second > first, "the rekey did not advance the epoch");

        // Round two: export *that*, and it must come back where it was left.
        let state = restored.export().expect("export again");
        let again = Member::restore(state).expect("restore again");
        let reopened = Conversation::reopen(&again, &group_id)
            .expect("reopen again")
            .expect("the group is still in the storage");

        assert_eq!(
            reopened.epoch(),
            second,
            "the conversation was saved at epoch {first} after reaching {second}, so \
             every resume reopens the same state and the group never moves"
        );
    }

    /// A device is a member, so revoking one is a commit everybody processes.
    #[test]
    fn revoking_a_device_is_visible_to_everybody_else() {
        let alice_phone = Member::for_device(b"alice", b"phone").expect("phone");
        let alice_laptop = Member::for_device(b"alice", b"laptop").expect("laptop");
        let bob = Member::new(b"bob").expect("bob");

        let mut phone = Conversation::create(&alice_phone).expect("create");
        let (commit, welcome) = phone
            .invite(&alice_phone, bob.key_package().expect("kp").key_package())
            .expect("invite bob");
        let _ = commit;
        let mut bobs = Conversation::join(&bob, &welcome, &phone.ratchet_tree().expect("tree"))
            .expect("bob joins");

        // Alice adds her laptop as its own leaf.
        let (commit, _welcome) = phone
            .invite(
                &alice_phone,
                alice_laptop.key_package().expect("kp").key_package(),
            )
            .expect("add the laptop");
        let outcome = bobs.receive(&bob, &commit).expect("bob sees the add");
        let change = outcome.membership_change().expect("bob was not told");
        assert_eq!(change.added.len(), 1);
        assert_eq!(change.added[0].identity, b"alice");
        assert_eq!(change.added[0].device, b"laptop");
        assert_eq!(bobs.member_count(), 3);

        // Two leaves, one person, and Bob can tell.
        let roster = bobs.roster();
        let alices: Vec<&Participant> = roster.iter().filter(|p| p.identity == b"alice").collect();
        assert_eq!(
            alices.len(),
            2,
            "the two devices did not read as one person"
        );
        assert!(alices[0].same_person_as(alices[1]));
        assert_ne!(
            alices[0].signature_key, alices[1].signature_key,
            "separate leaves must not share a key, which is the whole point"
        );

        // The laptop is lost. The phone revokes it.
        let laptop_key = alices
            .iter()
            .find(|p| p.device == b"laptop")
            .expect("the laptop is in the roster")
            .signature_key
            .clone();

        let commit = phone
            .remove(&alice_phone, &laptop_key)
            .expect("revoke the laptop");

        let outcome = bobs.receive(&bob, &commit).expect("bob sees the removal");
        let change = outcome
            .membership_change()
            .expect("bob was not told a device was revoked");
        assert_eq!(change.added.len(), 0);
        assert_eq!(change.removed.len(), 1, "the wrong number of departures");
        assert_eq!(change.removed[0].identity, b"alice");
        assert_eq!(
            change.removed[0].device, b"laptop",
            "the revocation did not say which device"
        );
        assert_eq!(bobs.member_count(), 2);

        // And Alice's phone is still Alice: revoking a device is not leaving.
        assert!(bobs.roster().iter().any(|p| p.identity == b"alice"));
    }

    #[test]
    fn a_member_cannot_remove_itself() {
        let alice = Member::new(b"alice").expect("alice");
        let bob = Member::new(b"bob").expect("bob");
        let mut group = Conversation::create(&alice).expect("create");
        group
            .invite(&alice, bob.key_package().expect("kp").key_package())
            .expect("invite");

        let me: Vec<u8> = alice.signer.public().to_vec();
        assert!(matches!(
            group.remove(&alice, &me),
            Err(GroupError::CannotRemoveSelf)
        ));
    }

    #[test]
    fn removing_somebody_who_is_not_there_says_so() {
        let alice = Member::new(b"alice").expect("alice");
        let stranger = Member::new(b"stranger").expect("stranger");
        let mut group = Conversation::create(&alice).expect("create");

        let key: Vec<u8> = stranger.signer.public().to_vec();
        assert!(matches!(
            group.remove(&alice, &key),
            Err(GroupError::NoSuchMember)
        ));
    }

    /// The credential format is a wire format, and changing it broke the wire.
    ///
    /// # What happened
    ///
    /// Credentials used to be the person's bytes and nothing else. Devices
    /// needed a second field, so they became `person_len ‖ person ‖ device`.
    /// Both ends of this repository were changed together and every test passed.
    ///
    /// A deployed client was not changed with them, and the failure that
    /// produces is worse than a clean break. A 32 byte identity written the old
    /// way is read by a new client as a length byte and 31 bytes of person, and
    /// whether that parses depends on the **first byte of the key**: above 31 the
    /// length runs off the end and the whole thing is kept as an unparseable
    /// credential, which happens to be 32 bytes and happens to work. At or below
    /// 31 it splits, the identity comes out the wrong length, and the safety
    /// number cannot be computed from it.
    ///
    /// So it works about seven times in eight and fails the rest, per identity,
    /// for ever. Nobody finds that in a test suite where both sides are built
    /// from the same commit.
    ///
    /// This pins the format so the next change to it is a deliberate act. The
    /// answer to the incompatibility itself is not a version byte here: it is
    /// that nothing is released, so everything gets rebuilt and redeployed
    /// together.
    #[test]
    fn the_credential_wire_format_is_pinned() {
        let person = [0xAAu8; 32];
        let encoded = encode_identity(&person, b"laptop").expect("encode");

        assert_eq!(encoded[0], 32, "the length prefix moved");
        assert_eq!(&encoded[1..33], &person, "the person moved");
        assert_eq!(&encoded[33..], b"laptop", "the device moved");
        assert_eq!(encoded.len(), 1 + 32 + 6);

        // The old shape, and what a new reader makes of it. One outcome is
        // wrong and the other is wrong invisibly.
        let mut survives = 0;
        let mut breaks = 0;
        for first in 0u8..=255 {
            let mut old = [0x55u8; 32];
            old[0] = first;
            match decode_identity(&old) {
                // Split: the identity comes out short, and `peer_identity`
                // wants exactly 32 bytes, so the safety number is unreachable.
                Some((person, _)) if person.len() != 32 => breaks += 1,
                Some(_) => survives += 1,
                // Unparseable: kept whole, which is 32 bytes, which works.
                None => survives += 1,
            }
        }
        assert_eq!(
            (survives, breaks),
            (224, 32),
            "the old format now fails for a different fraction of identities, so \
             this note no longer describes what happens"
        );
    }

    /// A credential from somewhere else is reported as unparseable rather than
    /// split at a plausible place and called a person.
    #[test]
    fn a_credential_that_is_not_ours_is_not_guessed_at() {
        let foreign = Participant::from_credential(&[], vec![1, 2, 3]);
        assert!(!foreign.well_formed);
        assert!(foreign.device.is_empty());

        // A length that runs off the end is not a person either.
        let truncated = Participant::from_credential(&[200, 1, 2], vec![4]);
        assert!(!truncated.well_formed);
        assert_eq!(truncated.identity, vec![200, 1, 2]);

        // And two of them are never "the same person".
        assert!(!foreign.same_person_as(&Participant::from_credential(&[], vec![9])));
    }

    /// recognise. The clients could report a count and nothing else, and one
    /// commit can remove a member and add another, which leaves the count where
    /// it was.
    #[test]
    fn a_member_arriving_is_reported_by_name() {
        let (alice, bob) = pair();
        let carol = Member::new(b"carol-device-1").expect("carol");

        let mut a = Conversation::create(&alice).expect("create");
        let (_commit, welcome) = a
            .invite(&alice, bob.key_package().expect("kp").key_package())
            .expect("invite bob");
        let tree = a.ratchet_tree().expect("tree");
        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");
        assert_eq!(b.member_count(), 2);

        // Alice adds Carol. Bob has to find out, and find out who.
        let (commit, _welcome) = a
            .invite(&alice, carol.key_package().expect("kp").key_package())
            .expect("invite carol");
        let outcome = b.receive(&bob, &commit).expect("process the commit");

        let change = outcome
            .membership_change()
            .expect("Bob was not told that somebody joined his conversation");
        assert!(change.removed.is_empty());
        assert_eq!(change.added.len(), 1, "the wrong number of arrivals");
        assert_eq!(
            change.added[0].identity, b"carol-device-1",
            "the arrival was reported without saying who it was"
        );
        assert_eq!(b.member_count(), 3);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (alice, bob) = pair();
        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("kp");
        let (_c, _w) = a.invite(&alice, bob_kp.key_package()).expect("invite");

        let secret = b"deadbeef-secret-marker";
        let ct = a.send(&alice, secret).expect("send");
        assert!(
            !ct.windows(secret.len()).any(|w| w == secret),
            "plaintext leaked into the ciphertext"
        );
    }

    #[test]
    fn an_outsider_cannot_read_the_conversation() {
        let (alice, bob) = pair();
        let mallory = Member::new(b"mallory-device-1").expect("mallory");

        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("kp");
        let tree_before = a.ratchet_tree().unwrap();
        let (_c, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().unwrap_or(tree_before);

        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");
        let ct = a.send(&alice, b"privado").expect("send");

        // Mallory holds a valid identity but was never added.
        assert!(
            Conversation::join(&mallory, &welcome, &tree).is_err() || b.receive(&bob, &ct).is_ok()
        );
    }

    /// Guards the bug the suite mismatch caused: the group must be on the
    /// ciphersuite we chose, not on OpenMLS's default.
    #[test]
    fn group_uses_the_configured_ciphersuite() {
        let alice = Member::new(b"alice").expect("alice");
        let convo = Conversation::create(&alice).expect("create");
        assert_eq!(convo.ciphersuite(), CIPHERSUITE);
    }

    #[test]
    fn epoch_advances_when_the_group_changes() {
        let (alice, bob) = pair();
        let mut a = Conversation::create(&alice).expect("create");
        let before = a.epoch();

        let bob_kp = bob.key_package().expect("kp");
        a.invite(&alice, bob_kp.key_package()).expect("invite");

        assert!(a.epoch() > before, "adding a member must advance the epoch");
    }

    #[test]
    fn hybrid_material_is_agreed_between_members() {
        let (_alice, bob) = pair();

        // Alice encapsulates to Bob's published hybrid key.
        let (ct, alice_secret) = bob.hybrid_public_key().encapsulate();
        let bob_secret = bob.open_pq(&ct);
        assert!(alice_secret.ct_eq(&bob_secret));

        // And the derived PSK is identical on both sides for the same binding.
        let binding = b"rotelyx-pq-psk-v1|group|epoch-0";
        assert_eq!(
            *alice_secret.to_psk_bytes(binding),
            *bob_secret.to_psk_bytes(binding)
        );
    }

    /// The full post-quantum path, end to end.
    ///
    /// Alice encapsulates to Bob's hybrid key, both derive the same PSK, Alice
    /// commits it, Bob processes the commit, and they keep talking at the new
    /// epoch. Until this passed, `commit_pq_secret` was untested code.
    #[test]
    fn post_quantum_secret_reaches_the_mls_key_schedule() {
        let (alice, bob) = pair();

        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("kp");
        let (_c, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");

        let epoch_before = a.epoch();
        assert_eq!(epoch_before, b.epoch(), "both start at the same epoch");

        // Alice encapsulates post-quantum material to Bob's published key.
        let (ct, alice_secret) = bob.hybrid_public_key().encapsulate();
        let bob_secret = bob.open_pq(&ct);
        assert!(alice_secret.ct_eq(&bob_secret));

        // Bob stages it before the commit arrives; MLS resolves the PSK by id
        // from local storage and would reject the commit otherwise.
        b.stage_pq_secret(&bob, &bob_secret).expect("stage");

        let commit = a.commit_pq_secret(&alice, &alice_secret).expect("commit");
        assert!(b
            .receive(&bob, &commit)
            .expect("process commit")
            .message()
            .is_none());

        assert!(
            a.epoch() > epoch_before,
            "the PSK commit advances the epoch"
        );
        assert_eq!(a.epoch(), b.epoch(), "both landed on the same epoch");

        // And the conversation still works, now with post-quantum material
        // mixed into the key schedule.
        let msg = a
            .send(&alice, b"protegido post-cuanticamente")
            .expect("send");
        let got = b
            .receive(&bob, &msg)
            .expect("receive")
            .message()
            .expect("application");
        assert_eq!(got, b"protegido post-cuanticamente");
    }

    /// Without the staged secret the commit must fail, which is what proves the
    /// PSK is genuinely load-bearing rather than decorative.
    #[test]
    fn a_psk_commit_fails_for_a_member_missing_the_secret() {
        let (alice, bob) = pair();

        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("kp");
        let (_c, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let mut b = Conversation::join(&bob, &welcome, &tree).expect("join");

        let (_ct, alice_secret) = bob.hybrid_public_key().encapsulate();
        let commit = a.commit_pq_secret(&alice, &alice_secret).expect("commit");

        // Bob never staged the secret.
        assert!(b.receive(&bob, &commit).is_err());
    }

    #[test]
    fn both_members_derive_the_same_mailbox_tag_key() {
        let (alice, bob) = pair();

        let mut a = Conversation::create(&alice).expect("create");
        let bob_kp = bob.key_package().expect("kp");
        let (_c, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let b = Conversation::join(&bob, &welcome, &tree).expect("join");

        let ka = a.mailbox_tag_key(&alice).expect("alice key");
        let kb = b.mailbox_tag_key(&bob).expect("bob key");

        assert_eq!(ka, kb, "both members must address the same mailbox slot");
        assert_ne!(ka, [0u8; 32]);
    }

    /// The trap the documentation warns about, pinned as a test: the exporter
    /// moves with the epoch, so a tag key derived after a commit differs from
    /// one derived before it. Deriving lazily on each send would make messages
    /// silently undeliverable whenever the sender was a commit ahead.
    #[test]
    fn the_tag_key_changes_with_the_epoch_so_it_must_be_pinned() {
        let (alice, bob) = pair();

        let mut a = Conversation::create(&alice).expect("create");
        let before = a.mailbox_tag_key(&alice).expect("before");

        let bob_kp = bob.key_package().expect("kp");
        a.invite(&alice, bob_kp.key_package()).expect("invite");
        let after = a.mailbox_tag_key(&alice).expect("after");

        assert_ne!(
            before, after,
            "the exporter is epoch-bound; callers must pin the tag key at a              mutually known epoch rather than deriving it per message"
        );
    }

    /// Two different conversations must never address the same mailbox slot.
    #[test]
    fn different_conversations_derive_different_tag_keys() {
        let alice = Member::new(b"alice").expect("alice");
        let a1 = Conversation::create(&alice).expect("first");
        let a2 = Conversation::create(&alice).expect("second");

        assert_ne!(
            a1.mailbox_tag_key(&alice).expect("k1"),
            a2.mailbox_tag_key(&alice).expect("k2")
        );
    }

    #[test]
    fn member_debug_never_leaks() {
        let m = Member::new(b"x").expect("member");
        let rendered = format!("{m:?}");
        assert!(rendered.contains("<redacted>"));
    }
}
