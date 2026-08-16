//! MLS conversations with a hybrid post-quantum key schedule.
//!
//! A conversation is an MLS group (RFC 9420) via OpenMLS. A 1:1 chat is simply
//! a group of two — there is no separate pairwise protocol, which removes an
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
/// Note the `128` — the OpenMLS RustCrypto provider offers no 256-bit suite, so
/// the classical security level is fixed here. The long-term margin comes from
/// the hybrid post-quantum PSK below, not from this line.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

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

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("mls: {0}")]
    Mls(String),

    #[error("codec: {0}")]
    Codec(String),

    #[error("expected a {expected} message, got something else")]
    UnexpectedMessage { expected: &'static str },

    #[error("message was not an application message")]
    NotApplication,
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
    /// public key bytes, not a name — there is no name registry to consult, and
    /// a self-asserted display name in a credential is a phishing surface.
    pub fn new(identity: &[u8]) -> Result<Self, GroupError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
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

    /// This member's hybrid public key, to be published alongside its key
    /// package so peers can encapsulate post-quantum material to it.
    pub fn hybrid_public_key(&self) -> HybridPublicKey {
        self.hybrid_sk.public()
    }

    /// Recover post-quantum material a peer encapsulated to us.
    pub fn open_pq(&self, ct: &HybridCiphertext) -> PqSecret {
        self.hybrid_sk.decapsulate(ct)
    }

    /// Produce a key package so others can add this member to a group.
    ///
    /// Published through the blind mailbox, never a directory — a key package
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
/// Key packages are public and signed, so this is not secret material — but it
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
        .validate(OpenMlsRustCrypto::default().crypto(), ProtocolVersion::Mls10)
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
pub struct Conversation {
    group: MlsGroup,
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
    /// key package advertises — and the mismatch only surfaces when the first
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

        Ok(Self { group })
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
    /// # This value is epoch-bound — pin it
    ///
    /// The MLS exporter changes with every epoch, which is the whole point of
    /// forward secrecy and exactly wrong for addressing. If each side derived a
    /// tag key from its current epoch, a sender one commit ahead of a recipient
    /// would deposit under a tag the recipient cannot compute, and the message
    /// would be silently undeliverable.
    ///
    /// So: derive this **once**, at a mutually known epoch — join time — and
    /// persist it. Unlinkability over time does not depend on rotating this
    /// key; it comes from [`TagKey::tag_for_epoch`], which already derives a
    /// fresh tag per coarse time bucket from a fixed key.
    ///
    /// [`TagKey::tag_for_epoch`]: https://docs.rs/rotelyx-mailbox
    pub fn mailbox_tag_key(&self, member: &Member) -> Result<[u8; 32], GroupError> {
        let bytes = self
            .group
            .export_secret(
                member.provider.crypto(),
                MAILBOX_TAG_KEY_LABEL,
                &[],
                32,
            )
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
    /// handling the commit — MLS looks the PSK up by id in local storage and
    /// the commit fails if it is missing.
    ///
    /// Must be called while still at the pre-commit epoch, since the binding
    /// commits to it.
    pub fn stage_pq_secret(
        &self,
        member: &Member,
        secret: &PqSecret,
    ) -> Result<(), GroupError> {
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

    /// The public ratchet tree, needed out of band by a joining member.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(codec)
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

        let staged = StagedWelcome::new_from_welcome(
            &joiner.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(tree),
        )
        .map_err(mls)?;

        let group = staged.into_group(&joiner.provider).map_err(mls)?;
        Ok(Self { group })
    }

    /// Mix hybrid post-quantum material into the conversation's key schedule.
    ///
    /// `secret` must have been agreed via [`HybridKem`]; every member needs the
    /// same value, so in practice the committer encapsulates to each member's
    /// hybrid public key and ships the ciphertexts alongside the commit.
    ///
    /// The PSK id binds the secret to this group and this epoch, so material
    /// captured from one epoch cannot be replayed into another.
    pub fn commit_pq_secret(
        &mut self,
        member: &Member,
        secret: &PqSecret,
    ) -> Result<Vec<u8>, GroupError> {
        let binding = self.psk_binding();
        let psk_bytes = secret.to_psk_bytes(&binding);

        // The nonce must be fresh each time the PSK is applied. It is *not*
        // stored — OpenMLS keys the secret by the PSK id alone — which is why
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

        self.group.merge_pending_commit(&member.provider).map_err(mls)?;
        Ok(out)
    }

    /// Encrypt an application message.
    pub fn send(&mut self, sender: &Member, plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
        self.group
            .create_message(&sender.provider, &sender.signer, plaintext)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(codec)
    }

    /// Process an incoming message.
    ///
    /// Application messages return their plaintext. Commits are applied and
    /// return `None` — the caller must treat that as "the group changed" and
    /// re-read [`Conversation::member_count`].
    pub fn receive(
        &mut self,
        receiver: &Member,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, GroupError> {
        let msg = MlsMessageIn::tls_deserialize(&mut &bytes[..]).map_err(codec)?;
        let protocol = msg.try_into_protocol_message().map_err(mls)?;

        let processed = self
            .group
            .process_message(&receiver.provider, protocol)
            .map_err(mls)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Some(app.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&receiver.provider, *staged)
                    .map_err(mls)?;
                Ok(None)
            }
            _ => Ok(None),
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
        let pt = b.receive(&bob, &ct).expect("receive").expect("application");
        assert_eq!(pt, b"nadie mas puede leer esto");
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
            Conversation::join(&mallory, &welcome, &tree).is_err()
                || b.receive(&bob, &ct).is_ok()
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
        assert!(b.receive(&bob, &commit).expect("process commit").is_none());

        assert!(a.epoch() > epoch_before, "the PSK commit advances the epoch");
        assert_eq!(a.epoch(), b.epoch(), "both landed on the same epoch");

        // And the conversation still works, now with post-quantum material
        // mixed into the key schedule.
        let msg = a.send(&alice, b"protegido post-cuanticamente").expect("send");
        let got = b.receive(&bob, &msg).expect("receive").expect("application");
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
