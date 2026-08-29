//! Sealed envelopes: rotating tags and padding buckets.
//!
//! An envelope is everything the mailbox operator gets to see. By construction
//! that is: one opaque 32-byte tag, and a payload whose length is one of five
//! fixed values. No sender field, no recipient identity, no plaintext length.
//!
//! ## What this does and does not hide
//!
//! Hidden: who sent it, who it is for, how long the message is, what it says.
//!
//! **Not hidden: that an envelope was deposited, and when.** A mailbox that
//! logs everything can correlate a deposit with a collection by timing. That is
//! ADV-4 in the threat model and this module does not solve it: padding and
//! tag rotation raise the cost of correlation, they do not eliminate it.
//! Claiming otherwise would be the kind of overreach that makes a threat model
//! worthless.

use std::fmt;

use zeroize::Zeroizing;

/// Domain separator for tag derivation. Distinct from every other label in the
/// system so a tag can never collide with a key derived elsewhere.
const TAG_CONTEXT: &str = "rotelyx mailbox tag v1";

/// Separate context from [`TAG_CONTEXT`], so a per-member key can never be
/// mistaken for the group key it was derived from.
const MEMBER_TAG_CONTEXT: &str = "rotelyx mailbox member tag v1";

/// Separate again, so the key a payload is sealed under is not the key tags are
/// derived from and neither can be computed from the other.
const PAYLOAD_CONTEXT: &str = "rotelyx mailbox payload v1";

/// What a sealed payload starts with, so a version can be told from a length.
const PAYLOAD_VERSION: u8 = 2;

/// Domain separation inside the AEAD, bound as associated data.
const PAYLOAD_AAD: &[u8] = b"rotelyx envelope payload v2";

/// XChaCha20-Poly1305: 24 bytes of nonce, 16 of tag, one of version.
const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
/// Marks the end of the real bytes, before the envelope's zero padding.
const PADDING_TERMINATOR: u8 = 0x80;

pub const PAYLOAD_OVERHEAD: usize = 1 + NONCE_LEN + AEAD_TAG_LEN + 1;

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("payload of {len} bytes exceeds the largest bucket ({max})")]
    TooLarge { len: usize, max: usize },

    #[error("payload length {len} is not a valid bucket size")]
    NotABucket { len: usize },

    #[error("tag must be exactly 32 bytes, got {0}")]
    BadTag(usize),

    #[error("no randomness available to seal a payload with")]
    NoRandomness,

    #[error("could not seal the payload")]
    Sealing,

    #[error("this is not a sealed payload of a version we know")]
    NotSealed,

    #[error("the payload did not open: it belongs to another conversation or another epoch")]
    NotOurs,
}

/// Fixed payload sizes.
///
/// Every envelope is padded up to one of these, so the operator learns only
/// which bucket a message fell into rather than its length. The steps are wide
/// on purpose: fine-grained buckets would leak nearly as much as no padding.
///
/// ### Why `SMALL` is 1 KiB and not 256 bytes
///
/// The first version used 256, which looked generous for a chat message and was
/// not. MLS adds a constant 145 bytes of overhead, so a 256-byte bucket holds
/// barely a hundred characters of text, and ordinary messages straddled the
/// boundary, which told the operator "short" or "long" for every message sent.
/// A cross-layer test caught it: a 2-byte message produced a 288-byte envelope
/// while a 150-byte message produced 4128.
///
/// At 1 KiB, combined with the 256-byte plaintext padding applied at L2, normal
/// conversation collapses into a single bucket. The cost is bandwidth: a
/// one-word reply occupies 1 KiB. On a messaging workload that is cheap, and it
/// is the entire point.
/// # Why the ladder is fine above the floor and coarse at it
///
/// The floor is what protects conversation. Everything from a one word reply to
/// a long paragraph lands in the same 1 KiB bucket, so an observer learns
/// nothing about what was said. That property is untouched by anything below.
///
/// Above the floor the steps double. The earlier ladder jumped 64 KiB straight
/// to 1 MiB, and that gap was expensive for no benefit. Two things sit up
/// there: files, whose length is far less revealing than a sentence's, and
/// **group commits, whose size is a function of the number of members**, which
/// the operator already knows, because a fan-out names every recipient. Padding
/// an 85 KB commit up to 1 MiB was paying twelve times over to hide a number
/// already in plain view.
///
/// The cost is real and worth stating: above 1 KiB a length is now known to
/// within a factor of two rather than a factor of eight. That is the trade that
/// makes a group of a thousand affordable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket(usize);

impl Bucket {
    /// The floor. Normal conversation never leaves it.
    pub const SMALL: Bucket = Bucket(1_024);

    /// The ceiling. Anything larger goes over a direct transfer, not the
    /// mailbox: a blind mailbox is not a file host.
    pub const MAX: Bucket = Bucket(8_388_608);

    /// Every size, ascending.
    pub const SIZES: [usize; 14] = [
        1_024,
        2_048,
        4_096,
        8_192,
        16_384,
        32_768,
        65_536,
        131_072,
        262_144,
        524_288,
        1_048_576,
        2_097_152,
        4_194_304,
        8_388_608,
    ];

    pub const fn size(self) -> usize {
        self.0
    }

    /// Smallest bucket that fits `len`.
    pub fn for_len(len: usize) -> Result<Self, EnvelopeError> {
        Self::SIZES
            .into_iter()
            .find(|&size| size >= len)
            .map(Bucket)
            .ok_or(EnvelopeError::TooLarge {
                len,
                max: Bucket::MAX.size(),
            })
    }

    /// The bucket a payload of exactly this size belongs to, or `None` if the
    /// size is not a bucket at all.
    ///
    /// Public so a server can refuse a payload that has not been padded. A
    /// server that padded on the client's behalf would be handed the true
    /// length, which is the one thing the buckets exist to withhold.
    pub fn from_size(size: usize) -> Option<Self> {
        Self::SIZES.into_iter().find(|&s| s == size).map(Bucket)
    }
}

/// A secret shared between a sender and a recipient, used only to derive tags.
///
/// Kept separate from any encryption key: a tag key leaking reveals *where* to
/// look in a mailbox, which is bad, but it must never also reveal content.
/// Derive it from an MLS exporter secret rather than reusing a message key.
pub struct TagKey(Zeroizing<[u8; 32]>);

impl TagKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw key, for a caller that must persist it.
    ///
    /// Secret. Exposed because a client that cannot write this down cannot
    /// survive a restart: the key comes from an MLS exporter, and MLS discards
    /// what an epoch was derived from as soon as the epoch passes. There is no
    /// recomputing it later.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    /// The tag key for one specific recipient in a group.
    ///
    /// # Why a group cannot share one tag
    ///
    /// A shared tag works for two, because the sender is never handed its own
    /// deposit and the other side is therefore the only reader. It breaks at
    /// three: every member would read every other member's mail, and whichever
    /// acknowledged a message first would remove it from under the rest.
    ///
    /// So a sender addresses each recipient separately, deriving their tag key
    /// from the group's pinned key and that recipient's signature key. The cost
    /// is one deposit per recipient, and an operator that sees a burst of them
    /// can infer the size of the group. That is a real disclosure and the
    /// reason group size is worth keeping modest.
    ///
    /// `recipient` must be something unique and stable per member for as long
    /// as they are in the group. A signature key is; a leaf index is not, since
    /// MLS reuses a slot after a removal.
    pub fn for_member(&self, recipient: &[u8]) -> TagKey {
        let mut hasher = blake3::Hasher::new_derive_key(MEMBER_TAG_CONTEXT);
        hasher.update(&self.0[..]);
        // Length-prefixed so that two different recipients cannot be split from
        // the same concatenation.
        hasher.update(&(recipient.len() as u64).to_be_bytes());
        hasher.update(recipient);

        let mut out = Zeroizing::new([0u8; 32]);
        hasher.finalize_xof().fill(&mut out[..]);
        TagKey(out)
    }

    /// The key an envelope's payload is sealed under.
    ///
    /// # Why a payload needs sealing at all
    ///
    /// Because the thing being deposited was never opaque. An envelope carried
    /// the serialised MLS message verbatim, and RFC 9420 puts `group_id` and
    /// `epoch` in **cleartext** in the framing, ahead of the encrypted content.
    /// So an operator read a stable group identifier out of every envelope it
    /// held, with no key at all, and every envelope of a conversation linked to
    /// every other one across every tag rotation and all of time. Rotating tags
    /// hid *who*. They did not hide *that these belong together*, which is most
    /// of a social graph, and it is the property this crate exists to provide.
    ///
    /// # Why this key and not the tag key
    ///
    /// Derived from the same group secret through a separate context, so that
    /// holding a tag never yields the key that opens what it addresses. It is
    /// the **group** key rather than a per-member one on purpose: one payload is
    /// deposited under many tags when a group message fans out, so every
    /// recipient must open the same bytes.
    ///
    /// The epoch is already inside it, because the tag key comes from the MLS
    /// exporter and that changes with every epoch. A payload from a spent epoch
    /// therefore cannot be opened under the current one, without anything extra
    /// being bound in.
    pub fn payload_key(&self) -> PayloadKey {
        let mut hasher = blake3::Hasher::new_derive_key(PAYLOAD_CONTEXT);
        hasher.update(&self.0[..]);
        let mut out = Zeroizing::new([0u8; 32]);
        hasher.finalize_xof().fill(&mut out[..]);
        PayloadKey(out)
    }

    /// The tag to use for `epoch`.
    ///
    /// `epoch` is a coarse time bucket agreed by both sides: hours, not
    /// seconds. Passing it in rather than reading a clock keeps this crate
    /// deterministic and testable, and makes clock skew an explicit caller
    /// concern rather than a hidden failure.
    ///
    /// An observer sees unlinkable 32-byte values: without the key, two tags
    /// from the same pair are as unrelated as tags from different pairs.
    pub fn tag_for_epoch(&self, epoch: u64) -> Tag {
        let mut hasher = blake3::Hasher::new_derive_key(TAG_CONTEXT);
        hasher.update(&self.0[..]);
        hasher.update(&epoch.to_be_bytes());

        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        Tag(out)
    }

    /// Tags a recipient should poll for: the current epoch plus `lookback`
    /// previous ones.
    ///
    /// Lookback exists because a sender's clock may lag, and because a
    /// recipient that was offline still needs to find envelopes left under
    /// earlier tags. It costs one extra lookup per epoch of slack.
    pub fn polling_tags(&self, current_epoch: u64, lookback: u64) -> Vec<Tag> {
        (0..=lookback)
            .filter_map(|back| current_epoch.checked_sub(back))
            .map(|e| self.tag_for_epoch(e))
            .collect()
    }
}

#[cfg(test)]
mod member_tag_tests {
    use super::*;

    /// Two members of one group must never share a tag, or a message meant for
    /// one is collected by the other and lost.
    #[test]
    fn each_member_gets_a_different_tag() {
        let group = TagKey::new([7u8; 32]);
        let alice = group.for_member(b"alice-signature-key");
        let bob = group.for_member(b"bob-signature-key");

        assert_ne!(
            alice.tag_for_epoch(5),
            bob.tag_for_epoch(5),
            "two members must not collide"
        );
        assert_ne!(
            alice.tag_for_epoch(5),
            group.tag_for_epoch(5),
            "a member tag must differ from the group key it came from"
        );
    }

    /// Every member derives the same tag for a given recipient, or a sender
    /// deposits somewhere the recipient never looks.
    #[test]
    fn every_member_derives_the_same_tag_for_a_recipient() {
        let from_alice = TagKey::new([7u8; 32]).for_member(b"carol");
        let from_bob = TagKey::new([7u8; 32]).for_member(b"carol");

        assert_eq!(from_alice.tag_for_epoch(9), from_bob.tag_for_epoch(9));
    }

    /// Recipient bytes are length-prefixed, so no two distinct recipients can
    /// produce the same input to the hash.
    #[test]
    fn recipients_cannot_be_confused_by_concatenation() {
        let group = TagKey::new([7u8; 32]);
        assert_ne!(
            group.for_member(b"ab").tag_for_epoch(0),
            group.for_member(b"a").tag_for_epoch(0),
        );
        // The classic split: "ab" + "" vs "a" + "b" must not collide.
        assert_ne!(
            group.for_member(b"abc").tag_for_epoch(0),
            group.for_member(b"abcd").tag_for_epoch(0),
        );
    }
}

impl fmt::Debug for TagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TagKey(<redacted>)")
    }
}

/// An opaque mailbox address. This is the only routing information the operator
/// receives, and it carries no identity.
// `Hash` is derived while `PartialEq` is written by hand, which clippy refuses
// at deny level and is correct here. The hand-written `eq` is constant time and
// compares the same 32 bytes the derived `hash` reads, so the invariant clippy
// protects, that equal values hash equally, holds. Making `hash` constant time
// would mean a linear scan of every subscriber for every deposit, and a hash is
// not a comparison of secrets.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Copy, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct Tag([u8; 32]);

/// Equality in constant time.
///
/// # Whether this was necessary
///
/// Written down because the answer is "no, and do it anyway", and the next
/// person to read this deserves the reasoning rather than having to redo it.
///
/// A tag is derived from a conversation secret and is known to the operator,
/// which is why the note below says tags are not secret. They are not secret
/// *from the operator*. They are secret from everybody else, and knowing one
/// buys the ability to deposit into that mailbox and to correlate its traffic.
///
/// So: could somebody who does not know a tag learn one by timing a comparison?
/// The comparison that matters is on the client, checking an arriving envelope
/// against the tag it expected. To reach it, an attacker has to get an envelope
/// delivered, and the mailbox only delivers to subscribers of the tag the
/// envelope names. Getting your bytes in front of that comparison already
/// requires knowing the answer. **Not reachable.**
///
/// The server side compares tags too, routing a deposit to its subscribers, and
/// there the attacker does choose the tag. But the reply already says whether
/// anybody was subscribed, so timing reveals nothing the protocol does not.
///
/// It is still done in constant time, for one reason: the argument above is
/// four paragraphs long and depends on details of delivery that could change in
/// a single commit by somebody who never read this. A variable-time comparison
/// on secret-derived material is a standing obligation to keep re-deriving that
/// argument. `ct_eq` costs one pass over 32 bytes and discharges it.
///
/// `Ord` and `Hash` stay derived and stay variable-time, deliberately: they
/// exist so a tag can be a key in the map the server routes with, that map is
/// the server's own subscription table, and making it constant time would mean
/// a linear scan of every subscriber for every deposit.
impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Tag {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EnvelopeError::BadTag(bytes.len()))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tags are not secret from the operator, who holds them all, but
        // printing 64 hex characters in every log line is unreadable.
        let hex = data_encoding::HEXLOWER.encode(&self.0);
        write!(f, "Tag({}…)", &hex[..12])
    }
}

/// The key a payload is sealed under. See [`TagKey::payload_key`].
pub struct PayloadKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for PayloadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PayloadKey(<redacted>)")
    }
}

impl PayloadKey {
    /// Make a payload opaque, before it is put in an envelope.
    ///
    /// The result is what the operator holds. Nothing about the conversation is
    /// readable in it: not the group, not the epoch, not the length past the
    /// bucket it is padded to afterwards.
    /// `tag` binds the payload to the address it is deposited under.
    ///
    /// `None` is for the one path that cannot: a group fan-out uploads one
    /// payload and names every recipient, so the same bytes land under many
    /// tags and no single one can be bound in. That path already concedes the
    /// recipient set to the operator, and this is the other half of the same
    /// trade, said out loud rather than left implicit.
    ///
    /// Everywhere else, binding the tag is what stops an operator moving an
    /// envelope from one address to another. The inner MLS layer would refuse
    /// the result, so the consequence was small, but "another layer catches it"
    /// is not the same as "it cannot be done".
    pub fn seal(&self, tag: Option<Tag>, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| EnvelopeError::NoRandomness)?;

        let aad = Self::aad(tag);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.0[..])
            .map_err(|_| EnvelopeError::Sealing)?;
        let sealed = cipher
            .encrypt(
                &XNonce::try_from(&nonce[..]).expect("NONCE_LEN bytes, just built"),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::Sealing)?;

        let mut out = Vec::with_capacity(PAYLOAD_OVERHEAD + plaintext.len());
        out.push(PAYLOAD_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        // A terminator, so the end of the real bytes can be found without
        // reading them. The envelope pads with zeroes to a bucket and carries no
        // length, by design: a length field would hand the operator exactly what
        // the buckets exist to hide. That leaves the recipient to find where the
        // padding starts, and "the last byte that is not zero" is wrong, because
        // the last byte of an authentication tag is zero one time in two hundred
        // and fifty six. This is the ISO 7816-4 answer and it costs one byte.
        out.push(PADDING_TERMINATOR);
        Ok(out)
    }

    /// The associated data: a label, and the tag when there is one.
    ///
    /// A discriminator byte separates "bound to this tag" from "bound to none",
    /// so a fan-out payload cannot be passed off as a payload for a particular
    /// address, or the reverse.
    fn aad(tag: Option<Tag>) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYLOAD_AAD.len() + 33);
        out.extend_from_slice(PAYLOAD_AAD);
        match tag {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(t.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// And back, for a recipient who holds the same group secret.
    pub fn open(&self, tag: Option<Tag>, sealed: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        // Trailing zeroes from the bucket padding are still attached. The AEAD
        // would refuse them, so they come off first, and a version byte at the
        // front is what makes the start of the real bytes findable at all.
        let sealed = match sealed.iter().rposition(|b| *b != 0) {
            Some(last) if sealed[last] == PADDING_TERMINATOR => &sealed[..last],
            _ => return Err(EnvelopeError::NotSealed),
        };

        if sealed.len() < PAYLOAD_OVERHEAD || sealed[0] != PAYLOAD_VERSION {
            return Err(EnvelopeError::NotSealed);
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&self.0[..])
            .map_err(|_| EnvelopeError::Sealing)?;
        cipher
            .decrypt(
                &XNonce::try_from(&sealed[1..1 + NONCE_LEN]).expect("NONCE_LEN bytes, length checked above"),
                Payload {
                    msg: &sealed[1 + NONCE_LEN..],
                    aad: &Self::aad(tag),
                },
            )
            .map_err(|_| EnvelopeError::NotOurs)
    }
}

/// What the operator stores: a tag, and a bucket-sized opaque payload.
#[derive(Clone, PartialEq, Eq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    tag: Tag,
    payload: Vec<u8>,
}

impl Envelope {
    /// Seal `ciphertext` under `tag`, padded to the smallest bucket that fits.
    ///
    /// `ciphertext` must already be encrypted by L2: this function provides no
    /// confidentiality whatsoever, only length hiding and blind addressing.
    ///
    /// No length prefix is written. The padding is trailing zeroes, and the
    /// recipient recovers the real content because the inner MLS message is
    /// self-delimiting. A cleartext length field would have handed the operator
    /// exactly the information the buckets exist to hide.
    pub fn seal(tag: Tag, ciphertext: &[u8]) -> Result<Self, EnvelopeError> {
        let bucket = Bucket::for_len(ciphertext.len())?;

        let mut payload = vec![0u8; bucket.size()];
        payload[..ciphertext.len()].copy_from_slice(ciphertext);

        Ok(Self { tag, payload })
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// What a recipient names this envelope by when acknowledging it.
    ///
    /// Collection used to remove on delivery, which meant anybody who learned a
    /// tag could drain it and the messages simply never arrived: silent,
    /// permanent, and invisible to both ends. Delivery and removal are separate
    /// now, and this is the handle in between. It is derived from the stored
    /// bytes, so a receipt cannot name an envelope the sender never sent.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("rotelyx envelope receipt v1");
        hasher.update(self.tag.as_bytes());
        hasher.update(&self.payload);
        *hasher.finalize().as_bytes()
    }

    pub fn bucket(&self) -> Result<Bucket, EnvelopeError> {
        Bucket::from_size(self.payload.len()).ok_or(EnvelopeError::NotABucket {
            len: self.payload.len(),
        })
    }

    /// The padded payload, to hand to L2 for decryption.
    ///
    /// Trailing zeroes are included; the MLS deserialiser stops at the end of
    /// the real message and ignores them.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Total size on the wire, for accounting.
    pub fn wire_len(&self) -> usize {
        32 + self.payload.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.tag.0);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < 32 {
            return Err(EnvelopeError::BadTag(bytes.len()));
        }
        let (tag_bytes, payload) = bytes.split_at(32);
        let tag = Tag::from_bytes(tag_bytes)?;

        // Reject anything that is not exactly a bucket. An operator, or an
        // attacker posing as one: must not be able to store odd-sized blobs
        // that would stand out from everything else in the mailbox.
        if Bucket::from_size(payload.len()).is_none() {
            return Err(EnvelopeError::NotABucket { len: payload.len() });
        }

        Ok(Self {
            tag,
            payload: payload.to_vec(),
        })
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("tag", &self.tag)
            .field("bucket", &self.payload.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    /// The padding must come off whatever the ciphertext ends with.
    ///
    /// This is the regression test for a one-in-two-hundred-and-fifty-six bug.
    /// The envelope pads with zeroes and carries no length, so the recipient has
    /// to find where the real bytes stop, and the first version looked for the
    /// last byte that is not zero. The last byte of a Poly1305 tag is zero as
    /// often as any other value, and when it was, a byte of the tag was eaten
    /// with the padding and the payload did not open. Intermittent, and it
    /// looked like a clock-skew problem.
    #[test]
    fn a_payload_opens_whatever_its_last_byte_is() {
        let key = TagKey::new([9u8; 32]).payload_key();
        let tag = Tag::from_bytes(&[4u8; 32]).expect("tag");

        // Enough attempts that a tag ending in zero is a near certainty.
        for i in 0..1000u32 {
            let plaintext = format!("message {i}");
            let sealed = key.seal(Some(tag), plaintext.as_bytes()).expect("seal");

            // Padded exactly as an envelope pads it.
            let envelope = Envelope::seal(tag, &sealed).expect("envelope");

            let opened = key
                .open(Some(tag), envelope.payload())
                .unwrap_or_else(|e| panic!("attempt {i} did not open: {e}"));
            assert_eq!(opened, plaintext.as_bytes());
        }
    }

    /// A payload bound to one tag must not open under another.
    #[test]
    fn a_payload_does_not_move_between_tags() {
        let key = TagKey::new([9u8; 32]).payload_key();
        let here = Tag::from_bytes(&[1u8; 32]).expect("tag");
        let there = Tag::from_bytes(&[2u8; 32]).expect("tag");

        let sealed = key.seal(Some(here), b"addressed to one place").expect("seal");
        assert!(key.open(Some(here), &sealed).is_ok());
        assert!(
            key.open(Some(there), &sealed).is_err(),
            "an operator moved an envelope to another tag and it still opened"
        );
        assert!(key.open(None, &sealed).is_err());
    }

    use super::*;

    #[test]
    fn tags_are_deterministic_for_the_same_epoch() {
        let k = TagKey::new([3u8; 32]);
        assert_eq!(k.tag_for_epoch(100), k.tag_for_epoch(100));
    }

    #[test]
    fn tags_rotate_between_epochs() {
        let k = TagKey::new([3u8; 32]);
        assert_ne!(k.tag_for_epoch(100), k.tag_for_epoch(101));
    }

    /// The unlinkability property the whole design rests on: without the key,
    /// two tags for the same pair look no more related than tags for different
    /// pairs.
    #[test]
    fn tags_from_different_keys_are_unrelated() {
        let a = TagKey::new([1u8; 32]);
        let b = TagKey::new([2u8; 32]);
        assert_ne!(a.tag_for_epoch(7), b.tag_for_epoch(7));
    }

    #[test]
    fn polling_covers_the_lookback_window() {
        let k = TagKey::new([5u8; 32]);
        let tags = k.polling_tags(10, 3);
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[0], k.tag_for_epoch(10));
        assert_eq!(tags[3], k.tag_for_epoch(7));
    }

    /// Near genesis there are no earlier epochs to poll; this must not
    /// underflow.
    #[test]
    fn polling_near_epoch_zero_does_not_underflow() {
        let k = TagKey::new([5u8; 32]);
        assert_eq!(k.polling_tags(1, 5).len(), 2);
        assert_eq!(k.polling_tags(0, 5).len(), 1);
    }

    #[test]
    fn buckets_round_up() {
        assert_eq!(Bucket::for_len(0).unwrap().size(), 1_024);
        assert_eq!(Bucket::for_len(1_024).unwrap().size(), 1_024);
        assert_eq!(Bucket::for_len(1_025).unwrap().size(), 2_048);
        assert_eq!(Bucket::for_len(8_192).unwrap().size(), 8_192);
        assert_eq!(Bucket::for_len(8_193).unwrap().size(), 16_384);
    }

    /// The floor is what protects conversation, and it has not moved. Making
    /// the ladder finer above it must not make short messages distinguishable.
    #[test]
    fn conversation_still_collapses_into_one_bucket() {
        for len in [0usize, 1, 50, 200, 512, 900, 1_024] {
            assert_eq!(
                Bucket::for_len(len).unwrap().size(),
                1_024,
                "a {len} byte message must be indistinguishable from every other short one"
            );
        }
    }

    /// The steps double, so nothing above the floor ever pays more than twice
    /// its own size. The old ladder jumped 64 KiB straight to 1 MiB.
    #[test]
    fn no_payload_pays_more_than_double() {
        for size in Bucket::SIZES {
            let just_over = size + 1;
            if just_over > Bucket::MAX.size() {
                continue;
            }
            let chosen = Bucket::for_len(just_over).unwrap().size();
            assert!(
                chosen <= just_over * 2,
                "{just_over} bytes padded to {chosen}, more than double"
            );
        }
    }

    /// The measured commit sizes for real groups, so the ladder cannot silently
    /// regress into another cliff.
    #[test]
    fn a_group_commit_does_not_fall_off_a_cliff() {
        // Measured with crates/rotelyx-crypto/tests/group_scale.rs.
        for (members, commit, expected) in [
            (256usize, 21_824usize, 32_768usize),
            (512, 42_816, 65_536),
            (768, 64_064, 65_536),
            (1024, 85_056, 131_072),
        ] {
            let padded = Bucket::for_len(commit).unwrap().size();
            assert_eq!(
                padded, expected,
                "a {members} member commit of {commit} bytes padded to {padded}"
            );
            assert!(
                padded < commit * 2,
                "a {members} member commit pays more than double"
            );
        }
    }

    #[test]
    fn oversized_payloads_are_refused() {
        assert!(matches!(
            Bucket::for_len(Bucket::MAX.size() + 1),
            Err(EnvelopeError::TooLarge { .. })
        ));
    }

    /// The length-hiding property: two messages of very different sizes must be
    /// indistinguishable on the wire when they share a bucket.
    #[test]
    fn different_lengths_in_one_bucket_are_indistinguishable() {
        let tag = TagKey::new([9u8; 32]).tag_for_epoch(1);

        let short = Envelope::seal(tag, b"si").expect("seal");
        let long = Envelope::seal(tag, &[7u8; 200]).expect("seal");

        assert_eq!(short.wire_len(), long.wire_len());
        assert_eq!(short.bucket().unwrap(), long.bucket().unwrap());
    }

    #[test]
    fn the_ciphertext_survives_padding() {
        let tag = TagKey::new([9u8; 32]).tag_for_epoch(1);
        let ct = b"this stands in for an MLS message";

        let env = Envelope::seal(tag, ct).expect("seal");
        assert_eq!(&env.payload()[..ct.len()], ct);
        assert!(
            env.payload()[ct.len()..].iter().all(|&b| b == 0),
            "padding must be zeroes"
        );
    }

    #[test]
    fn envelopes_survive_serialisation() {
        let tag = TagKey::new([9u8; 32]).tag_for_epoch(42);
        let env = Envelope::seal(tag, b"hello").expect("seal");

        let back = Envelope::from_bytes(&env.to_bytes()).expect("roundtrip");
        assert_eq!(env, back);
        assert_eq!(back.tag(), tag);
    }

    /// An odd-sized payload would stand out from every other envelope in the
    /// mailbox, which defeats the buckets entirely.
    #[test]
    fn non_bucket_sizes_are_rejected_on_parse() {
        let mut bytes = vec![0u8; 32];
        bytes.extend_from_slice(&[1u8; 300]);

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::NotABucket { len: 300 })
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(Envelope::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn tag_key_debug_never_leaks() {
        let k = TagKey::new([1u8; 32]);
        assert_eq!(format!("{k:?}"), "TagKey(<redacted>)");
    }
}
