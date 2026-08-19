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

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("payload of {len} bytes exceeds the largest bucket ({max})")]
    TooLarge { len: usize, max: usize },

    #[error("payload length {len} is not a valid bucket size")]
    NotABucket { len: usize },

    #[error("tag must be exactly 32 bytes, got {0}")]
    BadTag(usize),
}

/// Fixed payload sizes.
///
/// Every envelope is padded up to one of these, so the operator learns only
/// which bucket a message fell into rather than its length. The steps are wide
/// on purpose: fine-grained buckets would leak nearly as much as no padding.
///
/// ### Why `Small` is 1 KiB and not 256 bytes
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
    /// Collection removes. With two members that is exactly right: the sender
    /// cannot collect its own deposit, so the other side gets it. With three it
    /// breaks: a message deposited under one shared tag is collected by
    /// whichever member reaches it first, and the rest never see it.
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
