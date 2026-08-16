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
//! ADV-4 in the threat model and this module does not solve it — padding and
//! tag rotation raise the cost of correlation, they do not eliminate it.
//! Claiming otherwise would be the kind of overreach that makes a threat model
//! worthless.

use std::fmt;

use zeroize::Zeroizing;

/// Domain separator for tag derivation. Distinct from every other label in the
/// system so a tag can never collide with a key derived elsewhere.
const TAG_CONTEXT: &str = "rotelyx mailbox tag v1";

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
/// barely a hundred characters of text — and ordinary messages straddled the
/// boundary, which told the operator "short" or "long" for every message sent.
/// A cross-layer test caught it: a 2-byte message produced a 288-byte envelope
/// while a 150-byte message produced 4128.
///
/// At 1 KiB, combined with the 256-byte plaintext padding applied at L2, normal
/// conversation collapses into a single bucket. The cost is bandwidth: a
/// one-word reply occupies 1 KiB. On a messaging workload that is cheap, and it
/// is the entire point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum Bucket {
    /// Text messages, receipts, typing indicators.
    Small = 1_024,
    /// Longer text, key packages.
    Medium = 8_192,
    /// Small media, group commits.
    Large = 65_536,
    /// Images.
    Huge = 1_048_576,
    /// The ceiling. Anything larger goes over a direct transfer, not the
    /// mailbox — a blind mailbox is not a file host.
    Max = 8_388_608,
}

impl Bucket {
    pub const ALL: [Bucket; 5] = [
        Bucket::Small,
        Bucket::Medium,
        Bucket::Large,
        Bucket::Huge,
        Bucket::Max,
    ];

    pub const fn size(self) -> usize {
        self as usize
    }

    /// Smallest bucket that fits `len`.
    pub fn for_len(len: usize) -> Result<Self, EnvelopeError> {
        Self::ALL
            .into_iter()
            .find(|b| b.size() >= len)
            .ok_or(EnvelopeError::TooLarge {
                len,
                max: Bucket::Max.size(),
            })
    }

    fn from_size(size: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.size() == size)
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

    /// The tag to use for `epoch`.
    ///
    /// `epoch` is a coarse time bucket agreed by both sides — hours, not
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

impl fmt::Debug for TagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TagKey(<redacted>)")
    }
}

/// An opaque mailbox address. This is the only routing information the operator
/// receives, and it carries no identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag([u8; 32]);

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
        // Tags are not secret — the operator holds them — but printing 64 hex
        // characters in every log line is unreadable.
        let hex = data_encoding::HEXLOWER.encode(&self.0);
        write!(f, "Tag({}…)", &hex[..12])
    }
}

/// What the operator stores: a tag, and a bucket-sized opaque payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    tag: Tag,
    payload: Vec<u8>,
}

impl Envelope {
    /// Seal `ciphertext` under `tag`, padded to the smallest bucket that fits.
    ///
    /// `ciphertext` must already be encrypted by L2 — this function provides no
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

        // Reject anything that is not exactly a bucket. An operator — or an
        // attacker posing as one — must not be able to store odd-sized blobs
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
        assert_eq!(Bucket::for_len(0).unwrap(), Bucket::Small);
        assert_eq!(Bucket::for_len(1_024).unwrap(), Bucket::Small);
        assert_eq!(Bucket::for_len(1_025).unwrap(), Bucket::Medium);
        assert_eq!(Bucket::for_len(8_192).unwrap(), Bucket::Medium);
        assert_eq!(Bucket::for_len(8_193).unwrap(), Bucket::Large);
    }

    #[test]
    fn oversized_payloads_are_refused() {
        assert!(matches!(
            Bucket::for_len(Bucket::Max.size() + 1),
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
        let env = Envelope::seal(tag, b"hola").expect("seal");

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
