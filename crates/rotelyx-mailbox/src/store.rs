//! The mailbox store.
//!
//! Deliberately dumb: it maps opaque tags to opaque envelopes, expires them,
//! and forgets them on collection. It has no notion of users, accounts,
//! conversations, or identities, because the operator must not be able to
//! reconstruct any of those from a seized disk.
//!
//! ## What an operator can still do
//!
//! Retain envelopes past their TTL, log deposits and collections with
//! timestamps, and correlate the two. Deletion here is a promise the *code*
//! makes; nothing in the protocol enforces it against a hostile operator.
//! Clients must therefore never treat a mailbox acknowledgement as proof that
//! anything was deleted, and the mailbox must never be the only copy.
//!
//! That is why self-hosting matters more than any feature in this file.

use std::collections::HashMap;

use crate::envelope::{Envelope, Tag};

/// The absolute ceiling on envelopes held under a single tag.
///
/// Without a cap, anyone who learns a tag can fill a disk. They cannot read
/// anything, but they can deny delivery, and availability is still worth
/// defending cheaply.
///
/// This is the ceiling, not the working limit: [`Mailbox::deposit_with`] takes
/// the depositor's own limit and clamps it here. It must therefore be at least
/// as large as the most generous tier an operator offers, or that tier silently
/// receives less than it was sold.
pub const MAX_PER_TAG: usize = 256;

/// How long an envelope lives if nobody collects it.
///
/// Short on purpose. A mailbox is a relay point for peers who were briefly
/// offline, not an archive: the longer the retention, the more a seizure is
/// worth.
pub const DEFAULT_TTL_SECONDS: u64 = 7 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("tag is full: {MAX_PER_TAG} envelopes already pending")]
    TagFull,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Stored {
    envelope: Envelope,
    /// Deposit time, supplied by the caller rather than read from a clock so
    /// the store stays deterministic and testable.
    deposited_at: u64,
    /// How long this envelope is kept.
    ///
    /// Per envelope rather than per store because retention is something an
    /// operator may sell: one deposit may be kept a week and the next a month.
    /// Holding a single store-wide value would make a tier that promises longer
    /// retention a promise nothing enforces.
    ttl_seconds: u64,
}

/// An in-memory blind mailbox.
///
/// A persistent implementation would replace the map with a keyed store; the
/// interface is deliberately narrow so that swap changes nothing else.
#[derive(Debug, Default)]
pub struct Mailbox {
    slots: HashMap<Tag, Vec<Stored>>,
    ttl_seconds: u64,
}

impl Mailbox {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            slots: HashMap::new(),
            ttl_seconds,
        }
    }

    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_TTL_SECONDS)
    }

    /// Deposit an envelope with this store's defaults.
    pub fn deposit(&mut self, envelope: Envelope, now: u64) -> Result<(), StoreError> {
        self.deposit_with(envelope, now, self.ttl_seconds, MAX_PER_TAG)
    }

    /// Deposit an envelope under explicit retention.
    ///
    /// `ttl_seconds` and `max_per_tag` come from the depositor's tier. The
    /// depositor is still never identified or recorded: what arrives here is a
    /// pair of numbers, not a customer.
    ///
    /// `max_per_tag` is capped at [`MAX_PER_TAG`] regardless of what is asked
    /// for, so a tier cannot be configured into letting one tag consume the
    /// whole store.
    pub fn deposit_with(
        &mut self,
        envelope: Envelope,
        now: u64,
        ttl_seconds: u64,
        max_per_tag: usize,
    ) -> Result<(), StoreError> {
        let ceiling = max_per_tag.min(MAX_PER_TAG);
        let slot = self.slots.entry(envelope.tag()).or_default();

        // Count only what is still live, or a tag stays full until the sweep
        // runs even though everything in it has expired.
        let live = slot
            .iter()
            .filter(|s| !Self::expired(s, now, s.ttl_seconds))
            .count();

        if live >= ceiling {
            return Err(StoreError::TagFull);
        }

        slot.push(Stored {
            envelope,
            deposited_at: now,
            ttl_seconds,
        });
        Ok(())
    }

    /// How many live envelopes wait under `tag`. For capacity accounting only.
    pub fn pending(&self, tag: Tag, now: u64) -> usize {
        self.slots
            .get(&tag)
            .map(|slot| {
                slot.iter()
                    .filter(|s| !Self::expired(s, now, s.ttl_seconds))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Collect and remove everything waiting under `tag`.
    ///
    /// Collection is destructive: an envelope handed over is gone. A client
    /// that crashes mid-collection loses those messages, which is the correct
    /// trade: the alternative is a mailbox that keeps copies, and that is
    /// exactly what we are trying not to build.
    pub fn collect(&mut self, tag: Tag, now: u64) -> Vec<Envelope> {
        let Some(slot) = self.slots.remove(&tag) else {
            return Vec::new();
        };

        slot.into_iter()
            .filter(|s| !self.is_expired(s, now))
            .map(|s| s.envelope)
            .collect()
    }

    /// Collect across a recipient's whole polling window in one call.
    pub fn collect_many(&mut self, tags: &[Tag], now: u64) -> Vec<Envelope> {
        tags.iter()
            .flat_map(|t| self.collect(*t, now))
            .collect()
    }

    /// Drop everything past its TTL. A deployment runs this periodically;
    /// expiry is also enforced on collection so a lapsed sweep cannot cause an
    /// expired envelope to be served.
    pub fn sweep(&mut self, now: u64) -> usize {
        let mut removed = 0;
        self.slots.retain(|_, slot| {
            let before = slot.len();
            slot.retain(|s| !Self::expired(s, now, s.ttl_seconds));
            removed += before - slot.len();
            !slot.is_empty()
        });
        removed
    }

    /// Total envelopes held. For operator capacity metrics only: it says
    /// nothing about who or what.
    pub fn len(&self) -> usize {
        self.slots.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Everything held, for an operator to write down and read back.
    ///
    /// Returns the raw pairs rather than a file format, so the crate that
    /// stores them owns the encryption. A mailbox that wrote plaintext to disk
    /// would be handing a future seizure the tags it spends the rest of its
    /// design hiding.
    pub fn snapshot(&self) -> Vec<(Tag, Vec<u8>)> {
        self.slots
            .iter()
            .filter_map(|(tag, slot)| {
                postcard::to_allocvec(slot).ok().map(|bytes| (*tag, bytes))
            })
            .collect()
    }

    /// Restore from a snapshot, dropping anything already expired.
    pub fn restore(ttl_seconds: u64, entries: Vec<(Tag, Vec<u8>)>, now: u64) -> Self {
        let mut mailbox = Self::new(ttl_seconds);

        for (tag, bytes) in entries {
            let Ok(slot) = postcard::from_bytes::<Vec<Stored>>(&bytes) else {
                continue;
            };
            let live: Vec<Stored> = slot
                .into_iter()
                .filter(|s| !Self::expired(s, now, s.ttl_seconds))
                .collect();

            if !live.is_empty() {
                mailbox.slots.insert(tag, live);
            }
        }
        mailbox
    }

    fn is_expired(&self, s: &Stored, now: u64) -> bool {
        Self::expired(s, now, s.ttl_seconds)
    }

    fn expired(s: &Stored, now: u64, ttl: u64) -> bool {
        now.saturating_sub(s.deposited_at) >= ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::TagKey;

    fn tag(n: u64) -> Tag {
        TagKey::new([1u8; 32]).tag_for_epoch(n)
    }

    fn env(t: Tag, body: &[u8]) -> Envelope {
        Envelope::seal(t, body).expect("seal")
    }

    #[test]
    fn deposit_then_collect() {
        let mut mb = Mailbox::with_default_ttl();
        let t = tag(1);

        mb.deposit(env(t, b"uno"), 0).expect("deposit");
        let got = mb.collect(t, 1);

        assert_eq!(got.len(), 1);
        assert_eq!(&got[0].payload()[..3], b"uno");
    }

    #[test]
    fn collection_is_destructive() {
        let mut mb = Mailbox::with_default_ttl();
        let t = tag(1);

        mb.deposit(env(t, b"uno"), 0).expect("deposit");
        assert_eq!(mb.collect(t, 1).len(), 1);
        assert_eq!(mb.collect(t, 1).len(), 0, "nothing may survive collection");
        assert!(mb.is_empty());
    }

    #[test]
    fn collecting_an_unknown_tag_yields_nothing() {
        let mut mb = Mailbox::with_default_ttl();
        assert!(mb.collect(tag(99), 0).is_empty());
    }

    #[test]
    fn envelopes_expire() {
        let mut mb = Mailbox::new(100);
        let t = tag(1);

        mb.deposit(env(t, b"viejo"), 0).expect("deposit");
        assert!(
            mb.collect(t, 100).is_empty(),
            "an envelope at its TTL must not be served"
        );
    }

    /// Expiry must hold even if the periodic sweep has not run: otherwise a
    /// missed sweep silently extends retention.
    #[test]
    fn expiry_is_enforced_on_collection_not_only_on_sweep() {
        let mut mb = Mailbox::new(10);
        let t = tag(1);

        mb.deposit(env(t, b"a"), 0).expect("deposit");
        mb.deposit(env(t, b"b"), 20).expect("deposit");

        let got = mb.collect(t, 25);
        assert_eq!(got.len(), 1, "only the fresh envelope survives");
        assert_eq!(&got[0].payload()[..1], b"b");
    }

    #[test]
    fn sweep_removes_expired_and_reports_the_count() {
        let mut mb = Mailbox::new(10);
        mb.deposit(env(tag(1), b"a"), 0).expect("deposit");
        mb.deposit(env(tag(2), b"b"), 0).expect("deposit");
        // Age 5 at sweep time, so this one survives.
        mb.deposit(env(tag(3), b"c"), 55).expect("deposit");

        assert_eq!(mb.sweep(60), 2);
        assert_eq!(mb.len(), 1);
    }

    /// Expiry is inclusive: an envelope exactly at its TTL is already gone.
    ///
    /// Pinned as its own test because the boundary is a security choice, when
    /// in doubt a mailbox should forget early, not late, and an off-by-one
    /// here silently extends retention for every message in the system.
    #[test]
    fn an_envelope_expires_at_exactly_its_ttl() {
        let mut mb = Mailbox::new(10);
        let t = tag(1);

        mb.deposit(env(t, b"a"), 0).expect("deposit");
        assert_eq!(mb.sweep(9), 0, "one second short of the TTL it survives");

        mb.deposit(env(tag(2), b"b"), 0).expect("deposit");
        assert_eq!(mb.sweep(10), 2, "at the TTL it is gone");
    }

    #[test]
    fn a_tag_cannot_be_filled_without_limit() {
        let mut mb = Mailbox::with_default_ttl();
        let t = tag(1);

        for _ in 0..MAX_PER_TAG {
            mb.deposit(env(t, b"x"), 0).expect("deposit");
        }
        assert!(matches!(
            mb.deposit(env(t, b"x"), 0),
            Err(StoreError::TagFull)
        ));
    }

    #[test]
    fn polling_window_collects_across_epochs() {
        let mut mb = Mailbox::with_default_ttl();
        let key = TagKey::new([1u8; 32]);

        // The sender's clock lagged: it deposited under an earlier epoch.
        mb.deposit(env(key.tag_for_epoch(8), b"tarde"), 0).expect("deposit");
        mb.deposit(env(key.tag_for_epoch(10), b"ahora"), 0).expect("deposit");

        let got = mb.collect_many(&key.polling_tags(10, 3), 1);
        assert_eq!(got.len(), 2, "lookback must find the lagged deposit");
    }

    /// The store holds no identity of any kind: everything it maps is a tag
    /// derived from a key it does not have.
    #[test]
    fn the_store_never_sees_an_identity() {
        let mut mb = Mailbox::with_default_ttl();
        let t = tag(1);
        mb.deposit(env(t, b"secret"), 0).expect("deposit");

        // The only key material in the store is the tag itself.
        let keys: Vec<Tag> = mb.slots.keys().copied().collect();
        assert_eq!(keys, vec![t]);
    }
}
