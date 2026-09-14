//! The constellation directory, and where a tag is placed across mailboxes.
//!
//! # What a constellation is, and what this crate is
//!
//! A conversation's envelopes live on a mailbox. With one mailbox that mailbox
//! is a single point of failure and a single point of load, and it is the one
//! operator that sees all of the conversation's activity. A constellation is a set
//! of mailboxes among which each conversation's tag is placed on a few, so the
//! conversation survives one going down, the load spreads, and no single
//! operator sees the whole. See `docs/CONSTELLATION.md`.
//!
//! This crate is the part of that which is pure computation: the directory (the
//! list of mailboxes in a constellation) and the placement function (which
//! mailboxes hold a given tag). It touches no network and holds no state, so it
//! can be reviewed on its own, the way the front's sealed session and the relay
//! circuit were. Serving the directory and using it are the caller's job.
//!
//! # Why there is no signature here
//!
//! Trust in which mailboxes are real is the domain, not a signature. Every
//! Rotelyx mailbox is a subdomain of one domain the operator owns, TLS proves a
//! server is really under that domain, and the client already refuses to speak
//! to any host that is not (the `no_foreign_infrastructure` guard). So a
//! directory is a list of that domain's own subdomains, and a forged entry is
//! rejected because it is not under the domain or cannot present the domain's
//! certificate. A signature would only earn its place if the constellation ever
//! spanned domains the one operator does not own, which is a later question the
//! format leaves room for and this crate does not decide.
//!
//! # Placement: rendezvous hashing
//!
//! Both ends of a conversation share the tag and both hold the directory, so
//! both must compute the same set of mailboxes from those two things with no
//! coordination. Rendezvous hashing (highest random weight, Thaler and
//! Ravishankar, 1996) does exactly that: score every mailbox against the tag,
//! sort, take the top few. It is chosen over consistent hashing because it needs
//! no ring to maintain and, more importantly, because adding or removing one
//! mailbox re-places only the tags that scored it into or out of the top set,
//! not the whole space, so a constellation that grows does not reshuffle every
//! conversation at once.

use serde::{Deserialize, Serialize};

/// A mailbox in a constellation: a stable id, and where to reach it now.
///
/// The id and the address are separate on purpose. Placement hashes the **id**,
/// so the id is what must be stable: a mailbox keeps its id for life, and its
/// address can change (a new subdomain, a move) without moving a single tag off
/// it. The address is only where a client connects once placement has named the
/// mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    /// The stable identifier hashed for placement. Any distinct string per
    /// mailbox; it never changes for the life of the mailbox.
    pub id: String,
    /// Where a client reaches this mailbox now, for example a WebSocket URL.
    /// May change without moving any tag, because placement hashes the id.
    pub url: String,
}

/// The list of mailboxes in a constellation, and how many hold each tag.
///
/// # Forward compatibility
///
/// Unknown fields are ignored rather than refused, so a newer directory that
/// carries a field this build has not heard of still parses and is usable. This
/// is the rule the whole protocol keeps: a change is additive, and an old client
/// reads a new document by ignoring what it does not know. A directory that
/// dropped this and refused unknown fields would break every old client the
/// moment a field was added, which is the one failure constellation exists to
/// avoid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    /// Bumped each time the set changes, so a client keeps the newest it has
    /// seen and ignores an older one that arrives late.
    pub version: u64,
    /// How many mailboxes hold each tag. Two survives one failure; three
    /// survives two. It lives here rather than in the client so it can be
    /// raised without a client change.
    pub replicas: usize,
    /// The mailboxes, in any order. Placement does not depend on the order.
    pub mailboxes: Vec<Mailbox>,
}

impl Directory {
    /// Parse a directory from its JSON bytes, ignoring fields not known here.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The directory as JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        // Serialising a list of strings and integers cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The mailboxes that hold this tag, most preferred first.
    ///
    /// The top `replicas` mailboxes by rendezvous score, or all of them when the
    /// constellation is smaller than `replicas`. Both ends of a conversation call
    /// this with the same tag and the same directory and get the same list, in
    /// the same order, which is what lets a depositor write to all of them and a
    /// collector read from any of them without either side being told where the
    /// other looked.
    pub fn placement(&self, tag: &[u8; 32]) -> Vec<Mailbox> {
        let mut scored: Vec<(u64, &Mailbox)> = self
            .mailboxes
            .iter()
            .map(|m| (score(&m.id, tag), m))
            .collect();

        // Highest score first. A tie is broken by the id so the order is total
        // and every client resolves it the same way; two mailboxes almost never
        // tie on a 64 bit score, and when they do the result must still be
        // deterministic rather than left to sort's stability.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));

        scored
            .into_iter()
            .take(self.replicas)
            .map(|(_, m)| m.clone())
            .collect()
    }
}

/// How a tag's placement changes when the directory does.
///
/// A client holding live conversations needs three lists when a new directory
/// arrives, not just the new placement: the mailboxes now holding the tag that
/// were not before (`added`, to subscribe to and begin depositing to), the ones
/// that held it and no longer do (`removed`, to stop subscribing to), and the
/// ones in both (`kept`, already connected, left alone). Applying only the
/// difference is what keeps a set change cheap: rendezvous hashing moves a tag
/// off a mailbox only when the change actually reordered its top set, so for
/// most tags `added` and `removed` are empty and the client does nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementDelta {
    /// Mailboxes in the new placement that were not in the old one.
    pub added: Vec<Mailbox>,
    /// Mailboxes in the old placement that are not in the new one.
    pub removed: Vec<Mailbox>,
    /// Mailboxes in both, by id. Their address is taken from the new directory,
    /// so a mailbox that only changed its url appears here with the new url and
    /// the client reconnects to it rather than treating it as unchanged.
    pub kept: Vec<Mailbox>,
}

impl PlacementDelta {
    /// Whether nothing about where this tag lives changed. The common case, and
    /// the one a client can skip all work for.
    pub fn is_unchanged(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl Directory {
    /// Whether this directory should replace `current` for a client that holds
    /// both. Newer by version wins; an equal or older version is ignored, so a
    /// stale copy arriving late never rolls a client back. Version is the only
    /// thing compared: two directories with the same version are treated as the
    /// same even if their contents differ, because the operator bumps the
    /// version whenever the set changes, and trusting content order instead
    /// would let a replayed old copy with a coincidental field difference win.
    pub fn supersedes(&self, current: &Directory) -> bool {
        self.version > current.version
    }

    /// What changes for one tag when moving from this directory to `next`.
    ///
    /// Called on the directory a client currently holds, with the newer one it
    /// just fetched. The result is the difference to apply for that tag: what to
    /// subscribe to, what to drop, what to leave. See [`PlacementDelta`]. A
    /// mailbox that kept the tag but changed its url is reported in `kept` with
    /// its new url, because the client must reconnect there.
    pub fn placement_delta(&self, next: &Directory, tag: &[u8; 32]) -> PlacementDelta {
        let before = self.placement(tag);
        let after = next.placement(tag);

        let before_ids: std::collections::HashSet<&str> =
            before.iter().map(|m| m.id.as_str()).collect();
        let after_ids: std::collections::HashSet<&str> =
            after.iter().map(|m| m.id.as_str()).collect();

        let added = after
            .iter()
            .filter(|m| !before_ids.contains(m.id.as_str()))
            .cloned()
            .collect();
        let removed = before
            .iter()
            .filter(|m| !after_ids.contains(m.id.as_str()))
            .cloned()
            .collect();
        // Kept mailboxes carry the new directory's address, so a url change is
        // seen and reconnected to rather than silently kept on the stale one.
        let kept = after
            .iter()
            .filter(|m| before_ids.contains(m.id.as_str()))
            .cloned()
            .collect();

        PlacementDelta { added, removed, kept }
    }
}

/// The rendezvous score of one mailbox for one tag.
///
/// `blake3(id || tag)`, read as a big-endian u64. The id and the tag are length
/// prefixed so that no two different `(id, tag)` pairs produce the same input
/// bytes: without a boundary, an id ending in a byte and a tag beginning with
/// one could collide with a different split of the same concatenation. Length
/// prefixing is the same defence the group wrap and the circuit binding use.
fn score(id: &str, tag: &[u8; 32]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    hasher.update(tag);
    let digest = hasher.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(first8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(id: &str) -> Mailbox {
        Mailbox {
            id: id.into(),
            url: format!("wss://{id}.telyx.me/mailbox"),
        }
    }

    fn directory(ids: &[&str], replicas: usize) -> Directory {
        Directory {
            version: 1,
            replicas,
            mailboxes: ids.iter().map(|i| mailbox(i)).collect(),
        }
    }

    fn tag(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn both_ends_compute_the_same_placement() {
        // The property the whole thing rests on: two independent computations
        // of the same tag against the same directory agree, in order.
        let dir = directory(&["a", "b", "c", "d", "e"], 2);
        let t = tag(7);
        assert_eq!(dir.placement(&t), dir.placement(&t));
    }

    #[test]
    fn placement_returns_replicas_mailboxes() {
        let dir = directory(&["a", "b", "c", "d", "e"], 2);
        assert_eq!(dir.placement(&tag(1)).len(), 2);
        assert_eq!(directory(&["a", "b", "c", "d", "e"], 3).placement(&tag(1)).len(), 3);
    }

    #[test]
    fn fewer_mailboxes_than_replicas_returns_all() {
        // A constellation of two with a replica factor of three places on both,
        // rather than failing or inventing a third.
        let dir = directory(&["a", "b"], 3);
        assert_eq!(dir.placement(&tag(1)).len(), 2);
    }

    #[test]
    fn different_tags_land_on_different_sets() {
        // If every tag landed on the same mailboxes the constellation would shard
        // nothing. Over many tags the placements must vary.
        let dir = directory(&["a", "b", "c", "d", "e"], 2);
        let mut seen = std::collections::HashSet::new();
        for seed in 0..64u8 {
            let ids: Vec<String> = dir.placement(&tag(seed)).into_iter().map(|m| m.id).collect();
            seen.insert(ids);
        }
        assert!(seen.len() > 5, "placements barely varied: {}", seen.len());
    }

    #[test]
    fn load_spreads_roughly_evenly() {
        // Every mailbox should be first for roughly its fair share of tags. With
        // five mailboxes that is a fifth each; the bound is loose because this
        // is a hash, not a guarantee, but a badly skewed hash would fail it.
        let dir = directory(&["a", "b", "c", "d", "e"], 1);
        let mut count = std::collections::HashMap::new();
        let trials = 5000u32;
        for i in 0..trials {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&i.to_be_bytes());
            let first = dir.placement(&t).remove(0).id;
            *count.entry(first).or_insert(0u32) += 1;
        }
        let fair = trials / 5;
        for (id, n) in &count {
            assert!(
                *n > fair / 2 && *n < fair * 2,
                "mailbox {id} got {n} of {trials}, far from the fair {fair}"
            );
        }
        assert_eq!(count.len(), 5, "every mailbox should be first for some tags");
    }

    #[test]
    fn adding_a_mailbox_moves_only_a_small_share() {
        // The reason rendezvous hashing rather than a fixed assignment: growing
        // the constellation re-places only the tags that scored the newcomer into
        // their top set, not everything. From five to six, well under half of
        // placements should change.
        let before = directory(&["a", "b", "c", "d", "e"], 2);
        let after = directory(&["a", "b", "c", "d", "e", "f"], 2);
        let mut moved = 0;
        let trials = 3000u32;
        for i in 0..trials {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&i.to_be_bytes());
            let b: Vec<String> = before.placement(&t).into_iter().map(|m| m.id).collect();
            let a: Vec<String> = after.placement(&t).into_iter().map(|m| m.id).collect();
            if a != b {
                moved += 1;
            }
        }
        assert!(
            moved < trials / 2,
            "adding one mailbox moved {moved} of {trials}, which is too many"
        );
    }

    #[test]
    fn a_url_change_does_not_move_a_tag() {
        // Placement hashes the id, so a mailbox that changes its address keeps
        // every tag it held. This is what lets a mailbox move without a
        // reshuffle, and why id and url are separate.
        let dir = directory(&["a", "b", "c"], 2);
        let mut moved = dir.clone();
        moved.mailboxes[0].url = "wss://a-new.telyx.me/mailbox".into();
        for seed in 0..64u8 {
            let one: Vec<String> = dir.placement(&tag(seed)).into_iter().map(|m| m.id).collect();
            let two: Vec<String> = moved.placement(&tag(seed)).into_iter().map(|m| m.id).collect();
            assert_eq!(one, two, "a url change moved a tag");
        }
    }

    #[test]
    fn an_empty_constellation_places_nothing() {
        let dir = directory(&[], 2);
        assert!(dir.placement(&tag(1)).is_empty());
    }

    #[test]
    fn a_directory_survives_the_wire() {
        let dir = directory(&["a", "b", "c"], 2);
        let back = Directory::from_json(&dir.to_json()).expect("parse");
        assert_eq!(back, dir);
    }

    #[test]
    fn an_unknown_field_is_ignored_not_refused() {
        // The forward-compatibility rule: a newer directory with a field this
        // build has not heard of still parses, so a change never breaks an old
        // client. See the note on `Directory`.
        let json = br#"{"version":3,"replicas":2,"region":"someday","mailboxes":[{"id":"a","url":"wss://a.telyx.me/mailbox","note":"new"}]}"#;
        let dir = Directory::from_json(json).expect("an unknown field must not refuse the parse");
        assert_eq!(dir.version, 3);
        assert_eq!(dir.mailboxes[0].id, "a");
    }

    #[test]
    fn a_newer_version_supersedes_an_older_one() {
        let old = directory(&["a", "b", "c"], 2);
        let mut new = directory(&["a", "b", "c", "d"], 2);
        new.version = old.version + 1;
        assert!(new.supersedes(&old), "a higher version must win");
        assert!(!old.supersedes(&new), "a lower version must not");
        assert!(!new.supersedes(&new), "the same version is not newer than itself");
    }

    #[test]
    fn an_unchanged_directory_moves_no_tag() {
        // Refreshing to an identical set is a no-op for every tag: nothing is
        // added or removed, so the client does no work.
        let dir = directory(&["a", "b", "c", "d", "e"], 2);
        let same = dir.clone();
        for seed in 0..64u8 {
            let delta = dir.placement_delta(&same, &tag(seed));
            assert!(delta.is_unchanged(), "an identical refresh changed tag {seed}");
        }
    }

    #[test]
    fn a_url_change_is_reported_as_kept_with_the_new_address() {
        // A mailbox that only moved keeps every tag it held, but the client must
        // reconnect to the new address, so it appears in `kept` with the new url
        // and never in added or removed.
        let dir = directory(&["a", "b", "c"], 2);
        let mut moved = dir.clone();
        moved.version += 1;
        moved.mailboxes[0].url = "wss://a-moved.telyx.me/mailbox".into();
        let mut saw_new_url = false;
        for seed in 0..64u8 {
            let t = tag(seed);
            let delta = dir.placement_delta(&moved, &t);
            assert!(delta.is_unchanged(), "a url change must not add or remove for tag {seed}");
            if let Some(m) = delta.kept.iter().find(|m| m.id == "a") {
                assert_eq!(m.url, "wss://a-moved.telyx.me/mailbox", "kept must carry the new url");
                saw_new_url = true;
            }
        }
        assert!(saw_new_url, "mailbox a should have held some tag to check");
    }

    #[test]
    fn adding_a_mailbox_moves_only_a_small_share_of_tags() {
        // The delta view of the churn property: growing the constellation adds or
        // removes a replica for well under half of tags, and for the rest the
        // delta is empty. This is the same guarantee as the placement level
        // test, seen the way a client applies it.
        let before = directory(&["a", "b", "c", "d", "e"], 2);
        let mut after = directory(&["a", "b", "c", "d", "e", "f"], 2);
        after.version += 1;
        let mut changed = 0;
        let trials = 3000u32;
        for i in 0..trials {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&i.to_be_bytes());
            let delta = before.placement_delta(&after, &t);
            if !delta.is_unchanged() {
                changed += 1;
                // Whatever changed, the new placement still has `replicas`.
                assert_eq!(after.placement(&t).len(), 2);
            }
        }
        assert!(
            changed < trials / 2,
            "adding one mailbox changed {changed} of {trials} tags, too many"
        );
        assert!(changed > 0, "adding a mailbox should change at least some tags");
    }

    #[test]
    fn a_removed_mailbox_is_reported_for_the_tags_it_held() {
        // When a mailbox leaves, every tag it held reports it in `removed` and
        // names a replacement in `added`, so the client knows to resubscribe
        // elsewhere. The placement stays full at `replicas`.
        let before = directory(&["a", "b", "c", "d", "e"], 2);
        let mut after = directory(&["a", "b", "c", "d"], 2); // e is gone
        after.version += 1;
        let mut e_removed_somewhere = false;
        for i in 0..500u32 {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&i.to_be_bytes());
            let delta = before.placement_delta(&after, &t);
            if delta.removed.iter().any(|m| m.id == "e") {
                e_removed_somewhere = true;
                // Losing a replica is made up by a new one, so the count holds.
                assert_eq!(delta.added.len(), delta.removed.len());
                assert_eq!(after.placement(&t).len(), 2);
            }
            assert!(!delta.kept.iter().chain(&delta.added).any(|m| m.id == "e"),
                "a gone mailbox must not appear as kept or added");
        }
        assert!(e_removed_somewhere, "e held some tags before it left");
    }

    #[test]
    fn the_score_is_a_frozen_vector() {
        // A pinned value, so a change to the hashing or the byte layout that
        // would re-place every tag in a running constellation fails here first and
        // is therefore a deliberate act rather than a silent break. See the
        // backward-compatibility rule: a change to placement is not additive,
        // so it must never happen by accident.
        assert_eq!(score("m1", &[0x11; 32]), 0x45c8_8497_6849_d6a1);
    }
}
