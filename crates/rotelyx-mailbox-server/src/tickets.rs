//! Where a device leaves word of how to wake it, without saying who it is.
//!
//! # What is stored
//!
//! `tag -> sealed tickets`. A ticket is a push token sealed to the notifier's
//! key, and this server has no way to read one. Every ticket is freshly
//! randomised, so the same device leaving one under each of its tags leaves
//! rows with nothing in common: there is no repeated value to follow across a
//! rotation, which is the whole reason the rotation exists.
//!
//! # Why several per tag
//!
//! A person has more than one device, and each one seals its own. A tag is a
//! member of a conversation, not a handset.
//!
//! # Why they expire
//!
//! The notifier refuses a ticket past its own window, so one kept here beyond
//! that is a row that can never do anything. Dropping it is tidiness rather
//! than a control, and the control it looks like should not be mistaken for
//! one: a ticket buys a contentless wake and nothing else.

use std::collections::HashMap;

use rotelyx_mailbox::Tag;

/// How many devices may leave a ticket under one tag.
///
/// A person with a phone, a tablet and a desktop is three. Eight is generous
/// and still bounds what one tag can cost in wakes.
pub const MAX_PER_TAG: usize = 8;

/// How many tags may hold tickets at once.
///
/// The same shape of bound as the mailbox itself: without one, leaving tickets
/// under invented tags is a way to fill memory for free.
pub const MAX_TAGS: usize = 200_000;

/// How long a row is kept, in seconds.
///
/// Matches the window the notifier will honour. Keeping one longer would keep
/// a row that can no longer wake anybody.
pub const TICKET_TTL: u64 = 48 * 3600;

struct Left {
    ticket: String,
    at: u64,
}

/// Tickets, by tag.
#[derive(Default)]
pub struct Tickets {
    by_tag: HashMap<Tag, Vec<Left>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// This server is holding tickets under as many tags as it will.
    Full,
    /// This tag already has as many devices as it may.
    TagFull,
}

impl Tickets {
    /// Leave a ticket under a tag, replacing this device's previous one.
    ///
    /// Replacement is by exact bytes, which never matches: two tickets from
    /// one device are different every time. So a device that re-registers adds
    /// a row rather than updating one, and [`MAX_PER_TAG`] is what stops that
    /// growing without end. That is deliberate and it is the cost of the rows
    /// being unlinkable: to update one you would have to be able to recognise
    /// it, and nobody here can.
    pub fn leave(&mut self, tag: Tag, ticket: String, now: u64) -> Result<(), Refused> {
        if !self.by_tag.contains_key(&tag) && self.by_tag.len() >= MAX_TAGS {
            return Err(Refused::Full);
        }

        let held = self.by_tag.entry(tag).or_default();
        held.retain(|l| now.saturating_sub(l.at) < TICKET_TTL);

        if held.len() >= MAX_PER_TAG {
            // The oldest goes, because a device that has not renewed in two
            // days is one whose ticket the notifier would refuse anyway.
            held.remove(0);
        }

        held.push(Left { ticket, at: now });
        Ok(())
    }

    /// Every live ticket under a tag.
    pub fn for_tag(&self, tag: &Tag, now: u64) -> Vec<String> {
        self.by_tag
            .get(tag)
            .map(|held| {
                held.iter()
                    .filter(|l| now.saturating_sub(l.at) < TICKET_TTL)
                    .map(|l| l.ticket.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Tickets belonging to other tags, to send alongside a real one.
    ///
    /// # Why this is not random enough to be called random
    ///
    /// The set is walked from an arbitrary starting point rather than sampled
    /// uniformly, because a `HashMap` has no cheap uniform sample and this
    /// runs on the path of every deposit. What the decoys have to achieve is
    /// that the notifier cannot tell which ticket was the real one, and for
    /// that they only have to be indistinguishable *to it*: it opens all of
    /// them, pushes all of them, and sees the same shape either way.
    ///
    /// What they do not achieve is hiding anything from somebody watching this
    /// server choose them. That is the mailbox operator, who already knows the
    /// tag, and is not who decoys are for.
    pub fn decoys(&self, avoid: &Tag, want: usize, now: u64, from: usize) -> Vec<String> {
        if want == 0 || self.by_tag.is_empty() {
            return Vec::new();
        }

        let start = from % self.by_tag.len();
        let mut out = Vec::with_capacity(want);

        for (tag, held) in self.by_tag.iter().cycle().skip(start).take(self.by_tag.len()) {
            if tag == avoid {
                continue;
            }
            if let Some(l) = held
                .iter()
                .find(|l| now.saturating_sub(l.at) < TICKET_TTL)
            {
                out.push(l.ticket.clone());
                if out.len() == want {
                    break;
                }
            }
        }

        out
    }

    /// Drop what can no longer wake anybody.
    pub fn sweep(&mut self, now: u64) {
        self.by_tag.retain(|_, held| {
            held.retain(|l| now.saturating_sub(l.at) < TICKET_TTL);
            !held.is_empty()
        });
    }

    pub fn tags(&self) -> usize {
        self.by_tag.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(seed: u8) -> Tag {
        Tag::from_bytes(&[seed; 32]).expect("thirty two bytes")
    }

    #[test]
    fn a_ticket_comes_back_under_its_own_tag_and_no_other() {
        let mut tickets = Tickets::default();
        tickets.leave(tag(1), "one".into(), 0).expect("leave");
        tickets.leave(tag(2), "two".into(), 0).expect("leave");

        assert_eq!(tickets.for_tag(&tag(1), 0), vec!["one".to_owned()]);
        assert_eq!(tickets.for_tag(&tag(2), 0), vec!["two".to_owned()]);
        assert!(tickets.for_tag(&tag(3), 0).is_empty());
    }

    #[test]
    fn several_devices_may_share_a_tag() {
        let mut tickets = Tickets::default();
        for n in 0..3 {
            tickets.leave(tag(1), format!("device-{n}"), 0).expect("leave");
        }
        assert_eq!(tickets.for_tag(&tag(1), 0).len(), 3);
    }

    /// One tag must not be able to cost unbounded wakes.
    #[test]
    fn a_tag_holds_only_so_many() {
        let mut tickets = Tickets::default();
        for n in 0..MAX_PER_TAG + 5 {
            tickets.leave(tag(1), format!("device-{n}"), 0).expect("leave");
        }
        assert_eq!(tickets.for_tag(&tag(1), 0).len(), MAX_PER_TAG);
    }

    /// A row that can no longer wake anybody is not kept.
    #[test]
    fn a_ticket_past_its_window_is_gone() {
        let mut tickets = Tickets::default();
        tickets.leave(tag(1), "one".into(), 0).expect("leave");

        assert_eq!(tickets.for_tag(&tag(1), TICKET_TTL - 1).len(), 1);
        assert!(tickets.for_tag(&tag(1), TICKET_TTL).is_empty());

        tickets.sweep(TICKET_TTL);
        assert_eq!(tickets.tags(), 0, "the empty tag was kept");
    }

    /// The decoys must never include the tag they are hiding.
    ///
    /// A decoy set that contained the real tag's other tickets would narrow
    /// rather than widen: the notifier would see a group where more than one
    /// belonged together.
    #[test]
    fn decoys_never_come_from_the_tag_being_hidden() {
        let mut tickets = Tickets::default();
        tickets.leave(tag(1), "real-a".into(), 0).expect("leave");
        tickets.leave(tag(1), "real-b".into(), 0).expect("leave");
        for n in 2..12u8 {
            tickets.leave(tag(n), format!("other-{n}"), 0).expect("leave");
        }

        let decoys = tickets.decoys(&tag(1), 5, 0, 0);
        assert_eq!(decoys.len(), 5);
        assert!(
            !decoys.iter().any(|d| d.starts_with("real-")),
            "a decoy came from the tag it was hiding: {decoys:?}"
        );
    }

    /// Asking for more decoys than exist gives what there is rather than
    /// looping for ever.
    #[test]
    fn asking_for_more_decoys_than_exist_terminates() {
        let mut tickets = Tickets::default();
        tickets.leave(tag(1), "real".into(), 0).expect("leave");
        tickets.leave(tag(2), "other".into(), 0).expect("leave");

        let decoys = tickets.decoys(&tag(1), 50, 0, 0);
        assert_eq!(decoys, vec!["other".to_owned()]);
    }

    #[test]
    fn decoys_from_an_empty_store_are_none() {
        let tickets = Tickets::default();
        assert!(tickets.decoys(&tag(1), 5, 0, 0).is_empty());
    }

    /// Different starting points reach different tags, or the same handful
    /// would be woken for every deposit on the server.
    #[test]
    fn where_the_walk_starts_changes_what_it_finds() {
        let mut tickets = Tickets::default();
        for n in 1..30u8 {
            tickets.leave(tag(n), format!("t-{n}"), 0).expect("leave");
        }

        let seen: std::collections::BTreeSet<String> = (0..30)
            .flat_map(|from| tickets.decoys(&tag(1), 3, 0, from))
            .collect();

        assert!(
            seen.len() > 3,
            "every deposit drew the same decoys: {} distinct",
            seen.len()
        );
    }
}
