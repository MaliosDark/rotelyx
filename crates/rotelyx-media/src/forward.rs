//! Routing media for a group call without being able to read it.
//!
//! # Why a forwarding unit at all
//!
//! Below a handful of participants nothing is needed: everybody sends to
//! everybody. The cost of that is quadratic in the wrong place. Each speaker
//! uploads one copy per listener, so a six-way call asks a phone on a home
//! connection to upload five streams at once, and phones on home connections are
//! where calls actually happen. A forwarder takes one copy and makes five.
//!
//! # What it can and cannot see
//!
//! It cannot read a frame. The media key is exported from the MLS epoch and the
//! forwarder is not in the group, so what it holds is a header and a sealed
//! body, and the header is authenticated as associated data rather than
//! encrypted precisely so that this is possible: [`crate::SenderKeys::header`]
//! carries a sender id and a counter, which is enough to route and nothing more.
//! This is the shape SFrame (RFC 9605) uses, followed rather than invented so
//! that a forwarder written by somebody else could do the same job.
//!
//! What it does see, unavoidably, is **which sender each datagram came from and
//! when**. Over a conversation that is its rhythm: who interrupts whom, who
//! goes quiet when a name is mentioned, how long each person holds the floor.
//! That is most of what a transcript would tell you about a meeting, and no
//! amount of encryption touches it.
//!
//! Two things narrow it, and both are the caller's to switch on:
//!
//! - [`crate::Sender::pad_to`] makes every datagram the same size, so silence
//!   and speech stop being distinguishable by length. Without it the sizes alone
//!   are a voice activity detector anybody on the path can run.
//! - [`Forwarder::relay_silence`] keeps a stream flowing from a participant who
//!   has stopped sending, so the forwarder's *output* does not go quiet when a
//!   person does. It costs bandwidth for people who are not talking, which is
//!   exactly what it is buying.
//!
//! Neither hides the sender id from the forwarder itself. That would need the
//! frames to be onion-routed or the group to be small enough not to need one,
//! and it is worth saying plainly rather than implying a property this does not
//! have.
//!
//! # What this module is not
//!
//! It is the routing decision, not a server. It holds no sockets, spawns
//! nothing, and does not authenticate anybody: given a datagram and the
//! participant it arrived from, it says where the copies go. Admission, tying a
//! connection to a participant, and the sockets themselves belong to whatever
//! runs it, the way `rotelyx-relay` wraps its own admission around
//! `rotelyx-relay-proto`.

use std::collections::HashMap;

use crate::{MediaError, SenderKeys, MAX_SENDERS};

/// What a forwarder refuses.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    #[error("the call already has {MAX_SENDERS} participants")]
    Full,

    #[error("participant {id} is already in this call")]
    AlreadyJoined { id: u8 },

    #[error("participant {id} is not in this call")]
    NotJoined { id: u8 },

    #[error(
        "a datagram claiming to be from participant {claimed} arrived on \
         participant {arrived_on}'s connection"
    )]
    WrongSender { claimed: u8, arrived_on: u8 },

    #[error(transparent)]
    Media(#[from] MediaError),
}

/// One call's participants.
#[derive(Debug, Default)]
pub struct Forwarder {
    /// Frames seen per participant, so an operator can see a stream stop without
    /// being told anything about what was in it.
    seen: HashMap<u8, u64>,
    relay_silence: bool,
}

/// Where one arriving datagram goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    /// The participants this copy is for. Never includes the sender.
    pub to: Vec<u8>,
    /// Which participant sent it, read from the header.
    pub from: u8,
    /// Its counter, read from the header. Not used for routing; carried so an
    /// operator can see loss without decrypting.
    pub counter: u64,
}

impl Forwarder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep a participant's stream flowing to the others when they stop
    /// sending. Off by default: it costs bandwidth for people not talking.
    pub fn relay_silence(&mut self, on: bool) {
        self.relay_silence = on;
    }

    pub fn join(&mut self, id: u8) -> Result<(), ForwardError> {
        if usize::from(id) >= MAX_SENDERS {
            return Err(ForwardError::Media(MediaError::SenderOutOfRange { id }));
        }
        if self.seen.contains_key(&id) {
            return Err(ForwardError::AlreadyJoined { id });
        }
        if self.seen.len() >= MAX_SENDERS {
            return Err(ForwardError::Full);
        }
        self.seen.insert(id, 0);
        Ok(())
    }

    pub fn leave(&mut self, id: u8) -> Result<(), ForwardError> {
        self.seen
            .remove(&id)
            .map(|_| ())
            .ok_or(ForwardError::NotJoined { id })
    }

    pub fn participants(&self) -> Vec<u8> {
        let mut ids: Vec<u8> = self.seen.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Frames forwarded for each participant so far.
    pub fn frames_seen(&self, id: u8) -> Option<u64> {
        self.seen.get(&id).copied()
    }

    /// Route one datagram that arrived on `arrived_on`'s connection.
    ///
    /// # Why the connection is checked against the header
    ///
    /// The sender id in the header is not authenticated to the forwarder: it is
    /// associated data, so the *recipients* can tell it was not altered, but the
    /// forwarder holds no key and cannot check anything. Without this a
    /// participant could put somebody else's id in its header and the forwarder
    /// would deliver it as though it came from them.
    ///
    /// The recipients would refuse it, because the tag is under the real
    /// sender's key. But they would refuse it *after* the impersonated stream
    /// had already consumed their replay window at those counters, which is a
    /// way to silence somebody without ever holding their key. So it is caught
    /// here, where the connection is the thing that is actually known.
    pub fn route(&mut self, arrived_on: u8, datagram: &[u8]) -> Result<Routed, ForwardError> {
        let (claimed, counter, _) = SenderKeys::parse_header(datagram)?;

        if !self.seen.contains_key(&arrived_on) {
            return Err(ForwardError::NotJoined { id: arrived_on });
        }
        if claimed != arrived_on {
            return Err(ForwardError::WrongSender {
                claimed,
                arrived_on,
            });
        }

        if let Some(count) = self.seen.get_mut(&arrived_on) {
            *count = count.saturating_add(1);
        }

        let mut to: Vec<u8> = self
            .seen
            .keys()
            .copied()
            .filter(|&id| id != arrived_on)
            .collect();
        to.sort_unstable();

        Ok(Routed {
            to,
            from: arrived_on,
            counter,
        })
    }

    /// Whether a participant's stream should be kept alive towards the others.
    ///
    /// The forwarder cannot invent a frame: it has no key, so anything it made
    /// up would fail every recipient's tag check. What it can do is tell the
    /// caller that a stream has gone quiet, and let the caller decide, which for
    /// a real deployment means asking that participant's client to keep sending.
    /// Whether that is worth the bandwidth is why this is a switch.
    pub fn wants_filler(&self, id: u8) -> bool {
        self.relay_silence && self.seen.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {

    /// A fixed binding, for the cases that are not about the binding itself.
    fn test_call() -> crate::CallBinding {
        crate::CallBinding::new(b"a-test-call-0001").expect("long enough")
    }
    use super::*;
    use crate::{Receiver, Sender};

    fn keys(id: u8) -> (Sender, Receiver) {
        let base = [7u8; 32];
        let sender = Sender::new(SenderKeys::derive(&base, id, &test_call())).expect("sender");
        let receiver = Receiver::new(SenderKeys::derive(&base, id, &test_call())).expect("receiver");
        (sender, receiver)
    }

    #[test]
    fn a_frame_goes_to_everybody_except_the_person_who_sent_it() {
        let mut forwarder = Forwarder::new();
        for id in [1u8, 2, 3, 4] {
            forwarder.join(id).expect("join");
        }

        let (mut sender, _) = keys(2);
        let datagram = sender.protect(b"a coded frame").expect("protect");

        let routed = forwarder.route(2, &datagram).expect("route");
        assert_eq!(routed.from, 2);
        assert_eq!(
            routed.to,
            vec![1, 3, 4],
            "a speaker was sent their own voice back"
        );
    }

    /// The forwarder holds no key, so it must not be the thing that decides a
    /// sender id is genuine.
    #[test]
    fn a_participant_cannot_send_as_somebody_else() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");
        forwarder.join(2).expect("join");

        // Participant 2 builds a frame under participant 1's id and puts it on
        // its own connection.
        let (mut impostor, _) = keys(1);
        let datagram = impostor.protect(b"not mine to send").expect("protect");

        assert_eq!(
            forwarder.route(2, &datagram),
            Err(ForwardError::WrongSender {
                claimed: 1,
                arrived_on: 2
            })
        );
    }

    /// What is forwarded has to still open on the other side. If routing touched
    /// a byte the tag would fail, and it would fail only in a real call.
    #[test]
    fn what_comes_out_still_opens() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");
        forwarder.join(2).expect("join");

        let (mut sender, _) = keys(1);
        let (_, mut receiver) = keys(1);

        let frame = b"the audio itself";
        let datagram = sender.protect(frame).expect("protect");
        let routed = forwarder.route(1, &datagram).expect("route");

        assert_eq!(routed.to, vec![2]);
        assert_eq!(
            receiver.unprotect(&datagram).expect("unprotect"),
            frame,
            "the frame did not survive being forwarded"
        );
    }

    #[test]
    fn a_stranger_is_not_forwarded_for() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");

        let (mut sender, _) = keys(9);
        let datagram = sender.protect(b"uninvited").expect("protect");

        assert_eq!(
            forwarder.route(9, &datagram),
            Err(ForwardError::NotJoined { id: 9 })
        );
    }

    #[test]
    fn leaving_stops_the_copies() {
        let mut forwarder = Forwarder::new();
        for id in [1u8, 2, 3] {
            forwarder.join(id).expect("join");
        }
        forwarder.leave(2).expect("leave");

        let (mut sender, _) = keys(1);
        let datagram = sender.protect(b"still talking").expect("protect");
        assert_eq!(forwarder.route(1, &datagram).expect("route").to, vec![3]);

        assert_eq!(forwarder.leave(2), Err(ForwardError::NotJoined { id: 2 }));
    }

    #[test]
    fn one_person_in_a_call_sends_to_nobody() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");

        let (mut sender, _) = keys(1);
        let datagram = sender.protect(b"hello?").expect("protect");
        assert!(forwarder.route(1, &datagram).expect("route").to.is_empty());
    }

    #[test]
    fn a_call_cannot_hold_more_participants_than_the_header_can_name() {
        let mut forwarder = Forwarder::new();
        for id in 0..MAX_SENDERS as u8 {
            forwarder.join(id).expect("join");
        }
        assert_eq!(
            forwarder.join(MAX_SENDERS as u8),
            Err(ForwardError::Media(MediaError::SenderOutOfRange {
                id: MAX_SENDERS as u8
            }))
        );
        assert_eq!(forwarder.participants().len(), MAX_SENDERS);
    }

    /// The counter is carried through so an operator can see loss. It must not
    /// be the thing that decides anything: that is the receiver's replay window.
    #[test]
    fn the_counter_travels_but_decides_nothing() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");
        forwarder.join(2).expect("join");

        let (mut sender, _) = keys(1);
        let first = sender.protect(b"one").expect("protect");
        let second = sender.protect(b"two").expect("protect");

        assert_eq!(forwarder.route(1, &first).expect("route").counter, 0);
        assert_eq!(forwarder.route(1, &second).expect("route").counter, 1);

        // And the same frame twice is still forwarded: refusing a replay is the
        // recipient's job, and a forwarder that dropped it would be deciding
        // something it cannot check.
        assert_eq!(forwarder.route(1, &first).expect("route").to, vec![2]);
        assert_eq!(forwarder.frames_seen(1), Some(3));
    }

    #[test]
    fn filler_is_off_until_it_is_asked_for() {
        let mut forwarder = Forwarder::new();
        forwarder.join(1).expect("join");
        assert!(!forwarder.wants_filler(1));

        forwarder.relay_silence(true);
        assert!(forwarder.wants_filler(1));
        assert!(!forwarder.wants_filler(2), "for somebody not in the call");
    }
}
