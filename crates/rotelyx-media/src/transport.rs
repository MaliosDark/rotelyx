//! Carrying protected frames over the Rotelyx transport.
//!
//! # Why datagrams and not a stream
//!
//! Everything else in Rotelyx travels over a QUIC stream, which is ordered and
//! reliable. For audio that is the wrong guarantee twice over.
//!
//! A stream that loses a packet stops delivering until the retransmission
//! arrives. The frames behind the gap are already decoded and waiting, and the
//! transport holds them back to preserve an order the audio does not need. The
//! result is a stall that grows with the round trip, which is exactly the
//! stutter that makes a call unbearable on a bad connection.
//!
//! And a retransmitted frame is worthless. By the time it arrives its twenty
//! milliseconds have passed. Spending bandwidth and delay to deliver audio that
//! will be thrown away makes the next frame late too.
//!
//! So media takes QUIC's unreliable datagrams: lost is lost, late is dropped,
//! and the jitter buffer above decides what to do about it.
//!
//! # A call is never on a direct path
//!
//! The one policy this module enforces rather than accepts. Constructing a
//! media session over a connection whose policy permits a direct path is
//! refused, because on a call the address a direct path reveals goes to the
//! other participants rather than to an operator.

use rotelyx_path::PathPolicy;

use std::collections::BTreeMap;

use crate::jitter::{JitterBuffer, Mode, Playout};
use crate::{MediaError, Receiver, Sender, SenderKeys};

/// The largest protected frame that may be sent.
///
/// QUIC datagrams are not fragmented: one that exceeds the path MTU is refused
/// rather than split, which is the behaviour audio wants. 1100 bytes leaves
/// room under a 1200 byte minimum QUIC MTU for headers, and a 20 ms Opus frame
/// at any sensible bitrate is a small fraction of it.
///
/// A video frame is not a fraction of it, which is why video will need its own
/// fragmentation layer above this rather than a larger number here.
pub const MAX_FRAME: usize = 1100;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error(
        "a call refuses to run on a connection that permits a direct path: on a call the \
         address a direct path reveals goes to the other participants, not to an operator"
    )]
    DirectPathPermitted,

    #[error("protected frame is {len} bytes, over the {MAX_FRAME} a datagram carries")]
    TooLarge { len: usize },

    #[error(transparent)]
    Media(#[from] MediaError),
}

/// One participant's outgoing media, bound to a connection.
///
/// Holds no connection itself: `frame` returns bytes and the caller hands them
/// to `send_datagram`. Keeping the socket out means the whole path can be
/// tested without one, which is the only way the size and policy rules get
/// exercised at all.
/// How many recently sent frames are kept for retransmission.
///
/// 256 frames is 5.12 seconds, which matches the anti-replay window: a frame
/// older than that would be refused on arrival anyway, so holding it would be
/// holding something that cannot be used. At a hundred bytes a frame this is
/// about 26 KB per sender.
const HISTORY: usize = 256;

pub struct MediaOut {
    sender: Sender,
    mode: Mode,

    /// Recently sent frames, by counter, kept so a receiver can ask for one
    /// again.
    ///
    /// Already protected, so a retransmission is the identical bytes rather
    /// than a re-encryption. Re-encrypting would need a fresh counter, and a
    /// fresh counter would land in a slot the receiver has already passed.
    history: BTreeMap<u64, Vec<u8>>,
}

impl MediaOut {
    /// Refuses unless the connection's policy forbids a direct path.
    pub fn new(policy: PathPolicy, keys: SenderKeys) -> Result<Self, TransportError> {
        Self::with_mode(policy, keys, Mode::Conversational)
    }

    pub fn with_mode(
        policy: PathPolicy,
        keys: SenderKeys,
        mode: Mode,
    ) -> Result<Self, TransportError> {
        if policy.permits_direct() {
            return Err(TransportError::DirectPathPermitted);
        }
        Ok(Self {
            sender: Sender::new(keys)?,
            mode,
            history: BTreeMap::new(),
        })
    }

    /// A frame that was sent before, for a receiver that did not get it.
    ///
    /// `None` when it has aged out, which is the honest answer: the receiver
    /// would refuse it as too old anyway, and pretending otherwise would put a
    /// packet on the wire that cannot help.
    pub fn resend(&self, counter: u64) -> Option<Vec<u8>> {
        self.history.get(&counter).cloned()
    }

    /// How many frames are still available to resend.
    pub fn recoverable(&self) -> usize {
        self.history.len()
    }

    /// Protect one frame and check it fits a datagram.
    ///
    /// Refusing here rather than at `send_datagram` means an oversized frame is
    /// a caller error with a clear cause, not a transport error at the far end
    /// of an encode pipeline.
    pub fn frame(&mut self, audio: &[u8]) -> Result<Vec<u8>, TransportError> {
        let counter = self.sender.frames_sent();
        let protected = self.sender.protect(audio)?;

        if protected.len() > MAX_FRAME {
            return Err(TransportError::TooLarge {
                len: protected.len(),
            });
        }

        // Only fidelity mode can use a retransmission, so only fidelity mode
        // pays the memory for one.
        if self.mode == Mode::Fidelity {
            self.history.insert(counter, protected.clone());
            while self.history.len() > HISTORY {
                let oldest = *self.history.keys().next().expect("non-empty");
                self.history.remove(&oldest);
            }
        }

        Ok(protected)
    }

    /// How many plaintext bytes fit in a datagram of `datagram_bytes`.
    ///
    /// A layered encoder needs this before it decides how many refinements to
    /// attach: the answer is the datagram size less this sender's current
    /// header and its tag, and the header grows as the call goes on.
    pub fn payload_budget(&self, datagram_bytes: usize) -> usize {
        self.sender.payload_budget(datagram_bytes)
    }

    /// The earliest counter still in the retransmission history.
    ///
    /// The receiver needs this to recover the start of a call: it cannot see a
    /// gap before the first frame it ever received.
    pub fn oldest_recoverable(&self) -> Option<u64> {
        self.history.keys().next().copied()
    }

    pub fn frames_sent(&self) -> u64 {
        self.sender.frames_sent()
    }
}

/// One participant's incoming media: decrypt, then buffer for playback.
///
/// The two belong together. A frame that fails to authenticate and a frame that
/// arrives after its slot are both dropped, and separating the two stages would
/// mean a caller had to know which of them was responsible in order to do
/// nothing about either.
pub struct MediaIn {
    receiver: Receiver,
    buffer: JitterBuffer,

    /// Frames refused since the session began.
    ///
    /// Counted rather than logged: on a call these are ordinary, and a log line
    /// per lost packet is a denial of service against the operator's disk.
    dropped: u64,
}

impl MediaIn {
    pub fn new(policy: PathPolicy, keys: SenderKeys) -> Result<Self, TransportError> {
        Self::with_mode(policy, keys, Mode::Conversational)
    }

    pub fn with_mode(
        policy: PathPolicy,
        keys: SenderKeys,
        mode: Mode,
    ) -> Result<Self, TransportError> {
        if policy.permits_direct() {
            return Err(TransportError::DirectPathPermitted);
        }
        Ok(Self {
            receiver: Receiver::new(keys)?,
            buffer: JitterBuffer::with_mode(mode),
            dropped: 0,
        })
    }

    /// The counters to ask the far end to send again.
    ///
    /// Empty in conversational mode, where a recovered frame arrives after the
    /// slot it belonged to. In fidelity mode this is the whole mechanism:
    /// a deep buffer is time, and time is enough round trips to get back what
    /// the network dropped.
    pub fn to_recover(&self) -> Vec<u64> {
        self.buffer.recoverable()
    }

    /// The counters to ask for, when the far end has said how many it sent.
    ///
    /// The version that can recover the tail of a recording. A gap is normally
    /// visible because something arrived behind it; the last frames have
    /// nothing behind them, so the sender's own count is the only way to know
    /// they are missing rather than that the speaker stopped.
    /// As [`Self::to_recover_through`], but also told the earliest counter the
    /// sender can still supply, which is the only way the start of a call can
    /// be recovered. See [`JitterBuffer::recoverable_between`].
    pub fn to_recover_between(&self, oldest_sent: Option<u64>, highest_sent: u64) -> Vec<u64> {
        self.buffer.recoverable_between(oldest_sent, highest_sent)
    }

    pub fn to_recover_through(&self, highest_sent: u64) -> Vec<u64> {
        self.buffer.recoverable_through(highest_sent)
    }

    /// Unprotect one datagram and buffer it for playback.
    ///
    /// A frame that does not authenticate, repeats, or arrives too late is
    /// counted and discarded rather than raised. On a call every one of those
    /// is a normal event, and a caller that had to handle each as an error
    /// would either stop the call or ignore the result.
    ///
    /// `now_ms` is arrival time on the local clock, which the buffer uses to
    /// follow the network's jitter.
    pub fn accept(&mut self, datagram: &[u8], now_ms: u64) {
        // The counter has to be read before decryption to know where the frame
        // belongs, and it is safe to read early only because nothing acts on it
        // until the tag has verified: `unprotect` checks the replay window and
        // the tag itself.
        let Ok((_, counter, _)) = SenderKeys::parse_header(datagram) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };

        match self.receiver.unprotect(datagram) {
            Ok(audio) => self.buffer.push(counter, now_ms, audio),
            Err(_) => self.dropped = self.dropped.saturating_add(1),
        }
    }

    /// Take the frame for the next playback slot.
    ///
    /// Called on the audio device's clock, once every `FRAME_MS`.
    pub fn play(&mut self) -> Playout {
        self.buffer.pop()
    }

    /// Unprotect one datagram and return it immediately, bypassing the buffer.
    ///
    /// For tests and for a caller doing its own buffering. A real call uses
    /// `accept` and `play`.
    pub fn frame(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        match self.receiver.unprotect(datagram) {
            Ok(audio) => Some(audio),
            Err(_) => {
                self.dropped = self.dropped.saturating_add(1);
                None
            }
        }
    }

    /// The buffer's current target depth, in milliseconds. What a call quality
    /// indicator shows as latency.
    pub fn delay_ms(&self) -> u32 {
        self.buffer.target_ms()
    }

    /// How many frames were discarded. The number a call quality indicator
    /// should be reading.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(id: u8) -> SenderKeys {
        SenderKeys::derive(&[7u8; 32], id)
    }

    /// The rule this module exists to enforce.
    #[test]
    fn a_call_refuses_every_policy_that_allows_a_direct_path() {
        for policy in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
        ] {
            assert!(
                matches!(
                    MediaOut::new(policy, keys(0)),
                    Err(TransportError::DirectPathPermitted)
                ),
                "{policy:?} was accepted for a call"
            );
            assert!(MediaIn::new(policy, keys(0)).is_err(), "{policy:?} on the way in");
        }

        assert!(MediaOut::new(PathPolicy::RelayOnly, keys(0)).is_ok());
        assert!(MediaIn::new(PathPolicy::RelayOnly, keys(0)).is_ok());
    }

    #[test]
    fn a_frame_crosses_the_transport() {
        let mut out = MediaOut::new(PathPolicy::RelayOnly, keys(1)).expect("out");
        let mut incoming = MediaIn::new(PathPolicy::RelayOnly, keys(1)).expect("in");

        for n in 0..40u32 {
            let audio = format!("frame {n}").into_bytes();
            let datagram = out.frame(&audio).expect("protect");
            assert_eq!(incoming.frame(&datagram), Some(audio));
        }
        assert_eq!(incoming.dropped(), 0);
    }

    /// A datagram is not fragmented, so an oversized frame must be refused
    /// where the cause is visible rather than at the socket.
    #[test]
    fn an_oversized_frame_is_refused_before_the_socket() {
        let mut out = MediaOut::new(PathPolicy::RelayOnly, keys(1)).expect("out");

        assert!(out.frame(&vec![0u8; MAX_FRAME - 100]).is_ok());
        assert!(matches!(
            out.frame(&vec![0u8; MAX_FRAME]),
            Err(TransportError::TooLarge { .. })
        ));
    }

    /// Loss, reordering and duplication are ordinary on a call. None of them
    /// may stop it.
    #[test]
    fn a_lossy_link_does_not_stop_the_call() {
        let mut out = MediaOut::new(PathPolicy::RelayOnly, keys(1)).expect("out");
        let mut incoming = MediaIn::new(PathPolicy::RelayOnly, keys(1)).expect("in");

        let frames: Vec<Vec<u8>> = (0..20)
            .map(|n| out.frame(format!("{n}").as_bytes()).expect("protect"))
            .collect();

        let mut heard = 0;
        for (n, frame) in frames.iter().enumerate() {
            if n % 3 == 0 {
                continue; // lost in the network
            }
            if incoming.frame(frame).is_some() {
                heard += 1;
            }
            // A duplicate, which the replay window must refuse without fuss.
            assert!(incoming.frame(frame).is_none());
        }

        assert_eq!(heard, 13, "the frames that arrived were all played");
        assert_eq!(incoming.dropped(), 13, "each duplicate was counted");
    }

    /// The whole chain: protect, cross a network that misbehaves, decrypt,
    /// buffer, play on a steady clock.
    #[test]
    fn a_call_survives_a_network_that_misbehaves() {
        let mut out = MediaOut::new(PathPolicy::RelayOnly, keys(1)).expect("out");
        let mut incoming = MediaIn::new(PathPolicy::RelayOnly, keys(1)).expect("in");

        let spoken: Vec<Vec<u8>> = (0..60u64)
            .map(|n| format!("frame {n}").into_bytes())
            .collect();

        let datagrams: Vec<Vec<u8>> = spoken
            .iter()
            .map(|audio| out.frame(audio).expect("protect"))
            .collect();

        // Delivered with loss, reordering, duplication and jitter.
        let mut arrival = 0u64;
        for (n, datagram) in datagrams.iter().enumerate() {
            arrival += if n % 5 == 0 { 45 } else { 12 };

            if n % 11 == 0 {
                continue; // lost
            }

            if n % 7 == 0 && n + 1 < datagrams.len() {
                // Swapped with the next one.
                incoming.accept(&datagrams[n + 1], arrival);
                incoming.accept(datagram, arrival + 3);
                continue;
            }

            incoming.accept(datagram, arrival);
            if n % 13 == 0 {
                incoming.accept(datagram, arrival + 1); // duplicate
            }
        }

        // Play the whole call out, then trim the silence after the last frame:
        // pops past the end of the audio are the call finishing, not gaps in
        // it, and counting them would make any test of loss meaningless.
        let mut played = Vec::new();
        for _ in 0..200 {
            match incoming.play() {
                Playout::Starved => break,
                other => played.push(other),
            }
        }
        while matches!(played.last(), Some(Playout::Missing)) {
            played.pop();
        }

        let heard = played
            .iter()
            .filter(|p| match p {
                Playout::Frame(audio) => {
                    assert!(spoken.contains(audio), "played something never spoken");
                    true
                }
                _ => false,
            })
            .count();
        let concealed = played.len() - heard;

        assert!(
            heard >= 50,
            "only {heard} of 60 frames survived a network that is bad but ordinary"
        );
        assert!(
            concealed <= 10,
            "{concealed} gaps inside the call, against the 6 frames actually lost"
        );
        assert!(
            incoming.delay_ms() <= crate::jitter::MAX_DELAY_MS,
            "the buffer let the delay run away"
        );
    }

    /// The mode this project exists to offer: a network dropping one packet in
    /// five, and not a word lost.
    ///
    /// Every real-time stack would conceal those packets and the listener would
    /// hear the holes. This one spends the delay it is allowed and asks for
    /// them back.
    #[test]
    fn fidelity_mode_loses_nothing_on_a_network_dropping_a_fifth() {
        let mut out =
            MediaOut::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("out");
        let mut incoming =
            MediaIn::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("in");

        let spoken: Vec<Vec<u8>> = (0..200u64)
            .map(|n| format!("word {n}").into_bytes())
            .collect();

        let mut arrival = 0u64;
        let mut heard: Vec<Vec<u8>> = Vec::new();

        for (n, audio) in spoken.iter().enumerate() {
            let datagram = out.frame(audio).expect("protect");
            arrival += 20;

            // One packet in five never arrives.
            if n % 5 != 3 {
                incoming.accept(&datagram, arrival);
            }

            // The receiver notices the gaps and asks for them; the sender still
            // holds them. This is one round trip's worth of recovery per frame
            // period, which a 2 second buffer affords a hundred times over.
            for counter in incoming.to_recover() {
                if let Some(again) = out.resend(counter) {
                    incoming.accept(&again, arrival);
                }
            }

            // Play out whatever is ready.
            loop {
                match incoming.play() {
                    Playout::Frame(audio) => heard.push(audio),
                    // Waiting and Starved both mean "not yet", which in this
                    // mode is a promise rather than a failure.
                    _ => break,
                }
            }
        }

        // Drain, still asking for what is missing. A receiver does not stop
        // requesting a frame because the speaker stopped talking, and the tail
        // of a recording is exactly where a one-shot drain loses a word.
        let sent_through = out.frames_sent() - 1;
        for _ in 0..400 {
            for counter in incoming.to_recover_through(sent_through) {
                if let Some(again) = out.resend(counter) {
                    arrival += 1;
                    incoming.accept(&again, arrival);
                }
            }
            match incoming.play() {
                Playout::Frame(audio) => heard.push(audio),
                Playout::Waiting => continue,
                _ => break,
            }
        }

        assert_eq!(
            heard.len(),
            spoken.len(),
            "{} of {} frames survived: fidelity mode lost audio",
            heard.len(),
            spoken.len()
        );
        assert_eq!(heard, spoken, "the words arrived out of order or altered");
    }

    /// The same network in conversational mode. The loss is heard, and that is
    /// the correct behaviour there: a recovered frame would arrive after the
    /// slot it belonged to.
    #[test]
    fn conversational_mode_accepts_the_loss_the_other_recovers() {
        let mut out = MediaOut::new(PathPolicy::RelayOnly, keys(1)).expect("out");
        let mut incoming = MediaIn::new(PathPolicy::RelayOnly, keys(1)).expect("in");

        let mut arrival = 0u64;
        for n in 0..100u64 {
            let datagram = out.frame(format!("{n}").as_bytes()).expect("protect");
            arrival += 20;
            if n % 5 != 3 {
                incoming.accept(&datagram, arrival);
            }
        }

        assert!(
            incoming.to_recover().is_empty(),
            "conversational mode must not ask for frames it could not use"
        );
        assert_eq!(
            out.recoverable(),
            0,
            "and must not pay memory for a history it will never read"
        );

        let mut gaps = 0;
        for _ in 0..120 {
            match incoming.play() {
                Playout::Missing => gaps += 1,
                Playout::Starved => break,
                _ => {}
            }
        }
        assert!(gaps > 10, "the loss should be audible here, and it is what it is");
    }

    /// Where "nothing is cut off" stops being true.
    ///
    /// The other test shows fidelity mode losing nothing at one packet in two.
    /// That invites the question this answers: what does break it, and at what
    /// point. The answer is not loss. Every retransmission is lost at the same
    /// rate as the original, so the chance a frame never arrives after `n`
    /// rounds is `p^n`, which goes to zero however bad `p` is. What runs out is
    /// **time**: the sender keeps only `HISTORY` frames, so a frame that has
    /// not made it across in that many frame periods is gone for good.
    ///
    /// So the limit is a number of round trips, not a percentage, and the thing
    /// that costs is delay rather than words.
    #[test]
    fn where_recovery_stops_working() {
        println!("\n  loss    heard/spoken   frames lost   worst delay");
        for percent in [10u64, 30, 50, 70, 80, 90, 95, 98] {
            let mut out =
                MediaOut::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("out");
            let mut incoming =
                MediaIn::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("in");

            let spoken: Vec<Vec<u8>> = (0..200u64).map(|n| format!("{n}").into_bytes()).collect();

            // A deterministic source, so a surprise can be reproduced.
            let mut seed = 0x2545_f491_4f6c_dd1du64;
            let mut lost = |()| -> bool {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed % 100 < percent
            };

            let mut arrival = 0u64;
            let mut heard: Vec<Vec<u8>> = Vec::new();
            let mut sent_at = std::collections::HashMap::new();
            let mut worst_delay = 0u64;

            for (n, audio) in spoken.iter().enumerate() {
                let datagram = out.frame(audio).expect("protect");
                arrival += 20;
                sent_at.insert(n as u64, arrival);

                if !lost(()) {
                    incoming.accept(&datagram, arrival);
                }

                for counter in incoming.to_recover_between(out.oldest_recoverable(), out.frames_sent() - 1) {
                    if lost(()) {
                        continue;
                    }
                    if let Some(again) = out.resend(counter) {
                        incoming.accept(&again, arrival);
                    }
                }

                while let Playout::Frame(audio) = incoming.play() {
                    let index: u64 = String::from_utf8_lossy(&audio).parse().unwrap_or(0);
                    worst_delay = worst_delay.max(arrival - sent_at[&index]);
                    heard.push(audio);
                }
            }

            // Drain: a receiver keeps asking after the speaker stops.
            let through = out.frames_sent() - 1;
            for _ in 0..2_000 {
                for counter in incoming.to_recover_between(out.oldest_recoverable(), through) {
                    if lost(()) {
                        continue;
                    }
                    if let Some(again) = out.resend(counter) {
                        arrival += 1;
                        incoming.accept(&again, arrival);
                    }
                }
                while let Playout::Frame(audio) = incoming.play() {
                    let index: u64 = String::from_utf8_lossy(&audio).parse().unwrap_or(0);
                    worst_delay = worst_delay.max(arrival.saturating_sub(sent_at[&index]));
                    heard.push(audio);
                }
            }

            let got: std::collections::HashSet<u64> = heard
                .iter()
                .map(|a| String::from_utf8_lossy(a).parse().unwrap_or(u64::MAX))
                .collect();
            let missing: Vec<u64> = (0..spoken.len() as u64).filter(|n| !got.contains(n)).collect();

            println!(
                "  {percent:>3}%   {:>4}/{:<4}      {:>6}        {:>5} ms   missing: {:?}",
                heard.len(),
                spoken.len(),
                spoken.len() - heard.len(),
                worst_delay,
                &missing[..missing.len().min(15)]
            );

            // The whole point of the mode. Loss costs delay, never words.
            assert!(
                missing.is_empty(),
                "at {percent}% loss the call lost {} frames: {:?}. Fidelity mode \
                 is allowed to be slow and is not allowed to be short",
                missing.len(),
                &missing[..missing.len().min(15)]
            );
        }
        println!("\n  History is {HISTORY} frames, which at 20 ms each is {} ms of", HISTORY * 20);
        println!("  room for retransmission. That, not the loss rate, is the limit.");
    }

    /// Where it actually breaks, measured rather than claimed.
    ///
    /// A single recovery attempt per frame period is one round trip. The
    /// interesting number is how much loss survives that, and what happens past
    /// it: the answer should be that quality degrades rather than that the call
    /// falls over.
    #[test]
    fn the_loss_it_survives_is_measured() {
        for (drop_one_in, expect_perfect) in
            [(10u64, true), (5, true), (3, true), (2, true)]
        {
            let mut out =
                MediaOut::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("out");
            let mut incoming =
                MediaIn::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("in");

            let spoken: Vec<Vec<u8>> = (0..150u64).map(|n| format!("{n}").into_bytes()).collect();
            let mut arrival = 0u64;
            let mut round = 0u64;
            let mut heard: Vec<Vec<u8>> = Vec::new();

            for (n, audio) in spoken.iter().enumerate() {
                let datagram = out.frame(audio).expect("protect");
                arrival += 20;

                if (n as u64) % drop_one_in != drop_one_in - 1 {
                    incoming.accept(&datagram, arrival);
                }

                // One recovery round per frame period. The retransmissions are
                // lost at the same rate, which is what makes this a real test
                // rather than a demonstration.
                //
                // Loss keyed on the counter and the round, not on position in
                // the list: keying it on position drops the same slot every
                // round, which is a pathology no network produces and which no
                // amount of retransmission can escape.
                round += 1;
                for counter in incoming.to_recover_through(out.frames_sent() - 1) {
                    if (counter + round) % drop_one_in == drop_one_in - 1 {
                        continue;
                    }
                    if let Some(again) = out.resend(counter) {
                        incoming.accept(&again, arrival);
                    }
                }

                while let Playout::Frame(audio) = incoming.play() {
                    heard.push(audio);
                }
            }

            // Drain, still asking. A receiver does not stop requesting a frame
            // because the speaker stopped talking, and the tail of a recording
            // is exactly where a one-shot drain quietly loses a word.
            let sent_through = out.frames_sent() - 1;
            for _ in 0..600 {
                round += 1;
                for counter in incoming.to_recover_through(sent_through) {
                    if (counter + round) % drop_one_in == drop_one_in - 1 {
                        continue;
                    }
                    if let Some(again) = out.resend(counter) {
                        arrival += 1;
                        incoming.accept(&again, arrival);
                    }
                }
                match incoming.play() {
                    Playout::Frame(audio) => heard.push(audio),
                    Playout::Waiting => continue,
                    _ => break,
                }
            }

            let lost = spoken.len() - heard.len();
            if expect_perfect {
                assert_eq!(
                    lost, 0,
                    "one packet in {drop_one_in} lost {lost} frames, and this mode promises none"
                );
            }
            assert_eq!(
                heard,
                spoken[..heard.len()],
                "one packet in {drop_one_in}: what arrived was out of order"
            );
        }
    }

    /// A frame too old to be accepted must not be offered for resend. Putting
    /// it on the wire would spend bandwidth on something the receiver refuses.
    #[test]
    fn a_frame_past_the_window_is_not_offered_again() {
        let mut out =
            MediaOut::with_mode(PathPolicy::RelayOnly, keys(1), Mode::Fidelity).expect("out");

        for n in 0..400u64 {
            out.frame(format!("{n}").as_bytes()).expect("protect");
        }

        assert!(out.resend(399).is_some(), "the most recent is available");
        assert!(
            out.resend(0).is_none(),
            "the first frame is long past the anti-replay window and must not be re-sent"
        );
        assert!(out.recoverable() <= HISTORY);
    }

    /// Garbage on the wire must be counted and dropped, never raised. A caller
    /// that had to handle every corrupted packet as an error would either stop
    /// the call or learn to ignore the result.
    #[test]
    fn garbage_is_counted_rather_than_raised() {
        let mut incoming = MediaIn::new(PathPolicy::RelayOnly, keys(1)).expect("in");

        assert_eq!(incoming.frame(&[]), None);
        assert_eq!(incoming.frame(&[0xff; 200]), None);
        assert_eq!(incoming.frame(&[0x21, 0x01, 0x02]), None);
        assert_eq!(incoming.dropped(), 3);
    }
}
