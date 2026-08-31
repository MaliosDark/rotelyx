//! The jitter buffer.
//!
//! # Why this is the piece that decides whether a call sounds good
//!
//! Frames are produced every twenty milliseconds and arrive whenever the
//! network feels like delivering them. The playback device, meanwhile, wants a
//! frame every twenty milliseconds exactly and has nothing useful to do with
//! one that is early or late. Something has to absorb the difference, and that
//! something is a queue with a deliberately chosen depth.
//!
//! The depth is the whole trade:
//!
//! - Too shallow and every late frame is a gap. The call sounds broken on a
//!   network that is merely ordinary.
//! - Too deep and every word arrives late. The call sounds fine and nobody can
//!   hold a conversation, because two people talking over each other by three
//!   hundred milliseconds is not a conversation.
//!
//! No fixed depth is right, because networks are not fixed. So the depth
//! follows the observed jitter, and how quickly it follows is itself a trade:
//! growing fast keeps a sudden burst of jitter from being heard, shrinking
//! slowly keeps the delay from oscillating audibly.
//!
//! # Why we write this rather than take one
//!
//! The codec is not worth writing: Opus is the result of a decade of work by
//! people who do nothing else, and a worse codec is worse in ways nobody can
//! argue with. A jitter buffer is different. It is a policy, it is small, and
//! its behaviour under a hostile network is exactly the thing a caller notices.
//! It is also the piece most implementations tune for the average case and
//! never for the case where somebody is on a train.

use std::collections::BTreeMap;

/// How long one frame represents, in milliseconds.
///
/// Twenty is the Opus default and what every sensible deployment uses: short
/// enough that a lost frame is not a syllable, long enough that per frame
/// overhead is not the packet.
pub const FRAME_MS: u32 = 20;

/// The shallowest the buffer will go.
///
/// One frame of slack. Below this any reordering at all is a gap, and even a
/// local network reorders.
pub const MIN_DELAY_MS: u32 = FRAME_MS;

/// The deepest a conversational call will buffer.
///
/// Two hundred milliseconds plus the network's own delay is already at the edge
/// of where a conversation stops feeling like one. Past this a conversational
/// call accepts gaps rather than becoming unusable, because a caller can talk
/// through gaps and cannot talk through delay.
pub const MAX_DELAY_MS: u32 = 200;

/// The deepest a fidelity call will buffer.
///
/// Five seconds. Deliberately far past anything conversational, because in this
/// mode delay is not the thing being protected.
pub const MAX_FIDELITY_DELAY_MS: u32 = 5_000;

/// What the call is optimising for.
///
/// # Two different products wearing the same name
///
/// Every real-time media stack in existence optimises latency and accepts loss,
/// because that is what a telephone call needs: two people interrupting each
/// other cannot be doing it half a second apart.
///
/// That is not the only thing a voice channel can be. A recorded message, a
/// briefing, a broadcast, anything where one person speaks and others listen,
/// wants the opposite: **every word arrives, however long it takes**. Nobody is
/// waiting to interrupt.
///
/// The two cannot be served by one setting, so they are two modes rather than a
/// number somebody tunes. What makes the second possible at all is the delay
/// itself: a deep buffer is time, and time is enough round trips to ask for
/// what went missing and get it back before the slot comes up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Latency first. A frame that has not arrived by its slot is concealed and
    /// the call moves on. What a telephone does.
    Conversational,

    /// Completeness first. The buffer runs deep, missing frames are asked for
    /// again, and a slot waits as long as the buffer allows before it gives up.
    ///
    /// Costs seconds of delay. Buys speech that does not cut out on a network
    /// that drops a tenth of everything.
    Fidelity,
}

impl Mode {
    fn max_delay_ms(self) -> u32 {
        match self {
            Mode::Conversational => MAX_DELAY_MS,
            Mode::Fidelity => MAX_FIDELITY_DELAY_MS,
        }
    }

    /// The depth a fidelity call holds regardless of how calm the network
    /// looks, because the point is to have room to recover when it stops
    /// looking calm.
    fn floor_ms(self) -> u32 {
        match self {
            Mode::Conversational => MIN_DELAY_MS,
            Mode::Fidelity => 2_000,
        }
    }
}

/// What a pop produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Playout {
    /// A frame, ready to decode.
    Frame(Vec<u8>),

    /// Nothing arrived in time for this slot.
    ///
    /// Not an error. The decoder should conceal it, which for Opus means
    /// calling the decoder with no data so it can extrapolate rather than
    /// producing a click.
    Missing,

    /// Nothing is buffered at all: the far end is silent or gone.
    Starved,

    /// The frame is not here yet and the slot is being held for it.
    ///
    /// Fidelity mode only. The caller should play silence for this slot and try
    /// again, rather than advancing: the frame is expected to arrive.
    Waiting,
}

/// Buffers frames and hands them out on a steady clock.
pub struct JitterBuffer {
    mode: Mode,
    frames: BTreeMap<u64, Vec<u8>>,

    /// The next counter to play. `None` until the first frame arrives, because
    /// a call does not necessarily start at zero.
    next: Option<u64>,

    /// The lowest counter ever seen, which is where playback begins.
    ///
    /// # Why this is not just the lowest frame in the buffer
    ///
    /// It was, and on a bad enough network that quietly ate the start of the
    /// call. Playback begins once the buffer reaches its target depth; under
    /// heavy loss the frames that filled it are late ones, and starting at the
    /// lowest *buffered* counter puts the play head past frames that had not
    /// arrived yet. They could still be recovered, and were, and then had
    /// nowhere to go.
    ///
    /// Measured with one packet in five surviving, the first 13 frames, 260 ms,
    /// were lost every time however long recovery was given. Not the tail, the
    /// head, and it was invisible at any loss rate up to one in two.
    ///
    /// Starting from the lowest counter *seen* turns those into ordinary gaps,
    /// which the waiting logic below already knows how to hold open. A receiver
    /// joining a call late is unaffected: the lowest it has seen is where it
    /// joined, not zero.
    lowest_seen: Option<u64>,

    /// Current target depth, in milliseconds.
    target_ms: u32,

    /// Smoothed inter-arrival jitter, in milliseconds.
    ///
    /// RFC 3550's estimator: `J += (|D| - J) / 16`. A first order filter with a
    /// long memory, so one late packet moves it a little and a sustained change
    /// moves it a lot.
    jitter_ms: f64,

    /// Arrival time and counter of the previous frame, for the jitter estimate.
    previous: Option<(u64, u64)>,

    /// Frames handed out, frames that were not there, frames refused for being
    /// too late. What a quality indicator reads.
    played: u64,
    missing: u64,
    late: u64,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    pub fn new() -> Self {
        Self::with_mode(Mode::Conversational)
    }

    /// A buffer optimising for the given mode.
    pub fn with_mode(mode: Mode) -> Self {
        Self {
            mode,
            frames: BTreeMap::new(),
            next: None,
            lowest_seen: None,
            target_ms: mode.floor_ms().max(MIN_DELAY_MS * 2),
            jitter_ms: 0.0,
            previous: None,
            played: 0,
            missing: 0,
            late: 0,
        }
    }

    /// Accept a frame.
    ///
    /// `counter` is the media frame counter and `now_ms` is arrival time on the
    /// local clock. Both are supplied rather than read here so the buffer is
    /// deterministic, which is the only way its behaviour under a given network
    /// can be asserted rather than described.
    pub fn push(&mut self, counter: u64, now_ms: u64, frame: Vec<u8>) {
        self.observe_jitter(counter, now_ms);

        // Recorded before the lateness check below, so that a frame recovered
        // from before the play head still tells us where the call began.
        self.lowest_seen = Some(match self.lowest_seen {
            Some(seen) => seen.min(counter),
            None => counter,
        });

        // A frame for a slot already played is not late, it is useless: the
        // audio for that instant has already gone to the device.
        if let Some(next) = self.next {
            if counter < next {
                self.late += 1;
                return;
            }
        }

        self.frames.insert(counter, frame);
    }

    /// Update the delay target from the arrival pattern.
    ///
    /// Grows quickly and shrinks slowly, on purpose. A burst of jitter that is
    /// not absorbed is heard immediately; a delay that is larger than it needs
    /// to be for a few seconds is not heard at all.
    fn observe_jitter(&mut self, counter: u64, now_ms: u64) {
        if let Some((last_counter, last_arrival)) = self.previous {
            let expected = (counter as i64 - last_counter as i64) * FRAME_MS as i64;
            let actual = now_ms as i64 - last_arrival as i64;
            let d = (actual - expected).abs() as f64;

            self.jitter_ms += (d - self.jitter_ms) / 16.0;

            // Three times the smoothed jitter covers the overwhelming majority
            // of arrivals for any distribution a network actually produces,
            // without chasing the tail into unusable delay.
            let wanted = ((self.jitter_ms * 3.0) as u32)
                .max(self.mode.floor_ms())
                .min(self.mode.max_delay_ms());

            self.target_ms = if wanted > self.target_ms {
                wanted
            } else {
                // Shrink by one frame at a time. Collapsing the buffer the
                // moment the network calms down means the next disturbance is
                // heard in full.
                self.target_ms.saturating_sub(1).max(wanted)
            };
        }

        self.previous = Some((counter, now_ms));
    }

    /// Take the frame for the next slot.
    ///
    /// Called on the playback clock, once per frame period.
    pub fn pop(&mut self) -> Playout {
        let Some(&lowest) = self.frames.keys().next() else {
            return if self.next.is_some() {
                // We know where we are and there is simply nothing buffered.
                Playout::Missing
            } else {
                Playout::Starved
            };
        };

        // The first frame of a call sets the position, and playback waits until
        // the buffer has reached its target depth. Starting immediately means
        // starting with an empty buffer, which means the first disturbance is a
        // gap.
        let next = match self.next {
            Some(next) => next,
            None => {
                if self.buffered_ms() < self.target_ms {
                    return Playout::Starved;
                }
                let start = self.lowest_seen.unwrap_or(lowest).min(lowest);
                self.next = Some(start);
                start
            }
        };

        self.next = Some(next + 1);

        match self.frames.remove(&next) {
            Some(frame) => {
                self.played += 1;
                Playout::Frame(frame)
            }
            None => {
                // The slot is empty but later frames are waiting.
                //
                // Conversationally the answer is to conceal and move on:
                // waiting would delay everything behind it to recover audio
                // already too late to matter.
                //
                // In fidelity mode the answer is the opposite. Hold the slot
                // while the buffer still has room, so a retransmission has time
                // to arrive. The cost is delay, which is the thing this mode
                // spends.
                if self.may_wait() {
                    self.next = Some(next);
                    return Playout::Waiting;
                }
                self.missing += 1;
                Playout::Missing
            }
        }
    }

    /// How much audio is buffered, in milliseconds.
    pub fn buffered_ms(&self) -> u32 {
        (self.frames.len() as u32).saturating_mul(FRAME_MS)
    }

    /// The current target depth.
    pub fn target_ms(&self) -> u32 {
        self.target_ms
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The counters that are missing and can still be rescued.
    ///
    /// A gap between the next slot and the deepest frame held. Ask the sender
    /// for these; they have until their slot comes up to arrive.
    ///
    /// Empty in conversational mode, where by the time a gap is visible the
    /// round trip to recover it has already cost more than the frame is worth.
    ///
    /// # The tail this cannot see
    ///
    /// A gap is only visible because something arrived **after** it. If the
    /// last frames of a recording are lost, nothing arrived behind them, and
    /// this returns nothing: the receiver has no evidence those frames were
    /// ever sent, and inventing it would mean asking for frames that do not
    /// exist every time somebody stops speaking.
    ///
    /// Use [`JitterBuffer::recoverable_through`] where the highest sent counter
    /// is known. It is the last word of every recording, so it matters more
    /// than its rarity suggests.
    pub fn recoverable(&self) -> Vec<u64> {
        match self.frames.keys().next_back() {
            Some(&highest) => self.recoverable_through(highest),
            None => Vec::new(),
        }
    }

    /// The counters missing between the next slot and `highest_sent`.
    ///
    /// `highest_sent` comes from the sender, which is the only party that knows
    /// it. Without it the tail of a recording cannot be recovered, because a
    /// gap with nothing behind it is indistinguishable from silence.
    pub fn recoverable_through(&self, highest_sent: u64) -> Vec<u64> {
        self.recoverable_between(None, highest_sent)
    }

    /// The counters missing between `oldest_sent` and `highest_sent`.
    ///
    /// # Why the bottom of the range has to come from the sender too
    ///
    /// A receiver knows a frame is missing because it can see the gap. It
    /// cannot see a gap before the first frame it ever received: nothing tells
    /// it those frames existed. So the very start of a call, the frames lost
    /// before anything got through, was never requested by anybody.
    ///
    /// That was invisible up to one packet in two, where the first frame nearly
    /// always arrives. With one in five getting through it cost the first 13
    /// frames, 260 ms, on every run, and no amount of extra recovery time
    /// helped, because the request was never made.
    ///
    /// `oldest_sent` is the earliest counter the sender can still supply. Only
    /// consulted before playback begins, which is the window where the receiver
    /// has no other way to know what it missed.
    pub fn recoverable_between(&self, oldest_sent: Option<u64>, highest_sent: u64) -> Vec<u64> {
        if self.mode != Mode::Fidelity {
            return Vec::new();
        }

        // Recovery must work **before** playback begins, not only after.
        //
        // It used to start at `next`, which is unset until the buffer reaches
        // its target depth. On a badly lossy link the buffer never reaches that
        // depth precisely because frames are missing, so nothing was ever
        // requested and the call never started at all. The worse the network,
        // the more completely it failed.
        let from = match self.next {
            Some(next) => next,
            None => {
                let seen = match self.frames.keys().next() {
                    Some(&lowest) => lowest,
                    None => return Vec::new(),
                };
                // Before playback, reach back to whatever the sender still has.
                match oldest_sent {
                    Some(oldest) => oldest.min(seen),
                    None => seen,
                }
            }
        };

        (from..=highest_sent)
            .filter(|counter| !self.frames.contains_key(counter))
            .collect()
    }

    /// Whether the slot may wait rather than be concealed.
    ///
    /// In fidelity mode a missing frame holds the line while there is still
    /// buffer behind it: waiting costs delay, which this mode has, and
    /// concealing costs a word, which it does not accept.
    fn may_wait(&self) -> bool {
        self.mode == Mode::Fidelity && self.buffered_ms() < self.target_ms
    }

    /// The smoothed jitter estimate.
    pub fn jitter_ms(&self) -> f64 {
        self.jitter_ms
    }

    /// Frames played, concealed, and discarded for arriving after their slot.
    pub fn counts(&self) -> (u64, u64, u64) {
        (self.played, self.missing, self.late)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: u64) -> Vec<u8> {
        format!("frame {n}").into_bytes()
    }

    /// Fill to the target so playback can begin, then hand back the buffer.
    fn primed() -> JitterBuffer {
        let mut jb = JitterBuffer::new();
        for n in 0..10 {
            jb.push(n, n * FRAME_MS as u64, frame(n));
        }
        jb
    }

    /// A network that delivers perfectly must produce no gaps at all.
    #[test]
    fn a_clean_network_plays_every_frame() {
        let mut jb = primed();

        for n in 0..10 {
            assert_eq!(jb.pop(), Playout::Frame(frame(n)), "frame {n}");
        }

        let (played, missing, late) = jb.counts();
        assert_eq!((played, missing, late), (10, 0, 0));
    }

    /// Playback must not start on an empty buffer, or the first disturbance is
    /// a gap.
    #[test]
    fn playback_waits_for_the_buffer_to_fill() {
        let mut jb = JitterBuffer::new();

        assert_eq!(jb.pop(), Playout::Starved, "nothing has arrived");

        jb.push(0, 0, frame(0));
        assert_eq!(
            jb.pop(),
            Playout::Starved,
            "one frame is not a buffer, and starting here means starting empty"
        );

        for n in 1..5 {
            jb.push(n, n * FRAME_MS as u64, frame(n));
        }
        assert_eq!(jb.pop(), Playout::Frame(frame(0)), "now it has depth");
    }

    /// Reordering is ordinary. It must not be heard.
    #[test]
    fn reordering_within_the_buffer_is_absorbed() {
        let mut jb = JitterBuffer::new();

        // Arriving backwards, which is the worst case a network offers.
        for n in (0..8u64).rev() {
            jb.push(n, (7 - n) * 5, frame(n));
        }

        for n in 0..8 {
            assert_eq!(jb.pop(), Playout::Frame(frame(n)), "frame {n} out of order");
        }
        assert_eq!(jb.counts().1, 0, "reordering must not produce a gap");
    }

    /// A lost frame is concealed, and everything behind it plays on time. The
    /// alternative is stalling to recover audio that is already too late.
    #[test]
    fn a_gap_does_not_stall_what_is_behind_it() {
        let mut jb = JitterBuffer::new();

        for n in 0..10u64 {
            if n == 4 {
                continue; // lost
            }
            jb.push(n, n * FRAME_MS as u64, frame(n));
        }

        let played: Vec<Playout> = (0..10).map(|_| jb.pop()).collect();

        assert_eq!(played[3], Playout::Frame(frame(3)));
        assert_eq!(played[4], Playout::Missing, "the lost slot is concealed");
        assert_eq!(
            played[5],
            Playout::Frame(frame(5)),
            "the frame behind the gap must not be delayed by it"
        );
        assert_eq!(jb.counts().1, 1);
    }

    /// A frame for a slot already played is useless. Accepting it would put
    /// audio out of order at the device.
    #[test]
    fn a_frame_after_its_slot_is_discarded() {
        let mut jb = primed();

        for _ in 0..5 {
            jb.pop();
        }

        jb.push(1, 500, frame(1));
        assert_eq!(jb.counts().2, 1, "the late frame was counted");

        // And it did not corrupt the sequence.
        assert_eq!(jb.pop(), Playout::Frame(frame(5)));
    }

    /// The depth has to follow the network, or it is right for exactly one
    /// network.
    #[test]
    fn the_target_grows_with_jitter() {
        let mut jb = JitterBuffer::new();

        // A steady stream: the target should settle at the floor.
        for n in 0..40u64 {
            jb.push(n, n * FRAME_MS as u64, frame(n));
        }
        let calm = jb.target_ms();
        assert_eq!(
            calm, MIN_DELAY_MS,
            "a clean network needs no depth beyond one frame"
        );

        // Now a network that jitters by 60 ms either way.
        let mut arrival = 40 * FRAME_MS as u64;
        for n in 40..120u64 {
            arrival += if n % 2 == 0 { 80 } else { 0 };
            jb.push(n, arrival, frame(n));
        }

        assert!(
            jb.target_ms() > calm,
            "the target did not grow: {} then {}",
            calm,
            jb.target_ms()
        );
        assert!(jb.jitter_ms() > 10.0, "the jitter estimate did not react");
    }

    /// Delay must never run away, whatever the network does. A caller can talk
    /// through gaps and cannot talk through delay.
    #[test]
    fn the_target_is_bounded() {
        let mut jb = JitterBuffer::new();

        // A network behaving as badly as one can.
        let mut arrival = 0u64;
        for n in 0..500u64 {
            arrival += if n % 2 == 0 { 2_000 } else { 1 };
            jb.push(n, arrival, frame(n));
        }

        assert!(
            jb.target_ms() <= MAX_DELAY_MS,
            "the target ran away to {} ms",
            jb.target_ms()
        );
    }

    /// Growing must be fast and shrinking slow, or the delay oscillates
    /// audibly every time the network twitches.
    ///
    /// Measured rather than asserted by eye: count the frames it takes to reach
    /// a deep target, then the frames it takes to come back.
    #[test]
    fn the_target_grows_fast_and_shrinks_slowly() {
        let mut jb = JitterBuffer::new();
        let mut arrival = 0u64;
        let mut counter = 0u64;

        // A burst of jitter. How long before the buffer is deep?
        let mut frames_to_grow = 0;
        while jb.target_ms() < 100 && frames_to_grow < 1_000 {
            arrival += if counter % 2 == 0 { 300 } else { 1 };
            jb.push(counter, arrival, frame(counter));
            counter += 1;
            frames_to_grow += 1;
        }
        let peak = jb.target_ms();
        assert!(peak >= 100, "the burst was never absorbed");

        // The network calms completely. How long before the buffer is shallow?
        let mut frames_to_shrink = 0;
        while jb.target_ms() > MIN_DELAY_MS * 2 && frames_to_shrink < 10_000 {
            arrival += FRAME_MS as u64;
            jb.push(counter, arrival, frame(counter));
            counter += 1;
            frames_to_shrink += 1;
        }

        assert!(
            jb.target_ms() <= MIN_DELAY_MS * 2,
            "the target never came back down: {} ms",
            jb.target_ms()
        );
        assert!(
            frames_to_shrink > frames_to_grow * 4,
            "shrinking took {frames_to_shrink} frames against {frames_to_grow} to grow, \
             which is not slow enough to stop the delay oscillating"
        );
    }

    /// Ten quiet frames after a storm must not collapse the buffer. The next
    /// disturbance would be heard in full.
    #[test]
    fn a_brief_calm_does_not_collapse_the_buffer() {
        let mut jb = JitterBuffer::new();
        let mut arrival = 0u64;

        for n in 0..60u64 {
            arrival += if n % 2 == 0 { 300 } else { 1 };
            jb.push(n, arrival, frame(n));
        }
        let peak = jb.target_ms();

        for n in 60..70u64 {
            arrival += FRAME_MS as u64;
            jb.push(n, arrival, frame(n));
        }

        assert!(
            jb.target_ms() > peak / 2,
            "ten quiet frames took the target from {peak} to {}, which is a collapse",
            jb.target_ms()
        );
    }

    /// A far end that stops talking must be distinguishable from one that is
    /// dropping packets, because the two call for different behaviour.
    #[test]
    fn silence_and_loss_are_different_answers() {
        let mut jb = JitterBuffer::new();
        assert_eq!(jb.pop(), Playout::Starved, "nothing has ever arrived");

        let mut jb = primed();
        for _ in 0..10 {
            jb.pop();
        }
        assert_eq!(
            jb.pop(),
            Playout::Missing,
            "we know where we are and the frame is not here"
        );
    }
}
