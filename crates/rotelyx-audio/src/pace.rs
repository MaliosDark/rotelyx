//! Deciding how many bytes a voice frame is allowed to be.
//!
//! # Why a call needs this and a file transfer does not
//!
//! A file transfer slows down and arrives later. A call cannot: audio that is
//! late is worth nothing, so the send path drops it rather than queueing it.
//! That makes congestion invisible in the ordinary way. Nothing backs up, the
//! sender keeps producing at the same rate, and what a listener hears is not a
//! slower call but a broken one, with holes in it.
//!
//! So the rate has to come down on purpose. The codec is layered, which means a
//! frame can simply be cut shorter and still decode: it decodes rougher. That is
//! the knob. This decides where to set it.
//!
//! # What it watches
//!
//! Loss and delay, which say different things. Loss says packets are being
//! discarded, which is a queue that already overflowed. Delay says a queue is
//! filling, which is the same event earlier and is what a call should react to,
//! because by the time a queue overflows somebody has already heard the hole.
//!
//! The round trip time on its own says nothing: a satellite link is slow and
//! empty. What matters is the round trip time *against the lowest this
//! connection has managed*, because the difference is the queue.
//!
//! # Why it comes down fast and goes up slowly
//!
//! Coming down is cheap: a rougher frame for a second is a small cost, and it
//! empties a queue that is hurting every other flow on the same link as well.
//! Going up is expensive to get wrong: it refills the queue and the listener
//! hears it. So a bad sign halves the distance to the floor and a good one adds
//! a few bytes.

use std::time::Duration;

/// The smallest frame worth sending.
///
/// Thirty bytes is 12 kbit/s, which is the lowest rate anybody has listened to
/// this codec at and found usable. Going below a rate nobody has heard would be
/// choosing a number because the arithmetic allows it.
pub const FLOOR_BYTES: usize = 30;

/// The largest. Beyond this the codec has nothing more to say at this
/// bandwidth, so the bytes would be spent on nothing.
pub const CEILING_BYTES: usize = 120;

/// Where a call starts, which is the rate the listening test used.
pub const START_BYTES: usize = 60;

/// How much of the lowest round trip counts as a queue rather than noise.
const QUEUE_TOLERANCE: f32 = 1.35;

/// Added per good observation.
const CLIMB_BYTES: f32 = 1.5;

/// Kept after a bad one.
const BACK_OFF: f32 = 0.85;

/// The rate control for one direction of one call.
pub struct Pace {
    target: f32,
    lowest_rtt: Option<Duration>,
    last_lost: u64,
    /// Observations so far, so the first one does not read a loss counter that
    /// has been counting since before this call.
    seen: u32,
}

impl Default for Pace {
    fn default() -> Self {
        Self::new()
    }
}

impl Pace {
    pub fn new() -> Self {
        Self {
            target: START_BYTES as f32,
            lowest_rtt: None,
            last_lost: 0,
            seen: 0,
        }
    }

    /// Take one reading and return the frame size to use from now.
    ///
    /// `lost` is the connection's cumulative lost packet count, and `rtt` its
    /// current round trip. Both are what the transport already tracks: a call
    /// that asked the far end to report loss would be adding a message and a
    /// round trip to learn something the sender's own stack knows.
    pub fn observe(&mut self, lost: u64, rtt: Option<Duration>) -> usize {
        if let Some(rtt) = rtt {
            self.lowest_rtt = Some(match self.lowest_rtt {
                Some(low) => low.min(rtt),
                None => rtt,
            });
        }

        let newly_lost = lost.saturating_sub(self.last_lost);
        self.last_lost = lost;

        // The first reading establishes where the counters are. Acting on it
        // would react to whatever the connection did before the call started.
        if self.seen == 0 {
            self.seen = 1;
            return self.target as usize;
        }
        self.seen = self.seen.saturating_add(1);

        let queueing = match (rtt, self.lowest_rtt) {
            (Some(now), Some(low)) if low > Duration::ZERO => {
                now.as_secs_f32() > low.as_secs_f32() * QUEUE_TOLERANCE
            }
            _ => false,
        };

        if newly_lost > 0 || queueing {
            self.target = (self.target * BACK_OFF).max(FLOOR_BYTES as f32);
        } else {
            self.target = (self.target + CLIMB_BYTES).min(CEILING_BYTES as f32);
        }

        self.target as usize
    }

    /// The current frame size, without taking a reading.
    pub fn frame_bytes(&self) -> usize {
        self.target as usize
    }

    /// What that works out to on the wire, for a quality indicator.
    pub fn kbit_per_second(&self) -> usize {
        // Fifty frames a second at 20 ms each.
        self.target as usize * 50 * 8 / 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Option<Duration> {
        Some(Duration::from_millis(n))
    }

    /// A quiet link should let a call use more of it.
    #[test]
    fn a_link_with_room_is_used() {
        let mut pace = Pace::new();
        pace.observe(0, ms(40));
        for _ in 0..200 {
            pace.observe(0, ms(40));
        }
        assert_eq!(
            pace.frame_bytes(),
            CEILING_BYTES,
            "a link that never lost anything was not used"
        );
    }

    /// Loss must bring the rate down, and quickly.
    ///
    /// A dropped voice frame is a hole somebody heard. Coming down slowly means
    /// more holes while the arithmetic catches up.
    #[test]
    fn loss_brings_the_rate_down() {
        let mut pace = Pace::new();
        pace.observe(0, ms(40));
        for _ in 0..50 {
            pace.observe(0, ms(40));
        }
        let comfortable = pace.frame_bytes();

        let mut lost = 0;
        for _ in 0..10 {
            lost += 3;
            pace.observe(lost, ms(40));
        }
        assert!(
            pace.frame_bytes() < comfortable / 2,
            "ten lossy readings only took it from {comfortable} to {}",
            pace.frame_bytes()
        );
    }

    /// A queue that is filling must be reacted to before it overflows.
    ///
    /// # Why this matters more than loss does
    ///
    /// Loss is a queue that already overflowed, which means somebody already
    /// heard the hole. The round trip climbing above the lowest this connection
    /// has managed is the same event a second earlier, while it can still be
    /// avoided.
    #[test]
    fn a_filling_queue_is_reacted_to_without_any_loss() {
        let mut pace = Pace::new();
        pace.observe(0, ms(20));
        for _ in 0..40 {
            pace.observe(0, ms(20));
        }
        let comfortable = pace.frame_bytes();

        // No loss at all, and the round trip triples.
        for _ in 0..10 {
            pace.observe(0, ms(60));
        }
        assert!(
            pace.frame_bytes() < comfortable,
            "a queue filling from 20 ms to 60 ms changed nothing: still {}",
            pace.frame_bytes()
        );
    }

    /// A slow link is not a congested one.
    #[test]
    fn a_link_that_is_merely_far_away_is_not_throttled() {
        let mut pace = Pace::new();
        // Half a second, steadily. A satellite, not a queue.
        pace.observe(0, ms(500));
        for _ in 0..100 {
            pace.observe(0, ms(500));
        }
        assert_eq!(
            pace.frame_bytes(),
            CEILING_BYTES,
            "distance was mistaken for congestion"
        );
    }

    /// It must never go below a rate somebody has actually listened to.
    #[test]
    fn it_stops_at_a_rate_that_has_been_heard() {
        let mut pace = Pace::new();
        pace.observe(0, ms(40));
        let mut lost = 0;
        for _ in 0..500 {
            lost += 10;
            pace.observe(lost, ms(400));
        }
        assert_eq!(pace.frame_bytes(), FLOOR_BYTES);
        assert_eq!(pace.kbit_per_second(), 12, "the floor is not 12 kbit/s");
    }

    /// The first reading must not react to a counter from before the call.
    #[test]
    fn the_first_reading_only_establishes_where_the_counters_are() {
        let mut pace = Pace::new();
        // A connection that has been up for a while and lost packets doing
        // something else entirely.
        assert_eq!(pace.observe(9_000, ms(40)), START_BYTES);
    }
}
