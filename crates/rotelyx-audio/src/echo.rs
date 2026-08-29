//! Taking the loudspeaker back out of the microphone.
//!
//! # What the problem is
//!
//! A microphone in the same room as a loudspeaker hears the loudspeaker. On a
//! call that means the far end hears itself, delayed by however long the round
//! trip took, which is the single most unpleasant thing a telephone can do.
//! Headphones avoid it by keeping the two apart; a speakerphone cannot.
//!
//! # Why an adaptive filter rather than a subtraction
//!
//! What reaches the microphone is not what was played. It is what was played
//! convolved with the room: reflections off walls, the case of the machine, the
//! frequency response of both transducers, and a delay nobody knows in advance
//! because it depends on the buffering of two devices. Subtracting the playback
//! signal would remove none of it.
//!
//! So the room is measured instead. An adaptive filter estimates the path from
//! the loudspeaker to the microphone, predicts what the echo will look like,
//! and subtracts the prediction. It learns from its own error, so it follows a
//! path that changes when somebody moves or picks the machine up.
//!
//! # Why in the frequency domain, in partitions
//!
//! The path is long: a hundred milliseconds at 48 kHz is 4,800 taps, and a
//! straightforward time-domain filter of that length costs 4,800 multiplies per
//! sample, which is a quarter of a billion a second for one direction of one
//! call. The same filter as a set of short blocks in the frequency domain costs
//! a few transforms per block instead, because convolution there is
//! multiplication. That is the whole reason this is written the way it is.
//!
//! # What it does not do
//!
//! Non-linear echo. A small loudspeaker driven hard distorts, and what comes
//! back is not a linear function of what went out, so no linear filter can
//! predict it. Suppressing the residue needs a different mechanism and is not
//! here. This is honest about what it removes and leaves the rest audible
//! rather than damaging speech to hide it.

use std::f32::consts::PI;

/// Samples per processing block.
///
/// Small enough that the delay this adds is under six milliseconds, large
/// enough that the transforms are worth their overhead.
const BLOCK: usize = 256;

/// Transform length: two blocks, which is what overlap-save needs to make a
/// linear convolution out of a circular one.
const FFT_LEN: usize = 2 * BLOCK;

/// How many blocks of room the filter can account for.
///
/// Twenty-four blocks is 128 ms at 48 kHz, which covers the buffering of two
/// ordinary devices plus a small room. A path longer than this is not cancelled
/// and is not pretended to be.
const PARTITIONS: usize = 24;

/// How fast the filter follows the room. Between zero and one; higher is faster
/// and less stable.
const STEP: f32 = 0.35;

/// Keeps a division from exploding on silence.
const FLOOR: f32 = 1e-6;

/// How much of what the linear filter left is assumed to still be echo.
///
/// The filter removes what a linear model of the room can remove. What is left
/// is the part no linear model can: the reverberant tail past the 128 ms the
/// filter covers, and whatever the speaker added that a speaker is not supposed
/// to add. Measured against a real room the linear stage alone removed -0.0 dB
/// and the two together remove 1.3 running continuously, which is how a call
/// runs, or 6.1 when something keeps the filter aligned. So this stage is not a
/// refinement, it is nearly all of what is removed there, and what is removed
/// there is still small. See `docs/ACOUSTIC.md`.
///
/// The estimate is `leak · far energy`, where `leak` is learned from what
/// actually came through while only the far end was talking, rather than
/// assumed. Over-subtracting by a factor is the same trick the noise suppressor
/// uses and for the same reason: an estimate that is right on average is too low
/// half the time, and the half where it is too low is the half you can hear.
const RESIDUAL_OVER_SUBTRACT: f32 = 2.0;

/// The quietest the suppressor may make a block, as an amplitude.
///
/// Not zero. A gate that closes completely makes the room disappear between
/// syllables, and a listener hears that as the line dropping rather than as
/// quiet. -20 dB is enough to stop echo being intelligible while leaving
/// something behind it.
const RESIDUAL_FLOOR_GAIN: f32 = 0.1;

/// How fast the leak estimate comes **down**, towards a quieter observation.
///
/// # Why this is a minimum and not an average
///
/// The leak is what fraction of the far end still comes through, and it is
/// learned from what is left over. Anything the near end says is also left over,
/// so an average is dragged upwards by their voice, and a leak estimate that is
/// too high suppresses them. That is not a theory: averaging cost 92% of the
/// near end's voice in `a_voice_on_this_end_survives_double_talk`, which is the
/// exact failure that test exists to catch.
///
/// Tracking the minimum instead works on the same fact the noise suppressor uses:
/// the quietest the residual has been recently is echo, because a voice adds and
/// never subtracts. It comes down quickly to follow a room that got easier and
/// climbs back slowly, so a moment of somebody talking moves it almost not at
/// all.
const LEAK_FALL: f32 = 0.3;

/// How fast it climbs when everything observed is louder. About four seconds to
/// double, which is slower than anybody talks and faster than a room changes.
const LEAK_CLIMB: f32 = 1.001;

/// How fast the applied gain may move, per block.
///
/// A gain that jumps between blocks modulates whatever is under it, and 256
/// samples is 5 ms, which is fast enough for that to be heard as roughness.
/// Attack is quicker than release: coming down on an echo late is worse than
/// staying down on silence a moment too long.
const GAIN_ATTACK: f32 = 0.4;
const GAIN_RELEASE: f32 = 0.1;

#[derive(Clone, Copy, Default)]
pub(crate) struct C {
    pub(crate) re: f32,
    pub(crate) im: f32,
}

impl C {
    pub(crate) const ZERO: C = C { re: 0.0, im: 0.0 };

    pub(crate) fn add(self, o: C) -> C {
        C {
            re: self.re + o.re,
            im: self.im + o.im,
        }
    }

    pub(crate) fn sub(self, o: C) -> C {
        C {
            re: self.re - o.re,
            im: self.im - o.im,
        }
    }

    pub(crate) fn mul(self, o: C) -> C {
        C {
            re: self.re * o.re - self.im * o.im,
            im: self.re * o.im + self.im * o.re,
        }
    }

    pub(crate) fn conj(self) -> C {
        C {
            re: self.re,
            im: -self.im,
        }
    }

    pub(crate) fn scale(self, k: f32) -> C {
        C {
            re: self.re * k,
            im: self.im * k,
        }
    }

    pub(crate) fn norm_sq(self) -> f32 {
        self.re * self.re + self.im * self.im
    }
}

/// Radix-2 in place, for a power of two length.
///
/// Written here rather than borrowed from the codec because the codec's is
/// private to its own transform and shaped for it. This one is thirty lines and
/// has one caller.
pub(crate) fn fft(buf: &mut [C], inverse: bool) {
    let n = buf.len();
    debug_assert!(n.is_power_of_two());

    // Bit reversal.
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            buf.swap(i, j);
        }
    }

    let sign = if inverse { 1.0 } else { -1.0 };
    let mut len = 2;
    while len <= n {
        let theta = sign * 2.0 * PI / len as f32;
        let step = C {
            re: theta.cos(),
            im: theta.sin(),
        };
        let mut i = 0;
        while i < n {
            let mut w = C { re: 1.0, im: 0.0 };
            for k in 0..len / 2 {
                let u = buf[i + k];
                let v = buf[i + k + len / 2].mul(w);
                buf[i + k] = u.add(v);
                buf[i + k + len / 2] = u.sub(v);
                w = w.mul(step);
            }
            i += len;
        }
        len <<= 1;
    }

    if inverse {
        let k = 1.0 / n as f32;
        for x in buf.iter_mut() {
            *x = x.scale(k);
        }
    }
}

/// One direction of one call: what was played, and what the microphone heard.
pub struct EchoCanceller {
    /// Frequency-domain far-end blocks, newest first.
    far: Vec<[C; FFT_LEN]>,
    /// The filter, one block of coefficients per partition.
    filter: Vec<[C; FFT_LEN]>,
    /// The tail of the previous far-end block, which overlap-save needs.
    far_tail: [f32; BLOCK],
    /// Samples handed in but not yet a whole block.
    played_pending: Vec<f32>,
    captured_pending: Vec<f32>,
    /// Cancelled output waiting to be taken.
    ready: Vec<f32>,
    /// Running energies, for the loss figure and for the double-talk guard.
    heard_energy: f32,
    left_energy: f32,
    /// Which partition to tidy this block. See `constrain`.
    next_constrained: usize,

    /// How much of the far end's energy still comes through the linear filter,
    /// learned while only the far end is talking. See [`RESIDUAL_OVER_SUBTRACT`].
    leak: f32,
    /// The suppression gain actually applied, smoothed so it cannot jump.
    gain: f32,

}

impl Default for EchoCanceller {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoCanceller {
    pub fn new() -> Self {
        Self {
            far: vec![[C::ZERO; FFT_LEN]; PARTITIONS],
            filter: vec![[C::ZERO; FFT_LEN]; PARTITIONS],
            far_tail: [0.0; BLOCK],
            played_pending: Vec::new(),
            captured_pending: Vec::new(),
            ready: Vec::new(),
            heard_energy: FLOOR,
            left_energy: FLOOR,
            next_constrained: 0,
            leak: 0.0,
            gain: 1.0,
        }
    }

    /// What went to the loudspeaker.
    ///
    /// Must be given every sample that is played, in order, or the filter is
    /// estimating a path from a signal that was never there.
    pub fn played(&mut self, samples: &[f32]) {
        self.played_pending.extend_from_slice(samples);
    }

    /// Reference samples handed in but not yet used.
    ///
    /// A caller matching a microphone against a loudspeaker needs this: when
    /// the loudspeaker has played less than the microphone has heard, the
    /// difference is silence that nobody queued, and it has to be said so
    /// rather than left out. Leaving it out stalls the microphone waiting for
    /// audio that is not coming.
    pub fn reference_available(&self) -> usize {
        self.played_pending.len()
    }

    /// What the microphone heard. Returns as many cancelled samples as it can.
    ///
    /// It can only work on whole blocks and only when it has as much played
    /// audio as captured audio, so the answer is shorter than the input until
    /// both sides have enough. Nothing is lost: what is held back comes out of
    /// the next call.
    pub fn capture(&mut self, samples: &[f32]) -> Vec<f32> {
        self.captured_pending.extend_from_slice(samples);

        while self.captured_pending.len() >= BLOCK && self.played_pending.len() >= BLOCK {
            let mut far = [0.0f32; BLOCK];
            far.copy_from_slice(&self.played_pending[..BLOCK]);
            self.played_pending.drain(..BLOCK);

            let mut near = [0.0f32; BLOCK];
            near.copy_from_slice(&self.captured_pending[..BLOCK]);
            self.captured_pending.drain(..BLOCK);

            let cleaned = self.block(&far, &near);
            self.ready.extend_from_slice(&cleaned);
        }

        std::mem::take(&mut self.ready)
    }

    /// One block, the whole algorithm.
    fn block(&mut self, far: &[f32; BLOCK], near: &[f32; BLOCK]) -> [f32; BLOCK] {
        // The far end, as the previous block followed by this one: overlap-save
        // turns the circular convolution a transform gives into the linear one
        // a room actually performs.
        let mut x = [C::ZERO; FFT_LEN];
        for i in 0..BLOCK {
            x[i] = C {
                re: self.far_tail[i],
                im: 0.0,
            };
            x[BLOCK + i] = C {
                re: far[i],
                im: 0.0,
            };
        }
        self.far_tail = *far;
        fft(&mut x, false);

        // Newest first, oldest falls off the end.
        self.far.rotate_right(1);
        self.far[0] = x;

        // Predict the echo: multiply and sum across partitions, which is what
        // convolving with the whole filter would be in the time domain.
        let mut y = [C::ZERO; FFT_LEN];
        for p in 0..PARTITIONS {
            for k in 0..FFT_LEN {
                y[k] = y[k].add(self.filter[p][k].mul(self.far[p][k]));
            }
        }
        fft(&mut y, true);

        // Only the second half of an overlap-save block is the real answer.
        let mut error = [0.0f32; BLOCK];
        let mut heard = 0.0f32;
        let mut left = 0.0f32;
        for i in 0..BLOCK {
            let predicted = y[BLOCK + i].re;
            error[i] = near[i] - predicted;
            heard += near[i] * near[i];
            left += error[i] * error[i];
        }

        // A slow average, so the figure a caller reads is not one loud block.
        self.heard_energy = 0.95 * self.heard_energy + 0.05 * heard;
        self.left_energy = 0.95 * self.left_energy + 0.05 * left;

        // Do not learn while both ends are talking.
        //
        // The filter learns by assuming everything left over is echo it failed
        // to predict. When the near end is speaking that assumption is false,
        // and adapting on their voice pulls the filter away from the room and
        // towards cancelling *them*, which is how a canceller ends up chewing
        // words. Freezing is the safe answer: a frozen filter is merely stale.
        let far_energy: f32 = far.iter().map(|s| s * s).sum();
        let talking_over = left > 2.0 * far_energy.max(FLOOR);
        if !talking_over && far_energy > FLOOR {
            let mut e = [C::ZERO; FFT_LEN];
            for i in 0..BLOCK {
                e[BLOCK + i] = C {
                    re: error[i],
                    im: 0.0,
                };
            }
            fft(&mut e, false);

            // Normalised per bin against the power in *every* partition, not
            // each one on its own.
            //
            // Dividing each partition by its own power was the first thing
            // written here and it diverges: twenty four partitions each take a
            // full step, so the filter overshoots by that factor every block
            // and the output comes out louder than the microphone. Measured at
            // -26 dB, which is to say it was adding echo. The sum is what makes
            // one step one step.
            let mut power = [0.0f32; FFT_LEN];
            for p in 0..PARTITIONS {
                for k in 0..FFT_LEN {
                    power[k] += self.far[p][k].norm_sq();
                }
            }

            for p in 0..PARTITIONS {
                for k in 0..FFT_LEN {
                    let grad = self.far[p][k]
                        .conj()
                        .mul(e[k])
                        .scale(STEP / (power[k] + FLOOR));
                    self.filter[p][k] = self.filter[p][k].add(grad);
                }
            }

            // Tidy one partition per block.
            //
            // A partition of the filter is one block of an impulse response,
            // and an impulse response that long has nothing in its second half:
            // that half only exists because the transform is twice the block.
            // Left alone it fills with the circular wrap-around the transform
            // invents, which is not part of any room, and the filter spends its
            // step size chasing it. Zeroing it costs two transforms, so one
            // partition takes its turn each block rather than all of them
            // paying every time.
            let p = self.next_constrained;
            self.next_constrained = (self.next_constrained + 1) % PARTITIONS;
            self.constrain(p);
        }

        self.suppress_residual(&mut error, far_energy, left, talking_over);
        error
    }

    /// Attenuate what the linear filter could not remove.
    ///
    /// # Why a linear filter is not enough on its own
    ///
    /// It removes what a linear model of the room can remove. A room is not
    /// linear at the ends: the reverberant tail runs past the 128 ms the filter
    /// covers, and a small speaker driven hard adds harmonics that were never in
    /// the signal, so no filter of any length can predict them from it.
    ///
    /// Measured against a real speaker and a real microphone, the linear stage
    /// alone removed **-0.0 dB**, against 38 on a path this project generated.
    /// With this stage the same room gives **1.3 dB** run continuously, 6.1 when
    /// something keeps the filter aligned, and the synthetic path 58. Quote the
    /// continuous figure: a call does not realign. That is the gap this stage
    /// closes and it is why every canceller that ships has one, and it is also
    /// why a desktop call still wants headphones. `docs/ACOUSTIC.md` has the
    /// measurements.
    ///
    /// # Why one gain and not a spectrum
    ///
    /// A per-bin gain suppresses more for the same damage, and it needs its own
    /// transform, its own overlap, and a smoothing rule per bin to stop it
    /// warbling. One gain per block cannot warble, cannot be got wrong per bin,
    /// and is what the measurement says is missing. A spectral version is worth
    /// having later and is worth having *after* something works.
    ///
    /// # What protects the near end
    ///
    /// Nothing here can tell an echo from a person by looking at it, so it does
    /// not try: it suppresses only when the far end is talking and this end is
    /// not, which is the same condition the filter uses to decide whether to
    /// learn. During double talk the gain is released rather than held, because
    /// the failure that matters is chewing somebody's words, and a moment of
    /// echo is a smaller price than a syllable.
    fn suppress_residual(
        &mut self,
        error: &mut [f32; BLOCK],
        far_energy: f32,
        left: f32,
        talking_over: bool,
    ) {
        // Learn the leak whenever the far end is loud enough to be echoing.
        //
        // Not gated on the double-talk flag, deliberately. That flag asks whether
        // the residual is more than twice the far end's energy, which is a bar a
        // near-end voice clears only if it is louder than the loudspeaker. It is
        // the right question for whether to freeze the filter, where a missed
        // detection costs a stale tap. It is the wrong one here, where a missed
        // detection costs a syllable, and in
        // `a_voice_on_this_end_survives_double_talk` it never fires at all.
        //
        // The minimum tracking below is what makes the flag unnecessary: a voice
        // raises the observation, and raising it is the direction this barely
        // moves in.
        if far_energy > FLOOR {
            let observed = left / far_energy.max(FLOOR);
            if observed < self.leak || self.leak == 0.0 {
                self.leak += LEAK_FALL * (observed - self.leak);
            } else {
                self.leak *= LEAK_CLIMB;
            }
        }

        let target = if talking_over || far_energy <= FLOOR {
            // Somebody here is speaking, or there is nothing to echo. Either way
            // this stage has no business touching the signal.
            1.0
        } else {
            let echo_estimate = RESIDUAL_OVER_SUBTRACT * self.leak * far_energy;
            let power_gain = 1.0 - echo_estimate / left.max(FLOOR);
            power_gain.max(0.0).sqrt().max(RESIDUAL_FLOOR_GAIN)
        };

        let rate = if target < self.gain {
            GAIN_ATTACK
        } else {
            GAIN_RELEASE
        };
        self.gain += rate * (target - self.gain);

        for sample in error.iter_mut() {
            *sample *= self.gain;
        }
    }

    /// Zero the half of one partition's impulse response that cannot be real.
    fn constrain(&mut self, p: usize) {
        let mut h = self.filter[p];
        fft(&mut h, true);
        for x in h.iter_mut().skip(BLOCK) {
            *x = C::ZERO;
        }
        fft(&mut h, false);
        self.filter[p] = h;
    }

    /// How much of the echo is gone, in decibels.
    ///
    /// Zero means nothing was removed. This is the number to show beside a
    /// speakerphone: it says whether the room is being cancelled or merely
    /// endured.
    pub fn loss_db(&self) -> f32 {
        10.0 * (self.heard_energy / self.left_energy.max(FLOOR)).max(1.0).log10()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A room, as a delay and a few reflections.
    ///
    /// Not a real impulse response, and it does not need to be: what is under
    /// test is whether the filter finds a path it was not told about, and a
    /// handful of taps at an unknown offset is that problem in miniature.
    fn through_a_room(played: &[f32]) -> Vec<f32> {
        const DELAY: usize = 700;
        let taps = [(0usize, 0.6f32), (37, -0.3), (129, 0.18), (400, -0.09)];
        let mut out = vec![0.0f32; played.len()];
        for (offset, gain) in taps {
            let d = DELAY + offset;
            for n in d..played.len() {
                out[n] += gain * played[n - d];
            }
        }
        out
    }

    fn noise(n: usize, seed: u32) -> Vec<f32> {
        let mut state = seed | 1;
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state as f32 / u32::MAX as f32) * 2.0 - 1.0
            })
            .collect()
    }

    fn energy(x: &[f32]) -> f32 {
        x.iter().map(|s| s * s).sum::<f32>() / x.len().max(1) as f32
    }

    /// The far end must stop hearing itself.
    ///
    /// # What this measures
    ///
    /// Echo return loss enhancement: how much quieter what leaves the machine
    /// is than what the microphone heard, once the filter has settled. The
    /// microphone here hears *only* the echo, which is the case a speakerphone
    /// is in whenever the person holding it is listening rather than talking,
    /// and it is the case that decides whether the other end can bear it.
    #[test]
    fn the_echo_is_removed() {
        let mut aec = EchoCanceller::new();
        let played = noise(48_000 * 4, 0x1234_5678);
        let heard = through_a_room(&played);

        let mut cleaned = Vec::new();
        for start in (0..played.len()).step_by(BLOCK) {
            let end = (start + BLOCK).min(played.len());
            aec.played(&played[start..end]);
            cleaned.extend(aec.capture(&heard[start..end]));
        }

        // The last second, by which time the filter has had three to converge.
        let tail = cleaned.len().saturating_sub(48_000);
        let before = energy(&heard[heard.len() - 48_000..]);
        let after = energy(&cleaned[tail..]);
        let db = 10.0 * (before / after.max(1e-12)).log10();

        println!("  echo removed: {db:.1} dB, reported {:.1} dB", aec.loss_db());
        assert!(
            db > 20.0,
            "only {db:.1} dB of echo was removed, which the other end still hears"
        );
        assert!(
            aec.loss_db() > 15.0,
            "the reported loss, {:.1} dB, does not match what was measured",
            aec.loss_db()
        );
    }

    /// A voice on this end must come through, not be cancelled.
    ///
    /// # The failure this catches
    ///
    /// A canceller learns by assuming whatever it could not predict is echo. If
    /// it keeps learning while the near end speaks, it learns to predict *them*
    /// and starts subtracting their voice: the far end hears words chewed away
    /// mid-syllable. Freezing adaptation during double talk is what stops it,
    /// and this is the test that says the freezing works.
    #[test]
    fn a_voice_on_this_end_survives_double_talk() {
        let mut aec = EchoCanceller::new();
        let played = noise(48_000 * 4, 0xfeed_face);
        let echo = through_a_room(&played);

        // Silence for three seconds while it converges, then somebody speaks.
        let mut speech = vec![0.0f32; echo.len()];
        for (n, s) in speech.iter_mut().enumerate().skip(48_000 * 3) {
            let t = n as f32 / 48_000.0;
            *s = 0.5 * (2.0 * std::f32::consts::PI * 300.0 * t).sin();
        }
        let heard: Vec<f32> = echo.iter().zip(&speech).map(|(e, s)| e + s).collect();

        let mut cleaned = Vec::new();
        for start in (0..played.len()).step_by(BLOCK) {
            let end = (start + BLOCK).min(played.len());
            aec.played(&played[start..end]);
            cleaned.extend(aec.capture(&heard[start..end]));
        }

        let tail = cleaned.len().saturating_sub(48_000);
        let kept = energy(&cleaned[tail..]);
        let spoken = energy(&speech[speech.len() - 48_000..]);

        assert!(
            kept > spoken * 0.25,
            "the near end's voice was cancelled along with the echo: {kept:.5} left \
             of {spoken:.5} spoken"
        );
    }

    /// The microphone must not stall when the other end goes quiet.
    ///
    /// # The failure this catches
    ///
    /// The canceller holds a captured block back until it has a played block to
    /// match it against, which is right: cancelling against audio that has not
    /// arrived would be guessing. But the loudspeaker plays nothing while the
    /// other end is silent, so a caller that only hands over what was actually
    /// queued hands over nothing, and this direction of the call goes silent
    /// whenever the other one does. The shortfall is silence and has to be said
    /// so. Only the shortfall: padding every block as well as queueing the real
    /// audio puts twice as much reference through as microphone, and the filter
    /// is then aligned against nothing at all.
    #[test]
    fn silence_from_the_other_end_does_not_stall_the_microphone() {
        let mut aec = EchoCanceller::new();
        let heard = noise(BLOCK * 4, 0x5eed_1234);

        let mut out = Vec::new();
        for chunk in heard.chunks(BLOCK) {
            let deficit = chunk.len().saturating_sub(aec.reference_available());
            if deficit > 0 {
                aec.played(&vec![0.0f32; deficit]);
            }
            out.extend(aec.capture(chunk));
        }

        assert_eq!(
            out.len(),
            heard.len(),
            "the microphone stalled while the other end was quiet"
        );
        for (a, b) in out.iter().zip(&heard) {
            assert!((a - b).abs() < 1e-6, "silence changed the microphone");
        }
    }

    /// Nothing played means nothing to cancel, and nothing damaged.
    #[test]
    fn a_microphone_with_no_playback_is_untouched() {
        let mut aec = EchoCanceller::new();
        let heard = noise(BLOCK * 8, 0x0bad_beef);

        // No `played` at all: the canceller has no reference and must hold the
        // audio rather than pass through a guess.
        assert!(
            aec.capture(&heard).is_empty(),
            "audio was let through before there was anything to cancel against"
        );

        // Once silence is played, what comes out is what went in.
        aec.played(&vec![0.0f32; heard.len()]);
        let out = aec.capture(&[]);
        assert_eq!(out.len(), heard.len());
        for (a, b) in out.iter().zip(&heard) {
            assert!((a - b).abs() < 1e-6, "silence changed the microphone");
        }
    }
}
