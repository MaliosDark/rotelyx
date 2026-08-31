//! Taking the room out of a voice.
//!
//! # What this is for
//!
//! A codec at 12 kbit/s spends its bits on whatever is loudest. In a quiet room
//! that is somebody talking. In a kitchen with a fan it is the fan, and the
//! voice gets what is left, so the call sounds worse than the same call in a
//! quiet room by more than the noise itself accounts for. Removing steady noise
//! before encoding gives those bits back.
//!
//! # How the noise is found without being told
//!
//! Nobody labels which moments are speech. What separates them is that a voice
//! comes and goes and a fan does not: over a second or two, every frequency a
//! fan occupies has a moment where only the fan is in it, and every frequency a
//! voice occupies has a moment where the voice is not. So the quietest thing
//! each frequency has been over the last while is the noise in it, and that is
//! what this tracks. It needs no voice detector and it cannot be fooled by
//! somebody who talks continuously, because the tracking is per frequency
//! rather than over the whole signal.
//!
//! # Why it does not remove all of it
//!
//! Subtracting an estimate exactly leaves the places where the estimate was
//! slightly wrong, and those come out as short tones appearing and vanishing:
//! "musical noise", which is far more distracting than the steady hiss it
//! replaced. Leaving a floor under the subtraction keeps the residue steady, so
//! what is left sounds like a quieter room rather than like a broken machine.

use crate::echo::{fft, C};

const BLOCK: usize = 256;
const FFT_LEN: usize = 2 * BLOCK;

/// How much of the estimate to take out.
///
/// Above one on purpose: an estimate that is right on average is too low half
/// the time, and what is left over in those moments is what turns into musical
/// noise.
const OVER_SUBTRACT: f32 = 1.6;

/// The quietest a bin is allowed to get, as a fraction of what came in.
///
/// This is the difference between a quieter room and a broken machine.
const FLOOR: f32 = 0.15;

/// How fast the running power follows the signal.
const SMOOTHING: f32 = 0.7;

/// How fast the noise estimate is allowed to climb.
///
/// Slowly, and far slower than it falls. A voice is a rise; a fan starting is
/// also a rise, and telling them apart is not possible in the moment. Rising
/// slowly means a voice never becomes the noise estimate, at the cost of a
/// second or two of hiss when the fan does start.
const NOISE_CLIMB: f32 = 1.02;

/// And how fast it may fall, which is as fast as the signal does.
const NOISE_FALL: f32 = 0.85;

pub struct Denoiser {
    window: Vec<f32>,
    /// Smoothed power per bin.
    power: Vec<f32>,
    /// The quietest each bin has been lately, which is the noise in it.
    noise: Vec<f32>,
    /// The half-block that overlap-add still owes the output.
    tail: Vec<f32>,
    pending: Vec<f32>,
    ready: Vec<f32>,
    started: bool,
}

impl Default for Denoiser {
    fn default() -> Self {
        Self::new()
    }
}

impl Denoiser {
    pub fn new() -> Self {
        // A Hann window, which sums to one across a half-block hop and so
        // reconstructs exactly when nothing is changed.
        let window: Vec<f32> = (0..FFT_LEN)
            .map(|n| {
                let t = n as f32 / FFT_LEN as f32;
                0.5 - 0.5 * (2.0 * std::f32::consts::PI * t).cos()
            })
            .collect();

        Self {
            window,
            power: vec![0.0; FFT_LEN],
            noise: vec![0.0; FFT_LEN],
            tail: vec![0.0; BLOCK],
            pending: Vec::new(),
            ready: Vec::new(),
            started: false,
        }
    }

    /// Clean what the microphone heard. Returns whole blocks as they finish.
    pub fn process(&mut self, samples: &[f32]) -> Vec<f32> {
        self.pending.extend_from_slice(samples);
        while self.pending.len() >= FFT_LEN {
            let mut frame = [C::ZERO; FFT_LEN];
            for (slot, (sample, w)) in frame
                .iter_mut()
                .zip(self.pending.iter().zip(self.window.iter()))
            {
                *slot = C {
                    re: sample * w,
                    im: 0.0,
                };
            }
            // Hop by half a window: the second half of this block is the first
            // half of the next.
            self.pending.drain(..BLOCK);

            fft(&mut frame, false);
            self.shape(&mut frame);
            fft(&mut frame, true);

            let mut out = vec![0.0f32; BLOCK];
            for i in 0..BLOCK {
                out[i] = self.tail[i] + frame[i].re * self.window[i];
                self.tail[i] = frame[BLOCK + i].re * self.window[BLOCK + i];
            }
            self.ready.extend_from_slice(&out);
        }
        std::mem::take(&mut self.ready)
    }

    /// Track the noise and pull each bin down towards it.
    fn shape(&mut self, frame: &mut [C; FFT_LEN]) {
        for (k, bin) in frame.iter_mut().enumerate() {
            let p = bin.norm_sq();
            self.power[k] = if self.started {
                SMOOTHING * self.power[k] + (1.0 - SMOOTHING) * p
            } else {
                p
            };

            // The quietest it has been, chased down quickly and up slowly.
            self.noise[k] = if !self.started {
                self.power[k]
            } else if self.power[k] < self.noise[k] {
                self.noise[k] * NOISE_FALL + self.power[k] * (1.0 - NOISE_FALL)
            } else {
                (self.noise[k] * NOISE_CLIMB).min(self.power[k])
            };

            let gain = if self.power[k] > 0.0 {
                (1.0 - OVER_SUBTRACT * self.noise[k] / self.power[k]).max(FLOOR)
            } else {
                FLOOR
            };
            *bin = bin.scale(gain);
        }
        self.started = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hiss(n: usize, seed: u32, level: f32) -> Vec<f32> {
        let mut state = seed | 1;
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                ((state as f32 / u32::MAX as f32) * 2.0 - 1.0) * level
            })
            .collect()
    }

    fn tone(n: usize, hz: f32, level: f32) -> Vec<f32> {
        (0..n)
            .map(|i| {
                let t = i as f32 / 48_000.0;
                level * (2.0 * std::f32::consts::PI * hz * t).sin()
            })
            .collect()
    }

    fn energy(x: &[f32]) -> f32 {
        x.iter().map(|s| s * s).sum::<f32>() / x.len().max(1) as f32
    }

    fn run(input: &[f32]) -> Vec<f32> {
        let mut d = Denoiser::new();
        let mut out = Vec::new();
        for chunk in input.chunks(BLOCK) {
            out.extend(d.process(chunk));
        }
        out
    }

    /// A steady room must get quieter.
    #[test]
    fn steady_noise_is_reduced() {
        let noisy = hiss(48_000 * 2, 0x1357_9bdf, 0.2);
        let out = run(&noisy);

        let tail = out.len().saturating_sub(24_000);
        let before = energy(&noisy[noisy.len() - 24_000..]);
        let after = energy(&out[tail..]);
        let db = 10.0 * (before / after.max(1e-12)).log10();

        assert!(
            db > 8.0,
            "only {db:.1} dB of a steady room was removed, which is not worth \
             the distortion any of this costs"
        );
    }

    /// A voice must come through it.
    ///
    /// # The failure this catches
    ///
    /// A suppressor tuned by how much noise it removes removes the voice too:
    /// the quietest possible output is silence. What matters is the difference
    /// between the two, so this asserts that speech survives the same setting
    /// that takes 8 dB off the room.
    ///
    /// # Why the speech here comes and goes
    ///
    /// Because that is what separates it from a fan. This finds the noise by
    /// tracking the quietest each frequency has been, which works on the fact
    /// that a voice leaves gaps and a fan does not. A first version of this
    /// test used a continuous tone and the suppressor removed 98% of it,
    /// correctly: a tone that never stops *is* stationary noise by every
    /// measure this has. Speech is not, and the test now says so instead of
    /// asking for something no estimator of this kind can give.
    #[test]
    fn a_voice_survives() {
        // Syllables: two hundred milliseconds on, a hundred off.
        let n = 48_000 * 3;
        let mut voice = vec![0.0f32; n];
        let mut i = 0;
        while i < n {
            let on = (48_000.0 * 0.2) as usize;
            let burst = tone(on.min(n - i), 300.0, 0.35);
            voice[i..i + burst.len()].copy_from_slice(&burst);
            i += on + (48_000.0 * 0.1) as usize;
        }

        let noisy: Vec<f32> = voice
            .iter()
            .zip(hiss(voice.len(), 0x2468_ace0, 0.2))
            .map(|(v, n)| v + n)
            .collect();

        let out = run(&noisy);
        let tail = out.len().saturating_sub(48_000);
        let kept = energy(&out[tail..]);
        let spoken = energy(&voice[voice.len() - 48_000..]);

        // Printed so a change of a few percent is visible without reading the
        // source to find out what the bounds were.
        let fraction = kept / spoken;
        println!("  the voice keeps {:.0}% of its energy", fraction * 100.0);

        // Bounded on both sides, and the reason for each is different.
        //
        // **Below**, because taking the voice out with the room is the failure
        // this exists to catch. It measures 56% and the bound was 30%, which
        // left room for the suppressor to get half again as destructive without
        // anything failing: a guard that has stopped guarding. Fifty leaves six
        // points for a legitimate change and catches a real one.
        //
        // **Above**, because a suppressor that does nothing passed. The input
        // here is voice plus hiss, so leaving it untouched keeps *more* than the
        // voice had, and every assertion below a hundred percent was satisfied
        // by removing nothing at all. The other test in this module watches a
        // held tone, which is a different signal and would not have caught it
        // either.
        assert!(
            fraction > 0.50,
            "the voice was taken out with the room: {:.0}% left, and it measures 56",
            fraction * 100.0
        );
        assert!(
            fraction < 0.75,
            "the suppressor kept {:.0}% of voice-plus-hiss, which is more voice \
             than there was: it is not removing the hiss",
            fraction * 100.0
        );
    }

    /// What this cannot do, said out loud.
    ///
    /// A sound that never stops is noise to this, whatever it is. A held organ
    /// note, a siren on one pitch, somebody humming without a breath: all of
    /// them are what a fan looks like to an estimator that separates speech
    /// from noise by which one leaves gaps. This is written as a test rather
    /// than a comment so that it stays true, and so that anybody who changes
    /// the tracking has to decide about it on purpose.
    #[test]
    fn a_sound_that_never_stops_is_treated_as_noise() {
        let held = tone(48_000 * 2, 300.0, 0.35);
        let out = run(&held);

        let tail = out.len().saturating_sub(24_000);
        let before = energy(&held[held.len() - 24_000..]);
        let after = energy(&out[tail..]);

        assert!(
            after < before * 0.1,
            "a continuous tone was kept, which means the noise tracking has \
             changed and the comment above it is now wrong"
        );
    }

    /// Silence in must be silence out, not a machine hunting for noise.
    #[test]
    fn silence_stays_silent() {
        let out = run(&vec![0.0f32; BLOCK * 40]);
        assert!(
            out.iter().all(|s| s.abs() < 1e-6),
            "something was invented in a silent room"
        );
    }
}
