//! Telyx: a transform speech codec for a channel where latency is free.
//!
//! # Why write one at all
//!
//! Opus is excellent and is not going to be beaten at its own objective, which
//! is quality per bit **under a hard twenty millisecond latency budget**. That
//! budget is not a detail, it is the constraint the whole design bends around:
//! short windows, no lookahead, and loss concealment carried inside the codec
//! because the transport cannot be trusted to recover anything in time.
//!
//! Rotelyx's fidelity channel has none of those constraints. Delay is spendable,
//! the whole utterance can be looked at, and `rotelyx-media` already recovers
//! lost frames rather than concealing them. A codec built for *that* is a
//! different codec, and the difference is not a tuning parameter.
//!
//! So this is not "Opus but ours". It is the codec the constraint we actually
//! have would produce, and where it borrows a good idea it says so.
//!
//! # What is honestly measurable here, and what is not
//!
//! Everything in the tests is objective: reconstruction error, bitrate, how
//! gracefully quality falls as bits are removed. Those are real numbers and
//! they are asserted.
//!
//! **Perceptual quality is not measured, because it cannot be without ears.**
//! Codec quality is settled by listening panels, and a decade of Opus's
//! advantage is exactly that tuning. Signal-to-noise ratio correlates with what
//! a person hears only loosely, and any claim here that Telyx *sounds* better
//! than anything would be a claim nobody has tested. It has not been listened
//! to. That has to happen before a single word of comparison is published.
//!
//! # Measured, on a synthetic voice-like signal
//!
//! | kbit/s | SNR before PVQ | SNR now | Level error |
//! |---|---|---|---|
//! | 8 | 1.3 dB | 3.0 dB | +0.03 dB |
//! | 12 | 2.7 dB | **12.9 dB** | +0.09 dB |
//! | 16 | 7.4 dB | **20.3 dB** | +0.11 dB |
//! | 24 | 8.4 dB | **26.2 dB** | +0.10 dB |
//! | 32 | 6.3 dB | 26.3 dB | +0.10 dB |
//!
//! Two changes account for all of it. The bit allocator became reverse
//! water-filling, which stopped a wide high band buying its way in ahead of the
//! narrow ones where speech is understood. And the shape quantiser became PVQ,
//! which removed the floor of one bit per coefficient that had been leaving the
//! entire budget unspent.
//!
//! The curve flattens above 24 kbit/s because the test signal has nothing above
//! 2.4 kHz left to describe, not because the codec stops improving.
//!
//! The level is accurate to a tenth of a decibel throughout, which is the
//! property that matters most: a listener notices loudness that drifts long
//! before they notice texture that is rough.
//!
//! # What is not built, in the order it should be
//!
//! **A listening test.** Every number above is objective and codec quality is
//! not. Nobody has heard a second of this, and until somebody has, no
//! comparison with any other codec may be made.
//!
//! **An entropy coder.** The bit packer is fixed width. Energy deltas between
//! adjacent frames cluster hard around zero and are written at six bits each
//! regardless. The cheapest remaining twenty percent.
//!
//! **Block switching**, so a plosive is not smeared across forty milliseconds.
//!
//! **A fast transform.** The MDCT is written from the definition, which is
//! O(n²) and far slower than real time.
//!
//! **Long term prediction**, which is where most of the remaining redundancy in
//! voiced speech lives.

pub mod bands;
pub mod entropy;
pub mod grouped;
pub mod layered;
pub mod pvq;
pub mod rvq;
pub mod tns;
pub mod mdct;
pub mod rangecoder;

use bands::BANDS;
use mdct::{FRAME, WINDOW};
use rangecoder::{Decoder, Encoder};

/// Bytes per frame, which at 20 ms per frame sets the bitrate.
///
/// 60 bytes is 24 kbit/s, in the range where Opus is transparent for speech and
/// well above where it is merely intelligible. Chosen as a starting point to
/// measure against rather than as a claim.
pub const DEFAULT_BYTES_PER_FRAME: usize = 60;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("a frame is {FRAME} samples, not {got}")]
    WrongFrameSize { got: usize },
    #[error("encoded frame is malformed or truncated")]
    Malformed,
    #[error("a {bytes} byte frame cannot carry the band energies, which need {needed}")]
    RateTooLow { bytes: usize, needed: usize },
}

/// Quantisation levels for a band's energy, in decibels.
///
/// Energy is coded in the log domain because hearing is logarithmic: the step
/// from quiet to slightly less quiet matters as much as the step from loud to
/// slightly less loud, and a linear scale spends all its precision at the top.
/// # Why the step and the count are not free to move separately
///
/// They multiply to the range the scale can express, and a band louder than
/// that range clamps to the top level and loses its real energy. Halving the
/// step to buy accuracy, with the count left alone, halves the range instead:
/// measured, that took the codec from 26.2 dB to 5.4 dB, because every loud
/// band in the signal was pinned to the ceiling.
///
/// So the range is the constant and the count follows from the step. A level
/// still has to fit in a `u8` and in one arithmetic symbol, which bounds how
/// fine the step can go.
pub(crate) const ENERGY_STEP_DB: f32 = 0.5;
pub(crate) const ENERGY_MIN_DB: f32 = -60.0;
/// The scale spans this many decibels, whatever the step is.
pub(crate) const ENERGY_RANGE_DB: f32 = 96.0;
pub(crate) const ENERGY_LEVELS: usize = (ENERGY_RANGE_DB / ENERGY_STEP_DB) as usize;

/// How many scale steps one coded energy increment spans, given the rate.
///
/// # Why this is not one number
///
/// The band energies and the band shapes are paid for out of the same frame,
/// so spending on one is a decision not to spend on the other, and the right
/// split is not the same at every rate. Measured end to end, in dB SNR:
///
/// | step   | 12 kbit/s | 16 kbit/s | 24 kbit/s | 32 kbit/s and up |
/// |--------|-----------|-----------|-----------|------------------|
/// | 1.5 dB | **12.9**  | **20.3**  | 26.2      | 26.3             |
/// | 1.0 dB | 10.5      | 19.0      | 27.0      | 27.5             |
/// | 0.75 dB| 10.6      | 19.1      | 27.8      | 28.3             |
/// | 0.5 dB | 7.6       | 16.0      | **28.2**  | **29.2**         |
///
/// Two things are in that table. At low rates a finer envelope is paid for out
/// of the shapes and is not worth it. At high rates the envelope is the
/// ceiling: the codec used to saturate at 26.3 dB however many bits it was
/// given, and 26.3 dB is almost exactly what a 0.43 dB rms gain error predicts.
/// Every bit above 24 kbit/s was being spent refining a shape that was then
/// multiplied by the wrong number.
///
/// The quantum is derived from the frame size rather than signalled, because
/// both sides already know the frame size and a signalled field would cost bits
/// to say something neither side had to be told.
pub(crate) fn level_quantum(bytes_per_frame: usize) -> u8 {
    match bytes_per_frame {
        0..=44 => 3, // 1.5 dB: the envelope must not crowd out the shapes
        45..=59 => 2, // 1.0 dB
        _ => 1,      // 0.5 dB: above 24 kbit/s the envelope is what limits us
    }
}

/// The smallest frame that can carry the band energies at a given size.
///
/// A caller choosing a rate needs this, because below it the envelope does not
/// fit and there is nothing sensible for the encoder to do: the energies are
/// not optional, and a frame without them is not a quiet frame but a wrong one.
///
/// Self-referential by nature, since the quantum depends on the frame size, so
/// it is resolved by asking what a frame of that size would use.
pub fn minimum_bytes_per_frame(bytes_per_frame: usize) -> usize {
    let quantum = level_quantum(bytes_per_frame) as usize;
    let coded = ENERGY_LEVELS.div_ceil(quantum);
    let bits = coded.next_power_of_two().trailing_zeros() as usize;
    (BANDS * bits).div_ceil(8)
}

/// Round a level to a multiple of the quantum.
///
/// The scale itself stays at its finest throughout, and coarsening happens by
/// only ever emitting multiples. That keeps one set of constants, one alphabet
/// and one ring for the residuals, and lets the adaptive models discover the
/// spacing rather than being told it.
pub(crate) fn coarsen(level: u8, quantum: u8) -> u8 {
    let q = quantum as u16;
    let rounded = ((level as u16 + q / 2) / q) * q;
    rounded.min((ENERGY_LEVELS - 1) as u16) as u8
}

pub(crate) fn energy_to_level(energy: f32) -> u8 {
    let db = 20.0 * energy.max(1e-6).log10();
    let level = ((db - ENERGY_MIN_DB) / ENERGY_STEP_DB).round();
    level.clamp(0.0, (ENERGY_LEVELS - 1) as f32) as u8
}

pub(crate) fn level_to_energy(level: u8) -> f32 {
    let db = ENERGY_MIN_DB + level as f32 * ENERGY_STEP_DB;
    10f32.powf(db / 20.0)
}

/// Encodes frames.
pub struct TelyxEncoder {
    window: Vec<f32>,
    bytes_per_frame: usize,
    /// Previous frame's energy levels, for differential coding.
    ///
    /// Spectra change slowly between adjacent 20 ms frames, so the difference
    /// is almost always small and costs far fewer bits than the value.
    previous: [u8; BANDS],
    started: bool,
    /// Scale steps per coded increment, from [`level_quantum`].
    quantum: u8,
    /// How many distinct coded values that leaves.
    coded_levels: usize,
    /// And how many bits one of them needs.
    ///
    /// Derived, because this was a literal `6` in four places while the level
    /// count was a literal `64` somewhere else. They agreed until the step
    /// changed, and then the top of every level was silently truncated and the
    /// codec decoded at 0 dB.
    level_bits: usize,
}

impl TelyxEncoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            window: mdct::window(),
            bytes_per_frame,
            previous: [0; BANDS],
            started: false,
            quantum: level_quantum(bytes_per_frame),
            coded_levels: ENERGY_LEVELS.div_ceil(level_quantum(bytes_per_frame) as usize),
            level_bits: ENERGY_LEVELS
                .div_ceil(level_quantum(bytes_per_frame) as usize)
                .next_power_of_two()
                .trailing_zeros() as usize,
        }
    }

    /// Encode one window of audio into one frame.
    ///
    /// The input is `WINDOW` samples, of which the second half will also be the
    /// first half of the next call: frames overlap, which is what makes the
    /// transform invertible.
    pub fn encode(&mut self, audio: &[f32]) -> Result<Vec<u8>, CodecError> {
        if audio.len() != WINDOW {
            return Err(CodecError::WrongFrameSize { got: audio.len() });
        }

        let mut coefficients = mdct::forward(audio, &self.window);

        // Shaping happens before the energies are measured: what gets quantised
        // from here on is the prediction error, and the levels have to describe
        // that rather than the coefficients it came from.
        // Two separate questions. Whether the frame carries shaping bits at all
        // depends only on the rate, which the decoder also knows, so it stays out
        // of the bitstream. Whether the filter in those bits is active depends on
        // the audio, which the decoder does not know, so it travels as the flag.
        let shaping = tns::allowed(self.bytes_per_frame);
        let filter = if shaping && tns::is_transient(audio) {
            tns::analyse(&coefficients)
        } else {
            tns::Filter::default()
        };
        filter.apply(&mut coefficients);

        let measured = bands::energies(&coefficients);

        // Quantise the energies **first**, and use the quantised values for
        // everything after.
        //
        // The bit allocation is derived from the energies, and the decoder only
        // ever has the quantised ones. Allocating from the exact values here
        // produces a different split than the decoder computes, so it reads the
        // wrong bits for every band and the output is noise. It was written
        // that way first, and the symptom was a codec that appeared to work at
        // every stage in isolation.
        let measured_levels: Vec<u8> = measured
            .iter()
            .map(|&e| coarsen(energy_to_level(e), self.quantum))
            .collect();
        let energies: Vec<f32> = measured_levels.iter().map(|&l| level_to_energy(l)).collect();

        let shape = bands::normalise(&coefficients, &energies);

        // The shapes are quantised before the levels are written, so the levels
        // can be chosen against the shape the decoder will hold rather than
        // against the energy that was measured. The level section is a fixed
        // number of bits, so the budget is known without having written it.
        let spent = if shaping { filter.bits() } else { 0 } + BANDS * self.level_bits;
        let budget = self.bytes_per_frame.saturating_mul(8).saturating_sub(spent);
        let allocation = bands::allocate(&energies, budget);

        let coded: Vec<Option<CodedShape>> = (0..BANDS)
            .map(|b| quantise_band_shape(&shape[bands::range(b)], allocation[b]))
            .collect();

        let levels = refine_levels(
            &coefficients,
            &coded,
            measured_levels,
            self.quantum,
            self.coded_levels,
            &allocation,
            budget,
        );

        let mut encoder = Encoder::new();
        if shaping {
            filter.write(&mut encoder);
        }

        for b in 0..BANDS {
            if self.started {
                // Taken modulo the number of levels rather than written as a
                // signed number, so that a delta too large for the field wraps
                // into a value the decoder recovers exactly instead of being
                // truncated into a different level.
                let delta = ((levels[b] as i16 - self.previous[b] as i16)
                    / self.quantum as i16)
                    .rem_euclid(self.coded_levels as i16);
                encoder.write_bits(delta as u32, self.level_bits);
            } else {
                encoder.write_bits(levels[b] as u32 / self.quantum as u32, self.level_bits);
            }
        }
        self.previous.copy_from_slice(&levels);
        self.started = true;

        // --- shape, with what is left of the budget ---
        debug_assert_eq!(
            encoder.len_bits(),
            spent,
            "the level section is not the size the allocation was computed against"
        );

        for coded in &coded {
            write_coded_shape(&mut encoder, coded.as_ref());
        }

        let mut out = encoder.finish();

        // `resize` pads, and it also truncates. The truncating case was never
        // considered and it was reachable: at fifteen bytes a frame the band
        // energies alone need eighteen, so the last bands' levels were cut off,
        // read back out of the zero padding, and the whole frame decoded six
        // decibels quiet. Silently, and it went into a published table as a
        // low quality rate rather than a broken one.
        if out.len() > self.bytes_per_frame {
            return Err(CodecError::RateTooLow {
                bytes: self.bytes_per_frame,
                needed: out.len(),
            });
        }
        out.resize(self.bytes_per_frame, 0);
        Ok(out)
    }
}

/// Decodes frames.
pub struct TelyxDecoder {
    window: Vec<f32>,
    bytes_per_frame: usize,
    /// Advances every frame, so an invented texture never repeats.
    ///
    /// Decoder-local and never transmitted: nothing on the encoding side has to
    /// agree with it, so it does not matter that a lost frame makes it drift.
    frames_decoded: u32,
    previous: [u8; BANDS],
    started: bool,
    /// Scale steps per coded increment, from [`level_quantum`].
    quantum: u8,
    /// How many distinct coded values that leaves.
    coded_levels: usize,
    /// And how many bits one of them needs.
    ///
    /// Derived, because this was a literal `6` in four places while the level
    /// count was a literal `64` somewhere else. They agreed until the step
    /// changed, and then the top of every level was silently truncated and the
    /// codec decoded at 0 dB.
    level_bits: usize,
    overlap: mdct::OverlapAdd,
}

impl TelyxDecoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            frames_decoded: 0,
            window: mdct::window(),
            bytes_per_frame,
            previous: [0; BANDS],
            started: false,
            quantum: level_quantum(bytes_per_frame),
            coded_levels: ENERGY_LEVELS.div_ceil(level_quantum(bytes_per_frame) as usize),
            level_bits: ENERGY_LEVELS
                .div_ceil(level_quantum(bytes_per_frame) as usize)
                .next_power_of_two()
                .trailing_zeros() as usize,
            overlap: mdct::OverlapAdd::new(),
        }
    }

    /// Decode one frame into `FRAME` finished samples.
    pub fn decode(&mut self, frame: &[u8]) -> Result<Vec<f32>, CodecError> {
        if frame.len() != self.bytes_per_frame {
            return Err(CodecError::Malformed);
        }
        self.frames_decoded = self.frames_decoded.wrapping_add(1);

        let mut decoder = Decoder::new(frame);
        let filter = if tns::allowed(self.bytes_per_frame) {
            tns::Filter::read(&mut decoder)
        } else {
            tns::Filter::default()
        };

        let mut levels = [0u8; BANDS];
        for b in 0..BANDS {
            levels[b] = if self.started {
                let delta = decoder.read_bits(self.level_bits) as i16 * self.quantum as i16;
                (self.previous[b] as i16 + delta)
                    .rem_euclid(self.coded_levels as i16 * self.quantum as i16) as u8
            } else {
                (decoder.read_bits(self.level_bits) * self.quantum as u32) as u8
            };
        }
        self.previous.copy_from_slice(&levels);
        self.started = true;

        let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();

        let spent = decoder.position_bits();
        let budget = self.bytes_per_frame.saturating_mul(8).saturating_sub(spent);
        let allocation = bands::allocate(&energies, budget);

        let mut shape = vec![0.0f32; FRAME];
        for b in 0..BANDS {
            // The band index goes into the seed as well as the frame counter,
            // so two unfunded bands in one frame do not get the same texture.
            let seed = self
                .frames_decoded
                .wrapping_mul(BANDS as u32)
                .wrapping_add(b as u32);
            read_band_shape(&mut decoder, &mut shape[bands::range(b)], allocation[b], seed);
        }

        let mut coefficients = bands::denormalise(&shape, &energies);
        filter.undo(&mut coefficients);
        Ok(self.overlap.push(&mdct::inverse(&coefficients, &self.window)))
    }
}

/// Write one band's normalised shape with `bits` of budget.
///
/// # Why this is a vector quantiser and not a scalar one
///
/// The first version coded a sign and a magnitude per coefficient. That has a
/// floor of one bit each, and the budget is routinely a third of that, so every
/// band fell through to noise while the whole budget went unspent.
///
/// PVQ has no such floor. The band is described as a direction on the unit
/// sphere, chosen from every way of placing `k` signed pulses across its
/// coefficients, and `k` sets the rate continuously. A 32 coefficient band can
/// be coded in six bits or in thirty two, and both are real descriptions of the
/// whole band rather than a precise description of a fraction of it.
/// One band's shape once quantised: what goes on the wire, and what the decoder
/// will hold when it comes back off.
///
/// Both, because the encoder needs the second to answer a question it cannot
/// answer from the first. See [`refine_levels`].
struct CodedShape {
    index: u64,
    width: usize,
    decoded: Vec<f32>,
}

/// Quantise one band's shape, without writing it anywhere yet.
fn quantise_band_shape(shape: &[f32], bits: usize) -> Option<CodedShape> {
    let n = shape.len();
    if n == 0 {
        return None;
    }
    let k = pvq::pulses_for(n, bits);
    if k == 0 {
        // Nothing affordable. The band is reconstructed from its energy alone,
        // which is noise at the right level rather than silence.
        return None;
    }
    let y = pvq::search(shape, k);
    Some(CodedShape {
        index: pvq::index(&y),
        width: pvq::bits(n, k).ceil() as usize,
        decoded: pvq::to_shape(&y),
    })
}

fn write_coded_shape(encoder: &mut Encoder, coded: Option<&CodedShape>) {
    let Some(coded) = coded else {
        return;
    };
    // The index fits in `width` bits by construction, but a codebook can need
    // more than 32, so it is written in two halves.
    if coded.width > 32 {
        encoder.write_bits((coded.index >> 32) as u32, coded.width - 32);
        encoder.write_bits(coded.index as u32, 32);
    } else {
        encoder.write_bits(coded.index as u32, coded.width);
    }
}

/// Choose each band's level against the shape the decoder will actually hold,
/// rather than against the energy that was measured.
///
/// # The two questions that are not the same question
///
/// The encoder measures a band's energy and rounds it to the nearest level on
/// the grid. That is the best answer to "how loud was this band". It is not the
/// best answer to "which level, times *this* shape, lands closest to the
/// coefficients", and the second is the one that decides what is heard, because
/// the decoder rebuilds the band as level times shape.
///
/// They differ because the pyramid's shape is not the direction the energy was
/// measured along. The error is a parabola in the gain with its minimum at the
/// projection `<x, s> / <s, s>`, and the measured energy sits above that
/// whenever the shape is imperfect, which is always. So the band comes out
/// slightly too loud, and always in the same direction.
///
/// # Why this is free
///
/// The pyramid codes direction and every search normalises before it starts, so
/// a band's shape bits do not depend on its level at all. Only the bit
/// allocation does. A level may therefore move at no cost whenever the
/// allocation does not follow it, which is what the check below is for: propose
/// the best level, keep it only if the split of bits across bands comes out
/// identical. No extra bits, no second search, and it cannot make the frame
/// worse because a change that does not reduce the error is not taken.
///
/// # What it is worth, measured
///
/// `measure_the_gain_left_on_the_table` reports it per rate, and the shape of
/// the answer is that it grows as the rate falls, because a starved band gets a
/// cruder shape and a cruder shape projects further from the energy:
///
/// | bytes a frame | as sent | with this | the unreachable ideal |
/// |---|---:|---:|---:|
/// | 20 | 8.45 dB | 8.85 dB | 9.01 dB |
/// | 30 | 14.07 dB | 14.39 dB | 14.74 dB |
/// | 60 | 26.26 dB | 26.32 dB | 26.77 dB |
/// | 120 | 28.23 dB | 28.23 dB | 28.95 dB |
///
/// Nothing at the top of the range and a third of a decibel at the bottom,
/// which is where a call spends its worst moments.
fn refine_levels(
    coefficients: &[f32],
    coded: &[Option<CodedShape>],
    mut levels: Vec<u8>,
    quantum: u8,
    coded_levels: usize,
    allocation: &[usize],
    budget: usize,
) -> Vec<u8> {
    let ceiling = (coded_levels * quantum as usize).min(256) as i16;

    for b in 0..BANDS {
        let Some(shape) = coded[b].as_ref() else {
            continue;
        };
        let x = &coefficients[bands::range(b)];
        let ss: f32 = shape.decoded.iter().map(|s| s * s).sum();
        if ss <= 1e-12 {
            continue;
        }

        let error_at = |gain: f32| -> f64 {
            x.iter()
                .zip(&shape.decoded)
                .map(|(&c, &s)| {
                    let d = (c - gain * s) as f64;
                    d * d
                })
                .sum()
        };

        let here = levels[b];
        let mut best = error_at(level_to_energy(here));
        let mut best_at = here;

        // Four steps either way is more than the projection can ever move a
        // level, and stopping there keeps this from being a search.
        for step in -4i16..=4 {
            let candidate = (here as i16 + step * quantum as i16).clamp(0, ceiling - 1) as u8;
            let candidate = coarsen(candidate, quantum);
            if candidate == here {
                continue;
            }
            let e = error_at(level_to_energy(candidate));
            if e < best {
                best = e;
                best_at = candidate;
            }
        }

        if best_at == here {
            continue;
        }

        // Only if the bits fall the same way. Otherwise the decoder would split
        // the budget differently from the encoder that wrote the shapes, and
        // read every band from the wrong place.
        let mut trial = levels.clone();
        trial[b] = best_at;
        let trial_energies: Vec<f32> = trial.iter().map(|&l| level_to_energy(l)).collect();
        if bands::allocate(&trial_energies, budget) == allocation {
            levels = trial;
        }
    }

    levels
}

/// Invent a band's texture at unit level.
///
/// # Why this takes a seed, and what happened when it did not
///
/// The signs have to be random. Alternating them, which is the obvious thing to
/// write, produces `+ - + -`, a tone at the Nyquist frequency rather than
/// noise: it puts an audible whistle at the top of every unfunded band. That
/// was written first and it whistled, so it was replaced by a hash of the
/// coefficient index.
///
/// Which was a fixed pattern. The same one, in every frame, for ever. The
/// comment above it said the signs were random and they were merely
/// *scattered*: a decoded fricative had a frame-to-frame correlation of
/// **+0.991** where its input had +0.008, which is not noise at all but a
/// signal periodic at the frame rate, and 48000/960 is 50 Hz. An `/s/` came out
/// as a buzz.
///
/// So the seed advances with the decoder. Nothing on the encoding side has to
/// agree with it, because this texture is invented rather than transmitted:
/// the only requirement is that it does not repeat.
pub(crate) fn invent_shape(shape: &mut [f32], seed: u32) {
    for (i, c) in shape.iter_mut().enumerate() {
        let mut h = (i as u32)
            .wrapping_mul(2_654_435_761)
            .wrapping_add(seed.wrapping_mul(0x9e37_79b9));
        h ^= h >> 15;
        h = h.wrapping_mul(2_246_822_519);
        h ^= h >> 13;
        h = h.wrapping_mul(3_266_489_917);
        h ^= h >> 16;
        *c = if h & 1 == 0 { 1.0 } else { -1.0 };
    }
}

fn read_band_shape(decoder: &mut Decoder, shape: &mut [f32], bits: usize, seed: u32) {
    let n = shape.len();
    if n == 0 {
        return;
    }

    let k = pvq::pulses_for(n, bits);
    if k == 0 {
        // Noise at unit level: the energy is right even though the texture is
        // invented. See [`invent_shape`].
        invent_shape(shape, seed);
        return;
    }

    let width = pvq::bits(n, k).ceil() as usize;

    let index = if width > 32 {
        let high = decoder.read_bits(width - 32) as u64;
        (high << 32) | decoder.read_bits(32) as u64
    } else {
        decoder.read_bits(width) as u64
    };

    // An index past the end of the codebook means a corrupted frame. Clamping
    // rather than failing keeps one bad frame to one rough band.
    let total = pvq::count(n, k);
    let index = if total > 0 { index % total } else { 0 };

    shape.copy_from_slice(&pvq::to_shape(&pvq::deindex(n, k, index)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::PI;

    /// Something with the shape of speech: a pitch with harmonics, an envelope,
    /// and a formant-like emphasis. Not speech, but not a sine wave either.
    fn voice_like(samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|n| {
                let t = n as f32 / mdct::SAMPLE_RATE as f32;
                let pitch = 120.0 + 20.0 * (2.0 * PI * 3.0 * t).sin();

                let mut s = 0.0;
                for harmonic in 1..=12 {
                    let f = pitch * harmonic as f32;
                    if f > 8_000.0 {
                        break;
                    }
                    // Formant-ish emphasis around 700 Hz.
                    let gain = 1.0 / harmonic as f32 * (1.0 + 2.0 * (-(f - 700.0).abs() / 500.0).exp());
                    s += gain * (2.0 * PI * f * t).sin();
                }

                // Syllable envelope.
                // 0.25 rather than 0.3: at 0.3 this peaked at 1.113, which is
            // not audio. No device can represent a sample past full scale, and
            // measuring a codec on a signal that clips measures the clipping.
            s * 0.25 * (0.5 + 0.5 * (2.0 * PI * 4.0 * t).sin())
            })
            .collect()
    }

    /// Segmental signal-to-noise ratio, in decibels. Objective, and only
    /// loosely related to what a person would say about the sound.
    /// Whether the codec can hold a call, which is a different question from
    /// whether it sounds good and was for a long time the one nobody asked.
    ///
    /// The transform alone used to cost 270 percent of real time. It is the
    /// whole codec that has to fit, so it is the whole codec that is measured.
    #[test]
    fn the_codec_runs_faster_than_real_time() {
        use std::time::Instant;

        let signal = voice_like(mdct::FRAME * 60);
        let bytes = 60;

        let mut encoder = TelyxEncoder::new(bytes);
        let mut decoder = TelyxDecoder::new(bytes);

        let frames: Vec<&[f32]> = (0..signal.len() - mdct::WINDOW)
            .step_by(mdct::FRAME)
            .map(|s| &signal[s..s + mdct::WINDOW])
            .collect();

        let start = Instant::now();
        let mut sink = 0.0f32;
        for f in &frames {
            let packet = encoder.encode(f).expect("encode");
            sink += decoder.decode(&packet).expect("decode")[0];
        }
        let elapsed = start.elapsed().as_secs_f64();

        let audio_seconds = frames.len() as f64 * mdct::FRAME as f64 / mdct::SAMPLE_RATE as f64;
        let load = elapsed / audio_seconds;

        assert!(
            load < 0.25,
            "encoding and decoding costs {:.0}% of real time on one core, so a \
             call would not run (sink {sink})",
            load * 100.0
        );
        println!(
            "\n  encode and decode together: {:.1}% of real time on one core",
            load * 100.0
        );
    }

    /// The same, on the codec a call actually runs.
    ///
    /// The one above drives `TelyxEncoder`. Voice goes through
    /// `LayeredEncoder`, which does strictly more work: it codes every band
    /// into stages, trims to the link's budget, and then chooses each band's
    /// level against the stages that survived, one band at a time. That last
    /// part is an arithmetic encode per band it wants to move, so it is the
    /// part worth watching.
    #[test]
    fn the_layered_codec_runs_faster_than_real_time() {
        use crate::layered::{LayeredDecoder, LayeredEncoder};
        use std::time::Instant;

        let signal = voice_like(mdct::FRAME * 60);
        let bytes = 60;

        let mut encoder = LayeredEncoder::new(bytes);
        let mut decoder = LayeredDecoder::new(bytes);

        let frames: Vec<&[f32]> = (0..signal.len() - mdct::WINDOW)
            .step_by(mdct::FRAME)
            .map(|s| &signal[s..s + mdct::WINDOW])
            .collect();

        let start = Instant::now();
        let mut sink = 0.0f32;
        for f in &frames {
            let frame = encoder.encode_within(f, bytes).expect("encode");
            sink += decoder.decode(&frame).expect("decode")[0];
        }
        let elapsed = start.elapsed().as_secs_f64();

        let audio_seconds = frames.len() as f64 * mdct::FRAME as f64 / mdct::SAMPLE_RATE as f64;
        let load = elapsed / audio_seconds;

        assert!(
            load < 0.25,
            "the layered codec costs {:.0}% of real time on one core, so a call \
             would not run (sink {sink})",
            load * 100.0
        );
        println!(
            "\n  layered encode and decode together: {:.1}% of real time on one core",
            load * 100.0
        );
    }

    fn snr_db(original: &[f32], decoded: &[f32]) -> f32 {
        let signal: f32 = original.iter().map(|s| s * s).sum();
        let noise: f32 = original
            .iter()
            .zip(decoded)
            .map(|(a, b)| (a - b).powi(2))
            .sum();

        if noise < 1e-12 {
            return 99.0;
        }
        10.0 * (signal / noise).log10()
    }

    fn round_trip(signal: &[f32], bytes: usize) -> Vec<f32> {
        let mut encoder = TelyxEncoder::new(bytes);
        let mut decoder = TelyxDecoder::new(bytes);
        let mut out = Vec::new();

        for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
            let frame = encoder.encode(&signal[start..start + WINDOW]).expect("encode");
            assert_eq!(frame.len(), bytes, "the frame is not the size promised");
            out.extend(decoder.decode(&frame).expect("decode"));
        }
        out
    }

    /// What it does across the range, so the numbers are on record rather than
    /// claimed. Objective only: nobody has listened to this.
    #[test]
    #[ignore = "measurement"]
    fn measure_the_rate_quality_curve() {
        let signal = voice_like(FRAME * 14);
        let from = FRAME;

        println!("\n  kbit/s   bytes/frame   SNR dB   level error");
        for bytes in [15usize, 18, 20, 30, 40, 60, 80, 120, 160] {
            let needed = minimum_bytes_per_frame(bytes);
            if bytes < needed {
                println!(
                    "  {:6}   {bytes:11}   refused: the energies alone need {needed} bytes",
                    bytes * 8 * 50 / 1000
                );
                continue;
            }
            let decoded = round_trip(&signal, bytes);
            let len = decoded.len() - from;

            let snr = snr_db(&signal[from..from + len], &decoded[from..from + len]);

            let a = (signal[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();
            let b = (decoded[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();

            println!(
                "  {:6}   {:11}   {:6.1}   {:+.2} dB",
                bytes * 8 * 50 / 1000,
                bytes,
                snr,
                20.0 * (b / a).log10()
            );
        }
    }

    /// Where the error actually is, measured per band rather than guessed.
    #[test]
    #[ignore = "measurement"]
    fn measure_where_the_error_is() {
        let signal = voice_like(FRAME * 10);
        let decoded = round_trip(&signal, DEFAULT_BYTES_PER_FRAME);
        let from = FRAME;
        let len = decoded.len() - from;

        println!("\n  full band SNR: {:.1} dB", snr_db(&signal[from..from+len], &decoded[from..from+len]));

        let mut encoder = TelyxEncoder::new(DEFAULT_BYTES_PER_FRAME);
        let w = mdct::window();
        let c = mdct::forward(&signal[0..WINDOW], &w);
        let e = bands::energies(&c);
        let _ = encoder.encode(&signal[0..WINDOW]);
        let alloc = bands::allocate(&e, 336);

        println!("\n  band   hz            bins  bits  energy");
        for b in 0..BANDS {
            let (lo, hi) = bands::hz(b);
            println!("  {b:4}  {lo:6.0}-{hi:6.0}  {:4}  {:4}  {:.4}",
                bands::range(b).len(), alloc[b], e[b]);
        }
        let funded: f32 = (0..BANDS).filter(|&b| alloc[b] > 0).map(|b| e[b]*e[b]*bands::range(b).len() as f32).sum();
        let total: f32 = (0..BANDS).map(|b| e[b]*e[b]*bands::range(b).len() as f32).sum();
        println!("\n  energy in funded bands: {:.1}%", 100.0*funded/total);
    }

    /// How much is left on the table by choosing a band's level before its shape
    /// is known.
    ///
    /// The encoder measures a band's energy, rounds it to the nearest level on
    /// the grid, and sends that. The decoder rebuilds the band as that level
    /// times a shape the pyramid quantiser approximated. Those are two different
    /// questions. The level nearest the measured energy is the best answer to
    /// "how loud was this band"; it is not the best answer to "which level, times
    /// *this* shape, lands closest to the coefficients", because the shape is not
    /// the direction the energy was measured along.
    ///
    /// The gap is the projection: the error is smallest at the level nearest
    /// `<c, s> / <s, s>`, and the measured energy overshoots that whenever the
    /// shape is imperfect, which is always.
    ///
    /// Four numbers, and they are compared against each other rather than
    /// against what the encoder does today, because the encoder now does the
    /// second of them. See [`refine_levels`].
    ///
    /// - **nearest the energy**: round the measured energy to the grid, which is
    ///   what was done before this was measured.
    /// - **allocation kept**: the best level that leaves the split of bits
    ///   across bands untouched, so the shape bits do not change and it is free.
    ///   This is what ships.
    /// - **best level**: the best the grid can express, ignoring what it does to
    ///   the allocation. Not reachable without coding the frame twice.
    /// - **projection**: the exact `<x, s> / <s, s>`, off the grid entirely. The
    ///   ceiling, and only here to show how much of the gap is the grid's
    ///   coarseness rather than the choice of level.
    #[test]
    #[ignore = "a measurement, not a bound"]
    fn measure_the_gain_left_on_the_table() {
        let signal = voice_like(FRAME * 40);
        let window = mdct::window();
        println!();
        for rate in [20usize, 30, 60, 120] {
        let quantum = level_quantum(rate);

        let mut current = 0.0f64;
        let mut best_level = 0.0f64;
        let mut projection = 0.0f64;
        let mut original = 0.0f64;
        let mut moved = 0usize;
        let mut bands_counted = 0usize;
        let mut constrained = 0.0f64;

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let coefficients = mdct::forward(&signal[start..start + WINDOW], &window);
            let measured = bands::energies(&coefficients);
            let levels: Vec<u8> = measured
                .iter()
                .map(|&e| coarsen(energy_to_level(e), quantum))
                .collect();
            let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();
            let shape = bands::normalise(&coefficients, &energies);

            let spent = BANDS * 6;
            let allocation =
                bands::allocate(&energies, rate * 8 - spent.min(rate * 8));

            let mut candidate_levels = levels.clone();
            let mut per_band: Vec<(usize, f64, f64, u8)> = Vec::new();

            for b in 0..BANDS {
                let range = bands::range(b);
                let n = range.len();
                if allocation[b] == 0 {
                    continue;
                }

                // Exactly what the decoder will hold for this band.
                let mut encoder = Encoder::new();
                let quantised = quantise_band_shape(&shape[range.clone()], allocation[b]);
                write_coded_shape(&mut encoder, quantised.as_ref());
                let bytes = encoder.finish();
                let mut decoder = Decoder::new(&bytes);
                let mut decoded = vec![0.0f32; n];
                read_band_shape(&mut decoder, &mut decoded, allocation[b], 1);

                let c = &coefficients[range];
                let ss: f32 = decoded.iter().map(|s| s * s).sum();
                if ss <= 1e-12 {
                    continue;
                }
                let cs: f32 = c.iter().zip(&decoded).map(|(&x, &s)| x * s).sum();

                let error_at = |gain: f32| -> f64 {
                    c.iter()
                        .zip(&decoded)
                        .map(|(&x, &s)| {
                            let d = (x - gain * s) as f64;
                            d * d
                        })
                        .sum()
                };

                let sent = energies[b];
                let now = error_at(sent);

                // Every level the grid can express, near the one being sent.
                let here = levels[b];
                let mut best = now;
                let mut best_at = here;
                for step in -4i16..=4 {
                    let candidate = (here as i16 + step * quantum as i16).clamp(0, 255) as u8;
                    let candidate = coarsen(candidate, quantum);
                    let e = error_at(level_to_energy(candidate));
                    if e < best {
                        best = e;
                        best_at = candidate;
                    }
                }
                if best_at != here {
                    moved += 1;
                }
                candidate_levels[b] = best_at;

                current += now;
                best_level += best;
                projection += error_at(cs / ss);
                original += c.iter().map(|&x| (x * x) as f64).sum::<f64>();
                bands_counted += 1;
                per_band.push((b, now, best, best_at));
            }

            // Shape bits do not depend on the level: the pyramid codes direction
            // and every search normalises first. Only the allocation does. So a
            // level may move for free exactly when the allocation does not
            // follow it.
            let mut kept = levels.clone();
            for &(b, _, _, best_at) in &per_band {
                if best_at == kept[b] {
                    continue;
                }
                let mut trial = kept.clone();
                trial[b] = best_at;
                let trial_energies: Vec<f32> =
                    trial.iter().map(|&l| level_to_energy(l)).collect();
                if bands::allocate(&trial_energies, rate * 8 - spent.min(rate * 8))
                    == allocation
                {
                    kept = trial;
                }
            }
            for &(b, now, best, best_at) in &per_band {
                constrained += if kept[b] == best_at { best } else { now };
            }
        }

        let db = |err: f64| 10.0 * (original / err.max(1e-30)).log10();
        println!(
            "  {rate:3} bytes a frame, {bands_counted:5} funded bands:  \
             nearest the energy {:6.2}   allocation kept {:6.2}   \
             best level {:6.2}   projection {:6.2} dB   moved {moved}",
            db(current),
            db(constrained),
            db(best_level),
            db(projection),
        );
        }
    }

    #[test]
    fn a_frame_is_exactly_the_promised_size() {
        let signal = voice_like(WINDOW);
        let mut encoder = TelyxEncoder::new(DEFAULT_BYTES_PER_FRAME);

        let frame = encoder.encode(&signal).expect("encode");
        assert_eq!(frame.len(), DEFAULT_BYTES_PER_FRAME);

        // 60 bytes every 20 ms.
        let bitrate = DEFAULT_BYTES_PER_FRAME * 8 * 50;
        assert_eq!(bitrate, 24_000, "expected 24 kbit/s, got {bitrate}");
    }

    /// The codec must reconstruct something recognisably like the input, at a
    /// level that is right even where the texture is not.
    #[test]
    fn the_signal_survives_the_round_trip() {
        let signal = voice_like(FRAME * 12);
        let decoded = round_trip(&signal, DEFAULT_BYTES_PER_FRAME);

        // Skip the first frame, which has no overlap partner.
        let from = FRAME;
        let len = decoded.len() - from;

        let snr = snr_db(&signal[from..from + len], &decoded[from..from + len]);
        assert!(
            snr > 20.0,
            "signal to noise ratio {snr:.1} dB: the output is not tracking the input"
        );

        // And the level is right, which matters more than the texture.
        let original_rms =
            (signal[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();
        let decoded_rms =
            (decoded[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();

        let ratio = decoded_rms / original_rms;
        assert!(
            (0.5..2.0).contains(&ratio),
            "the decoded level is {ratio:.2}x the original, which is audible as a \
             volume change rather than as distortion"
        );
    }

    /// Quality must fall gradually as bits are removed, not collapse. This is
    /// the property that decides whether a codec is usable on a bad link.
    #[test]
    fn quality_degrades_gracefully_rather_than_collapsing() {
        let signal = voice_like(FRAME * 10);
        let from = FRAME;

        let mut previous = f32::INFINITY;

        for bytes in [120usize, 90, 60, 40, 25] {
            let decoded = round_trip(&signal, bytes);
            let len = decoded.len() - from;
            let snr = snr_db(&signal[from..from + len], &decoded[from..from + len]);

            assert!(
                snr.is_finite() && snr > -5.0,
                "{} kbit/s produced {snr:.1} dB, which is not a signal",
                bytes * 8 * 50 / 1000
            );
            assert!(
                snr <= previous + 3.0,
                "fewer bits produced better output, which means something is wrong \
                 with the measurement or the allocation"
            );
            previous = snr;
        }
    }

    /// Silence must not produce noise. A codec that hisses between words is
    /// worse than one that is merely rough during them.
    #[test]
    fn silence_stays_silent() {
        let silence = vec![0.0f32; FRAME * 6];
        let decoded = round_trip(&silence, DEFAULT_BYTES_PER_FRAME);

        let peak = decoded.iter().fold(0.0f32, |m, s| m.max(s.abs()));
        assert!(
            peak < 0.02,
            "silence decoded to a peak of {peak}, which is audible hiss"
        );
    }

    /// The energy envelope is what a listener hears as the shape of speech. It
    /// must survive even when the shape budget is starved.
    #[test]
    fn the_loudness_envelope_survives_a_starved_budget() {
        let signal = voice_like(FRAME * 10);
        let decoded = round_trip(&signal, 20); // 8 kbit/s

        let from = FRAME;
        let len = decoded.len() - from;

        // Compare loudness frame by frame rather than sample by sample.
        let mut tracked = 0;
        let mut frames = 0;

        for start in (from..from + len - FRAME).step_by(FRAME) {
            let a: f32 = signal[start..start + FRAME].iter().map(|s| s * s).sum();
            let b: f32 = decoded[start..start + FRAME].iter().map(|s| s * s).sum();
            frames += 1;

            let ratio = (b + 1e-9) / (a + 1e-9);
            if (0.25..4.0).contains(&ratio) {
                tracked += 1;
            }
        }

        assert!(
            tracked * 4 >= frames * 3,
            "only {tracked} of {frames} frames kept their loudness at 8 kbit/s"
        );
    }

    /// A frame of the wrong size must be refused rather than read past.
    #[test]
    fn a_malformed_frame_is_refused() {
        let mut encoder = TelyxEncoder::new(DEFAULT_BYTES_PER_FRAME);
        let mut decoder = TelyxDecoder::new(DEFAULT_BYTES_PER_FRAME);

        assert_eq!(
            encoder.encode(&[0.0; 100]),
            Err(CodecError::WrongFrameSize { got: 100 })
        );
        assert_eq!(decoder.decode(&[0u8; 10]), Err(CodecError::Malformed));
    }

    /// Energy levels must survive quantisation to within the step size, or the
    /// differential coding is drifting.
    #[test]
    fn energy_quantisation_is_accurate_to_its_step() {
        for db in [-60.0f32, -40.0, -20.0, -6.0, 0.0] {
            let energy = 10f32.powf(db / 20.0);
            let back = level_to_energy(energy_to_level(energy));

            let error_db = 20.0 * (back / energy).log10();
            assert!(
                error_db.abs() <= ENERGY_STEP_DB,
                "{db} dB came back {error_db:.2} dB out, more than one step"
            );
        }
    }
}
