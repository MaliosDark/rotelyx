//! Temporal noise shaping: making the quantisation noise follow the sound.
//!
//! # The problem this is for
//!
//! A transform codec quantises a whole window at once, so its error is spread
//! evenly across that window. For 40 ms of steady sound that is exactly right.
//! For a plosive it is not: the burst is loud enough to buy a lot of error, and
//! that error lands on the 35 ms of near-silence in front of it as well as on
//! the burst. The ear hears a click before the consonant, and it is the loudest
//! thing a long window does wrong. `a_plosive_smears_backwards_into_the_silence_before_it`
//! measures it.
//!
//! # Why this and not block switching
//!
//! The usual fix is to notice the transient and transform it as several short
//! windows instead of one long one. It works, and it costs the whole framing:
//! two more window shapes for the transitions, a second band layout for the
//! short blocks, and a decoder that has to agree with the encoder about which
//! shape every frame used or the overlap-add stops reconstructing. Rotelyx has
//! one hop, 20 ms, chosen for a conversation, and the band tables and the
//! pyramid quantiser are all built on it.
//!
//! Temporal noise shaping gets at the same problem from the other end and
//! leaves all of that alone. A transient in time is a smooth ridge across
//! frequency, so linear prediction *along the coefficients* has something to
//! predict. Code the prediction error instead of the coefficients and the
//! decoder's synthesis filter shapes the quantisation noise by the same
//! envelope it reconstructs, which is the temporal envelope of the frame. The
//! noise ends up under the burst, where the burst masks it, instead of spread
//! in front of it.
//!
//! It costs one flag bit, three bits of order, and four bits per coefficient.
//!
//! # What makes it exact
//!
//! The encoder runs the prediction error filter over the original coefficients
//! and the decoder runs the recursion over the ones it has rebuilt. Those are
//! inverses of each other as long as both use the same filter, which is why the
//! encoder throws away the coefficients it computed and re-derives the filter
//! from the quantised reflection coefficients it is about to transmit. Using
//! the unquantised ones would leave the decoder undoing a filter that was never
//! applied.
//!
//! Reflection coefficients rather than the direct form for the same reason they
//! are used everywhere else: `|k| < 1` is the stability condition and it
//! survives quantisation, so a decoder cannot be handed a synthesis filter that
//! rings away to infinity.

use crate::mdct::FRAME;
use crate::rangecoder::{Decoder, Encoder};

/// Longest prediction filter across frequency.
///
/// Eight taps is what AAC settled on. Beyond that the gain on a 900 coefficient
/// run stops paying for the four bits per tap.
pub const MAX_ORDER: usize = 8;

/// First coefficient the filter covers, at 25 Hz per coefficient.
///
/// 1.5 kHz. Below it the ear localises in frequency rather than in time, the
/// transform is already doing the right thing, and filtering there would spend
/// bits fighting the harmonic structure of a vowel.
pub const START: usize = 60;

/// Bytes per frame below which the frame cannot afford to be shaped.
///
/// The filter is 36 bits. At 30 bytes a frame, which is 12 kbit/s and the
/// lowest rate a call ever drops to, that is 15% of the frame and it still pays
/// for itself: pre-echo falls by 16 dB and the signal to noise ratio *rises*,
/// because noise moved out of the silence and under the burst that masks it.
///
/// Below that it stops paying, and below 20 bytes the band levels alone no
/// longer fit once the filter has taken its share. Both sides are built with
/// the rate, so neither has to be told: a frame under this size carries no
/// shaping bits at all, not even the flag saying there are none.
pub const MIN_BYTES_PER_FRAME: usize = 30;

/// Whether a frame at this rate carries shaping at all.
pub fn allowed(bytes_per_frame: usize) -> bool {
    bytes_per_frame >= MIN_BYTES_PER_FRAME
}

/// Prediction gain below which the filter is not worth its side information.
///
/// A frame with no transient predicts badly across frequency, and shaping noise
/// that was not concentrated anyway makes it worse while costing 35 bits.
const GAIN_THRESHOLD: f64 = 1.4;

/// Bits per reflection coefficient.
const COEFFICIENT_BITS: usize = 4;

/// The largest quantiser index, so the reconstructed `|k|` stays below one.
const MAX_INDEX: i32 = 7;

/// A filter as it travels: quantised, so both sides derive the same taps.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filter {
    /// Zero means the frame is coded without shaping.
    pub order: usize,
    /// Quantiser indices in `-7..=7`, one per tap.
    pub indices: [i8; MAX_ORDER],
}

impl Filter {
    pub fn is_active(&self) -> bool {
        self.order > 0
    }

    /// Bits this filter occupies in the frame.
    pub fn bits(&self) -> usize {
        if self.order == 0 {
            1
        } else {
            1 + 3 + self.order * COEFFICIENT_BITS
        }
    }

    fn reflection(&self) -> Vec<f64> {
        self.indices[..self.order]
            .iter()
            .map(|&q| dequantise(q))
            .collect()
    }

    /// Direct-form taps, `a[0] == 1`.
    fn taps(&self) -> Vec<f64> {
        step_up(&self.reflection())
    }

    /// Encoder side: replace the coefficients with the prediction error.
    pub fn apply(&self, coefficients: &mut [f32]) {
        if !self.is_active() {
            return;
        }
        let a = self.taps();
        let original: Vec<f64> = coefficients.iter().map(|&c| c as f64).collect();

        for n in START..coefficients.len() {
            let mut acc = original[n];
            for (j, tap) in a.iter().enumerate().skip(1) {
                // Before the range starts there is no history, which the decoder
                // assumes too.
                if n >= j + START {
                    acc += tap * original[n - j];
                }
            }
            coefficients[n] = acc as f32;
        }
    }

    /// Decoder side: run the recursion that undoes [`Filter::apply`].
    pub fn undo(&self, coefficients: &mut [f32]) {
        if !self.is_active() {
            return;
        }
        let a = self.taps();
        let mut rebuilt = vec![0.0f64; coefficients.len()];

        for n in START..coefficients.len() {
            let mut acc = coefficients[n] as f64;
            for (j, tap) in a.iter().enumerate().skip(1) {
                if n >= j + START {
                    acc -= tap * rebuilt[n - j];
                }
            }
            rebuilt[n] = acc;
            coefficients[n] = acc as f32;
        }
    }

    pub fn write(&self, encoder: &mut Encoder) {
        if self.order == 0 {
            encoder.write_bits(0, 1);
            return;
        }
        encoder.write_bits(1, 1);
        encoder.write_bits(self.order as u32 - 1, 3);
        for &q in &self.indices[..self.order] {
            encoder.write_bits((q as i32 + 8) as u32, COEFFICIENT_BITS);
        }
    }

    pub fn read(decoder: &mut Decoder) -> Self {
        if decoder.read_bits(1) == 0 {
            return Self::default();
        }
        let order = decoder.read_bits(3) as usize + 1;
        let mut indices = [0i8; MAX_ORDER];
        for index in indices.iter_mut().take(order) {
            // A malformed frame can name any index; clamping keeps `|k| < 1`
            // rather than trusting the wire for the stability of an IIR filter.
            let raw = decoder.read_bits(COEFFICIENT_BITS) as i32 - 8;
            *index = raw.clamp(-MAX_INDEX, MAX_INDEX) as i8;
        }
        Self { order, indices }
    }
}

/// Arcsine quantisation, which spreads the levels where the filter is sensitive.
///
/// A reflection coefficient near one matters far more than one near zero: the
/// pole it places moves fast as `|k|` approaches the unit circle. Uniform steps
/// in angle rather than in `k` put the resolution where it changes the sound.
fn quantise(k: f64) -> i8 {
    let scaled =
        (k.clamp(-0.999, 0.999).asin() / (std::f64::consts::PI / 2.0)) * (MAX_INDEX as f64 + 0.5);
    (scaled.round() as i32).clamp(-MAX_INDEX, MAX_INDEX) as i8
}

fn dequantise(q: i8) -> f64 {
    (q as f64 * (std::f64::consts::PI / 2.0) / (MAX_INDEX as f64 + 0.5)).sin()
}

/// Reflection coefficients to direct-form taps.
fn step_up(k: &[f64]) -> Vec<f64> {
    let mut a = vec![1.0f64];
    for (i, &ki) in k.iter().enumerate() {
        let mut next = a.clone();
        next.push(ki);
        for j in 1..=i {
            next[j] = a[j] + ki * a[i + 1 - j];
        }
        a = next;
    }
    a
}

/// Levinson-Durbin. Returns the reflection coefficients and the prediction gain.
fn levinson(r: &[f64], order: usize) -> (Vec<f64>, f64) {
    let mut a = vec![0.0f64; order + 1];
    a[0] = 1.0;
    let mut k = Vec::with_capacity(order);
    let mut error = r[0];
    if error <= 0.0 {
        return (k, 1.0);
    }

    for i in 0..order {
        let mut acc = r[i + 1];
        for j in 0..i {
            acc += a[j + 1] * r[i - j];
        }
        let ki = -acc / error;
        if !ki.is_finite() || ki.abs() >= 1.0 {
            break;
        }

        let previous = a.clone();
        for j in 1..=i {
            a[j] = previous[j] + ki * previous[i + 1 - j];
        }
        a[i + 1] = ki;
        k.push(ki);

        error *= 1.0 - ki * ki;
        if error <= 0.0 {
            break;
        }
    }

    let gain = if error > 0.0 { r[0] / error } else { 1.0 };
    (k, gain)
}

/// Blocks the window is split into when looking for a transient.
const ENVELOPE_BLOCKS: usize = 8;

/// How far above the frame's average a block has to rise to count as an onset.
///
/// Swept against the recorded speech, and it is a knee rather than a taste. At
/// 8 the filter almost never fires on real speech and buys nothing. At 2 it
/// fires on held sounds and costs 1.1 dB of signal to noise on nasals. At 3 the
/// gaps between words are 3.6 to 5.0 dB quieter and the cost is 0.4 dB on
/// nasals and 0.2 dB or less everywhere else.
const ONSET_RATIO: f32 = 3.0;

/// Does this window hold a transient, judged in time rather than in frequency.
///
/// # Why the frequency-domain prediction gain is not enough on its own
///
/// Linear prediction across frequency fits anything with regular structure in
/// frequency, and a nasal or a vowel has plenty: harmonics evenly spaced at the
/// pitch. The gain is high and it means the opposite of a transient. Shaping
/// those frames flattened the harmonic comb the band energies were already
/// exploiting and cost up to 2 dB of signal to noise on held sounds, for a
/// problem they do not have.
///
/// Pre-echo is a statement about time: error spread across a window where the
/// sound was not. So the question is asked in time. The window is cut into
/// eight blocks and shaping is offered only when one of them stands far above
/// the frame's average, which is what an onset is and what a held sound is not.
pub fn is_transient(audio: &[f32]) -> bool {
    let block = audio.len() / ENVELOPE_BLOCKS;
    if block == 0 {
        return false;
    }
    let energies: Vec<f32> = (0..ENVELOPE_BLOCKS)
        .map(|b| {
            audio[b * block..(b + 1) * block]
                .iter()
                .map(|s| s * s)
                .sum::<f32>()
                / block as f32
        })
        .collect();

    let mean = energies.iter().sum::<f32>() / ENVELOPE_BLOCKS as f32;
    if mean <= 1e-12 {
        return false;
    }
    let peak = energies.iter().cloned().fold(0.0f32, f32::max);
    peak / mean > ONSET_RATIO
}

/// Decide whether this frame wants shaping, and with what filter.
pub fn analyse(coefficients: &[f32]) -> Filter {
    debug_assert_eq!(coefficients.len(), FRAME);
    let region = &coefficients[START..];
    if region.len() <= MAX_ORDER * 4 {
        return Filter::default();
    }

    let mut r = vec![0.0f64; MAX_ORDER + 1];
    for (lag, slot) in r.iter_mut().enumerate() {
        *slot = region
            .iter()
            .zip(region.iter().skip(lag))
            .map(|(&x, &y)| x as f64 * y as f64)
            .sum();
    }
    if r[0] <= 0.0 {
        return Filter::default();
    }

    // A small ridge on the zero lag keeps a nearly singular autocorrelation from
    // producing a filter right up against the unit circle.
    r[0] *= 1.0001;

    let (k, gain) = levinson(&r, MAX_ORDER);
    if k.is_empty() || gain < GAIN_THRESHOLD {
        return Filter::default();
    }

    let mut indices = [0i8; MAX_ORDER];
    for (slot, &ki) in indices.iter_mut().zip(k.iter()) {
        *slot = quantise(ki);
    }

    // Trailing taps that quantised to nothing are taps nobody has to send.
    let mut order = k.len();
    while order > 0 && indices[order - 1] == 0 {
        order -= 1;
    }
    if order == 0 {
        return Filter::default();
    }

    Filter { order, indices }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transient() -> Vec<f32> {
        // A frame whose energy is concentrated at one instant looks, across
        // frequency, like something with structure to predict.
        let mut seed = 0x1234_5678u32;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            (seed as f32 / u32::MAX as f32) - 0.5
        };
        (0..FRAME)
            .map(|i| {
                let ramp = (i as f32 / FRAME as f32 * 6.0).cos();
                ramp * (1.0 + 0.3 * next())
            })
            .collect()
    }

    #[test]
    fn the_filter_and_its_inverse_return_the_coefficients() {
        let filter = Filter {
            order: 4,
            indices: [5, -3, 2, -1, 0, 0, 0, 0],
        };
        let original = transient();

        let mut working = original.clone();
        filter.apply(&mut working);
        assert_ne!(
            working[START + 20],
            original[START + 20],
            "the filter did nothing, so the inverse proves nothing"
        );

        filter.undo(&mut working);
        for (i, (&before, &after)) in original.iter().zip(working.iter()).enumerate() {
            assert!(
                (before - after).abs() < 1e-3 * before.abs().max(1.0),
                "coefficient {i} came back as {after} instead of {before}"
            );
        }
    }

    #[test]
    fn the_coefficients_below_the_range_are_left_alone() {
        let filter = Filter {
            order: 3,
            indices: [6, -4, 2, 0, 0, 0, 0, 0],
        };
        let original = transient();
        let mut working = original.clone();
        filter.apply(&mut working);
        assert_eq!(
            original[..START],
            working[..START],
            "shaping reached below where the ear stops localising in time"
        );
    }

    #[test]
    fn a_frame_with_nothing_to_predict_is_left_unshaped() {
        // White noise across frequency is a frame with a flat envelope in time.
        // There is no ridge to fit, so 35 bits of filter would buy nothing.
        let mut seed = 0x9e37_79b9u32;
        let flat: Vec<f32> = (0..FRAME)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                (seed as f32 / u32::MAX as f32) - 0.5
            })
            .collect();

        assert!(
            !analyse(&flat).is_active(),
            "a flat frame was given a filter it cannot use"
        );
    }

    #[test]
    fn silence_asks_for_nothing() {
        assert!(!analyse(&vec![0.0f32; FRAME]).is_active());
    }

    #[test]
    fn the_filter_survives_the_wire() {
        let filter = Filter {
            order: 6,
            indices: [7, -7, 3, 0, -2, 1, 0, 0],
        };
        let mut encoder = Encoder::new();
        filter.write(&mut encoder);
        assert_eq!(encoder.len_bits(), filter.bits());

        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(Filter::read(&mut decoder), filter);
    }

    #[test]
    fn an_absent_filter_costs_one_bit() {
        let filter = Filter::default();
        let mut encoder = Encoder::new();
        filter.write(&mut encoder);
        assert_eq!(encoder.len_bits(), 1);

        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes);
        assert!(!Filter::read(&mut decoder).is_active());
    }

    #[test]
    fn every_reachable_filter_is_stable() {
        // A decoder runs this as an IIR filter on whatever the wire said. Every
        // index the wire can name has to leave the poles inside the circle, or a
        // malformed frame is a way to make a decoder produce infinity.
        for q in -MAX_INDEX..=MAX_INDEX {
            let k = dequantise(q as i8);
            assert!(
                k.abs() < 1.0,
                "index {q} reconstructs to a reflection coefficient of {k}"
            );
        }
    }
}
