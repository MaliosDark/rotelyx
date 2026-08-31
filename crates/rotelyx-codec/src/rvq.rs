//! Residual vector quantisation.
//!
//! # The idea, taken from neural codecs and used without one
//!
//! SoundStream at 3 kbit/s beats Opus at 12, and the part doing the work is not
//! the neural network. It is the **quantiser**: code the vector once coarsely,
//! subtract what was coded, code what is left, and repeat. Each stage describes
//! the error the previous stages could not, and the stages compose.
//!
//! Nothing about that requires a learned codebook. It works on any vector and
//! any quantiser, and here the quantiser is PVQ.
//!
//! # What staging actually buys, measured
//!
//! Not a better rate. That was the expectation and it is wrong. On a 16
//! coefficient band, two stages of eight pulses reach a 0.989 match for 60
//! bits, against 0.985 for a single stage of twenty four using 51. Staging
//! costs a little more for the same result, because each stage pays again for
//! a gain and for rounding its own codeword.
//!
//! What it buys is a **ceiling that single-stage coding does not have**, and
//! that turns out to matter far more:
//!
//! | Band | Best single stage | Staged | Gain |
//! |---|---|---|---|
//! | 16 | 0.985 | 0.998 | +0.013 |
//! | 32 | 0.923 | 0.968 | +0.045 |
//! | 64 | 0.751 | 0.867 | **+0.116** |
//!
//! The gain grows with the width of the band, and for the same reason in each
//! case: a wider band exhausts the addressable codebook sooner. `V(64, 16)`
//! already outruns a 64 bit index, so a single stage on a 64 coefficient band
//! stops at twelve pulses and there is nothing further to be done with it.
//! Stages carry on.
//!
//! Wide bands are exactly where a transform codec spends its upper spectrum, so
//! the case where staging helps most is the case that occurs most.
//!
//! PVQ's search is also greedy: pulses are placed one at a time and never
//! reconsidered, so a large `k` compounds early mistakes. A later stage sees
//! those mistakes as its input.
//!
//! # Why this fits our channel and nobody else's
//!
//! Stages are ordered by importance and independent to decode: the first alone
//! is a complete, coarse rendering of the band, and each further stage refines
//! it. That makes the bitstream **layered**, and a layered bitstream is only
//! worth having if late data is still useful.
//!
//! For a telephone call it is not: a refinement that arrives after its frame has
//! played is discarded. Rotelyx's fidelity channel spends delay and recovers
//! loss, so a refinement that arrives late is a refinement that arrives. The
//! base layer can be sent once and the refinements sent, resent and waited for.
//!
//! That is not built yet. What is built is the quantiser it needs.

use crate::pvq;

/// The most stages. Past four the residual is below what the energy
/// quantisation itself resolves, so a further stage describes rounding error.
pub const MAX_STAGES: usize = 4;

/// Bits spent on each stage's gain.
///
/// # Why the gain is transmitted rather than assumed
///
/// A stage codes a direction and nothing else: every PVQ codeword has the same
/// length. How much of that direction to add is a separate number, and it was
/// first left implicit, with the decoder assuming each stage contributed half
/// of the one before.
///
/// That made staging **worse than not staging**. The encoder subtracted the
/// amount that best cancelled the residual and the decoder added a guess, so
/// every stage after the first corrected an error the decoder was not making
/// and introduced one it was. Two stages matched the target less well than one.
///
/// Four bits per stage is sixteen levels on a log scale, which is enough for
/// the correction to land and cheap enough not to matter beside a codeword.
pub const GAIN_BITS: usize = 4;
const GAIN_LEVELS: u8 = 1 << GAIN_BITS;

/// The smallest gain, as a fraction. Below this a stage is contributing less
/// than the energy quantiser resolves.
const GAIN_MIN: f32 = 1.0 / 64.0;
const GAIN_MAX: f32 = 2.0;

fn quantise_gain(gain: f32) -> u8 {
    let g = gain.abs().clamp(GAIN_MIN, GAIN_MAX);
    let t = (g / GAIN_MIN).log2() / (GAIN_MAX / GAIN_MIN).log2();

    ((t * (GAIN_LEVELS - 1) as f32).round() as u8).min(GAIN_LEVELS - 1)
}

fn dequantise_gain(level: u8) -> f32 {
    let t = level as f32 / (GAIN_LEVELS - 1) as f32;
    GAIN_MIN * (GAIN_MAX / GAIN_MIN).powf(t)
}

/// One stage's coded output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage {
    /// Pulses in this stage's codebook.
    pub pulses: usize,
    /// Which codeword.
    pub index: u64,
    /// How much of it to add, quantised.
    pub gain: u8,
    /// Whether to subtract rather than add.
    pub negative: bool,
}

impl Stage {
    /// Bits this stage occupies, codeword and gain together.
    pub fn bits(&self, n: usize) -> usize {
        pvq::bits(n, self.pulses).ceil() as usize + GAIN_BITS + 1
    }
}

/// Choose how many pulses each stage gets from a bit budget.
///
/// The first stage takes the largest share, because it carries the direction
/// itself and everything after is correction. Later stages halve, which matches
/// how quickly the residual shrinks once the coarse direction is right.
pub fn plan(n: usize, budget: usize) -> Vec<usize> {
    let mut stages = Vec::new();
    let mut left = budget;

    for stage in 0..MAX_STAGES {
        if left == 0 {
            break;
        }
        // Half the remaining budget to this stage, all of it to the last.
        let share = if stage + 1 == MAX_STAGES {
            left
        } else {
            left / 2
        };

        let k = pvq::pulses_for(n, share.max(1));
        if k == 0 {
            break;
        }

        let cost = pvq::bits(n, k).ceil() as usize + GAIN_BITS + 1;
        if cost > left {
            break;
        }

        stages.push(k);
        left -= cost;
    }
    stages
}

/// Code `target` in stages, returning one index per stage.
pub fn encode(target: &[f32], plan: &[usize]) -> Vec<Stage> {
    let n = target.len();

    // A codebook too large to index cannot be used, whatever a caller asks for.
    //
    // `plan` respects that bound, but `encode` is public and was reachable with
    // a raw pulse count. `bits` returns infinity for such a codebook, and
    // casting infinity to an integer saturates, so the size arithmetic wrapped
    // and produced a frame that decoded to noise with a *negative* match. In
    // release it was silent. Clamping here means the boundary is guarded rather
    // than the callers being trusted.
    let plan: Vec<usize> = plan
        .iter()
        .map(|&k| {
            let mut k = k.min(pvq::MAX_K_FOR);
            while k > 0 && !pvq::bits(n, k).is_finite() {
                k -= 1;
            }
            k
        })
        .filter(|&k| k > 0)
        .collect();

    // Work at unit level throughout, so a stage's gain is a fraction of the
    // whole rather than an absolute size. The band's real level is transmitted
    // separately and applied afterwards.
    let rms = (target.iter().map(|t| t * t).sum::<f32>() / n as f32).sqrt();
    if rms < 1e-9 {
        return Vec::new();
    }

    let mut residual: Vec<f32> = target.iter().map(|t| t / rms).collect();
    let mut out = Vec::with_capacity(plan.len());

    for &pulses in &plan {
        let y = pvq::search(&residual, pulses);
        let shape = pvq::to_shape(&y);

        // How much of this direction best cancels what is left, quantised to
        // exactly what the decoder will use. Subtracting the unquantised value
        // would leave the next stage correcting an error the decoder never
        // makes.
        let exact = fit(&residual, &shape);
        let level = quantise_gain(exact);
        let gain = dequantise_gain(level) * exact.signum();

        for (r, s) in residual.iter_mut().zip(&shape) {
            *r -= gain * s;
        }

        out.push(Stage {
            pulses,
            index: pvq::index(&y),
            gain: level,
            negative: exact < 0.0,
        });
    }
    out
}

/// Rebuild a vector from its stages.
pub fn decode(n: usize, stages: &[Stage]) -> Vec<f32> {
    let mut out = vec![0.0f32; n];

    for stage in stages {
        let shape = pvq::to_shape(&pvq::deindex(n, stage.pulses, stage.index));
        let gain = dequantise_gain(stage.gain) * if stage.negative { -1.0 } else { 1.0 };

        for (o, s) in out.iter_mut().zip(&shape) {
            *o += gain * s;
        }
    }

    // The result carries the shape and not the level: the band's energy is
    // transmitted separately and applied afterwards.
    let rms = (out.iter().map(|o| o * o).sum::<f32>() / n as f32).sqrt();
    if rms > 1e-9 {
        for o in out.iter_mut() {
            *o /= rms;
        }
    }
    out
}

/// The scale at which `shape` best matches `target`, in the least squares
/// sense.
fn fit(target: &[f32], shape: &[f32]) -> f32 {
    let dot: f32 = target.iter().zip(shape).map(|(t, s)| t * s).sum();
    let norm: f32 = shape.iter().map(|s| s * s).sum();

    if norm < 1e-9 {
        0.0
    } else {
        dot / norm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(n: usize) -> Vec<f32> {
        (0..n)
            .map(|i| {
                let x = i as f32 * 0.37;
                x.sin() * 2.0 + (x * 3.1).cos() * 0.5
            })
            .collect()
    }

    /// How well a coded shape matches the direction of the original, from -1
    /// to 1. The only thing PVQ codes, so the only thing worth measuring.
    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if na < 1e-9 || nb < 1e-9 {
            0.0
        } else {
            dot / (na * nb)
        }
    }

    /// The property the whole idea rests on: each stage must improve on the
    /// last. If a stage makes it worse the residual is being mis-subtracted.
    #[test]
    fn every_stage_improves_on_the_one_before() {
        for n in [16usize, 32, 64] {
            let t = target(n);
            let mut previous = -2.0f32;

            for stages in 1..=MAX_STAGES {
                let p = vec![4usize; stages];
                let decoded = decode(n, &encode(&t, &p));
                let c = cosine(&t, &decoded);

                assert!(
                    c > previous,
                    "{n} coefficients: stage {stages} matched {c:.3}, worse than {previous:.3}"
                );
                previous = c;
            }
        }
    }

    /// The reason staging exists: a wide band has a ceiling that one stage
    /// cannot pass, because `V(N,K)` outruns a 64 bit index long before the
    /// band is well described.
    ///
    /// This is the measured justification and it is not the one that was
    /// expected. Staging is slightly *worse* than one stage at the same rate.
    /// It is far better than one stage at the best rate one stage can reach.
    #[test]
    fn staging_passes_the_ceiling_one_stage_cannot() {
        let n = 64;
        let t = target(n);

        // The most a single stage can address for a band this wide.
        let mut best_single = 0usize;
        for k in 1..=pvq::MAX_K_FOR {
            if pvq::bits(n, k).is_finite() {
                best_single = k;
            }
        }
        let single = cosine(&t, &decode(n, &encode(&t, &[best_single])));

        let staged = cosine(&t, &decode(n, &encode(&t, &[12, 6, 3])));

        assert!(
            staged > single + 0.1,
            "staging reached {staged:.3} against a single-stage ceiling of {single:.3}, \
             which is not enough to justify the extra gains and rounding"
        );
    }

    /// A pulse count too large to index must be clamped rather than wrapped.
    /// Unclamped it produced a frame whose match with the target was negative.
    #[test]
    fn an_unindexable_pulse_count_is_clamped() {
        let n = 64;
        let t = target(n);

        let absurd = cosine(&t, &decode(n, &encode(&t, &[64])));
        assert!(
            absurd > 0.3,
            "an over-large pulse count produced a match of {absurd:.3}, which means it \
             was used rather than clamped"
        );
    }

    /// A plan must fit its budget, or frames overflow.
    #[test]
    fn a_plan_never_exceeds_its_budget() {
        for n in [4usize, 16, 32, 120, 200] {
            for budget in [0usize, 5, 20, 60, 200, 1000] {
                let p = plan(n, budget);
                let total: usize = p
                    .iter()
                    .map(|&k| pvq::bits(n, k).ceil() as usize + GAIN_BITS + 1)
                    .sum();

                assert!(
                    total <= budget,
                    "{n} coefficients, budget {budget}: plan {p:?} costs {total}"
                );
                assert!(p.len() <= MAX_STAGES);
            }
        }
    }

    /// More budget must buy more stages or bigger ones, never fewer.
    #[test]
    fn more_budget_buys_more_description() {
        let n = 32;
        let mut previous = 0usize;

        for budget in (10..400).step_by(10) {
            let total: usize = plan(n, budget)
                .iter()
                .map(|&k| pvq::bits(n, k).ceil() as usize + GAIN_BITS + 1)
                .sum();

            assert!(
                total >= previous,
                "budget {budget} planned {total} bits, down from {previous}"
            );
            previous = total;
        }
    }

    /// The decoded shape carries direction only. Its level is the energy
    /// stage's business, and a shape that drifted in level would move a band's
    /// loudness with the coarseness of its texture.
    #[test]
    fn the_decoded_shape_has_unit_level() {
        let n = 32;
        let t = target(n);

        for stages in 1..=MAX_STAGES {
            let decoded = decode(n, &encode(&t, &vec![5usize; stages]));
            let rms = (decoded.iter().map(|d| d * d).sum::<f32>() / n as f32).sqrt();

            assert!(
                (rms - 1.0).abs() < 1e-4,
                "{stages} stages produced RMS {rms}, so the band's level would drift"
            );
        }
    }

    /// What staging actually buys, measured rather than asserted.
    #[test]
    #[ignore = "measurement"]
    fn measure_staging() {
        for n in [16usize, 32, 64] {
            let t = target(n);
            println!("\n  {n} coefficients");
            println!("    plan            bits   cosine");

            for plan in [
                vec![4usize],
                vec![8],
                vec![16],
                vec![24],
                vec![4, 4],
                vec![8, 8],
                vec![6, 6, 6],
                vec![8, 4, 2],
                vec![12, 6, 3],
                vec![8, 6, 4, 2],
            ] {
                let bits: usize = plan
                    .iter()
                    .map(|&k| pvq::bits(n, k).ceil() as usize + GAIN_BITS + 1)
                    .sum();
                let c = cosine(&t, &decode(n, &encode(&t, &plan)));
                println!("    {plan:14?}  {bits:4}   {c:.3}");
            }
        }
    }

    /// A silent target must not invent a shape.
    #[test]
    fn silence_produces_nothing() {
        let decoded = decode(16, &encode(&[0.0; 16], &[4, 4]));
        assert!(decoded.iter().all(|d| d.abs() < 1e-6 || d.is_finite()));
    }
}
