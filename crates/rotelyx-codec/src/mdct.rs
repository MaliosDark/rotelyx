//! The modified discrete cosine transform, and the window that makes it
//! invertible.
//!
//! # What this buys and why the window is not optional
//!
//! Speech is far more compact in the frequency domain than the time domain: a
//! vowel that takes a thousand samples to write down is a handful of peaks to
//! describe. Any transform codec starts here.
//!
//! The awkward part is the seam between frames. Cut the signal into blocks,
//! transform each, and the edges do not line up on reconstruction: the result
//! clicks fifty times a second. The MDCT solves it by overlapping neighbouring
//! blocks by half and producing only half as many coefficients as it consumes,
//! so consecutive frames sum back to the original. That only works if the
//! window satisfies the Princen-Bradley condition, `w[n]² + w[n+M]² = 1`, which
//! is why the window here is a specific shape rather than a taste.
//!
//! # Why the window is long
//!
//! Opus works in 20 ms because it must: a conversation cannot wait. Telyx is
//! for a channel where waiting is allowed, and a longer window resolves
//! frequency more finely, which for the sustained sounds that make up most of
//! speech means fewer coefficients carrying more of the signal.
//!
//! The cost is the mirror image: a long window smears a transient across its
//! whole length, so a plosive becomes a smudge. That is what block switching is
//! for, and it is not built yet.
//!
//! # Speed, which turned out to be the whole story
//!
//! Written from the definition this transform is O(n²): 1.8 million multiplies
//! and as many calls to `cos` per frame, 28 ms forward and 26 ms back against a
//! frame representing 20 ms of audio. A call needs both directions, so the
//! transform alone was **270 percent of real time on one core**, and no amount
//! of work on quality would have made the codec usable.
//!
//! Factored through an FFT it is 0.5 percent, and the whole codec, encoding and
//! decoding together, is 1.2. It is also 775 times more accurate, because an
//! FFT accumulates in a tree of depth nine where the definition accumulates in
//! a line of length 1920 and loses precision the whole way down.

use std::f32::consts::PI;
use std::sync::OnceLock;

/// Samples per second the codec works at.
///
/// 48 kHz because that is what every audio device on a computer or phone
/// natively runs at, so anything else means resampling twice for no benefit.
pub const SAMPLE_RATE: u32 = 48_000;

/// Coefficients per frame, and therefore the hop between frames.
///
/// 960 at 48 kHz is 20 ms of new audio per frame, transformed with a 40 ms
/// window. Twice the frequency resolution Opus gets at the same hop, bought
/// with latency this channel is allowed to spend.
pub const FRAME: usize = 960;

/// The window covers two frames.
pub const WINDOW: usize = FRAME * 2;

/// The analysis and synthesis window.
///
/// `sin(pi/2 · sin²(...))`, the shape Vorbis uses. It satisfies Princen-Bradley
/// and rolls off more gently at the edges than a plain sine, which keeps
/// spectral leakage from one band into the next lower than the simpler choice.
pub fn window() -> Vec<f32> {
    (0..WINDOW)
        .map(|n| {
            let inner = (PI / (2.0 * FRAME as f32)) * (n as f32 + 0.5);
            (PI / 2.0 * inner.sin().powi(2)).sin()
        })
        .collect()
}

/// Forward MDCT written directly from the definition.
///
/// O(n²), about 1.8 million multiply-adds and as many calls to `cos` per frame.
/// Kept because it is transparently the transform the documentation describes,
/// and because [`forward`] is checked against it: a fast transform that agrees
/// with a slow one nobody doubts is a fast transform that is right.
pub fn forward_naive(input: &[f32], window: &[f32]) -> Vec<f32> {
    assert_eq!(input.len(), WINDOW);

    let windowed: Vec<f32> = input.iter().zip(window).map(|(x, w)| x * w).collect();
    let m = FRAME as f32;

    (0..FRAME)
        .map(|k| {
            let mut sum = 0.0f32;
            for (n, x) in windowed.iter().enumerate() {
                let phase = PI / m * (n as f32 + 0.5 + m / 2.0) * (k as f32 + 0.5);
                sum += x * phase.cos();
            }
            sum * (2.0 / m).sqrt()
        })
        .collect()
}

/// Inverse MDCT written directly from the definition. See [`forward_naive`].
pub fn inverse_naive(coefficients: &[f32], window: &[f32]) -> Vec<f32> {
    assert_eq!(coefficients.len(), FRAME);

    let m = FRAME as f32;

    (0..WINDOW)
        .map(|n| {
            let mut sum = 0.0f32;
            for (k, c) in coefficients.iter().enumerate() {
                let phase = PI / m * (n as f32 + 0.5 + m / 2.0) * (k as f32 + 0.5);
                sum += c * phase.cos();
            }
            sum * (2.0 / m).sqrt() * window[n]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The fast transform
// ---------------------------------------------------------------------------
//
// # Why this had to be built before anything else in the codec could ship
//
// The definition above costs 28 ms to run forward and 26 ms back, against a
// frame that represents 20 ms of audio. A call needs both, so the transform
// alone was **270 percent of real time on one core** and Telyx could not have
// carried a conversation on any hardware. Every quality figure recorded before
// this point was measured offline and was, in that sense, theoretical.
//
// # How it is done
//
// An MDCT of `2M` samples to `M` coefficients is a fold followed by a DCT-IV,
// and a DCT-IV of length `M` is a complex FFT of length `M/2` between two
// twiddles. So 960 coefficients cost one 480 point FFT.
//
// The fold comes from three symmetries of the MDCT's cosine kernel, writing
// `c(m) = cos(pi/M (m + 1/2)(k + 1/2))`:
//
//   c(m + 2M)     = -c(m)
//   c(2M - 1 - m) = -c(m)
//
// which let the 2M term sum be folded onto M values before any transform runs.
// The inverse fold is the transpose of the forward one, which is why they look
// like each other with the scatter and gather exchanged.
//
// # Why 480 is not a power of two
//
// 480 = 2^5 * 15. The FFT splits by two while it can and finishes with direct
// 15 point transforms, which is a rounding error on the total: five halvings
// leave thirty two of them at 225 multiplies each.

/// A complex number. Small enough that a dependency would cost more than it
/// saves.
#[derive(Clone, Copy, Debug, Default)]
struct C {
    re: f32,
    im: f32,
}

impl C {
    const ZERO: C = C { re: 0.0, im: 0.0 };

    fn mul(self, o: C) -> C {
        C {
            re: self.re * o.re - self.im * o.im,
            im: self.re * o.im + self.im * o.re,
        }
    }

    fn add(self, o: C) -> C {
        C {
            re: self.re + o.re,
            im: self.im + o.im,
        }
    }

    fn sub(self, o: C) -> C {
        C {
            re: self.re - o.re,
            im: self.im - o.im,
        }
    }
}

/// Half the coefficient count, and therefore the size of the FFT.
const HALF: usize = FRAME / 2;

/// Everything that depends only on the frame size, computed once.
struct Tables {
    /// `exp(-2i pi j / HALF)`, from which every sub-transform's twiddle is a
    /// stride: all the sub-sizes divide `HALF`, so one table serves them all.
    roots: Vec<C>,
    /// The DCT-IV pre-twiddle, `exp(-i pi (4l + 1) / 4M)`.
    pre: Vec<C>,
    /// And its post-twiddle, `exp(-i pi l / M)`.
    ///
    /// Not the same expression as the pre-twiddle, which is the mistake this
    /// was written with first: the two differ by a constant `pi / 4M`, the
    /// transform came out within a percent of correct, and a percent is exactly
    /// the size of error that looks like rounding.
    post: Vec<C>,
    scale: f32,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let m = FRAME as f64;
        let unit = |theta: f64| C {
            re: theta.cos() as f32,
            im: theta.sin() as f32,
        };
        Tables {
            roots: (0..HALF)
                .map(|j| unit(-2.0 * std::f64::consts::PI * j as f64 / HALF as f64))
                .collect(),
            pre: (0..HALF)
                .map(|l| unit(-std::f64::consts::PI * (4 * l + 1) as f64 / (4.0 * m)))
                .collect(),
            post: (0..HALF)
                .map(|l| unit(-std::f64::consts::PI * l as f64 / m))
                .collect(),
            scale: (2.0 / m as f32).sqrt(),
        }
    })
}

/// Decimation in time, halving while it can and finishing with a direct
/// transform on whatever odd length is left.
fn fft(input: &[C], stride: usize, out: &mut [C], roots: &[C]) {
    let n = out.len();

    if n % 2 == 1 {
        // The odd factor, done from the definition. `roots` is indexed by a
        // stride so this reads the same table as every other size.
        let step = HALF / n;
        for k in 0..n {
            let mut sum = C::ZERO;
            for j in 0..n {
                sum = sum.add(input[j * stride].mul(roots[(j * k % n) * step]));
            }
            out[k] = sum;
        }
        return;
    }

    let half = n / 2;
    let (even, odd) = out.split_at_mut(half);
    fft(input, stride * 2, even, roots);
    fft(&input[stride..], stride * 2, odd, roots);

    let step = HALF / n;
    for k in 0..half {
        let t = roots[k * step].mul(odd[k]);
        let e = even[k];
        even[k] = e.add(t);
        odd[k] = e.sub(t);
    }
}

/// DCT-IV of length [`FRAME`], in place of the caller's buffer.
fn dct4(u: &[f32], out: &mut [f32]) {
    let t = tables();
    let n = FRAME;

    let mut folded = vec![C::ZERO; HALF];
    for l in 0..HALF {
        let z = C {
            re: u[2 * l],
            im: u[n - 1 - 2 * l],
        };
        folded[l] = z.mul(t.pre[l]);
    }

    let mut spectrum = vec![C::ZERO; HALF];
    fft(&folded, 1, &mut spectrum, &t.roots);

    for l in 0..HALF {
        let v = spectrum[l].mul(t.post[l]);
        out[2 * l] = v.re;
        out[n - 1 - 2 * l] = -v.im;
    }
}

/// Forward MDCT: `WINDOW` windowed samples in, `FRAME` coefficients out.
pub fn forward(input: &[f32], window: &[f32]) -> Vec<f32> {
    assert_eq!(input.len(), WINDOW);

    let m = FRAME;
    let half = m / 2;
    let mut u = vec![0.0f32; m];

    // The fold. Three ranges because the kernel has three symmetries, and each
    // range lands somewhere different.
    for n in 0..half {
        u[n + half] += input[n] * window[n];
    }
    for n in half..3 * half {
        u[3 * half - 1 - n] -= input[n] * window[n];
    }
    for n in 3 * half..2 * m {
        u[n - 3 * half] -= input[n] * window[n];
    }

    let mut out = vec![0.0f32; m];
    dct4(&u, &mut out);

    let scale = tables().scale;
    for c in out.iter_mut() {
        *c *= scale;
    }
    out
}

/// Inverse MDCT: `FRAME` coefficients in, `WINDOW` windowed samples out.
///
/// The output is **not** the reconstructed signal. It is one half of it: the
/// caller must add the second half of the previous frame's output to the first
/// half of this one. That overlap-add is where the seam disappears, and a
/// caller that forgets it hears every frame boundary.
pub fn inverse(coefficients: &[f32], window: &[f32]) -> Vec<f32> {
    assert_eq!(coefficients.len(), FRAME);

    let m = FRAME;
    let half = m / 2;

    let mut v = vec![0.0f32; m];
    dct4(coefficients, &mut v);

    let scale = tables().scale;
    let mut out = vec![0.0f32; WINDOW];

    // The transpose of the forward fold: what was gathered is now scattered.
    out[..half].copy_from_slice(&v[half..half * 2]);
    for n in half..3 * half {
        out[n] = -v[3 * half - 1 - n];
    }
    for n in 3 * half..2 * m {
        out[n] = -v[n - 3 * half];
    }

    for (o, w) in out.iter_mut().zip(window) {
        *o *= scale * w;
    }
    out
}

/// Keeps the overlap between frames so a caller cannot forget it.
pub struct OverlapAdd {
    tail: Vec<f32>,
}

impl Default for OverlapAdd {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlapAdd {
    pub fn new() -> Self {
        Self {
            tail: vec![0.0; FRAME],
        }
    }

    /// Add this frame's output to the previous frame's tail and emit `FRAME`
    /// finished samples.
    ///
    /// # Why the output is clamped
    ///
    /// Every sample a decoder emits goes to a speaker, and a decoder does not
    /// get to choose what it is given. A single corrupted byte in a frame moves
    /// a band's energy level, and a level is exponential: measured, one flipped
    /// byte produced a peak of **3530**, which is 3530 times full scale. In
    /// headphones that is not an artefact, it is an injury.
    ///
    /// Authentication is supposed to stop a corrupted frame ever arriving, and
    /// mostly it does. That is an argument for the clamp rather than against
    /// it: the cost is one comparison per sample, and the thing it prevents is
    /// the worst outcome this software has.
    ///
    /// Clamping rather than scaling, because a frame this wrong has no useful
    /// content to preserve the shape of. A clamped burst is a click; the
    /// alternative is a scream.
    pub fn push(&mut self, windowed: &[f32]) -> Vec<f32> {
        assert_eq!(windowed.len(), WINDOW);

        let out: Vec<f32> = self
            .tail
            .iter()
            .zip(&windowed[..FRAME])
            .map(|(t, w)| (t + w).clamp(-1.0, 1.0))
            .collect();

        self.tail.copy_from_slice(&windowed[FRAME..]);
        out
    }
}

#[cfg(test)]
mod fast_tests {
    use super::*;

    fn signal(n: usize, seed: u32) -> Vec<f32> {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x as f32 / u32::MAX as f32) * 2.0 - 1.0
            })
            .collect()
    }

    /// The definition, evaluated in double precision.
    ///
    /// The reference has to be this rather than [`forward_naive`], and finding
    /// that out was worth the detour. The two disagreed by two parts in ten
    /// thousand, which looks exactly like a wrong twiddle. It is not: summing
    /// 1920 terms of similar size in `f32` loses about that much, and the FFT,
    /// which accumulates in a tree of depth nine instead of a line of length
    /// 1920, is the **more** accurate of the two. Checking a fast transform
    /// against a slow one only works while the slow one is the better.
    fn forward_exact(input: &[f32], window: &[f32]) -> Vec<f64> {
        let m = FRAME as f64;
        (0..FRAME)
            .map(|k| {
                let sum: f64 = input
                    .iter()
                    .zip(window)
                    .enumerate()
                    .map(|(n, (x, w))| {
                        let phase = std::f64::consts::PI / m
                            * (n as f64 + 0.5 + m / 2.0)
                            * (k as f64 + 0.5);
                        (*x as f64) * (*w as f64) * phase.cos()
                    })
                    .sum();
                sum * (2.0 / m).sqrt()
            })
            .collect()
    }

    fn inverse_exact(coefficients: &[f32], window: &[f32]) -> Vec<f64> {
        let m = FRAME as f64;
        (0..WINDOW)
            .map(|n| {
                let sum: f64 = coefficients
                    .iter()
                    .enumerate()
                    .map(|(k, c)| {
                        let phase = std::f64::consts::PI / m
                            * (n as f64 + 0.5 + m / 2.0)
                            * (k as f64 + 0.5);
                        (*c as f64) * phase.cos()
                    })
                    .sum();
                sum * (2.0 / m).sqrt() * window[n] as f64
            })
            .collect()
    }

    /// The whole justification for the fast transform: it computes the same
    /// thing.
    #[test]
    fn the_fast_transform_agrees_with_the_definition() {
        let w = window();

        for seed in 0..4 {
            let audio = signal(WINDOW, seed);

            let exact = forward_exact(&audio, &w);
            let fast = forward(&audio, &w);
            let peak = exact.iter().fold(0.0f64, |m, c| m.max(c.abs()));

            for (k, (a, b)) in exact.iter().zip(&fast).enumerate() {
                assert!(
                    (a - *b as f64).abs() < peak * 1e-5,
                    "forward coefficient {k} is {b} fast against {a} exact"
                );
            }

            let exact = inverse_exact(&fast, &w);
            let quick = inverse(&fast, &w);
            let peak = exact.iter().fold(0.0f64, |m, s| m.max(s.abs()));

            for (n, (a, b)) in exact.iter().zip(&quick).enumerate() {
                assert!(
                    (a - *b as f64).abs() < peak * 1e-5,
                    "inverse sample {n} is {b} fast against {a} exact"
                );
            }
        }
    }

    /// And it is the more accurate of the two, which is not what anyone expects
    /// a fast path to be.
    #[test]
    fn the_fast_transform_is_the_more_accurate_one() {
        let w = window();
        let audio = signal(WINDOW, 11);

        let exact = forward_exact(&audio, &w);
        let fast = forward(&audio, &w);
        let slow = forward_naive(&audio, &w);

        let error = |v: &[f32]| -> f64 {
            (v.iter()
                .zip(&exact)
                .map(|(a, b)| (*a as f64 - b).powi(2))
                .sum::<f64>()
                / FRAME as f64)
                .sqrt()
        };

        let (f, s) = (error(&fast), error(&slow));
        assert!(
            f < s,
            "the fast transform has rms error {f:.3e} against {s:.3e} for the \
             definition in f32; if that has reversed, the reason is worth knowing"
        );
        println!("  rms error: fast {f:.3e}, naive f32 {s:.3e}");
    }

    /// A transform that is fast and wrong is worse than one that is slow and
    /// right, so this asserts the speed too. The bound is loose because it runs
    /// on whatever machine happens to be building, and still an order of
    /// magnitude below where the naive one sat.
    ///
    /// # Why the fastest batch and not the average
    ///
    /// A single averaged run measures this machine's spare capacity as much as
    /// the transform, and fails when something else is compiling: it was seen
    /// at 10.6% against a 10% bound during a parallel build, and passed three
    /// times in a row on the same machine a minute later. A timing test that
    /// fails for reasons the code did not cause is one people learn to re-run,
    /// and a test people re-run has stopped guarding anything.
    ///
    /// The best of several batches is what the question actually asks. Time
    /// stolen by the scheduler only ever makes a batch slower, so the minimum is
    /// the closest reading of the transform itself, and a real regression slows
    /// every batch including that one.
    #[test]
    fn the_fast_transform_is_fast_enough_to_hold_a_call() {
        use std::time::Instant;

        let w = window();
        let audio = signal(WINDOW, 9);
        let rounds = 200;
        let batches = 5;

        let mut sink = 0.0f32;
        let mut each = f64::INFINITY;
        for _ in 0..batches {
            let t = Instant::now();
            for _ in 0..rounds {
                let c = forward(&audio, &w);
                sink += inverse(&c, &w)[0];
            }
            each = each.min(t.elapsed().as_secs_f64() / rounds as f64);
        }
        let frame_period = FRAME as f64 / SAMPLE_RATE as f64;
        let load = each / frame_period;

        assert!(
            load < 0.10,
            "a round trip through the transform costs {:.1}% of a frame period \
             ({:.3} ms of {:.1} ms); the definition cost 270%, and anything near \
             that cannot carry a call (sink {sink})",
            load * 100.0,
            each * 1e3,
            frame_period * 1e3
        );
        println!("  transform round trip: {:.1}% of real time", load * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without this the transform is not invertible and every frame boundary
    /// clicks.
    #[test]
    fn the_window_satisfies_princen_bradley() {
        let w = window();

        for n in 0..FRAME {
            let sum = w[n].powi(2) + w[n + FRAME].powi(2);
            assert!(
                (sum - 1.0).abs() < 1e-5,
                "w[{n}]^2 + w[{}]^2 = {sum}, not 1",
                n + FRAME
            );
        }
    }

    /// The whole point of the MDCT: consecutive frames must reconstruct the
    /// original exactly, despite each one throwing half its output away.
    #[test]
    fn overlapped_frames_reconstruct_the_signal() {
        let w = window();

        // Something with structure, so an error cannot hide in silence.
        let signal: Vec<f32> = (0..FRAME * 6)
            .map(|n| {
                let t = n as f32 / SAMPLE_RATE as f32;
                0.5 * (2.0 * PI * 220.0 * t).sin() + 0.3 * (2.0 * PI * 700.0 * t).sin()
            })
            .collect();

        let mut overlap = OverlapAdd::new();
        let mut out = Vec::new();

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let coefficients = forward(&signal[start..start + WINDOW], &w);
            out.extend(overlap.push(&inverse(&coefficients, &w)));
        }

        // The first frame is the ramp-in half and has nothing to add to, so
        // reconstruction begins one frame later.
        let reconstructed = &out[FRAME..];
        let original = &signal[FRAME..FRAME + reconstructed.len()];

        let error: f32 = reconstructed
            .iter()
            .zip(original)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            / reconstructed.len() as f32;

        assert!(
            error < 1e-6,
            "mean squared reconstruction error {error}, which means the transform is lossy \
             before a single bit has been thrown away"
        );
    }

    /// A pure tone must land in one place, or the transform is not resolving
    /// frequency and the codec has nothing to be efficient about.
    #[test]
    fn a_tone_concentrates_into_few_coefficients() {
        let w = window();
        let tone: Vec<f32> = (0..WINDOW)
            .map(|n| (2.0 * PI * 1000.0 * n as f32 / SAMPLE_RATE as f32).sin())
            .collect();

        let coefficients = forward(&tone, &w);
        let total: f32 = coefficients.iter().map(|c| c * c).sum();

        let peak = coefficients
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.abs().partial_cmp(&b.1.abs()).expect("finite"))
            .expect("non-empty")
            .0;

        // Energy within three bins of the peak.
        let near: f32 = coefficients[peak.saturating_sub(3)..(peak + 4).min(FRAME)]
            .iter()
            .map(|c| c * c)
            .sum();

        assert!(
            near / total > 0.9,
            "only {:.1}% of a pure tone's energy landed near one bin",
            100.0 * near / total
        );

        // And it landed where the tone actually is.
        let hz = peak as f32 * SAMPLE_RATE as f32 / (2.0 * FRAME as f32);
        assert!(
            (hz - 1000.0).abs() < 40.0,
            "the 1 kHz tone landed at {hz} Hz"
        );
    }

    /// A longer window resolves frequency more finely. This is the entire
    /// reason the codec spends latency, so it is asserted rather than assumed.
    #[test]
    fn the_long_window_resolves_finer_than_a_short_one() {
        let bin_hz = SAMPLE_RATE as f32 / (2.0 * FRAME as f32);

        // Opus at the same hop transforms 20 ms; Telyx transforms 40.
        let opus_like = SAMPLE_RATE as f32 / (2.0 * 480.0);

        assert!(
            bin_hz < opus_like,
            "Telyx resolves {bin_hz} Hz per bin against {opus_like}, which is not finer"
        );
        assert!(
            (bin_hz - 25.0).abs() < 0.1,
            "expected 25 Hz per bin, got {bin_hz}"
        );
    }
}
