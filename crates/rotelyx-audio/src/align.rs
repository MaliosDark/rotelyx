//! Where a played signal sits inside a recording.
//!
//! # Why this is not the obvious correlation
//!
//! The obvious one was here first, in the examples, and it produced two
//! confident wrong answers. Its own comment said why without drawing the
//! conclusion: *"the peak of a correlation this broad is not sharp"*. It was
//! plain normalised cross correlation between two half-second windows of
//! speech, and speech has almost no autocorrelation to find. Voiced sounds
//! repeat at the pitch period, unvoiced ones are noise, and the spectrum is
//! dominated by a handful of low frequencies that stay put for tens of
//! milliseconds. Slide two windows of that past each other and the match is
//! high and nearly flat across a wide range of lags.
//!
//! What that cost is written up in `docs/ACOUSTIC.md`: per-window alignments
//! spread over 471 ms with a line fit of 0.10, reported as -2024 ppm of clock
//! drift on one run and -4210 on the next. Two crystals 341 ppm apart move
//! eight milliseconds over that recording, not half a second. The estimate was
//! not measuring drift, or convergence, or anything at all.
//!
//! # The phase transform
//!
//! GCC-PHAT is the standard answer to exactly this. Take the cross spectrum of
//! the two signals and **divide out its magnitude**, keeping only the phase.
//! Every frequency bin then contributes equally regardless of how much energy
//! the talker put there, which is the same as correlating two whitened signals:
//! the broad peak collapses to something close to an impulse at the true lag.
//!
//! It buys sharpness with noise immunity, and that trade is the right way round
//! here. The path being measured is a loudspeaker into a microphone in a quiet
//! room, where the echo is loud and the interference is not.
//!
//! # Where it still fails, said before somebody finds out
//!
//! A **narrowband** signal has no energy in most bins, so whitening amplifies
//! whatever noise is in the empty ones. A pure tone gives a periodic
//! correlation with no single peak, and no transform fixes that. Speech over
//! half a second is broadband enough, a sine is not, and
//! [`Alignment::sharpness`] is what a caller checks rather than assuming.
//!
//! # Why it lives in the crate and not beside the examples
//!
//! It is an instrument, and the two answers it got wrong were both taken on
//! trust because nothing tested it. Here it has tests that give it a delay it
//! is supposed to find, which is the check that was missing.

use crate::echo::{fft, C};

/// The furthest a recording can plausibly lag the signal that produced it.
///
/// The real budget: the deliberate offset a harness inserts, plus whatever each
/// sound card buffers, plus flight time across a room, which is under a
/// hundredth of a second for any room somebody is in. Two seconds is generous
/// for all of it, and it excludes the peak three seconds out that an unbounded
/// search found once on a recording whose real offset was 650 ms.
pub const MAX_PLAUSIBLE_DELAY: usize = 48_000 * 2;

/// Below this many samples of reference there is not enough to correlate.
const MIN_WINDOW: usize = 4_800;

/// The reference is trimmed only so far as the search needs room, and no
/// further.
///
/// # Two mistakes, in opposite directions
///
/// The estimator this replaced took a fixed half second off the front. This one
/// used everything it was handed, and the acoustic harness hands it the whole
/// recording: 24.6 seconds of reference against 24.6 seconds of room leaves
/// **no lags to search**, so it refused and the harness said the microphone had
/// heard nothing. It had heard plenty, an RMS of 2894 out of 32768. No unit
/// test could see that, because every one of them passes a short window and the
/// whole-recording call happens once, at the top, on hardware.
///
/// The first fix was a fixed half second, copying the old estimator, and that
/// was the opposite mistake. **The window exists to leave room to search, not
/// to limit evidence.** With half a second the whitening sweep stopped being
/// able to tell 0.50 from 0.75 at all, both landing 203 samples out, where with
/// three seconds of reference 0.75 lands 22 out. Throwing away 98% of the
/// signal costs exactly what it sounds like it costs.
///
/// So the rule is the one the arithmetic asks for: keep as much reference as
/// leaves the search its whole range, which is `heard.len() - max_delay`.
fn reference_window(heard: usize, max_delay: usize) -> usize {
    heard.saturating_sub(max_delay).max(MIN_WINDOW)
}

/// Below this many candidate lags there is no floor to measure a peak against.
///
/// [`Alignment::sharpness`] is the peak divided by the root mean square of the
/// whole searched range. Search one lag and that ratio is 1 by construction,
/// search a handful and it is dominated by whichever of them the peak is. A
/// hundred milliseconds of candidates is enough for the floor to be a floor.
///
/// This is not hypothetical: the first run of these tests aligned a recording
/// exactly as long as the reference, leaving a single candidate, and the
/// function reported it with a confidence of exactly 1.0.
const MIN_REACH: usize = 4_800;

/// Lags this close to the winning peak belong to the same arrival.
///
/// Ten milliseconds. A room's early reflections land inside that and are the
/// same answer arriving twice, so counting them as rivals would penalise
/// exactly the paths this is built for.
const RUNNER_UP_GUARD: usize = 480;

/// How much of the cross spectrum's magnitude is divided out.
///
/// 0 is plain cross correlation and 1 is the textbook phase transform.
/// **Neither of them is the right value here**, and this is the one measurement
/// in this module that mattered. On 24.6 seconds of synthesised speech through a
/// simulated room, against a delay of 3,120 samples:
///
/// | gamma | global estimate | error |
/// |---|---:|---:|
/// | 0.00, plain correlation | 3,716 | 596 |
/// | 0.50 | 3,323 | 203 |
/// | **0.75** | **3,142** | **22** |
/// | 1.00, full phase transform | 95,999 | 92,879 |
///
/// Full whitening fails because speech leaves most of a 24 kHz band empty, and
/// dividing an empty bin by its own magnitude promotes the noise floor in it to
/// a full vote. Plain correlation fails differently and less badly: the room's
/// colouring and its reverberation pull and broaden the peak, which is the 596
/// samples of consistent lateness in the first row.
///
/// Three quarters removes enough of the colouring to find the direct arrival
/// and leaves enough magnitude weighting that empty bins stay quiet. It is the
/// known compromise and the sweep agrees with it.
///
/// `the_whitening_exponent_comes_from_a_sweep` fails if this constant stops
/// being what the measurement prefers.
const WHITENING: f32 = 0.75;

/// A recovered delay, and what could be measured about it.
///
/// # There is no confidence field, and that is a finding
///
/// This type carried `is_confident` until the measurement took it away. On 24.6
/// seconds of synthesised speech through a simulated room, the two windows
/// that aligned wrongly scored margins of 1.04 while the forty seven correct
/// ones spanned 1.07 to 2.37. Three hundredths of separation, from a wrong
/// population of two, is not a threshold.
///
/// Under full whitening it was worse. The single worst window of that run,
/// ninety three thousand samples from the truth, had the **second highest**
/// [`sharpness`](Self::sharpness) of the eight and a better
/// [`margin`](Self::margin) than most of the correct answers.
///
/// Two unrelated recordings do not fail either check either. They produce a
/// delay, a respectable margin, and nothing at all to say the two signals have
/// no relationship.
///
/// So these numbers are reported and **none of them is a licence to believe the
/// answer**. What keeps a bad window out is structural rather than statistical:
/// take one coarse delay from the whole recording, where there is far more
/// evidence to take it from, and let each window refine it inside a narrow band
/// with [`align_near`]. That is what took the per-window spread on that speech
/// from 471 ms to 13.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Alignment {
    /// Samples by which the recording lags the played signal.
    pub delay: usize,

    /// The correlation peak divided by the root mean square of the whole
    /// searched range.
    ///
    /// Reported because it is cheap and it is what the previous estimator
    /// offered. It does not separate a right answer from a wrong one: see this
    /// type's own documentation for the run where the worst window scored
    /// second best.
    pub sharpness: f32,

    /// The peak divided by the best rival outside its own arrival.
    ///
    /// The theory is that a true delay leaves one candidate standing while a
    /// spurious peak is one of several similar ones. The measurement does not
    /// support using it as a threshold, and the numbers are in this type's own
    /// documentation.
    pub margin: f32,

    /// Set when the winning lag is the first or last candidate searched.
    at_edge: bool,
}

impl Alignment {
    /// Whether the winning lag sits at either end of the searched range.
    ///
    /// A maximum at a boundary means the correlation was still climbing when
    /// the search ran out of room, so the real peak is outside it and this is a
    /// truncation rather than an answer. **Both** badly wrong windows in the
    /// speech measurement land here, one at lag zero and one at the far
    /// end.
    ///
    /// It is the only check on this type that was shown to catch anything, and
    /// it catches only this. A wrong answer in the middle of the range still
    /// looks exactly like a right one.
    pub fn at_edge(&self) -> bool {
        self.at_edge
    }
}

/// Find where `played` sits inside `heard`, searching lags up to `max_delay`.
///
/// Returns `None` when either signal is too short or carries no energy, which
/// is a different answer from a weak one: a weak answer comes back with a low
/// [`Alignment::sharpness`] so the caller can see what it rejected.
pub fn align(played: &[f32], heard: &[f32], max_delay: usize) -> Option<Alignment> {
    align_with(played, heard, max_delay, WHITENING)
}

/// [`align`], with the whitening exponent exposed so the tests can sweep it.
///
/// `gamma` of 0 is plain cross correlation, 1 is the full phase transform, and
/// the useful values are in between. See [`WHITENING`].
fn align_with(played: &[f32], heard: &[f32], max_delay: usize, gamma: f32) -> Option<Alignment> {
    // A leading slice when the reference is longer than the search can afford.
    // See `reference_window`.
    let played = &played[..played.len().min(reference_window(heard.len(), max_delay))];
    let window = played.len();
    if window < MIN_WINDOW || heard.len() < MIN_WINDOW {
        return None;
    }

    // How far the search can actually reach: past this the reference runs off
    // the end of the recording and the correlation is measuring padding.
    let reach = max_delay.min(heard.len().saturating_sub(window));
    if reach < MIN_REACH {
        return None;
    }

    if energy_of(played) <= 1e-9 || energy_of(&heard[..window + reach]) <= 1e-9 {
        return None;
    }

    // Linear correlation, not circular: the transform has to be long enough to
    // hold both signals without either wrapping onto the other. A shorter one
    // would fold a lag of n+d back onto d and invent a peak there.
    let n = (window + reach + 1).next_power_of_two();

    let mut reference = to_spectrum(played, n);
    let mut recording = to_spectrum(&heard[..window + reach], n);

    fft(&mut reference, false);
    fft(&mut recording, false);

    // The cross spectrum, with its magnitude divided out. `recording` is
    // overwritten in place because nothing needs it afterwards.
    for k in 0..n {
        let cross = recording[k].mul(reference[k].conj());
        let magnitude = cross.norm_sq().sqrt();
        recording[k] = if magnitude > 1e-12 {
            cross.scale(1.0 / magnitude.powf(gamma))
        } else {
            // A bin with no energy in one of the two signals says nothing about
            // the lag. Whitening it would turn rounding error into a vote.
            C::ZERO
        };
    }

    fft(&mut recording, true);

    let correlation = &recording[..=reach];

    let mut peak = (0usize, f32::MIN);
    let mut sum_of_squares = 0.0f64;
    for (lag, value) in correlation.iter().enumerate() {
        let v = value.re;
        sum_of_squares += (v as f64) * (v as f64);
        if v > peak.1 {
            peak = (lag, v);
        }
    }

    let rms = (sum_of_squares / correlation.len() as f64).sqrt() as f32;
    if rms <= f32::EPSILON {
        return None;
    }

    // The runner up: the best candidate that is not part of the winning
    // arrival. Reflections off the near surfaces land within a few
    // milliseconds of the direct sound and belong to the same answer, so the
    // guard skips them rather than counting them against it.
    let guard = RUNNER_UP_GUARD;
    let mut runner_up = 0.0f32;
    for (lag, value) in correlation.iter().enumerate() {
        if lag.abs_diff(peak.0) <= guard {
            continue;
        }
        if value.re > runner_up {
            runner_up = value.re;
        }
    }

    Some(Alignment {
        delay: peak.0,
        sharpness: peak.1 / rms,
        margin: if runner_up > 1e-9 {
            peak.1 / runner_up
        } else {
            f32::INFINITY
        },
        at_edge: peak.0 == 0 || peak.0 == reach,
    })
}

/// Find the delay of one window, searching only near a delay already known.
///
/// # Why the unbounded search is the wrong tool per window
///
/// [`align`] over a whole recording has seconds of speech to work with and gets
/// one answer from all of it. Run per half-second window it has forty six times
/// less evidence each time, and the measurement in this module's tests shows
/// what that costs: one window in eight landed ninety three thousand samples
/// from the truth, and **neither confidence measure caught it**. Its peak stood
/// 17.95 over the floor, second highest of the eight, and 2.25 over its nearest
/// rival. By every number the estimator had, it looked like the best answer of
/// the run.
///
/// No per-window statistic fixes that, because nothing inside one window says
/// the loudspeaker did not move ninety three thousand samples away. What says so
/// is physics: the path is the same path all through the recording. So the
/// coarse answer comes from all of it, and each window is only allowed to refine
/// that, which is what this does.
///
/// `tolerance` is how far a window may move from `expect`. It bounds what the
/// answer can be, so it must be wider than any drift or convergence the caller
/// is trying to see and narrower than the mistakes it is trying to exclude.
pub fn align_near(
    played: &[f32],
    heard: &[f32],
    expect: usize,
    tolerance: usize,
) -> Option<Alignment> {
    let lo = expect.saturating_sub(tolerance);
    if lo >= heard.len() {
        return None;
    }
    // The reach has to hold both sides of the tolerance, and `align` needs
    // enough candidates to judge a peak against.
    let reach = (2 * tolerance).max(MIN_REACH);
    let found = align(played, &heard[lo..], reach)?;
    Some(Alignment {
        delay: lo + found.delay,
        ..found
    })
}

/// Real samples into a complex buffer of length `n`, zero padded.
fn to_spectrum(samples: &[f32], n: usize) -> Vec<C> {
    let mut buf = vec![C::ZERO; n];
    for (slot, sample) in buf.iter_mut().zip(samples) {
        slot.re = *sample;
    }
    buf
}

fn energy_of(x: &[f32]) -> f64 {
    x.iter().map(|s| (*s as f64) * (*s as f64)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: usize = 48_000;

    /// A deterministic pseudo random source, so a failing test fails the same
    /// way twice.
    struct Noise(u32);

    impl Noise {
        fn next(&mut self) -> f32 {
            // xorshift32. Not for anything that matters, only for a signal.
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            (self.0 as f32 / u32::MAX as f32) * 2.0 - 1.0
        }
    }

    /// Something with the shape of a voice: a pitch with harmonics, shaped by
    /// three formants, with the pitch and the loudness moving the way a talker
    /// moves them.
    ///
    /// This is the signal the previous estimator could not handle, so it is the
    /// one worth testing against. White noise would prove almost nothing: it
    /// has a perfect autocorrelation and even the naive method finds it.
    fn speech_like(samples: usize) -> Vec<f32> {
        let formants = [700.0f32, 1220.0, 2600.0];
        (0..samples)
            .map(|i| {
                let t = i as f32 / RATE as f32;
                // Pitch wanders between 100 and 130 Hz.
                let pitch = 115.0 + 15.0 * (2.0 * std::f32::consts::PI * 1.7 * t).sin();
                let mut sample = 0.0f32;
                for harmonic in 1..=28 {
                    let f = pitch * harmonic as f32;
                    if f > 4_000.0 {
                        break;
                    }
                    // Closeness to a formant sets the harmonic's weight.
                    let gain: f32 = formants
                        .iter()
                        .map(|c| 1.0 / (1.0 + ((f - c) / 220.0).powi(2)))
                        .sum();
                    sample += gain * (2.0 * std::f32::consts::PI * f * t).sin();
                }
                // Syllables, so the energy is not constant across the window.
                let envelope = 0.25 + 0.75 * (2.0 * std::f32::consts::PI * 3.3 * t).sin().abs();
                sample * envelope * 0.05
            })
            .collect()
    }

    /// `heard` is `played` delayed, attenuated, and buried in noise.
    fn path(played: &[f32], delay: usize, gain: f32, noise: f32) -> Vec<f32> {
        let mut rng = Noise(0x5eed_1234);
        // The tail is not padding. A recording runs on after what it caught,
        // and without it a zero delay leaves the search exactly one candidate
        // and no floor to judge it against.
        let mut heard = vec![0.0f32; played.len() + delay + RATE / 2];
        for (i, sample) in played.iter().enumerate() {
            heard[i + delay] = sample * gain;
        }
        for sample in heard.iter_mut() {
            *sample += rng.next() * noise;
        }
        heard
    }

    /// What a loudspeaker into a microphone across a room actually does: a
    /// direct arrival, a handful of early reflections off the near surfaces, a
    /// decaying tail, and a passband narrower than the signal.
    ///
    /// The plain path above is a delayed copy, and a delayed copy is the case
    /// **both** methods solve. This is the case they are supposed to differ on.
    fn room_path(played: &[f32], delay: usize, noise: f32) -> Vec<f32> {
        let mut rng = Noise(0x5eed_1234);
        let mut heard = vec![0.0f32; played.len() + delay + RATE / 2];

        // Direct arrival plus early reflections, in samples and relative gain.
        // Negative gains are reflections that arrive inverted, which surfaces do.
        let arrivals = [
            (0usize, 1.00f32),
            (163, -0.62),
            (287, 0.51),
            (394, -0.44),
            (611, 0.38),
            (908, -0.29),
        ];
        for (offset, gain) in arrivals {
            for (i, sample) in played.iter().enumerate() {
                heard[i + delay + offset] += sample * gain * 0.5;
            }
        }

        // A tail: 1400 taps of decaying noise, which is what a room sounds like
        // after the reflections stop being countable.
        let taps: Vec<f32> = (0..1_400)
            .map(|i| rng.next() * 0.30 * (-(i as f32) / 420.0).exp())
            .collect();
        let dry: Vec<f32> = heard.clone();
        for (i, sample) in dry.iter().enumerate() {
            if *sample == 0.0 {
                continue;
            }
            for (k, tap) in taps.iter().enumerate() {
                if i + k < heard.len() {
                    heard[i + k] += sample * tap;
                }
            }
        }

        // The passband. A one pole high pass near 150 Hz because no small
        // loudspeaker reproduces below it, and a one pole low pass near 6 kHz
        // because the microphone and the room both roll off.
        let mut low = 0.0f32;
        let mut prev_in = 0.0f32;
        let mut prev_out = 0.0f32;
        for sample in heard.iter_mut() {
            low += 0.55 * (*sample - low);
            let hp = 0.98 * (prev_out + low - prev_in);
            prev_in = low;
            prev_out = hp;
            *sample = hp;
        }

        for sample in heard.iter_mut() {
            *sample += rng.next() * noise;
        }
        heard
    }

    /// The previous method, in the frequency domain so the comparison is about
    /// the phase transform and nothing else.
    ///
    /// Test only. It exists to be beaten.
    fn plain_align(played: &[f32], heard: &[f32], max_delay: usize) -> Option<Alignment> {
        let window = played.len();
        let reach = max_delay.min(heard.len().saturating_sub(window));
        if window < MIN_WINDOW || reach < MIN_REACH {
            return None;
        }
        let n = (window + reach + 1).next_power_of_two();
        let mut reference = to_spectrum(played, n);
        let mut recording = to_spectrum(&heard[..window + reach], n);
        fft(&mut reference, false);
        fft(&mut recording, false);
        for k in 0..n {
            recording[k] = recording[k].mul(reference[k].conj());
        }
        fft(&mut recording, true);

        let correlation = &recording[..=reach];
        let mut peak = (0usize, f32::MIN);
        let mut sum_of_squares = 0.0f64;
        for (lag, value) in correlation.iter().enumerate() {
            sum_of_squares += (value.re as f64) * (value.re as f64);
            if value.re > peak.1 {
                peak = (lag, value.re);
            }
        }
        let rms = (sum_of_squares / correlation.len() as f64).sqrt() as f32;
        let mut runner_up = 0.0f32;
        for (lag, value) in correlation.iter().enumerate() {
            if lag.abs_diff(peak.0) <= RUNNER_UP_GUARD {
                continue;
            }
            if value.re > runner_up {
                runner_up = value.re;
            }
        }
        Some(Alignment {
            delay: peak.0,
            sharpness: peak.1 / rms,
            margin: if runner_up > 1e-9 {
                peak.1 / runner_up
            } else {
                f32::INFINITY
            },
            at_edge: peak.0 == 0 || peak.0 == reach,
        })
    }

    /// How far apart the per-window answers land, which is the quantity the
    /// whole item turns on.
    fn spread_over_windows(
        method: fn(&[f32], &[f32], usize) -> Option<Alignment>,
        reference: &[f32],
        heard: &[f32],
    ) -> (usize, Vec<usize>) {
        let window = RATE / 2;
        let mut answers = Vec::new();
        let mut start = 0;
        while start + window <= reference.len() && start + window < heard.len() {
            if let Some(found) = method(
                &reference[start..start + window],
                &heard[start..],
                MAX_PLAUSIBLE_DELAY,
            ) {
                println!(
                    "    window {start:>7}  delay {:>6}  sharpness {:>6.2}  margin {:>6.2}",
                    found.delay, found.sharpness, found.margin
                );
                answers.push(found.delay);
            }
            start += window;
        }
        let spread = match (answers.iter().min(), answers.iter().max()) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => usize::MAX,
        };
        (spread, answers)
    }

    /// The synthesised speech clips the codec is measured on, joined into one
    /// signal, or `None` when they are not on this machine.
    ///
    /// # These are not recordings of people
    ///
    /// `scripts/make-speech` builds them with a neural text to speech model and
    /// says plainly what they are not: nothing here has been near a microphone
    /// or a room. They are a model's idea of a voice, which is more regular
    /// than a person and less regular than the sum of sines above.
    ///
    /// That is still the right signal for this measurement, because what
    /// defeats a correlation is the spectral shape of speech and its long
    /// stretches of near silence, and a synthesiser produces both. It is not
    /// the right signal for claiming the numbers hold for people, and nothing
    /// here claims that.
    ///
    /// # They are not in the repository either
    ///
    /// 2.3 MB of binary that git would carry for ever, regenerable from that
    /// script, so they are ignored and every measurement that wants them skips
    /// itself when they are absent. A fresh clone passes without them.
    ///
    /// **The cost is that the tests below are not gates on a clean checkout.**
    /// A corpus that could ship would turn them into ones, which is the same
    /// question as the codebook in section 6 of `TODO.md` and is open for the
    /// same reason.
    fn tts_speech() -> Option<Vec<f32>> {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rotelyx-codec/tests/speech/"
        );
        let mut all = Vec::new();
        let mut names: Vec<_> = std::fs::read_dir(root)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "wav"))
            .collect();
        names.sort();
        for path in names {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let mut at = 12;
            while at + 8 <= bytes.len() {
                let id = &bytes[at..at + 4];
                let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                if id == b"data" {
                    let body = &bytes[at + 8..(at + 8 + size).min(bytes.len())];
                    all.extend(
                        body.chunks_exact(2)
                            .map(|p| i16::from_le_bytes([p[0], p[1]]) as f32 / 32768.0),
                    );
                    break;
                }
                at += 8 + size + (size & 1);
            }
        }
        (all.len() > RATE).then_some(all)
    }

    /// Printed once by each test that needs the clips and cannot find them.
    fn no_clips() {
        println!("  no clips in rotelyx-codec/tests/speech, skipping.");
        println!("  scripts/make-speech rebuilds them.");
    }

    /// How much whitening actually helps, measured rather than assumed.
    ///
    /// This test is the reason [`WHITENING`] is the value it is. It skips
    /// itself without the clips, so on a clean checkout the constant is
    /// documented rather than guarded.
    #[test]
    fn the_whitening_exponent_comes_from_a_sweep() {
        let Some(speech) = tts_speech() else {
            return no_clips();
        };
        let truth = 3_120usize;
        let heard = room_path(&speech, truth, 0.002);
        let window = RATE / 2;

        println!("  gamma   coarse   error   windows within 1000 of truth");
        let mut best = (f32::NAN, usize::MAX);
        let mut tied: Vec<f32> = Vec::new();
        for gamma in [0.0f32, 0.25, 0.5, 0.75, 1.0] {
            let coarse = align_with(
                &speech[..(RATE * 3).min(speech.len())],
                &heard,
                MAX_PLAUSIBLE_DELAY,
                gamma,
            );

            let (mut close, mut total, mut start) = (0usize, 0usize, 0usize);
            while start + window <= speech.len() && start + window < heard.len() {
                if let Some(found) = align_with(
                    &speech[start..start + window],
                    &heard[start..],
                    MAX_PLAUSIBLE_DELAY,
                    gamma,
                ) {
                    total += 1;
                    if found.delay.abs_diff(truth) <= 1_000 {
                        close += 1;
                    }
                }
                start += 2 * window;
            }

            let (delay, error) = match coarse {
                Some(a) => (a.delay as i64, a.delay.abs_diff(truth)),
                None => (-1, usize::MAX),
            };
            println!("  {gamma:>5.2}  {delay:>7}  {error:>6}   {close:>3} of {total}");

            if error < best.1 {
                best = (gamma, error);
                tied.clear();
                tied.push(gamma);
            } else if error == best.1 {
                tied.push(gamma);
            }
        }

        // A tie is reported as one. Picking the first of several equal answers
        // and calling it a preference is how a constant ends up looking
        // measured when the measurement could not tell.
        assert!(
            tied.contains(&WHITENING),
            "the sweep's best error is {} at gamma {tied:?}, and WHITENING is \
             {WHITENING}. Change the constant to one the measurement prefers, or \
             say here why it should not be",
            best.1
        );
    }

    /// The call the acoustic harness actually makes: reference and recording the
    /// same length, delay somewhere inside.
    ///
    /// # Why this test exists
    ///
    /// It is the one shape none of the others had. They all pass a half-second
    /// window because that is what a per-window measurement does, and the call
    /// at the top of `acoustic-echo` hands over the whole recording. With the
    /// reference used whole there were no lags left to search, so the estimator
    /// refused and the harness said the microphone had heard nothing.
    ///
    /// It had heard plenty. Ten tests passed and the instrument was broken, and
    /// it took playing a sound through a real loudspeaker to find out.
    #[test]
    fn the_reference_may_be_as_long_as_the_recording() {
        let speech = speech_like(RATE * 3);
        let delay = 1_920;

        // As the harness has them: the clean signal, and a recording of the same
        // length that contains it.
        let mut heard = vec![0.0f32; speech.len()];
        for (i, sample) in speech.iter().enumerate() {
            if i + delay < heard.len() {
                heard[i + delay] = sample * 0.5;
            }
        }

        let found = align(&speech, &heard, MAX_PLAUSIBLE_DELAY)
            .expect("a reference as long as the recording still has lags to search");
        assert_eq!(
            found.delay, delay,
            "the harness's own call shape does not recover a delay it was given"
        );
    }

    /// The same comparison, on synthesised speech rather than on a sum of sines.
    #[test]
    fn through_a_room_on_synthesised_speech() {
        let Some(speech) = tts_speech() else {
            return no_clips();
        };
        let delay = 3_120;
        let heard = room_path(&speech, delay, 0.002);

        println!(
            "  {:.1}s of synthesised speech",
            speech.len() as f32 / RATE as f32
        );

        let (whitened_spread, whitened) = spread_over_windows(align, &speech, &heard);
        let (plain_spread, plain) = spread_over_windows(plain_align, &speech, &heard);
        println!("  unbounded spread {whitened_spread:>7}  {whitened:?}");
        println!("  plain     spread {plain_spread:>7}  {plain:?}");

        // The two populations the confidence field was supposed to separate.
        let window = RATE / 2;
        let (mut right, mut wrong): (Vec<f32>, Vec<f32>) = (Vec::new(), Vec::new());
        let mut at = 0;
        while at + window <= speech.len() && at + window < heard.len() {
            if let Some(a) = align(&speech[at..at + window], &heard[at..], MAX_PLAUSIBLE_DELAY) {
                if a.delay.abs_diff(delay) <= 1_000 {
                    right.push(a.margin)
                } else {
                    wrong.push(a.margin)
                }
            }
            at += window;
        }
        let lowest_right = right.iter().copied().fold(f32::INFINITY, f32::min);
        let highest_wrong = wrong.iter().copied().fold(0.0f32, f32::max);
        println!(
            "  margins: {} right from {lowest_right:.2}, {} wrong up to {highest_wrong:.2}",
            right.len(),
            wrong.len()
        );
        assert!(
            lowest_right - highest_wrong < 0.2,
            "the margin now separates right from wrong by {:.2}, which it did not when \
             the confidence field was taken off `Alignment`. If that holds up, put the \
             field back and set the threshold from these two populations",
            lowest_right - highest_wrong
        );

        let coarse = align(
            &speech[..(RATE * 3).min(speech.len())],
            &heard,
            MAX_PLAUSIBLE_DELAY,
        )
        .expect("a coarse answer");
        println!(
            "  coarse  delay {} margin {:.2}",
            coarse.delay, coarse.margin
        );

        let mut bounded = Vec::new();
        let mut start = 0;
        while start + window <= speech.len() && start + window < heard.len() {
            if let Some(found) = align_near(
                &speech[start..start + window],
                &heard[start..],
                coarse.delay,
                4_800,
            ) {
                bounded.push(found.delay);
            }
            start += window;
        }
        let bounded_spread = bounded.iter().max().unwrap() - bounded.iter().min().unwrap();
        println!("  bounded spread {bounded_spread:>7}  {bounded:?}");
    }

    /// The measurement this module exists for, run as a test so it cannot rot.
    ///
    /// Through a room, not through a delay line. The numbers it prints are what
    /// decided the assertion below it.
    #[test]
    fn partial_whitening_beats_plain_correlation() {
        let long = speech_like(RATE * 4);
        let heard = room_path(&long, 3_120, 0.002);

        let (phat_spread, phat) = spread_over_windows(align, &long, &heard);
        let (plain_spread, plain) = spread_over_windows(plain_align, &long, &heard);

        println!("phat  spread {phat_spread:>7} samples  {phat:?}");
        println!("plain spread {plain_spread:>7} samples  {plain:?}");

        // Coarse first, from the whole recording, then each window refines it.
        let coarse =
            align(&long[..RATE * 3], &heard, MAX_PLAUSIBLE_DELAY).expect("a coarse answer");
        println!("coarse delay {} margin {:.2}", coarse.delay, coarse.margin);

        let window = RATE / 2;
        let mut bounded = Vec::new();
        let mut start = 0;
        while start + window <= long.len() && start + window < heard.len() {
            if let Some(found) = align_near(
                &long[start..start + window],
                &heard[start..],
                coarse.delay,
                4_800,
            ) {
                bounded.push(found.delay);
            }
            start += window;
        }
        let bounded_spread = bounded.iter().max().unwrap() - bounded.iter().min().unwrap();
        println!("bounded spread {bounded_spread:>5} samples  {bounded:?}");

        assert!(
            phat_spread < plain_spread,
            "whitening at {WHITENING} did not help: {phat_spread} against {plain_spread} \
             for plain correlation. If that is the honest result then this module is \
             not the answer and docs/ACOUSTIC.md should say so"
        );
    }

    #[test]
    fn recovers_a_delay_it_was_given() {
        let played = speech_like(RATE / 2);
        for delay in [0usize, 1, 733, 4_801, 24_000, 48_000] {
            let heard = path(&played, delay, 0.6, 0.0);
            let found = align(&played, &heard, MAX_PLAUSIBLE_DELAY)
                .unwrap_or_else(|| panic!("no alignment at {delay}"));
            assert_eq!(
                found.delay, delay,
                "wanted {delay}, got {} at sharpness {}",
                found.delay, found.sharpness
            );
        }
    }

    /// The condition the whole item turns on: a half-second window has to align
    /// to the same place twice. Different windows of one recording all carry
    /// the same delay, so they must all report it.
    #[test]
    fn different_windows_agree() {
        let long = speech_like(RATE * 4);
        let delay = 3_120;
        let heard = path(&long, delay, 0.5, 0.01);

        let window = RATE / 2;
        let mut answers = Vec::new();
        for start in (0..RATE * 3).step_by(window) {
            let reference = &long[start..start + window];
            // The recording is searched from the same place, so the delay each
            // window sees is the same one.
            let found = align(reference, &heard[start..], MAX_PLAUSIBLE_DELAY)
                .expect("every window has signal");
            answers.push(found.delay);
        }

        assert!(answers.len() >= 6, "not enough windows to say anything");
        let spread = answers.iter().max().unwrap() - answers.iter().min().unwrap();
        assert!(
            spread <= 2,
            "windows disagree by {spread} samples: {answers:?}. This is the failure \
             the phase transform exists to fix, and 471 ms of spread is what the \
             plain correlation gave"
        );
    }

    /// Attenuation and noise are what a room does. Neither moves the answer.
    #[test]
    fn survives_a_quiet_and_noisy_path() {
        let played = speech_like(RATE / 2);
        let heard = path(&played, 6_400, 0.08, 0.004);
        let found = align(&played, &heard, MAX_PLAUSIBLE_DELAY).expect("still findable");
        assert_eq!(found.delay, 6_400);
        assert!(!found.at_edge(), "a real peak, not a truncation");
    }

    /// Two signals with nothing to do with each other **do** produce an answer
    /// that looks fine, and this test exists to keep that written down.
    ///
    /// It asserted the opposite first, because the opposite is what anybody
    /// would assume. The estimator has no way to know that two recordings are
    /// unrelated: it reports the best lag among those it searched, and when
    /// none of them is right the best one is still a number with a respectable
    /// margin behind it.
    ///
    /// Anything that aligns two signals has to establish elsewhere that they
    /// belong together. Here that is the harness, which played one and recorded
    /// the other in the same run.
    #[test]
    fn unrelated_signals_still_produce_an_answer() {
        let played = speech_like(RATE / 2);
        let mut rng = Noise(0xfeed_face);
        let heard: Vec<f32> = (0..RATE).map(|_| rng.next() * 0.1).collect();

        let found = align(&played, &heard, MAX_PLAUSIBLE_DELAY).expect("both carry energy");
        println!(
            "  unrelated: delay {} sharpness {:.2} margin {:.2} at_edge {}",
            found.delay,
            found.sharpness,
            found.margin,
            found.at_edge()
        );
        assert!(
            found.margin > 1.0,
            "if this ever drops to nothing then the margin has become a usable \
             filter and this test should become the assertion it started as"
        );
    }

    /// The bound is not advice. A delay past it is not reported as if it were
    /// inside.
    #[test]
    fn the_search_stays_inside_its_bound() {
        let played = speech_like(RATE / 2);
        // With a noise floor, so the searched range has something in it. Handed
        // pure silence the estimator returns `None`, which is also correct and
        // is a different assertion from this one.
        let heard = path(&played, 40_000, 0.6, 0.005);

        let found = align(&played, &heard, 8_000).expect("there is signal to look at");
        assert!(
            found.delay <= 8_000,
            "reported {} past the bound",
            found.delay
        );
        assert_ne!(
            found.delay, 40_000,
            "the bound is not advice: a delay outside it must not be reported"
        );
    }

    #[test]
    fn silence_and_stubs_are_refused() {
        let played = speech_like(RATE / 2);
        assert!(align(&played, &vec![0.0; RATE], MAX_PLAUSIBLE_DELAY).is_none());
        assert!(align(&vec![0.0; RATE], &played, MAX_PLAUSIBLE_DELAY).is_none());
        assert!(align(&played[..100], &played, MAX_PLAUSIBLE_DELAY).is_none());
        assert!(align(&played, &played[..100], MAX_PLAUSIBLE_DELAY).is_none());
    }
}
