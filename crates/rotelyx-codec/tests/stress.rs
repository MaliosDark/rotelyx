//! What the codec is bad at, measured rather than assumed.
//!
//! Every quality figure recorded for Telyx so far comes from one synthetic
//! signal: twelve harmonics with vibrato and amplitude modulation. That is a
//! sustained vowel and nothing else. It has no plosives, no fricatives and no
//! silence, which means it never touched the thing a 40 ms window is known to
//! handle badly.
//!
//! These signals are chosen to attack that. None of them needs a recording, so
//! none of them waits on getting a speech corpus, and none of them is a
//! substitute for one: a listening test is still the only thing that can say
//! whether the codec sounds good.

use rotelyx_codec::mdct::{self, FRAME, WINDOW};
use rotelyx_codec::{TelyxDecoder, TelyxEncoder};
use std::f32::consts::PI;

const RATE: f32 = mdct::SAMPLE_RATE as f32;

/// A deterministic noise source, so a failure can be reproduced.
struct Noise(u32);

impl Noise {
    fn next(&mut self) -> f32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        (self.0 as f32 / u32::MAX as f32) * 2.0 - 1.0
    }
}

/// A sustained vowel: the signal every previous measurement used.
fn vowel(n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            let t = i as f32 / RATE;
            let pitch = 120.0 + 20.0 * (2.0 * PI * 3.0 * t).sin();
            let mut s = 0.0;
            for h in 1..=12 {
                let f = pitch * h as f32;
                if f > 8_000.0 {
                    break;
                }
                s += (1.0 / h as f32) * (2.0 * PI * f * t).sin();
            }
            s * 0.3
        })
        .collect()
}

/// A plosive: silence, then a burst that decays in five milliseconds.
///
/// This is a /t/ or /k/, and it is the case a long window smears. The energy
/// belongs in five milliseconds and the transform has forty to spread it over.
fn plosive(n: usize) -> Vec<f32> {
    let mut noise = Noise(0x2545_f491);
    let onset = n / 2;
    (0..n)
        .map(|i| {
            if i < onset {
                0.0
            } else {
                let since = (i - onset) as f32 / RATE;
                0.9 * (-since / 0.005).exp() * noise.next()
            }
        })
        .collect()
}

/// A fricative: band limited noise from 4 to 10 kHz.
///
/// This is an /s/. It has no harmonic structure at all, so a quantiser that
/// codes directions through a pyramid has nothing to lock on to and the result
/// depends entirely on whether the noise fill is convincing.
fn fricative(n: usize) -> Vec<f32> {
    let mut noise = Noise(0x9e37_79b9);
    let mut low = 0.0f32;
    let mut high = 0.0f32;
    (0..n)
        .map(|_| {
            let x = noise.next();
            // Two one-pole filters differenced: crude, and the point is the
            // spectrum being broad and toneless rather than its exact shape.
            low += (x - low) * (2.0 * PI * 10_000.0 / RATE).min(1.0);
            high += (x - high) * (2.0 * PI * 4_000.0 / RATE).min(1.0);
            (low - high) * 0.5
        })
        .collect()
}

/// Silence, then a voiced onset at full level. A word starting after a pause.
fn onset(n: usize) -> Vec<f32> {
    let voiced = vowel(n);
    let start = n / 2;
    (0..n)
        .map(|i| if i < start { 0.0 } else { voiced[i] })
        .collect()
}

fn round_trip(signal: &[f32], bytes: usize) -> Vec<f32> {
    let mut encoder = TelyxEncoder::new(bytes);
    let mut decoder = TelyxDecoder::new(bytes);
    let mut out = Vec::new();

    for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
        let packet = encoder
            .encode(&signal[start..start + WINDOW])
            .expect("encode");
        out.extend(decoder.decode(&packet).expect("decode"));
    }
    out
}

/// Signal to noise, skipping the codec's first frame.
///
/// The overlap-add has no history for its first frame, so those samples are
/// warm-up and every other measurement in this project drops them. Stated here
/// because the convention has to match for the numbers to be comparable with
/// the ones already published.
fn snr_db(original: &[f32], decoded: &[f32]) -> f32 {
    let from = FRAME;
    let n = decoded.len().min(original.len());
    if n <= from {
        return 0.0;
    }
    let (a, b) = (&original[from..n], &decoded[from..n]);

    let signal: f32 = a.iter().map(|s| s * s).sum();
    let noise: f32 = a.iter().zip(b).map(|(x, y)| (x - y).powi(2)).sum();
    if noise < 1e-12 {
        return 99.0;
    }
    10.0 * (signal / noise).log10()
}

/// The signal every published figure was measured on: the vowel above plus a
/// formant boost around 700 Hz and a 4 Hz amplitude envelope.
fn vowel_with_formant(n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            let t = i as f32 / RATE;
            let pitch = 120.0 + 20.0 * (2.0 * PI * 3.0 * t).sin();
            let mut s = 0.0;
            for h in 1..=12 {
                let f = pitch * h as f32;
                if f > 8_000.0 {
                    break;
                }
                let gain = 1.0 / h as f32 * (1.0 + 2.0 * (-(f - 700.0).abs() / 500.0).exp());
                s += gain * (2.0 * PI * f * t).sin();
            }
            s * 0.3 * (0.5 + 0.5 * (2.0 * PI * 4.0 * t).sin())
        })
        .collect()
}

fn rms(x: &[f32]) -> f32 {
    if x.is_empty() {
        return 0.0;
    }
    (x.iter().map(|s| s * s).sum::<f32>() / x.len() as f32).sqrt()
}

/// The headline: how the codec does on each kind of sound.
///
/// Reported rather than asserted for the cases that are known weak, because a
/// number that moves is more use than a threshold that passes.
#[test]
fn what_each_kind_of_sound_costs() {
    let n = FRAME * 30;
    let cases: [(&str, Vec<f32>); 5] = [
        ("vowel with formant", vowel_with_formant(n)),
        ("sustained vowel", vowel(n)),
        ("voiced onset", onset(n)),
        ("fricative /s/", fricative(n)),
        ("plosive /t/", plosive(n)),
    ];

    println!("\n  signal              12 kbit/s   24 kbit/s");
    for (name, signal) in &cases {
        let a = snr_db(signal, &round_trip(signal, 30));
        let b = snr_db(signal, &round_trip(signal, 60));
        println!("  {name:<18} {a:8.1} dB {b:8.1} dB");
    }

    // The vowel is the only case with a floor worth defending, because it is
    // the only one the codec was tuned against.
    let vowel_snr = snr_db(&cases[0].1, &round_trip(&cases[0].1, 60));
    println!(
        "\n  the first row is the signal every published figure used. The second\n  \
         is the same harmonics with the formant and the envelope removed."
    );
    assert!(
        vowel_snr > 15.0,
        "the sustained vowel, which every other measurement used, fell to \
         {vowel_snr:.1} dB"
    );
}

/// Pre-echo: energy that arrives before the sound that caused it.
///
/// A transform codec spreads its quantisation error over the whole window, so a
/// burst at the end of a 40 ms window puts noise at the start of it, tens of
/// milliseconds before the burst. The ear hears that as a click ahead of the
/// consonant and it is the single most audible artefact a long window produces.
///
/// This measures it directly: the level in the silence before the plosive,
/// against the level of the plosive itself. Reported, not bounded, because the
/// fix is block switching and block switching is not built. Writing the number
/// down is what stops it being a surprise later.
#[test]
fn a_plosive_smears_backwards_into_the_silence_before_it() {
    let n = FRAME * 20;
    let signal = plosive(n);
    let decoded = round_trip(&signal, 60);

    let onset = n / 2;
    // One window before the burst, staying clear of the frame it lands in.
    let from = onset.saturating_sub(WINDOW);
    let to = onset.saturating_sub(FRAME / 2);

    let before_in = rms(&signal[from..to]);
    let before_out = rms(&decoded[from.min(decoded.len())..to.min(decoded.len())]);
    let burst = rms(&signal[onset..(onset + FRAME).min(n)]);

    let leak_db = 20.0 * (before_out.max(1e-9) / burst.max(1e-9)).log10();

    println!(
        "\n  before the burst: input {before_in:.2e}, output {before_out:.2e}\n  \
         pre-echo is {leak_db:.1} dB below the burst"
    );
    assert!(
        before_in < 1e-6,
        "the test signal is not silent before the burst, so this measures nothing"
    );

    // Not a quality bar: a guard that the number stays a number. If pre-echo
    // ever reaches the level of the burst itself, something is broken rather
    // than merely untuned.
    assert!(
        leak_db < 0.0,
        "pre-echo is at or above the level of the burst that caused it"
    );
}

/// A fricative has no harmonics, so what matters is that the level survives
/// even when the fine structure cannot.
///
/// This is the case the design is supposed to handle by construction: every PVQ
/// codeword has the same norm, so a starved band comes back as a rough version
/// of itself at the right loudness rather than as a quiet one.
#[test]
fn a_fricative_keeps_its_level_even_when_it_loses_its_detail() {
    let n = FRAME * 20;
    let signal = fricative(n);

    println!("\n  bytes/frame   level as a fraction of the original");
    let mut worst = 1.0f32;
    for bytes in [18usize, 20, 30, 40, 60] {
        let decoded = round_trip(&signal, bytes);
        let from = FRAME;
        let level = rms(&decoded[from..]) / rms(&signal[from..decoded.len()]);
        println!("  {bytes:>11}   {level:.2}  ({:+.1} dB)", 20.0 * level.log10());
        if (level - 1.0).abs() > (worst - 1.0).abs() {
            worst = level;
        }
    }
    for bytes in [20usize, 30, 60] {
        let decoded = round_trip(&signal, bytes);
        let from = FRAME;
        let level = rms(&decoded[from..]) / rms(&signal[from..decoded.len()]);

        assert!(
            (0.5..2.0).contains(&level),
            "at {bytes} bytes a frame the fricative came back at {level:.2} times \
             its level; noise that changes loudness is heard as a different \
             sound, and every codeword having the same norm is supposed to make \
             that impossible"
        );
    }
}

/// Invented texture must be noise, and noise does not repeat.
///
/// The fill was a hash of the coefficient index and nothing else, so it
/// produced the same pattern in every frame for ever. A decoded fricative
/// correlated with itself one frame later at **+0.991**, against +0.008 for the
/// noise going in: not a hiss but a buzz at the frame rate, which is 50 Hz.
///
/// This is the measurement that caught it, kept because the defect was invisible
/// to every other test in the project. Signal to noise cannot see it, the level
/// is right throughout, and the round trip tests pass either way.
#[test]
fn invented_texture_does_not_repeat_frame_to_frame() {
    let signal = fricative(FRAME * 30);

    let correlation = |x: &[f32]| -> f32 {
        let frames = x.len() / FRAME;
        let mut total = 0.0;
        let mut count = 0;
        for f in 2..frames.saturating_sub(1) {
            let a = &x[f * FRAME..(f + 1) * FRAME];
            let b = &x[(f + 1) * FRAME..(f + 2) * FRAME];
            let dot: f32 = a.iter().zip(b).map(|(p, q)| p * q).sum();
            let na = a.iter().map(|p| p * p).sum::<f32>().sqrt();
            let nb = b.iter().map(|p| p * p).sum::<f32>().sqrt();
            if na > 1e-9 && nb > 1e-9 {
                total += dot / (na * nb);
                count += 1;
            }
        }
        if count == 0 { 0.0 } else { total / count as f32 }
    };

    let input = correlation(&signal);
    println!("\n  bytes/frame   frame-to-frame correlation");
    for bytes in [18usize, 20, 30, 60] {
        let out = round_trip(&signal, bytes);
        let c = correlation(&out);
        println!("  {bytes:>11}   {c:+.3}");
        assert!(
            c.abs() < 0.25,
            "at {bytes} bytes a frame the output correlates with itself one \
             frame later at {c:+.3}, against {input:+.3} for the noise going in. \
             That is a tone at the frame rate rather than noise."
        );
    }
    println!("  {:>11}   {input:+.3}  <- the input, which is real noise", "input");
}

/// A rate too low to carry the band energies is refused, not delivered quiet.
#[test]
fn a_rate_that_cannot_carry_the_envelope_is_refused() {
    use rotelyx_codec::{minimum_bytes_per_frame, CodecError};

    let signal = vowel(WINDOW * 2);
    let needed = minimum_bytes_per_frame(15);
    assert!(needed > 15, "the test needs a rate that genuinely does not fit");

    let mut encoder = TelyxEncoder::new(15);
    assert!(
        matches!(
            encoder.encode(&signal[..WINDOW]),
            Err(CodecError::RateTooLow { bytes: 15, .. })
        ),
        "a fifteen byte frame, which cannot hold the {needed} bytes of band \
         energies, was encoded anyway. It used to be: the frame was truncated \
         to size, the last bands' levels were read back out of zero padding, \
         and the result decoded six decibels quiet with no error anywhere."
    );

    // And the smallest rate that does fit is accepted.
    let mut encoder = TelyxEncoder::new(needed);
    assert!(encoder.encode(&signal[..WINDOW]).is_ok());
}
