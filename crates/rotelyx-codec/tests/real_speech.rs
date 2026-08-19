//! The codec on speech, rather than on a signal built to look like speech.
//!
//! # Where these came from and what they are not
//!
//! Six clips of neural text-to-speech (Piper, medium models, several voices),
//! generated at 22.05 kHz and resampled to 48 kHz. They are **synthetic**: no
//! microphone, no room, no recorded person. What they do have, and what the
//! twelve-harmonic signal every previous measurement used did not, is the
//! structure of speech: plosives, sibilants, nasals, silence between words, and
//! prosody.
//!
//! Two limits, stated so no number here gets read as more than it is.
//!
//! **Nothing above 11 kHz.** The models synthesise at 22.05 kHz, so the top
//! half of the codec's range is empty. Real speech has little energy up there,
//! but "little" is not "none" and the high bands are not being exercised.
//!
//! **Still not a listening test.** Signal to noise cannot say whether something
//! sounds right, and for the noise-like sounds in these clips it cannot say
//! much at all. These figures narrow down where to look. They do not settle
//! anything.

use rotelyx_codec::bands::{self, BANDS};
use rotelyx_codec::mdct::{self, FRAME, WINDOW};
use rotelyx_codec::{TelyxDecoder, TelyxEncoder};
use std::fs;
use std::path::Path;

/// Read a 16 bit mono PCM WAV.
///
/// Written out rather than pulled in, because a decoder for a format this
/// simple is smaller than the argument about which crate to depend on. It is
/// strict about what it accepts: a test that silently reads stereo as mono
/// produces numbers that are wrong in a way nobody would question.
fn read_wav(path: &Path) -> Option<Vec<f32>> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }

    let mut at = 12;
    let mut format = None;
    let mut data = None;

    while at + 8 <= bytes.len() {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().ok()?) as usize;
        let body = at + 8;
        if body + size > bytes.len() {
            break;
        }
        match id {
            b"fmt " if size >= 16 => {
                let channels = u16::from_le_bytes(bytes[body + 2..body + 4].try_into().ok()?);
                let rate = u32::from_le_bytes(bytes[body + 4..body + 8].try_into().ok()?);
                let bits = u16::from_le_bytes(bytes[body + 14..body + 16].try_into().ok()?);
                format = Some((channels, rate, bits));
            }
            b"data" => data = Some(&bytes[body..body + size]),
            _ => {}
        }
        at = body + size + (size & 1);
    }

    let (channels, rate, bits) = format?;
    assert_eq!(channels, 1, "{path:?} is not mono");
    assert_eq!(rate, 48_000, "{path:?} is not 48 kHz");
    assert_eq!(bits, 16, "{path:?} is not 16 bit");

    let data = data?;
    Some(
        data.chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
            .collect(),
    )
}

fn clips() -> Vec<(String, Vec<f32>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/speech");
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&dir) else {
        return out;
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.extension().is_some_and(|e| e == "wav") {
            if let Some(samples) = read_wav(&p) {
                let name = p.file_stem().unwrap().to_string_lossy().to_string();
                out.push((name, samples));
            }
        }
    }
    out
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

fn rms(x: &[f32]) -> f32 {
    if x.is_empty() {
        return 0.0;
    }
    (x.iter().map(|s| s * s).sum::<f32>() / x.len() as f32).sqrt()
}

/// Signal to noise per clip, and the level, at the rates a call would use.
///
/// # The number this replaced
///
/// The synthetic vowel scores 28.2 dB at 24 kbit/s and that figure is in the
/// README, the paper and every note written about this codec. Real speech, at
/// the same rate and by the same measure, scores between 11.7 and 21.1.
///
/// The cause is not subtle and it is not the resampling: no bits at all are
/// spent above 11 kHz, so the empty top half costs nothing. It is that the
/// synthetic signal keeps 13 of the 24 bands awake and speech keeps 21. The
/// same sixty bytes spread over 21 bands instead of 13 is most of the
/// difference, and it means the codec had been tuned, measured and reported
/// against a signal materially easier than the one it exists for.
#[test]
fn speech_across_the_rates() {
    let clips = clips();
    if clips.is_empty() {
        println!("\n  no clips in tests/speech, skipping. scripts/make-speech rebuilds them.");
        return;
    }

    println!("\n  clip                     12 kbit/s   16 kbit/s   24 kbit/s");
    let mut worst = f32::MAX;
    for (name, signal) in &clips {
        let mut row = String::new();
        for bytes in [30usize, 40, 60] {
            let snr = snr_db(signal, &round_trip(signal, bytes));
            row += &format!("{snr:9.1} dB");
            worst = worst.min(snr);
        }
        println!("  {name:<22}{row}");
    }

    assert!(
        worst > 0.0,
        "some clip decoded with more error than signal ({worst:.1} dB), which on \
         speech rather than noise means something is wrong rather than merely \
         hard to measure"
    );
}

/// The level has to survive even where the waveform does not.
///
/// This is the property signal to noise cannot check and the ear notices
/// immediately: a sound that comes back at the wrong loudness is heard as a
/// different sound, however faithfully its texture was coded.
#[test]
fn speech_keeps_its_level() {
    // Silently a no-op without the clips, which is the point: they are not in
    // git, and a fresh clone has to build and pass without them.
    for (name, signal) in clips() {
        for bytes in [20usize, 30, 60] {
            let decoded = round_trip(&signal, bytes);
            let from = FRAME;
            let ratio = rms(&decoded[from..]) / rms(&signal[from..decoded.len()]);

            assert!(
                (0.7..1.4).contains(&ratio),
                "{name} at {bytes} bytes a frame came back at {ratio:.2} times its \
                 level"
            );
        }
    }
}

/// Silence between words must stay silent.
///
/// A codec that fills pauses with its own noise is exhausting to listen to over
/// a call, and it is a thing a long window does: quantisation error from the
/// word spreads into the gap beside it. This measures the quietest tenth of the
/// input against the same span of the output.
#[test]
fn the_gaps_between_words_stay_quiet() {
    if clips().is_empty() {
        return;
    }
    println!("\n  clip                    quietest tenth: input -> output");
    for (name, signal) in clips() {
        let decoded = round_trip(&signal, 60);
        let n = decoded.len().min(signal.len());

        // Frame-by-frame levels, to find where the input is actually quiet.
        let mut frames: Vec<(usize, f32)> = (FRAME..n - FRAME)
            .step_by(FRAME)
            .map(|i| (i, rms(&signal[i..i + FRAME])))
            .collect();
        frames.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        let quiet = &frames[..frames.len() / 10];
        let input: f32 = quiet.iter().map(|(_, l)| l).sum::<f32>() / quiet.len() as f32;
        let output: f32 = quiet
            .iter()
            .map(|(i, _)| rms(&decoded[*i..*i + FRAME]))
            .sum::<f32>()
            / quiet.len() as f32;

        let loud = rms(&signal[FRAME..n]);
        println!(
            "  {name:<22} {:.1} dB -> {:.1} dB below the clip",
            20.0 * (input / loud).log10(),
            20.0 * (output / loud).log10()
        );

        assert!(
            output < loud * 0.5,
            "{name}: the quiet parts came back at {:.2} of the whole clip's level, \
             which is a pause the codec filled in",
            output / loud
        );
    }
}

/// Where the error actually lands, which is the only honest way to report this.
///
/// # Why a single SNR figure for speech is misleading
///
/// The overall numbers above, 11.7 to 21.1 dB, invite the reading that the
/// codec is poor on speech. Broken down by band, at 24 kbit/s:
///
/// | band | bits/coefficient | SNR | share of all error |
/// |------|------|------|------|
/// | 0-800 Hz | 2.5 to 4.3 | 25 to 29 dB | 3.4% |
/// | 800 Hz - 3 kHz | 1.2 to 2.4 | 8.6 to 21.6 dB | 10.8% |
/// | 3 - 12 kHz | 0.01 to 0.78 | -2.5 to 5.3 dB | 85.7% |
///
/// Speech keeps about 79 percent of its energy below 800 Hz, and there the
/// codec reaches 25 to 29 dB. The 3 to 12 kHz region holds under one percent of
/// the energy, is deliberately given almost no bits, and contributes 86 percent
/// of the measured error. **The single figure is largely a measurement of the
/// bands the codec is choosing to starve**, weighted as though they mattered as
/// much as the ones carrying the voice.
///
/// This does not make the codec good. It makes signal to noise the wrong
/// instrument for the question, which is the same conclusion the fricative
/// reached from the other direction. Whether starving 3 to 12 kHz is the right
/// decision is a question about hearing, and no measurement here can answer it.
///
/// One caveat on the top row: the clips are resampled from 22.05 kHz, so
/// nothing above 11 kHz is real. Band 20 straddles that edge and bands 21 and
/// up are empty.
#[test]
fn per_band_error_on_speech() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/speech");
    if !dir.exists() || clips().is_empty() {
        println!("\n  no clips in tests/speech, skipping. scripts/make-speech rebuilds them.");
        return;
    }
    let w = mdct::window();

    let mut signal = [0.0f64; BANDS];
    let mut noise = [0.0f64; BANDS];
    let mut rate = [0.0f64; BANDS];
    let mut frames = 0.0f64;

    for e in fs::read_dir(&dir).expect("the directory was checked above") {
        let p = e.unwrap().path();
        if p.extension().is_none_or(|x| x != "wav") { continue; }
        let Some(x) = read_wav(&p) else { continue };

        let mut enc = TelyxEncoder::new(60);
        let mut dec = TelyxDecoder::new(60);
        let mut out: Vec<f32> = Vec::new();
        for s in (0..x.len().saturating_sub(WINDOW)).step_by(FRAME) {
            out.extend(dec.decode(&enc.encode(&x[s..s + WINDOW]).unwrap()).unwrap());
        }

        // Compare in the transform domain, frame by frame, skipping warm-up.
        for s in (FRAME..out.len().saturating_sub(WINDOW)).step_by(FRAME) {
            let a = mdct::forward(&x[s..s + WINDOW], &w);
            let b = mdct::forward(&out[s..s + WINDOW], &w);
            let en = bands::energies(&a);
            let alloc = bands::allocate(&en, 60 * 8 - 144);
            for band in 0..BANDS {
                let r = bands::range(band);
                let n = r.len() as f64;
                for i in r.clone() {
                    signal[band] += (a[i] * a[i]) as f64;
                    noise[band] += ((a[i] - b[i]) * (a[i] - b[i])) as f64;
                }
                rate[band] += alloc[band] as f64 / n;
            }
            frames += 1.0;
        }
    }

    println!("\n  band   hz            bits/coef   band SNR   share of all error");
    let total_noise: f64 = noise.iter().sum();

    // The claim the table is here to support, asserted so it cannot quietly
    // stop being true: most of the error is where almost none of the voice is.
    let voice_error: f64 = (0..8).map(|b| noise[b]).sum();
    let voice_signal: f64 = (0..8).map(|b| signal[b]).sum();
    let all_signal: f64 = signal.iter().sum();
    assert!(
        voice_signal / all_signal > 0.6,
        "under 800 Hz should hold most of the energy in speech"
    );
    assert!(
        voice_error / total_noise < 0.15,
        "the bands holding most of the voice hold {:.0}% of the error",
        100.0 * voice_error / total_noise
    );

    for b in 0..BANDS {
        let (lo, hi) = bands::hz(b);
        if signal[b] < 1e-20 { continue; }
        let snr = 10.0 * (signal[b] / noise[b].max(1e-30)).log10();
        println!(
            "  {b:>4}   {lo:>6.0}-{hi:<6.0} {:9.2} {:9.1} dB {:14.1}%",
            rate[b] / frames, snr, 100.0 * noise[b] / total_noise
        );
    }
}
