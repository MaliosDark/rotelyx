//! Shared by the acoustic measurements. Not part of the library.
//!
//! In a subdirectory so cargo does not try to build it as an example of its own.
//!
//! # Why the dead code is allowed
//!
//! Each example compiles this module into itself and uses the part it needs, so
//! anything the *other* example uses is dead in this one and warns. That is a
//! fact about how a shared module is built rather than about the code, and
//! silencing it here is what stops the two examples from having a copy each.
#![allow(dead_code, reason = "each example uses a different part of this")]

pub const RATE: usize = 48_000;

/// Sixteen bit mono, walking the chunks rather than assuming a 44 byte header:
/// what `parecord` writes and what a synthesiser writes do not have the same one.
pub fn read_wav(path: &str) -> Vec<f32> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("reading {path}: {e}");
        std::process::exit(1);
    });

    let mut at = 12;
    while at + 8 <= bytes.len() {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if id == b"data" {
            let body = &bytes[at + 8..(at + 8 + size).min(bytes.len())];
            return body
                .chunks_exact(2)
                .map(|p| i16::from_le_bytes([p[0], p[1]]) as f32 / 32768.0)
                .collect();
        }
        at += 8 + size + (size & 1);
    }
    eprintln!("{path} has no data chunk");
    std::process::exit(1);
}

/// The furthest the played signal can plausibly sit inside the recording.
///
/// # Why the search is bounded, and what it cost not to be
///
/// It was not, and it found 3295 ms with a correlation of 0.29 on a recording
/// that could not have been offset by more than a fraction of a second: the
/// harness starts recording, waits 0.4 s, then plays. A search over the whole
/// recording had twenty four seconds of speech to find a false peak in, and it
/// found one. Everything downstream was then aligned to a delay that does not
/// exist, and the canceller, fed a reference that has nothing to do with what
/// the microphone heard, adapted to noise and **added** 7 dB of echo.
///
/// The real budget: 0.4 s of deliberate offset, plus whatever the sound card
/// buffers on each side, plus the flight time across a room, which is under a
/// hundredth of a second for any room somebody is in. Two seconds is generous
/// for all of it and excludes a peak three seconds out.
///
/// A search that cannot find the answer says so. A search that finds the wrong
/// answer confidently is worse, and that is what this was.
pub const MAX_PLAUSIBLE_DELAY: usize = RATE as usize * 2;

/// Where the played signal sits inside the recording, by correlation.
///
/// A real path has a delay nobody controls: the sound card buffers, the speaker
/// is a distance away, the microphone buffers again, and the recording started
/// at a moment nobody chose. Measuring it is the first thing any of this needs.
///
/// Bounded by [`MAX_PLAUSIBLE_DELAY`]. Returns the correlation alongside the
/// delay so a caller can refuse a weak answer rather than align to it.
pub fn best_delay(played: &[f32], heard: &[f32]) -> Option<(usize, f32)> {
    let window = (RATE / 2).min(played.len()).min(heard.len());
    if window < RATE / 10 {
        return None;
    }
    let furthest = MAX_PLAUSIBLE_DELAY.min(heard.len().saturating_sub(window));

    let played_energy: f32 = played[..window].iter().map(|s| s * s).sum();
    if played_energy <= 1e-9 {
        return None;
    }

    let mut best = (0usize, 0.0f32);
    // Every 32 samples: the peak of a correlation this broad is not sharp, and
    // a sample-exact answer is not needed by anything downstream.
    let mut offset = 0;
    while offset <= furthest {
        let slice = &heard[offset..offset + window];
        let energy: f32 = slice.iter().map(|s| s * s).sum();
        if energy > 1e-9 {
            let dot: f32 = played[..window].iter().zip(slice).map(|(a, b)| a * b).sum();
            let normalised = dot / (played_energy.sqrt() * energy.sqrt());
            if normalised > best.1 {
                best = (offset, normalised);
            }
        }
        offset += 32;
    }

    (best.1 > 0.0).then_some(best)
}

pub fn energy(x: &[f32]) -> f64 {
    x.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>() / x.len().max(1) as f64
}

pub fn db(before: f64, after: f64) -> f64 {
    10.0 * (before / after.max(1e-30)).log10()
}
