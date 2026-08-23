//! Shared by the acoustic measurements. Not part of the library.
//!
//! In a subdirectory so cargo does not try to build it as an example of its own.

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

/// Where the played signal sits inside the recording, by correlation.
///
/// A real path has a delay nobody controls: the sound card buffers, the speaker
/// is a distance away, the microphone buffers again, and the recording started
/// at a moment nobody chose. Measuring it is the first thing any of this needs.
pub fn best_delay(played: &[f32], heard: &[f32]) -> Option<(usize, f32)> {
    let window = (RATE / 2).min(played.len()).min(heard.len());
    if window < RATE / 10 {
        return None;
    }

    let played_energy: f32 = played[..window].iter().map(|s| s * s).sum();
    if played_energy <= 1e-9 {
        return None;
    }

    let mut best = (0usize, 0.0f32);
    // Every 32 samples: the peak of a correlation this broad is not sharp, and
    // a sample-exact answer is not needed by anything downstream.
    let mut offset = 0;
    while offset + window < heard.len() {
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
