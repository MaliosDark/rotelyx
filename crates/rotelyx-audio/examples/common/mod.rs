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

// The delay estimator that used to live here now lives in the crate, in
// `rotelyx_audio::align`, with tests.
//
// It moved because it is an instrument and it had none. Two confident wrong
// answers came out of it, an unbounded search that found a peak 3295 ms out on
// a recording offset by 650, and a per-window estimate that reported -2024 ppm
// of clock drift on one run and -4210 on the next. Neither was caught by
// anything here, because there was nothing here to catch them.

pub fn energy(x: &[f32]) -> f64 {
    x.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>() / x.len().max(1) as f64
}

pub fn db(before: f64, after: f64) -> f64 {
    10.0 * (before / after.max(1e-30)).log10()
}
