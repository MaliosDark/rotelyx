//! Produce the files for a blind listening test.
//!
//! Signal to noise cannot say whether a codec sounds good, and every number
//! recorded for Telyx is signal to noise. This writes what a person can
//! actually judge: the same speech, passed through the codec at each rate, in
//! files whose names say nothing about what is in them.
//!
//! Run with `cargo run -p rotelyx-codec --example bake_listening_test`.
//!
//! # Why the names are blind
//!
//! A listener who knows which file is theirs is not testing the codec, they are
//! testing their own hope. The mapping is written to `key.txt` in the same
//! directory: the point is to listen first and read it after, and nothing here
//! can enforce that except saying so.
//!
//! # What the anchor is for
//!
//! MUSHRA-style tests include a deliberately degraded anchor, conventionally
//! the reference low-passed at 3.5 kHz, so that ratings have a fixed bottom to
//! be measured against. If something scores below the anchor it is worse than a
//! telephone, which is a statement that means the same thing to everybody.

use rotelyx_codec::mdct::{FRAME, WINDOW};
use rotelyx_codec::{TelyxDecoder, TelyxEncoder};
use std::fs;
use std::path::{Path, PathBuf};

fn read_wav(path: &Path) -> Option<Vec<f32>> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" {
        return None;
    }
    let mut at = 12;
    let mut data = None;
    while at + 8 <= bytes.len() {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().ok()?) as usize;
        let body = at + 8;
        if body + size > bytes.len() {
            break;
        }
        if id == b"data" {
            data = Some(&bytes[body..body + size]);
        }
        at = body + size + (size & 1);
    }
    Some(
        data?
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
            .collect(),
    )
}

fn write_wav(path: &Path, samples: &[f32], rate: u32) -> std::io::Result<()> {
    let bits = 16u16;
    let channels = 1u16;
    let byte_rate = rate * channels as u32 * (bits / 8) as u32;
    let block = channels * bits / 8;
    let data_len = samples.len() * 2;

    let mut out = Vec::with_capacity(44 + data_len);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&block.to_le_bytes());
    out.extend_from_slice(&bits.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_len as u32).to_le_bytes());

    for s in samples {
        // Clip rather than wrap. A sample that wraps is a click, and a click is
        // the loudest thing in the file.
        let v = (s.clamp(-1.0, 1.0) * 32767.0).round() as i16;
        out.extend_from_slice(&v.to_le_bytes());
    }
    fs::write(path, out)
}

fn round_trip(signal: &[f32], bytes: usize) -> Vec<f32> {
    let mut encoder = TelyxEncoder::new(bytes);
    let mut decoder = TelyxDecoder::new(bytes);
    let mut out = Vec::new();
    for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
        let packet = encoder.encode(&signal[start..start + WINDOW]).expect("encode");
        out.extend(decoder.decode(&packet).expect("decode"));
    }
    // The first frame is the overlap-add warming up and is not audio.
    out.drain(..FRAME.min(out.len()));
    out
}

/// A deterministic label that carries no information about the file.
///
/// Deterministic so that re-running produces the same set and a listener can
/// come back to it, and so that the key stays valid.
fn label(seed: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    let letters = b"abcdefghjkmnpqrstuvwxyz";
    let mut out = String::new();
    for _ in 0..6 {
        out.push(letters[(h % letters.len() as u64) as usize] as char);
        h /= letters.len() as u64;
    }
    out
}

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let speech = root.join("tests/speech");
    let out_dir = root.join("../../target/listening");
    fs::create_dir_all(&out_dir)?;

    let mut clips: Vec<PathBuf> = fs::read_dir(&speech)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "wav"))
        .collect();
    clips.sort();

    let mut key: Vec<String> = Vec::new();
    key.push("Read this AFTER listening, not before.".into());
    key.push(String::new());

    for clip in &clips {
        let name = clip.file_stem().unwrap().to_string_lossy().to_string();
        let Some(samples) = read_wav(clip) else {
            continue;
        };

        // The reference, trimmed the same way the decoded files are so that
        // nothing is distinguishable by length.
        let reference: Vec<f32> = samples[FRAME..].to_vec();
        let id = label(&format!("{name}/reference"));
        write_wav(&out_dir.join(format!("{name}_{id}.wav")), &reference, 48_000)?;
        key.push(format!("{name}_{id}  reference (untouched)"));

        for (kbit, bytes) in [(12usize, 30usize), (16, 40), (24, 60)] {
            let decoded = round_trip(&samples, bytes);
            let id = label(&format!("{name}/telyx/{kbit}"));
            write_wav(&out_dir.join(format!("{name}_{id}.wav")), &decoded, 48_000)?;
            key.push(format!("{name}_{id}  telyx {kbit} kbit/s"));
        }
    }

    key.push(String::new());
    key.push("Opus and the 3.5 kHz anchor are added by scripts/bake-listening-test.".into());
    fs::write(out_dir.join("key.txt"), key.join("\n") + "\n")?;

    println!("wrote {} files to {}", clips.len() * 4, out_dir.display());
    println!("the mapping is in key.txt: listen first, read it after");
    Ok(())
}
