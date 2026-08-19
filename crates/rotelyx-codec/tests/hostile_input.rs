//! The codec's parsers, given bytes that never came from an encoder.
//!
//! A decoder sits behind an authenticated transport, so in normal operation it
//! only ever sees what a real encoder produced. That is an argument for not
//! bothering, and it is wrong twice: the authentication can be misconfigured,
//! and a decoder is exactly the sort of component that gets reused later
//! somewhere the authentication is not there.
//!
//! It is also the newest code in the project, which is the other reason to
//! point this at it.
//!
//! Systematic mutation rather than a fuzzer, so it runs on every change.

use rotelyx_codec::layered::{LayeredEncoder, LayeredFrame};
use rotelyx_codec::mdct::{self, FRAME, WINDOW};
use rotelyx_codec::{TelyxDecoder, TelyxEncoder};
use std::f32::consts::PI;

fn tone(n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            let t = i as f32 / mdct::SAMPLE_RATE as f32;
            0.3 * (2.0 * PI * 220.0 * t).sin() + 0.1 * (2.0 * PI * 1310.0 * t).sin()
        })
        .collect()
}

/// A genuine layered frame, serialised.
fn layered_specimen() -> Vec<u8> {
    let audio = tone(WINDOW);
    LayeredEncoder::new(60)
        .encode(&audio)
        .expect("encode")
        .to_bytes()
}

/// A genuine fixed width frame.
fn telyx_specimen() -> Vec<u8> {
    TelyxEncoder::new(60).encode(&tone(WINDOW)).expect("encode")
}

#[test]
fn no_truncation_panics() {
    let valid = layered_specimen();
    for len in 0..=valid.len() {
        let _ = LayeredFrame::from_bytes(&valid[..len]);
    }

    let valid = telyx_specimen();
    for len in 0..=valid.len() {
        let _ = TelyxDecoder::new(60).decode(&valid[..len]);
    }
}

/// Every byte value at every position, for both frame formats.
///
/// The layered format's first byte is the layer count and the next few are
/// lengths, which is where a parser walks off the end if it is going to.
#[test]
fn no_single_byte_corruption_panics() {
    let valid = layered_specimen();
    for position in 0..valid.len() {
        for byte in 0u16..=255 {
            let mut corrupted = valid.clone();
            corrupted[position] = byte as u8;
            if let Ok(frame) = LayeredFrame::from_bytes(&corrupted) {
                // Parsing is only half of it: a frame that parses then gets
                // decoded, and the decoder reads codebook indices out of it.
                let _ = rotelyx_codec::layered::LayeredDecoder::new(60).decode(&frame);
            }
        }
    }

    let valid = telyx_specimen();
    for position in 0..valid.len() {
        for byte in [0x00u8, 0x01, 0x55, 0xaa, 0xfe, 0xff] {
            let mut corrupted = valid.clone();
            corrupted[position] = byte;
            let _ = TelyxDecoder::new(60).decode(&corrupted);
        }
    }
}

#[test]
fn no_extension_panics() {
    let valid = layered_specimen();
    for extra in [1usize, 9, 1024, 65_536] {
        let mut longer = valid.clone();
        longer.extend(std::iter::repeat_n(0xff, extra));
        if let Ok(frame) = LayeredFrame::from_bytes(&longer) {
            let _ = rotelyx_codec::layered::LayeredDecoder::new(60).decode(&frame);
        }
    }
}

#[test]
fn no_arbitrary_input_panics() {
    let mut state = 0xd1b5_4a32_d192_ed03u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for len in [0usize, 1, 2, 3, 4, 5, 59, 60, 61, 1024, 65_535] {
        for bytes in [vec![0x00; len], vec![0xff; len]] {
            if let Ok(frame) = LayeredFrame::from_bytes(&bytes) {
                let _ = rotelyx_codec::layered::LayeredDecoder::new(60).decode(&frame);
            }
            let _ = TelyxDecoder::new(60).decode(&bytes);
        }
        for _ in 0..30 {
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            if let Ok(frame) = LayeredFrame::from_bytes(&bytes) {
                let _ = rotelyx_codec::layered::LayeredDecoder::new(60).decode(&frame);
            }
            let _ = TelyxDecoder::new(60).decode(&bytes);
        }
    }
}

/// Whatever comes out of a corrupted frame, it may not be loud.
///
/// This is the property that matters more than not crashing. A decoder that
/// turns rubbish into full-scale noise is a decoder that can hurt somebody
/// wearing headphones, and a corrupt frame is not a rare event on a real
/// network.
#[test]
fn a_corrupted_frame_never_decodes_to_a_full_scale_burst() {
    let valid = telyx_specimen();
    let mut worst = 0.0f32;

    for position in 0..valid.len() {
        for byte in [0x00u8, 0xff, 0x55] {
            let mut corrupted = valid.clone();
            corrupted[position] = byte;
            if let Ok(audio) = TelyxDecoder::new(60).decode(&corrupted) {
                worst = worst.max(audio.iter().fold(0.0f32, |m, s| m.max(s.abs())));
            }
        }
    }

    assert!(
        worst <= 1.0,
        "a corrupted frame decoded to a peak of {worst:.2}, which clips and is \
         the loudest thing a listener will hear all call"
    );
    println!("\n  worst peak from a corrupted frame: {worst:.3}");
}

/// The genuine frames still work, so that rejecting everything cannot pass.
#[test]
fn the_valid_cases_still_work() {
    let frame = LayeredFrame::from_bytes(&layered_specimen()).expect("layered frame parses");
    assert!(!frame.base.is_empty());

    let audio = TelyxDecoder::new(60)
        .decode(&telyx_specimen())
        .expect("telyx frame decodes");
    assert_eq!(audio.len(), FRAME);
}
