//! The canceller measured through the audio path a call actually uses.
//!
//! # Why this exists beside `acoustic-echo`
//!
//! `scripts/measure-echo` plays with `paplay` and records with `parecord`. Those
//! are two streams with clocks of their own, and a call is not: `Call::start`
//! opens one [`Capture`] and one [`Playback`] through `cpal` and runs them
//! together. That difference has been written at the bottom of that script since
//! it was first written, as a suspicion nobody had acted on.
//!
//! Seven runs of that harness gave a mean of **-2.0 dB** for the canceller in
//! its continuous configuration, which is the configuration a call runs, with
//! six of the seven negative. The documented figure is +1.3 dB and it was not
//! reproduced once. That is a reason to act on the suspicion.
//!
//! So this measures the same thing through the same devices a call opens. If
//! the answer here is positive, the canceller is fine and the other harness was
//! measuring two clocks. If it is negative, a call on this hardware is worse
//! with the canceller than without it, and that is worth knowing before anybody
//! ships one.
//!
//!     cargo run -p rotelyx-audio --example acoustic-duplex
//!
//! # What it changes on the machine
//!
//! Nothing. It does not touch the volume, because it is not trying to reach the
//! operating point the other harness reaches; it is trying to compare two paths
//! at whatever volume the machine is at. Set that yourself and keep it the same
//! across runs, or the comparison is between volumes.

mod common;

use std::time::{Duration, Instant};

use common::{db, energy, read_wav, RATE};
use rotelyx_audio::align::{align, align_near, MAX_PLAUSIBLE_DELAY};
use rotelyx_audio::device::{Capture, Playback};
use rotelyx_audio::echo::EchoCanceller;

/// Samples handed to the canceller at a time. The same block the call uses.
const BLOCK: usize = 480;

fn main() {
    // A clip, or the synthesised set if none is named.
    //
    // Naming one matters more than it looks: every acoustic number in this
    // repository was measured against six clips from one text to speech model,
    // which is one way of placing a vowel and one pitch range.
    // `scripts/make-speech-corpus` builds clips from eight recorded people, and
    // pointing this at one of them is how a result stops being about a voice.
    let named = std::env::args().nth(1);

    let mut played: Vec<f32> = Vec::new();
    let source = match named.as_deref() {
        Some(path) => {
            if !std::path::Path::new(path).exists() {
                println!("\n  no clip at {path}");
                return;
            }
            played.extend(read_wav(path));
            path.to_string()
        }
        None => {
            for name in [
                "digits_alan",
                "fricatives_jenny",
                "nasals_libritts",
                "plosives_ryan",
                "sibilants_lessac",
                "transients_amy",
            ] {
                let path = format!("crates/rotelyx-codec/tests/speech/{name}.wav");
                if !std::path::Path::new(&path).exists() {
                    println!("\n  no clips in crates/rotelyx-codec/tests/speech, skipping.");
                    println!("  scripts/make-speech rebuilds them.");
                    return;
                }
                played.extend(read_wav(&path));
            }
            "the synthesised set".to_string()
        }
    };

    println!(
        "\n  {:.1}s from {source}, through the devices a call opens",
        played.len() as f32 / RATE as f32
    );

    let capture = match Capture::open() {
        Ok(c) => c,
        Err(e) => {
            println!("  no microphone: {e}");
            return;
        }
    };
    let playback = match Playback::open() {
        Ok(p) => p,
        Err(e) => {
            println!("  no speaker: {e}");
            return;
        }
    };

    // Drain whatever the microphone buffered while the streams were starting,
    // so the recording begins at a moment this program chose.
    std::thread::sleep(Duration::from_millis(300));
    while capture.take(BLOCK).is_some() {}

    let mut heard: Vec<f32> = Vec::new();
    let started = Instant::now();
    let mut at = 0usize;

    // Queue a little ahead, then keep the queue topped up while reading. A call
    // does the same: the playback side is fed from a jitter buffer and the
    // capture side is drained as it fills.
    while at < played.len()
        || started.elapsed() < Duration::from_secs_f32(played.len() as f32 / RATE as f32 + 1.0)
    {
        if at < played.len() && playback.backlog() < RATE / 5 {
            let end = (at + BLOCK * 4).min(played.len());
            playback.queue(&played[at..end]);
            at = end;
        }
        while let Some(block) = capture.take(BLOCK) {
            heard.extend(block);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    println!(
        "  heard {:.1}s",
        heard.len() as f32 / capture.channels().max(1) as f32 / RATE as f32
    );

    // Mono, whatever the microphone offered.
    let channels = capture.channels().max(1);
    let heard: Vec<f32> = if channels == 1 {
        heard
    } else {
        heard.chunks(channels).map(|f| f[0]).collect()
    };

    if energy(&heard) <= 1e-9 {
        println!("  the microphone recorded silence. Check it is not muted.");
        return;
    }

    let Some(coarse) = align(&played, &heard, MAX_PLAUSIBLE_DELAY) else {
        println!("  the played signal is not in the recording at all.");
        return;
    };
    if coarse.at_edge() {
        println!("  the alignment sits at the edge of the search, so it is a truncation");
        println!("  rather than an answer. Nothing below would mean anything.");
        return;
    }
    println!(
        "  the speaker reaches the microphone {:.0} ms later, margin {:.2}",
        coarse.delay as f32 * 1000.0 / RATE as f32,
        coarse.margin
    );

    // Continuous, which is what a call runs.
    let continuous = cancel(&played, &heard, coarse.delay);
    println!("  continuous, which is what a call runs: {continuous:.1} dB removed");

    // And windowed, for comparison with the other harness only. A call cannot
    // do this and nothing here suggests it should.
    let window = RATE / 2;
    let mut per_window = Vec::new();
    let mut start = 0;
    while start + window * 2 < played.len().min(heard.len().saturating_sub(coarse.delay)) {
        let far = &played[start..start + window];
        let expect = coarse.delay + start;
        if let Some(found) = align_near(far, &heard, expect, RATE / 10) {
            if !found.at_edge() && found.delay + window <= heard.len() {
                per_window.push(cancel(far, &heard[found.delay..found.delay + window], 0));
            }
        }
        start += window;
    }

    if per_window.is_empty() {
        println!("  not enough material for a windowed comparison");
    } else {
        let mean = per_window.iter().sum::<f32>() / per_window.len() as f32;
        println!(
            "  windowed and realigned, which a call cannot do: {mean:.1} dB over {} windows",
            per_window.len()
        );
    }

    println!();
    println!("  Run this several times. `scripts/measure-echo` gives a continuous");
    println!("  figure that moves five decibels between runs, and one number from");
    println!("  either harness says nothing about which of them is right.");
}

/// Feed the canceller and report what it removed.
fn cancel(far: &[f32], near: &[f32], delay: usize) -> f32 {
    let mut canceller = EchoCanceller::new();
    let mut before = 0.0f64;
    let mut after = 0.0f64;

    let near = &near[delay.min(near.len())..];
    for (f, n) in far.chunks(BLOCK).zip(near.chunks(BLOCK)) {
        if f.len() < BLOCK || n.len() < BLOCK {
            break;
        }
        canceller.played(f);
        let cleaned = canceller.capture(n);
        before += n.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
        after += cleaned
            .iter()
            .map(|s| (*s as f64) * (*s as f64))
            .sum::<f64>();
    }
    db(before, after) as f32
}
