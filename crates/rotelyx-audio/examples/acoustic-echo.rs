//! What the echo canceller removes from a real room.
//!
//! Driven by `scripts/measure-echo`, which does the playing and the recording.
//! This part takes the two files and does the arithmetic, so the measurement can
//! be re-run on a pair of recordings without a speaker present.
//!
//! # The delay is the whole problem
//!
//! A synthetic echo path starts when you say it starts. A real one does not: the
//! sound card buffers, the speaker is a distance away, the microphone buffers
//! again, and the recording started at a moment nobody controls. The canceller
//! models 128 ms of impulse response, and every millisecond spent on a delay it
//! could have been told about is a millisecond it cannot spend on the room.
//!
//! So the delay is measured by correlation first and reported, because it is a
//! property of the machine worth knowing on its own, and then removed. A
//! canceller fed an unaligned pair measures the alignment rather than the
//! canceller.

use std::env;

use rotelyx_audio::echo::EchoCanceller;

#[path = "common/mod.rs"]
mod common;
// `db` is not imported: this file defines its own below, which shadowed the
// one here and left the import unused.
use common::{best_delay, read_wav, RATE};

const BLOCK: usize = 960;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: acoustic-echo <played.wav> <heard.wav>");
        std::process::exit(2);
    }

    let played = read_wav(&args[1]);
    let heard = read_wav(&args[2]);

    // The control, and the reason the number below can be believed.
    //
    // A harness that reports no cancellation is indistinguishable from a
    // canceller that does none. So the same code path is run first against an
    // echo this program makes up: a delay and a decay, which is the shape the
    // canceller's own test uses. If that comes out near nothing too, the fault
    // is here rather than in the room.
    {
        let synthetic_echo = |far: &[f32]| -> Vec<f32> {
            let delay = RATE / 20;
            let mut out = vec![0.0f32; far.len()];
            for (i, s) in far.iter().enumerate() {
                if i + delay < out.len() {
                    out[i + delay] += 0.5 * s;
                }
                if i + delay * 2 < out.len() {
                    out[i + delay * 2] += 0.2 * s;
                }
            }
            out
        };

        let run = |far: &[f32]| -> f32 {
            let near = synthetic_echo(far);
            let mut control = EchoCanceller::new();
            let (mut b, mut a) = (0.0f64, 0.0f64);
            for (i, (f, n2)) in far.chunks(BLOCK).zip(near.chunks(BLOCK)).enumerate() {
                if f.len() < BLOCK || n2.len() < BLOCK {
                    break;
                }
                control.played(f);
                let cleaned = control.capture(n2);
                if i * BLOCK >= BLOCK * 25 {
                    b += n2.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
                    a += cleaned.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
                }
            }
            (10.0 * (b / a.max(1e-30)).log10()) as f32
        };

        // White noise: what `the_echo_is_removed` uses, and the easiest signal
        // an adaptive filter can be given. It excites every frequency at every
        // instant, which is the condition the convergence proof wants and the
        // condition a telephone call never has.
        let mut state = 0x1234_5678u32;
        let noise: Vec<f32> = (0..played.len())
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state as f32 / u32::MAX as f32) * 2.0 - 1.0
            })
            .collect();

        println!("  control, invented echo, white noise far end: {:.1} dB", run(&noise));
        println!("  control, invented echo, speech far end:      {:.1} dB", run(&played));
    }
    println!(
        "\n  played {:.1}s, heard {:.1}s",
        played.len() as f32 / RATE as f32,
        heard.len() as f32 / RATE as f32
    );

    let Some((delay, correlation)) = best_delay(&played, &heard) else {
        println!("  the microphone did not hear the speaker at all.");
        println!("  Nothing can be measured from this: check the output is not muted");
        println!("  and that the speaker is pointing at the microphone.");
        std::process::exit(1);
    };

    println!(
        "  the speaker reaches the microphone {:.0} ms later, correlation {:.2}",
        delay as f32 * 1000.0 / RATE as f32,
        correlation
    );
    if correlation < 0.05 {
        println!("  and barely: below about 0.05 this is a room that is not coupling,");
        println!("  so what follows measures noise rather than an echo path.");
    } else if correlation < 0.5 {
        // Said out loud because the number below is meaningless without it. A
        // direct acoustic path correlates strongly with what was played; a weak
        // peak means the alignment is a guess, and a canceller aligned to a
        // guess adapts to noise and makes the echo worse rather than better.
        println!("  that correlation is weak. A direct path from a speaker to a");
        println!("  microphone in the same room correlates far more strongly, so");
        println!("  this alignment is probably wrong and the figures below are");
        println!("  measuring a canceller that was handed the wrong reference.");
    }

    // Aligned, so the canceller spends its filter on the room rather than on a
    // delay it could have been told about.
    let aligned: Vec<f32> = heard[delay.min(heard.len())..].to_vec();
    let n = aligned.len().min(played.len());
    if n < BLOCK * 10 {
        println!("  too short to measure: {n} samples aligned");
        std::process::exit(1);
    }

    let mut canceller = EchoCanceller::new();
    let mut before = 0.0f64;
    let mut after = 0.0f64;

    // The first blocks are the filter converging, and including them measures
    // how fast it adapts rather than how well it ends up. Both are worth
    // knowing, so both are reported.
    let warm = BLOCK * 25;
    let mut early_before = 0.0f64;
    let mut early_after = 0.0f64;

    for (i, (far, near)) in played[..n]
        .chunks(BLOCK)
        .zip(aligned[..n].chunks(BLOCK))
        .enumerate()
    {
        if far.len() < BLOCK || near.len() < BLOCK {
            break;
        }
        canceller.played(far);
        let cleaned = canceller.capture(near);

        let b: f64 = near.iter().map(|s| (*s as f64) * (*s as f64)).sum();
        let a: f64 = cleaned.iter().map(|s| (*s as f64) * (*s as f64)).sum();

        if i * BLOCK < warm {
            early_before += b;
            early_after += a;
        } else {
            before += b;
            after += a;
        }
    }

    let db = |b: f64, a: f64| 10.0 * (b / a.max(1e-30)).log10();
    println!(
        "  while converging, the first 0.5s: {:.1} dB removed",
        db(early_before, early_after)
    );
    println!("  once converged:                {:.1} dB removed", db(before, after));
    println!(
        "  the canceller's own estimate:  {:.1} dB",
        canceller.loss_db()
    );

    // --- is it the room, or is it the clocks ---
    //
    // The speaker and the microphone are different devices with independent
    // crystals, so the recording runs at a slightly different rate from the
    // playback. An adaptive filter converging on an impulse response that slides
    // a few samples a second is chasing a target that keeps moving.
    //
    // Separated by measuring again on windows short enough for the slide to be
    // nothing. If the canceller works over half a second and not over four, the
    // drift is the answer and the canceller is not broken. If it fails over both,
    // it is.
    println!("\n  the same, on short windows, each realigned:");
    let window = RATE / 2;
    let mut totals: Vec<f32> = Vec::new();
    let mut at = 0usize;
    while at + window * 2 < played.len().min(heard.len().saturating_sub(delay)) {
        let far = &played[at..at + window];
        let region_start = delay + at;
        let region_end = (region_start + window * 2).min(heard.len());
        if region_end <= region_start + window {
            break;
        }
        // Realigned inside this window, so whatever the clocks have drifted to
        // by now is taken out before the canceller sees it.
        let Some((local, _)) = best_delay(far, &heard[region_start..region_end]) else {
            at += window;
            continue;
        };
        let near_start = region_start + local;
        if near_start + window > heard.len() {
            break;
        }
        let near = &heard[near_start..near_start + window];

        let mut fresh = EchoCanceller::new();
        let mut b = 0.0f64;
        let mut a = 0.0f64;
        for (f, n2) in far.chunks(BLOCK).zip(near.chunks(BLOCK)) {
            if f.len() < BLOCK || n2.len() < BLOCK {
                break;
            }
            fresh.played(f);
            let cleaned = fresh.capture(n2);
            b += n2.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
            a += cleaned.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
        }
        totals.push(db(b, a) as f32);
        at += window;
    }

    if totals.is_empty() {
        println!("  not enough material for a short-window measurement");
    } else {
        let text: Vec<String> = totals.iter().map(|d| format!("{d:.1}")).collect();
        let mean = totals.iter().sum::<f32>() / totals.len() as f32;
        println!("  {} dB", text.join(", "));
        println!("  mean {mean:.1} dB over {} windows", totals.len());
    }
    println!();
}
