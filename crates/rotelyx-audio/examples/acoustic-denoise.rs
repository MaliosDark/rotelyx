//! What the noise suppressor removes from a real room.
//!
//! Driven by `scripts/measure-denoise`, which does the recording.
//!
//! # The two numbers that have to be read together
//!
//! A suppressor tuned by how much noise it removes removes the voice too: the
//! quietest possible output is silence. So this reports both, always, and a
//! reader who takes one without the other has learned nothing:
//!
//! - how much quieter the **gaps between words** are, which is the noise
//! - how much of the **speech** is still there, which is the cost
//!
//! Where the gaps are is not guessed from the recording. It is read off the
//! reference that was played, aligned to the recording first, so a suppressor
//! that removed the speech cannot move the boundary and flatter itself.
//!
//! # The control
//!
//! A harness that reports no suppression is indistinguishable from a suppressor
//! that does none, which is the mistake `docs/ECHO.md` was written to avoid
//! repeating. So the same code path runs first against synthetic hiss added to
//! the same clip, which is the condition `steady_noise_is_reduced` measures 8 dB
//! under. If that comes out near nothing, the fault is here.

use std::env;

use rotelyx_audio::denoise::Denoiser;

#[path = "common/mod.rs"]
mod common;
use common::{best_delay, db, energy, read_wav, RATE};

const BLOCK: usize = 960;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: acoustic-denoise <played.wav> <heard.wav>");
        std::process::exit(2);
    }

    let played = read_wav(&args[1]);
    let heard = read_wav(&args[2]);

    // --- the control ---
    {
        let mut state = 0x1357_9bdfu32;
        let noisy: Vec<f32> = played
            .iter()
            .map(|s| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                s + 0.05 * ((state as f32 / u32::MAX as f32) * 2.0 - 1.0)
            })
            .collect();
        let cleaned = run(&noisy);
        let (noise_db, speech_kept) = compare(&played, &noisy, &cleaned);
        println!(
            "\n  control, hiss added to the clip: {noise_db:.1} dB off the gaps, \
             {:.0}% of the speech kept",
            speech_kept * 100.0
        );
    }

    // --- the room ---
    let Some((delay, correlation)) = best_delay(&played, &heard) else {
        println!("  the microphone did not hear the speaker at all.");
        std::process::exit(1);
    };
    println!(
        "  the speaker reaches the microphone {:.0} ms later, correlation {:.2}",
        delay as f32 * 1000.0 / RATE as f32,
        correlation
    );

    // What a gap in a room actually contains.
    //
    // A suppressor's job is stationary noise. A room's gaps are not only that:
    // they carry the reverberant tail of the speech that just stopped, which is
    // neither stationary nor noise, and a suppressor that removed it would be
    // removing the room's own answer to the voice. Measuring "energy in the
    // gaps" without separating the two would charge the suppressor for work it
    // should not do.
    if args.len() > 3 {
        let quiet = read_wav(&args[3]);
        if quiet.len() > RATE / 2 {
            println!(
                "  the room with nothing playing:   {:.5} rms",
                energy(&quiet).sqrt()
            );
        }
    }

    let aligned: Vec<f32> = heard[delay.min(heard.len())..].to_vec();
    let n = aligned.len().min(played.len());
    if n < BLOCK * 20 {
        println!("  too short to measure: {n} samples aligned");
        std::process::exit(1);
    }

    let room = &aligned[..n];
    let cleaned = run(room);
    let (noise_db, speech_kept) = compare(&played[..n], room, &cleaned);

    println!(
        "  the room:                        {noise_db:.1} dB off the gaps, \
         {:.0}% of the speech kept",
        speech_kept * 100.0
    );

    // And how much of those gaps was noise at all.
    if args.len() > 3 {
        let quiet = read_wav(&args[3]);
        if quiet.len() > RATE / 2 {
            let floor = energy(&quiet);
            let in_gaps = gap_energy(&played[..n], room);
            println!(
                "  the gaps are {:.1} dB above the quiet room, so most of what is in\n  \
                 them is the tail of the speech rather than noise. A suppressor that\n  \
                 removed that would be removing the room's answer to the voice.",
                db(in_gaps, floor)
            );
        }
    }
    println!();
}

/// Energy in the blocks the reference says are gaps.
fn gap_energy(reference: &[f32], signal: &[f32]) -> f64 {
    let n = reference.len().min(signal.len());
    let quiet_enough = energy(&reference[..n]) * 0.01;
    let mut total = 0.0f64;
    let mut blocks = 0usize;
    for at in (0..n.saturating_sub(BLOCK)).step_by(BLOCK) {
        let block = at..at + BLOCK;
        if energy(&reference[block.clone()]) < quiet_enough {
            total += energy(&signal[block]);
            blocks += 1;
        }
    }
    if blocks == 0 {
        0.0
    } else {
        total / blocks as f64
    }
}

fn run(input: &[f32]) -> Vec<f32> {
    let mut denoiser = Denoiser::new();
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(BLOCK) {
        out.extend(denoiser.process(chunk));
    }
    out
}

/// Noise removed from the gaps, and the fraction of speech energy left.
///
/// `reference` decides which blocks are speech and which are gaps. It is the
/// clean signal that was played, so the decision cannot be influenced by what
/// the suppressor did.
fn compare(reference: &[f32], before: &[f32], after: &[f32]) -> (f64, f64) {
    let n = reference.len().min(before.len()).min(after.len());

    // A block is a gap when the reference is well below its own average.
    let loud: f64 = energy(&reference[..n]);
    let quiet_enough = loud * 0.01;

    let (mut gap_before, mut gap_after, mut gaps) = (0.0f64, 0.0f64, 0usize);
    let (mut speech_before, mut speech_after) = (0.0f64, 0.0f64);

    for at in (0..n.saturating_sub(BLOCK)).step_by(BLOCK) {
        let block = at..at + BLOCK;
        if energy(&reference[block.clone()]) < quiet_enough {
            gap_before += energy(&before[block.clone()]);
            gap_after += energy(&after[block]);
            gaps += 1;
        } else {
            speech_before += energy(&before[block.clone()]);
            speech_after += energy(&after[block]);
        }
    }

    if gaps == 0 {
        // Nothing to measure the noise in, which is worth saying rather than
        // dividing by zero and printing an impressive number.
        return (0.0, speech_after / speech_before.max(1e-30));
    }
    (
        db(gap_before, gap_after),
        speech_after / speech_before.max(1e-30),
    )
}
