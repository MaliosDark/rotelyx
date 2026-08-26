//! A call, end to end, that you can listen to.
//!
//! Every piece of this has been tested on its own and the pieces had never been
//! joined: the codec had no consumer, `rotelyx-media` had no application, and
//! no binary anywhere in this repository made a call. This is that binary.
//!
//! ```sh
//! cargo run --release -p rotelyx-media --example call -- <in.wav> <out.wav> [loss%]
//! ```
//!
//! What it does not include, and why:
//!
//! **No microphone and no speaker.** Audio comes from a file and goes to a
//! file, so the run is deterministic and so it needs no hardware. Device
//! capture is a separate problem that cannot be solved without a device.
//!
//! **No QUIC hop.** The datagrams pass through an in-process network that
//! drops, delays and reorders them. The real transport is tested separately;
//! what had never been tested is the codec meeting the media layer, and putting
//! a socket in the middle would only make the failures harder to read.

use rotelyx_codec::mdct::{FRAME, WINDOW};
use rotelyx_codec::{TelyxDecoder, TelyxEncoder};
use rotelyx_media::transport::{MediaIn, MediaOut};
use rotelyx_media::{Mode, Playout};
use rotelyx_media::SenderKeys;
use rotelyx_path::PathPolicy;
use std::collections::VecDeque;

/// A fixed binding, for the cases that are not about the binding itself.
fn test_call() -> rotelyx_media::CallBinding {
    rotelyx_media::CallBinding::new(b"a-test-call-0001").expect("long enough")
}


const BYTES_PER_FRAME: usize = 60; // 24 kbit/s
const FRAME_MS: u64 = 20;

fn read_wav(path: &str) -> Result<Vec<f32>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(format!("{path} is not a WAV"));
    }
    let (mut at, mut fmt, mut data) = (12usize, None, None);
    while at + 8 <= bytes.len() {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        let body = at + 8;
        if body + size > bytes.len() {
            break;
        }
        match id {
            b"fmt " if size >= 16 => {
                fmt = Some((
                    u16::from_le_bytes(bytes[body + 2..body + 4].try_into().unwrap()),
                    u32::from_le_bytes(bytes[body + 4..body + 8].try_into().unwrap()),
                    u16::from_le_bytes(bytes[body + 14..body + 16].try_into().unwrap()),
                ));
            }
            b"data" => data = Some(&bytes[body..body + size]),
            _ => {}
        }
        at = body + size + (size & 1);
    }
    let (channels, rate, bits) = fmt.ok_or("no fmt chunk")?;
    if channels != 1 || rate != 48_000 || bits != 16 {
        return Err(format!(
            "{path} is {channels}ch {rate}Hz {bits}bit; this needs mono 48000 16"
        ));
    }
    Ok(data
        .ok_or("no data chunk")?
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
        .collect())
}

fn write_wav(path: &str, samples: &[f32]) -> std::io::Result<()> {
    let n = samples.len() * 2;
    let mut out = Vec::with_capacity(44 + n);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((36 + n) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&48_000u32.to_le_bytes());
    out.extend_from_slice(&96_000u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for s in samples {
        out.extend_from_slice(&((s.clamp(-1.0, 1.0) * 32767.0) as i16).to_le_bytes());
    }
    std::fs::write(path, out)
}

/// A network that is not a function call.
///
/// Drops at a fixed rate, delays everything by a round trip, and delivers out
/// of order, because a receiver that only ever sees frames in order is a
/// receiver whose reordering path has never run.
struct Wire {
    loss_percent: u64,
    in_flight: VecDeque<(u64, Vec<u8>)>,
    seed: u64,
}

impl Wire {
    fn new(loss_percent: u64) -> Self {
        Self {
            loss_percent,
            in_flight: VecDeque::new(),
            seed: 0x2545_f491_4f6c_dd1d,
        }
    }

    fn roll(&mut self) -> u64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed
    }

    fn send(&mut self, now_ms: u64, datagram: Vec<u8>) {
        if self.roll() % 100 < self.loss_percent {
            return;
        }
        // 30 ms one way, plus up to 25 ms of jitter, which is enough to put
        // frames out of order at a 20 ms spacing.
        let arrival = now_ms + 30 + self.roll() % 25;
        self.in_flight.push_back((arrival, datagram));
    }

    fn deliver(&mut self, now_ms: u64) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut keep = VecDeque::new();
        while let Some((at, d)) = self.in_flight.pop_front() {
            if at <= now_ms {
                out.push((at, d));
            } else {
                keep.push_back((at, d));
            }
        }
        self.in_flight = keep;
        out
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: call <in.wav> <out.wav> [loss%] [fidelity]");
        eprintln!("  the input must be mono, 48 kHz, 16 bit");
        std::process::exit(2);
    }
    let loss: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let fidelity = args.get(4).map(|s| s == "fidelity").unwrap_or(false);
    let mode = if fidelity { Mode::Fidelity } else { Mode::Conversational };

    let audio = match read_wav(&args[1]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // Both sides derive their keys from the same conversation secret, which in
    // a real call comes from the MLS group rather than from a constant.
    let base = [0x42u8; 32];
    let mut out = MediaOut::with_mode(
        PathPolicy::RelayOnly,
        SenderKeys::derive(&base, 0, &test_call()),
        mode,
    )
    .expect("sender");
    let mut inbound = MediaIn::with_mode(
        PathPolicy::RelayOnly,
        SenderKeys::derive(&base, 0, &test_call()),
        mode,
    )
    .expect("receiver");

    let mut encoder = TelyxEncoder::new(BYTES_PER_FRAME);
    let mut decoder = TelyxDecoder::new(BYTES_PER_FRAME);
    let mut wire = Wire::new(loss);

    let mut heard: Vec<f32> = Vec::new();
    let (mut sent, mut played, mut concealed) = (0u64, 0u64, 0u64);
    let mut now_ms = 0u64;

    let windows: Vec<&[f32]> = (0..audio.len().saturating_sub(WINDOW))
        .step_by(FRAME)
        .map(|s| &audio[s..s + WINDOW])
        .collect();

    // Runs past the end of the audio so the buffer drains, and stops as soon as
    // it has: counting the trailing silence as concealment would report 96 gaps
    // on a link with no loss at all, which is what the first version did.
    let mut idle = 0u32;
    for tick in 0..windows.len() + 200 {
        now_ms = tick as u64 * FRAME_MS;
        if tick >= windows.len() && wire.in_flight.is_empty() && idle > 3 {
            break;
        }

        if let Some(window) = windows.get(tick) {
            let packet = encoder.encode(window).expect("encode");
            let datagram = out.frame(&packet).expect("protect");
            wire.send(now_ms, datagram);
            sent += 1;
        }

        for (arrival, datagram) in wire.deliver(now_ms) {
            inbound.accept(&datagram, arrival);
        }

        // Fidelity mode asks for what it is missing. Conversational does not,
        // because a frame recovered after its slot has played is a frame that
        // delays everything behind it for nothing.
        if fidelity {
            for counter in inbound.to_recover_between(out.oldest_recoverable(), sent.saturating_sub(1)) {
                if let Some(again) = out.resend(counter) {
                    wire.send(now_ms, again);
                }
            }
        }

        match inbound.play() {
            Playout::Frame(packet) => {
                heard.extend(decoder.decode(&packet).expect("decode"));
                played += 1;
                idle = 0;
            }
            Playout::Missing => {
                // Conversational mode does not wait. Silence is a poor
                // concealment and an honest one: this is where packet loss
                // concealment goes, and it is not built.
                heard.extend(std::iter::repeat_n(0.0, FRAME));
                concealed += 1;
                idle += 1;
            }
            Playout::Waiting | Playout::Starved => idle += 1,
        }
    }

    if let Err(e) = write_wav(&args[2], &heard) {
        eprintln!("writing {}: {e}", args[2]);
        std::process::exit(1);
    }

    let seconds = heard.len() as f32 / 48_000.0;
    println!();
    println!("  {} -> {}", args[1], args[2]);
    println!(
        "  {loss}% loss, 30 ms each way plus up to 25 ms of jitter, {} mode",
        if fidelity { "fidelity" } else { "conversational" }
    );
    println!();
    println!("  frames sent        {sent}");
    println!("  frames played      {played}");
    println!("  gaps concealed     {concealed}");
    println!("  buffer depth       {} ms", inbound.delay_ms());
    println!("  dropped too late   {}", inbound.dropped());
    println!("  audio out          {seconds:.1} s");
    println!();
    println!("  Listen to both. That is the only thing that settles it.");
}
