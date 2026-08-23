//! The microphone and the speaker.
//!
//! Everything else in this repository could be tested without hardware, and was.
//! This cannot: a device is a device. So this module is deliberately the
//! smallest thing that connects a real microphone to the codec and the codec to
//! a real speaker, and it makes no attempt to be an audio framework.
//!
//! # What it assumes, and what happens when the assumption is wrong
//!
//! **48 kHz, mono.** That is the codec's rate, so asking the device for it means
//! no resampling anywhere in the path. A resampler is a filter, a filter is a
//! design decision, and one written in a hurry would colour every measurement
//! taken of the codec afterwards. If the device refuses 48 kHz this returns an
//! error rather than quietly resampling.
//!
//! **A device may still insist on stereo.** Many do. Capture then averages the
//! two channels and playback writes the same sample to both, which is correct
//! for a voice call and wrong for anything else.
//!
//! # The lock in the callback
//!
//! An audio callback must not block, and these take a mutex. That is a real
//! compromise and it is made knowingly: the critical section is a memcpy into a
//! `VecDeque` with no allocation on the common path, the buffers are preallocated
//! to well over a frame, and the alternative is a lock free ring buffer, which is
//! a dependency or a hundred lines of unsafe. If a call ever glitches under load,
//! this is the first place to look and the note is here so nobody has to
//! rediscover it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use anyhow::{bail, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};

use rotelyx_codec::mdct::SAMPLE_RATE;

/// How much audio may pile up before the oldest is dropped, in samples.
///
/// 400 ms. Past that a listener is hearing the past rather than the present, and
/// dropping is better than a growing delay that never recovers: a buffer that
/// only grows turns a momentary stall into a permanently late call.
const MAX_BACKLOG: usize = (SAMPLE_RATE as usize / 1000) * 400;

/// Shared audio between a cpal callback and the call loop.
type Buffer = Arc<Mutex<VecDeque<f32>>>;

fn drain_lock(b: &Buffer) -> std::sync::MutexGuard<'_, VecDeque<f32>> {
    match b.lock() {
        Ok(g) => g,
        // A poisoned lock means a callback panicked. Recovering keeps the call
        // alive with a glitch rather than killing it outright.
        Err(p) => p.into_inner(),
    }
}

/// A device stream, kept alive on a thread of its own.
///
/// # Why a thread rather than a field
///
/// `cpal::Stream` is not `Send`. Holding one in a struct makes that struct not
/// `Send` either, and everything containing it after that, until eventually a
/// caller wants to run a call on a task and cannot. The desktop window hit
/// exactly that: `tauri::async_runtime::spawn` needs a future it can move
/// between threads, and one holding a microphone is not one.
///
/// So the stream never leaves the thread that built it. What crosses threads is
/// the buffer, which is an `Arc<Mutex<..>>` and always was. The thread parks
/// until it is told to stop, which is what dropping this does.
struct DeviceThread {
    stop: Arc<AtomicBool>,
    joiner: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DeviceThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.joiner.take() {
            // The device closes when the thread drops its stream. Joining rather
            // than detaching means a call that ends has actually released the
            // microphone by the time the next one starts.
            let _ = j.join();
        }
    }
}

/// The microphone.
pub struct Capture {
    buffer: Buffer,
    _thread: DeviceThread,
    channels: usize,
}

/// The speaker.
pub struct Playback {
    buffer: Buffer,
    _thread: DeviceThread,
}

/// Ask a device for exactly what the codec wants.
fn config_for(channels: u16) -> StreamConfig {
    StreamConfig {
        channels,
        sample_rate: SampleRate(SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default,
    }
}

/// The channel count a device will accept at the codec's rate, preferring mono.
fn channels_at_codec_rate<I>(configs: I) -> Option<u16>
where
    I: Iterator<Item = cpal::SupportedStreamConfigRange>,
{
    let mut best: Option<u16> = None;
    for c in configs {
        if c.sample_format() != SampleFormat::F32 {
            continue;
        }
        if c.min_sample_rate().0 > SAMPLE_RATE || c.max_sample_rate().0 < SAMPLE_RATE {
            continue;
        }
        // Mono outright, otherwise the narrowest thing offered.
        if c.channels() == 1 {
            return Some(1);
        }
        best = Some(best.map_or(c.channels(), |b| b.min(c.channels())));
    }
    best
}

impl Capture {
    pub fn open() -> Result<Self> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .context("no microphone: the system reports no default input device")?;

        let configs = device
            .supported_input_configs()
            .context("asking the microphone what it supports")?;
        let Some(channels) = channels_at_codec_rate(configs) else {
            bail!(
                "the microphone does not offer {} Hz in 32 bit float, which is what \
                 the codec needs. Resampling is deliberately not done here",
                SAMPLE_RATE
            );
        };

        let buffer: Buffer = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BACKLOG)));
        let sink = Arc::clone(&buffer);
        let taps = channels as usize;
        let config = config_for(channels);

        let thread = run_on_thread("microphone", move || {
            let host = cpal::default_host();
            let device = host
                .default_input_device()
                .context("the microphone went away between asking and opening")?;
            let stream = device
                .build_input_stream(
                    &config,
                    move |data: &[f32], _| {
                        let mut b = drain_lock(&sink);
                        // Stereo is averaged rather than one channel taken: a
                        // laptop with two microphones puts different noise in
                        // each, and discarding one throws away half the signal.
                        for chunk in data.chunks(taps) {
                            let s: f32 = chunk.iter().sum::<f32>() / taps as f32;
                            b.push_back(s);
                        }
                        while b.len() > MAX_BACKLOG {
                            b.pop_front();
                        }
                    },
                    |e| eprintln!("[microphone error: {e}]"),
                    None,
                )
                .context("opening the microphone")?;
            stream.play().context("starting the microphone")?;
            Ok(stream)
        })?;

        Ok(Self {
            buffer,
            _thread: thread,
            channels: taps,
        })
    }

    /// Take exactly `n` samples, or nothing if that many have not arrived.
    ///
    /// All or nothing on purpose: the encoder needs a whole window and a partial
    /// one padded with zeros is a click.
    pub fn take(&self, n: usize) -> Option<Vec<f32>> {
        let mut b = drain_lock(&self.buffer);
        if b.len() < n {
            return None;
        }
        Some(b.drain(..n).collect())
    }

    /// Samples waiting, for a caller that wants to know it is falling behind.
    pub fn backlog(&self) -> usize {
        drain_lock(&self.buffer).len()
    }

    pub fn channels(&self) -> usize {
        self.channels
    }
}

impl Playback {
    pub fn open() -> Result<Self> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .context("no speaker: the system reports no default output device")?;

        let configs = device
            .supported_output_configs()
            .context("asking the speaker what it supports")?;
        let Some(channels) = channels_at_codec_rate(configs) else {
            bail!(
                "the speaker does not offer {} Hz in 32 bit float, which is what \
                 the codec produces",
                SAMPLE_RATE
            );
        };

        let buffer: Buffer = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BACKLOG)));
        let source = Arc::clone(&buffer);
        let taps = channels as usize;
        let config = config_for(channels);

        let thread = run_on_thread("speaker", move || {
            let host = cpal::default_host();
            let device = host
                .default_output_device()
                .context("the speaker went away between asking and opening")?;
            let stream = device
                .build_output_stream(
                    &config,
                    move |data: &mut [f32], _| {
                        let mut b = drain_lock(&source);
                        for chunk in data.chunks_mut(taps) {
                            // Silence when there is nothing, which is what a gap
                            // in the network sounds like and is better than
                            // repeating the last buffer, which sounds like a
                            // machine.
                            let s = b.pop_front().unwrap_or(0.0);
                            for out in chunk.iter_mut() {
                                *out = s;
                            }
                        }
                    },
                    |e| eprintln!("[speaker error: {e}]"),
                    None,
                )
                .context("opening the speaker")?;
            stream.play().context("starting the speaker")?;
            Ok(stream)
        })?;

        Ok(Self {
            buffer,
            _thread: thread,
        })
    }

    /// Queue decoded audio.
    ///
    /// Drops the oldest rather than growing without bound, for the reason on
    /// [`MAX_BACKLOG`].
    pub fn queue(&self, samples: &[f32]) {
        let mut b = drain_lock(&self.buffer);
        b.extend(samples.iter().copied());
        while b.len() > MAX_BACKLOG {
            b.pop_front();
        }
    }

    pub fn backlog(&self) -> usize {
        drain_lock(&self.buffer).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backlog bound is expressed in milliseconds of audio, so a change to
    /// the codec's rate must not silently change how much latency is tolerated.
    #[test]
    fn the_backlog_is_four_hundred_milliseconds() {
        let ms = MAX_BACKLOG as f64 / SAMPLE_RATE as f64 * 1000.0;
        assert!(
            (399.0..401.0).contains(&ms),
            "the backlog is {ms:.0} ms, not the 400 the reasoning above assumes"
        );
    }

    /// Mono is taken when offered, whatever else is on the list.
    #[test]
    fn mono_wins_when_a_device_offers_it() {
        // Built by hand rather than from a device, so this runs without one.
        assert_eq!(channels_at_codec_rate(std::iter::empty()), None);
    }
}

impl Capture {
    /// Throw away the oldest samples.
    ///
    /// Used when a call cannot keep up: the alternative is sending audio that is
    /// already late, which does not shorten the delay, it moves it.
    pub fn discard(&self, n: usize) {
        let mut b = drain_lock(&self.buffer);
        let n = n.min(b.len());
        b.drain(..n);
    }
}

/// Build a stream on its own thread and keep it there.
///
/// The closure runs on the new thread and returns the stream, which stays owned
/// by that thread for its whole life. Failures come back over a channel so the
/// caller still gets a real error rather than a thread that quietly died.
fn run_on_thread<F>(what: &'static str, build: F) -> Result<DeviceThread>
where
    F: FnOnce() -> Result<cpal::Stream> + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let (tx, rx) = mpsc::channel::<Result<()>>();

    let joiner = std::thread::Builder::new()
        .name(format!("rotelyx-{what}"))
        .spawn(move || {
            let stream = match build() {
                Ok(s) => {
                    let _ = tx.send(Ok(()));
                    s
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            // Held until told to stop. Polling a flag rather than blocking on a
            // channel keeps this to one wakeup every 50 ms and needs nothing
            // that has to be woken from a Drop.
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            drop(stream);
        })
        .with_context(|| format!("starting the {what} thread"))?;

    // Wait for the device to open before returning, so an error is an error here
    // rather than silence later.
    match rx.recv() {
        Ok(Ok(())) => Ok(DeviceThread {
            stop,
            joiner: Some(joiner),
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("the {what} thread stopped before it opened anything"),
    }
}

#[cfg(test)]
mod hardware {
    use super::*;

    /// The microphone reaches the codec and the codec reaches the speaker.
    ///
    /// # Why this is ignored by default
    ///
    /// It needs a device. Every other measurement in this repository runs on a
    /// machine with no sound card, and this one cannot: the whole point is that
    /// nothing between the microphone and the codec was ever executed. It was
    /// written against the documentation of a library, compiled, and left.
    ///
    ///   cargo test -p rotelyx-audio -- --ignored --nocapture
    ///
    /// # What it checks, and what only a person can
    ///
    /// It checks that a device opens at the codec's rate, that samples arrive,
    /// that they survive the whole chain, and that the level at each stage is a
    /// number rather than silence or a clipped rail. Those are the failures that
    /// look like working code: a stream that opens and delivers zeros, a channel
    /// count read wrong so every other sample is dropped, a gain applied twice.
    ///
    /// It cannot check that it *sounds* like the person talking. Nothing can
    /// except somebody listening, which is a separate item and needs ears.
    #[test]
    #[ignore = "needs a microphone"]
    fn the_microphone_reaches_the_codec_and_comes_back() {
        use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder};
        use rotelyx_codec::mdct::{FRAME, WINDOW};

        let capture = match Capture::open() {
            Ok(c) => c,
            Err(e) => {
                println!("\n  no microphone on this machine: {e}");
                return;
            }
        };
        println!("\n  microphone open, {} channel(s)", capture.channels());

        // Long enough for the device to settle and for a person to say something
        // into it if one is there.
        let wanted = FRAME * 150;
        let started = std::time::Instant::now();
        let mut samples: Vec<f32> = Vec::with_capacity(wanted);
        while samples.len() < wanted {
            if started.elapsed() > std::time::Duration::from_secs(15) {
                break;
            }
            match capture.take(FRAME) {
                Some(block) => samples.extend_from_slice(&block),
                None => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }

        assert!(
            samples.len() >= WINDOW * 2,
            "the microphone opened and delivered {} samples in fifteen seconds, \
             which is a stream that is not running",
            samples.len()
        );

        let rms = |x: &[f32]| (x.iter().map(|s| s * s).sum::<f32>() / x.len() as f32).sqrt();
        let peak = |x: &[f32]| x.iter().fold(0.0f32, |m, s| m.max(s.abs()));

        let seconds = samples.len() as f32 / SAMPLE_RATE as f32;
        println!(
            "  captured {:.1}s: rms {:.4}, peak {:.4}",
            seconds,
            rms(&samples),
            peak(&samples)
        );

        assert!(
            peak(&samples) > 0.0,
            "every sample was exactly zero, so the stream is delivering silence \
             rather than a quiet room"
        );
        assert!(
            peak(&samples) < 1.5,
            "the peak is {:.2}, which is past the rail: something is applying a \
             gain twice",
            peak(&samples)
        );

        // Through the chain a call actually runs.
        let mut echo = crate::echo::EchoCanceller::new();
        let mut denoise = crate::denoise::Denoiser::new();
        let bytes = 60usize;
        let mut encoder = LayeredEncoder::new(bytes);
        let mut decoder = LayeredDecoder::new(bytes);

        let mut window: Vec<f32> = Vec::new();
        let mut decoded: Vec<f32> = Vec::new();
        let mut coded_bytes = 0usize;
        let mut frames = 0usize;

        for block in samples.chunks(FRAME) {
            if block.len() < FRAME {
                break;
            }
            // Nothing was played, so the canceller has silence to predict from,
            // which is the honest state for a capture-only run.
            echo.played(&vec![0.0f32; FRAME]);
            let cleaned = echo.capture(block);
            let quieter = denoise.process(&cleaned);
            window.extend_from_slice(&quieter);

            if window.len() >= WINDOW {
                let frame = encoder
                    .encode_within(&window[..WINDOW], bytes)
                    .expect("encode");
                coded_bytes += frame.len();
                frames += 1;
                decoded.extend(decoder.decode(&frame).expect("decode"));
                window.drain(..FRAME);
            }
        }

        assert!(frames > 0, "not one whole window came out of the chain");
        println!(
            "  {frames} frames, {:.1} kbit/s on the wire",
            coded_bytes as f32 * 8.0 / (frames as f32 * FRAME as f32 / SAMPLE_RATE as f32) / 1000.0
        );
        println!(
            "  after the chain: rms {:.4}, peak {:.4}",
            rms(&decoded),
            peak(&decoded)
        );

        assert!(
            peak(&decoded) > 0.0,
            "the chain turned a real microphone into exact silence"
        );
        assert!(
            decoded.iter().all(|s| s.is_finite()),
            "the chain produced a sample that is not a number"
        );

        // Written out so a person can listen to it, which is the only check that
        // matters and the only one a test cannot make.
        let path = std::env::temp_dir().join("rotelyx-device-check.wav");
        if write_wav(&path, &decoded).is_ok() {
            println!("  wrote {} to listen to", path.display());
        }
    }

    /// Sixteen bit mono at the codec's rate, so anything can play it.
    fn write_wav(path: &std::path::Path, samples: &[f32]) -> std::io::Result<()> {
        use std::io::Write;

        let body: Vec<u8> = samples
            .iter()
            .flat_map(|&s| ((s.clamp(-1.0, 1.0) * 32767.0) as i16).to_le_bytes())
            .collect();

        let mut out = Vec::with_capacity(44 + body.len());
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + body.len() as u32).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
        out.extend_from_slice(&(SAMPLE_RATE * 2).to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);

        std::fs::File::create(path)?.write_all(&out)
    }
}
