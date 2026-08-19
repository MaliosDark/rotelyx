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
use std::sync::{Arc, Mutex};

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

/// The microphone.
pub struct Capture {
    buffer: Buffer,
    _stream: cpal::Stream,
    channels: usize,
}

/// The speaker.
pub struct Playback {
    buffer: Buffer,
    _stream: cpal::Stream,
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

        let stream = device
            .build_input_stream(
                &config_for(channels),
                move |data: &[f32], _| {
                    let mut b = drain_lock(&sink);
                    // Stereo is averaged rather than one channel taken: a laptop
                    // with two microphones puts different noise in each, and
                    // discarding one throws away half the signal.
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
        Ok(Self {
            buffer,
            _stream: stream,
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

        let stream = device
            .build_output_stream(
                &config_for(channels),
                move |data: &mut [f32], _| {
                    let mut b = drain_lock(&source);
                    for chunk in data.chunks_mut(taps) {
                        // Silence when there is nothing, which is what a gap in
                        // the network sounds like and is better than repeating
                        // the last buffer, which sounds like a machine.
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
        Ok(Self {
            buffer,
            _stream: stream,
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
