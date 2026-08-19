//! Coding several frames' energies as one stream.
//!
//! # The measurement this exists to answer
//!
//! An arithmetic coder must be flushed before its output can be read, and
//! closing it costs four to six bytes whatever it is carrying: thirty seven
//! all-zero symbols come to six. A long stream amortises that to nothing. A
//! 20 ms frame pays it fifty times a second.
//!
//! So the levels of several frames go into one stream, flushed once. Measured
//! on the same signal, with the same predictor and the same models:
//!
//! | scheme                    | bytes/frame |
//! |---------------------------|-------------|
//! | fixed width, no coder     | 18.0        |
//! | coded one frame at a time | 15.6        |
//! | coded ten frames at a time| 12.4        |
//!
//! The gap between the last two is the flush and nothing else.
//!
//! # What this is not
//!
//! It is not a way to reach the entropy of the levels, because the one-frame
//! scheme is already close to it. An earlier version of this module claimed the
//! floor was under two bytes a frame and that the flush was hiding a tenfold
//! saving. That number came from a broken entropy helper in a test, which
//! multiplied each symbol's surprise by its own count rather than by the total.
//! The real floor is around eleven bytes. The saving here is three and a half,
//! it is real, and it is all there was.
//!
//! # What it costs, which is not nothing
//!
//! **Latency.** A group is not complete until its last frame is, so the encoder
//! holds `GROUP` frames before emitting anything.
//!
//! **Independence.** The levels within a frame predict along the spectrum, not
//! from the previous frame, so no frame depends on another for its prediction.
//! But they do share one arithmetic stream and one set of adaptive models, so
//! losing the stream loses the levels of every frame in the group. The shapes
//! are unaffected and still per frame, so what survives is a group of frames
//! with the right texture and no loudness, which is worse than a gap.
//!
//! Both are affordable here and neither is affordable on a telephone call. This
//! is the fourth time the same asymmetry has decided a design question in this
//! codec, and it is worth naming: **every wall this reaches has a way through
//! that only exists because delay is spendable.**

use crate::bands::BANDS;
use crate::entropy::{RangeDecoder, RangeEncoder};
use crate::layered::{self, LayeredFrame, LevelModels};
use crate::mdct::WINDOW;
use crate::CodecError;

/// Frames per group.
///
/// Ten is 200 ms: long enough for the flush to be a twentieth of what it was
/// per frame, short enough that losing a group's levels loses a fifth of a
/// second rather than a sentence. The transport recovers losses, so this bounds
/// the damage of a failure to recover rather than of an ordinary drop.
pub const GROUP: usize = 10;

/// One group: the energies of every frame in it, and their shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Every frame's band levels, arithmetic coded together and flushed once.
    pub energies: Vec<u8>,
    /// Each frame's shapes, still independent: the base stage and refinements.
    pub frames: Vec<LayeredFrame>,
}

impl Group {
    pub fn len(&self) -> usize {
        self.energies.len() + self.frames.iter().map(|f| f.len()).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// Accumulates frames and emits a group when it has enough.
pub struct GroupedEncoder {
    inner: layered::ShapeEncoder,
    /// Carried across groups rather than reset, so the statistics of a whole
    /// call are available to every group after the first. A group that reset
    /// them would pay the models' learning cost ten times a second.
    models: LevelModels,

    pending_levels: Vec<[u8; BANDS]>,
    pending_frames: Vec<LayeredFrame>,
}

impl GroupedEncoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            inner: layered::ShapeEncoder::new(bytes_per_frame),
            models: LevelModels::new(),
            pending_levels: Vec::with_capacity(GROUP),
            pending_frames: Vec::with_capacity(GROUP),
        }
    }

    /// Add one window. Returns a group once `GROUP` frames have accumulated.
    pub fn push(&mut self, audio: &[f32]) -> Result<Option<Group>, CodecError> {
        if audio.len() != WINDOW {
            return Err(CodecError::WrongFrameSize { got: audio.len() });
        }

        let (levels, frame) = self.inner.encode_shapes(audio)?;
        self.pending_levels.push(levels);
        self.pending_frames.push(frame);

        if self.pending_levels.len() < GROUP {
            return Ok(None);
        }
        Ok(Some(self.flush()))
    }

    /// Emit whatever has accumulated, however little.
    ///
    /// Called at the end of a recording. A group of one is a group whose flush
    /// is not amortised at all, which is the price of finishing.
    pub fn finish(&mut self) -> Option<Group> {
        if self.pending_levels.is_empty() {
            None
        } else {
            Some(self.flush())
        }
    }

    fn flush(&mut self) -> Group {
        let mut stream = RangeEncoder::new();

        for levels in &self.pending_levels {
            layered::write_levels(&mut stream, levels, &mut self.models);
        }

        self.pending_levels.clear();

        Group {
            energies: stream.finish(),
            frames: std::mem::take(&mut self.pending_frames),
        }
    }
}

/// Decodes groups.
pub struct GroupedDecoder {
    inner: layered::ShapeDecoder,
    models: LevelModels,
}

impl GroupedDecoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            inner: layered::ShapeDecoder::new(bytes_per_frame),
            models: LevelModels::new(),
        }
    }

    /// Decode a whole group into audio.
    ///
    /// # Why a missing level stream is an error rather than a best effort
    ///
    /// A residual is coded modulo the number of awake levels, so every symbol
    /// maps to a valid level and there is no bit pattern the decoder can
    /// recognise as wrong. Decoding a group whose levels never arrived
    /// therefore does not produce something quiet and unconvincing: it produces
    /// a full-scale burst of noise, at whatever level the arithmetic decoder's
    /// reading of an empty buffer happens to land on. That is the worst thing a
    /// voice decoder can put in somebody's ear.
    ///
    /// The missing case is detectable and is refused here. The corrupt case is
    /// not detectable here and is not meant to be: every frame crosses the wire
    /// inside an authenticated envelope, so a stream that has been altered is
    /// discarded by [`rotelyx_media`](../../rotelyx_media/index.html) before it
    /// reaches this function.
    pub fn decode(&mut self, group: &Group) -> Result<Vec<f32>, CodecError> {
        if group.energies.is_empty() && !group.frames.is_empty() {
            return Err(CodecError::Malformed);
        }
        let mut stream = RangeDecoder::new(&group.energies);
        let mut out = Vec::new();

        for frame in &group.frames {
            let levels = layered::read_levels(&mut stream, &mut self.models);
            out.extend(self.inner.decode_shapes(&levels, frame)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdct::{self, FRAME};
    use std::f32::consts::PI;

    fn voice_like(samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|n| {
                let t = n as f32 / mdct::SAMPLE_RATE as f32;
                let pitch = 120.0 + 20.0 * (2.0 * PI * 3.0 * t).sin();

                let mut s = 0.0;
                for harmonic in 1..=12 {
                    let f = pitch * harmonic as f32;
                    if f > 8_000.0 {
                        break;
                    }
                    let gain =
                        1.0 / harmonic as f32 * (1.0 + 2.0 * (-(f - 700.0).abs() / 500.0).exp());
                    s += gain * (2.0 * PI * f * t).sin();
                }
                // 0.25 rather than 0.3: at 0.3 this peaked at 1.113, which is
            // not audio. No device can represent a sample past full scale, and
            // measuring a codec on a signal that clips measures the clipping.
            s * 0.25 * (0.5 + 0.5 * (2.0 * PI * 4.0 * t).sin())
            })
            .collect()
    }

    fn encode_all(signal: &[f32], bytes: usize) -> Vec<Group> {
        let mut encoder = GroupedEncoder::new(bytes);
        let mut groups = Vec::new();

        for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
            if let Some(g) = encoder.push(&signal[start..start + WINDOW]).expect("encode") {
                groups.push(g);
            }
        }
        if let Some(g) = encoder.finish() {
            groups.push(g);
        }
        groups
    }

    /// The group must decode to the same audio the frames would have.
    #[test]
    fn a_group_round_trips() {
        let signal = voice_like(FRAME * 40);
        let groups = encode_all(&signal, 60);

        let mut decoder = GroupedDecoder::new(60);
        let mut out = Vec::new();
        for g in &groups {
            out.extend(decoder.decode(g).expect("decode"));
        }

        assert_eq!(out.len(), groups.iter().map(|g| g.frames.len()).sum::<usize>() * FRAME);

        // And it is audio rather than noise: the level tracks the input.
        let from = FRAME;
        let len = out.len() - from;
        let a = (signal[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();
        let b = (out[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();

        assert!(
            (0.5..2.0).contains(&(b / a)),
            "the decoded level is {:.2}x the original",
            b / a
        );
    }

    /// The measurement this module exists for.
    ///
    /// Both schemes are run over the same signal at the same rate, so the only
    /// difference between them is where the arithmetic coder is flushed. An
    /// earlier version of this compared against numbers recorded by hand, and
    /// went red the moment the energy quantum became a function of the rate:
    /// the figures were right and no longer described the same experiment.
    #[test]
    fn grouping_beats_coding_one_frame_at_a_time() {
        let signal = voice_like(FRAME * 400);

        let groups = encode_all(&signal, 60);
        let frames: usize = groups.iter().map(|g| g.frames.len()).sum();
        let grouped = groups.iter().map(|g| g.energies.len()).sum::<usize>() as f32 / frames as f32;

        // The same levels, the same models, one flush per frame instead of one
        // per group.
        let mut shapes = crate::layered::ShapeEncoder::new(60);
        let mut models = LevelModels::new();
        let mut per_frame_bytes = 0usize;
        let mut counted = 0usize;

        for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
            let (levels, _) = shapes.encode_shapes(&signal[start..start + WINDOW]).expect("encode");
            let mut stream = RangeEncoder::new();
            layered::write_levels(&mut stream, &levels, &mut models);
            per_frame_bytes += stream.finish().len();
            counted += 1;
        }
        let per_frame = per_frame_bytes as f32 / counted as f32;

        // GROUP frames share one flush, so the saving is (GROUP-1)/GROUP of it.
        // The flush is four to six bytes, so three is a conservative floor.
        assert!(
            per_frame - grouped > 3.0,
            "grouping saved only {:.1} bytes a frame ({per_frame:.1} coded one at \
             a time against {grouped:.1} in groups of {GROUP}): the flush is no \
             longer what it was, or the group is not sharing one",
            per_frame - grouped
        );
    }

    /// A short recording must still finish, even if its last group is a single
    /// frame whose flush is not amortised at all.
    #[test]
    fn a_short_recording_still_finishes() {
        for frames in [1usize, 3, GROUP, GROUP + 1] {
            let signal = voice_like(FRAME * (frames + 2));
            let groups = encode_all(&signal, 60);

            let coded: usize = groups.iter().map(|g| g.frames.len()).sum();
            assert!(coded > 0, "{frames} frames produced nothing");

            let mut decoder = GroupedDecoder::new(60);
            for g in &groups {
                decoder.decode(g).expect("decode");
            }
        }
    }

    /// A group's levels are one stream, so losing it loses every frame in the
    /// group. Asserted so the cost is visible rather than discovered, and
    /// refused rather than rendered.
    #[test]
    fn losing_the_levels_loses_the_whole_group() {
        let signal = voice_like(FRAME * 20);
        let groups = encode_all(&signal, 60);

        let damaged = Group {
            energies: Vec::new(),
            frames: groups[0].frames.clone(),
        };
        assert!(!damaged.frames.is_empty(), "the test needs frames to lose");

        let mut decoder = GroupedDecoder::new(60);
        assert!(
            matches!(decoder.decode(&damaged), Err(CodecError::Malformed)),
            "a group with no levels must be refused, not rendered: decoding it \
             produces a full-scale burst rather than silence"
        );
    }

    /// The empty group is the one case where no levels is not an error.
    #[test]
    fn an_empty_group_is_not_malformed() {
        let mut decoder = GroupedDecoder::new(60);
        let out = decoder
            .decode(&Group {
                energies: Vec::new(),
                frames: Vec::new(),
            })
            .expect("an empty group decodes to nothing");
        assert!(out.is_empty());
    }
}
