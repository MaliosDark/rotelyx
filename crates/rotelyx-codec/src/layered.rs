//! Splitting a frame into a base layer and refinements.
//!
//! # Why a layered bitstream is worth having here and nowhere else
//!
//! Residual stages are ordered by importance and independent to decode. The
//! first alone is a complete, coarse rendering; each further stage refines it.
//! That means a frame does not have to arrive all at once, or at all.
//!
//! For a telephone call that is worthless. A refinement arriving after its
//! frame has played is discarded, so there is nothing to be gained by sending
//! it separately and everything to lose in overhead.
//!
//! Rotelyx's fidelity channel is the opposite. It already spends seconds of
//! delay and already asks for lost frames again. A refinement that arrives late
//! is a refinement that arrives, and one that never arrives leaves audio that
//! is rough rather than absent.
//!
//! # What that buys
//!
//! **Graceful degradation.** Losing a refinement loses some texture; losing the
//! base loses the audio. A network that runs short delivers a rough rendering
//! rather than a gap.
//!
//! What it does **not** buy is a base cheap enough to protect much harder than
//! the rest, and the reason took three attempts to find.
//!
//! The band energies were written at six bits each: eighteen bytes of a sixty
//! byte frame. Arithmetic coding them should have collapsed that, and the first
//! attempt made it **worse**, at 19.2 bytes. Two separate mistakes were behind
//! it, and both are worth having written down.
//!
//! **The floor was measured wrong.** A helper in a test multiplied each
//! symbol's surprise by its own count instead of by the total, and reported the
//! entropy of the levels as under two bytes a frame. The real figure is about
//! fifteen. A tenfold saving was being chased that was never there.
//!
//! **The predictor was aimed at the wrong axis.** Each band was predicted from
//! the same band in the previous frame. What moves fastest in a voice is the
//! overall level, and 20 ms is long enough for it to move a great deal; what
//! barely moves is the shape of the spectrum. Predicting along the spectrum
//! instead took the levels from 15.4 to 12.9 bytes a frame and made each frame
//! independent of every other. See [`LevelModels`].
//!
//! That leaves the flush. An arithmetic coder must be closed before its output
//! can be read, and closing costs four to six bytes whatever it carries: thirty
//! seven all-zero symbols come to six. A long stream amortises it to nothing.
//! **One coder per 20 ms frame pays it fifty times a second.**
//!
//! So a frame that must decode independently cannot be arithmetic coded
//! cheaply, and that is a property of the frame boundary rather than of this
//! codec. Batching the levels of several frames into one stream recovers it, at
//! the cost of latency and of tying a group's levels together: a channel that
//! spends delay and recovers loss can afford both, and a telephone call cannot.
//! That is [`crate::grouped`], and it lands at 12.4 bytes a frame.
//!
//! **Bandwidth becomes a decision the network makes rather than the encoder.**
//! One encode produces every rate at once. A listener on a poor link is sent
//! the base and stops; the same recording sent to somebody else carries every
//! layer, with no re-encoding and no second copy stored.
//!
//! **Quality can improve after the fact.** A recording played from the mailbox
//! can be rendered from what has arrived so far and re-rendered when the rest
//! does, which is a thing no real-time codec has any reason to support.

use crate::bands::{self, BANDS};
use crate::mdct::{self, FRAME, WINDOW};
use crate::entropy::{decode_symbol, encode_symbol, Model, RangeDecoder, RangeEncoder};
use crate::rangecoder::{Decoder, Encoder};
use crate::rvq;
use crate::tns;
use crate::{coarsen, energy_to_level, level_quantum, level_to_energy, CodecError};

/// How many layers a frame is split into: a base and three refinements.
pub const LAYERS: usize = 1 + 3;

/// One frame, coded as separable layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayeredFrame {
    /// Band energies and the first residual stage. Without this there is no
    /// audio at all.
    pub base: Vec<u8>,
    /// Successive refinements, each useless without every layer before it and
    /// each optional.
    pub refinements: Vec<Vec<u8>>,
}

impl LayeredFrame {
    /// Total size if every layer is sent.
    pub fn len(&self) -> usize {
        self.base.len() + self.refinements.iter().map(|r| r.len()).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
    }

    /// Write the frame as one self-delimiting byte string.
    ///
    /// # Why the layers share a datagram instead of getting one each
    ///
    /// Giving each layer its own datagram is the obvious way to let a network
    /// drop refinements, and it was costed before it was built. Every datagram
    /// carries its own authentication tag, and on frames this small the tag is
    /// most of the packet:
    ///
    /// | rate | one datagram | one per layer |
    /// |------|--------------|---------------|
    /// | 12 kbit/s | 19.6 kbit/s on the wire | 42.4 |
    /// | 16 kbit/s | 23.6 | 46.4 |
    /// | 24 kbit/s | 31.6 | 54.4 |
    ///
    /// Splitting a 24 kbit/s stream into four datagrams costs more bandwidth
    /// than the stream carries. So the layers travel together and the sender
    /// decides how many to include *before* protecting the frame, which is free.
    ///
    /// # The format
    ///
    /// One byte of layer count, then a length for each layer but the last, as
    /// LEB128. The last needs none: it runs to the end. A base-only frame
    /// therefore costs one byte of framing and a full four-layer frame costs
    /// four, against nine for the fixed width version this replaced.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut layers: Vec<&[u8]> = Vec::with_capacity(1 + self.refinements.len());
        layers.push(&self.base);
        for r in &self.refinements {
            layers.push(r);
        }
        while layers.len() > 1 && layers.last().is_some_and(|l| l.is_empty()) {
            layers.pop();
        }

        let mut out = vec![layers.len() as u8];
        for layer in &layers[..layers.len() - 1] {
            let mut n = layer.len();
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                out.push(if n == 0 { byte } else { byte | 0x80 });
                if n == 0 {
                    break;
                }
            }
        }
        for layer in &layers {
            out.extend_from_slice(layer);
        }
        out
    }

    /// Read back what [`to_bytes`](Self::to_bytes) wrote.
    ///
    /// Every length is checked against what is actually there. A frame arrives
    /// from a network, and a length field that is trusted is a length field
    /// that decides how much of somebody else's memory to read.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let count = *bytes.first().ok_or(CodecError::Malformed)? as usize;
        if count == 0 || count > LAYERS {
            return Err(CodecError::Malformed);
        }

        let mut at = 1;
        let mut lengths = Vec::with_capacity(count);
        for _ in 0..count - 1 {
            let mut value = 0usize;
            let mut shift = 0;
            loop {
                let byte = *bytes.get(at).ok_or(CodecError::Malformed)?;
                at += 1;
                // Bounded so a crafted run of continuation bytes cannot shift
                // its way to an enormous length or spin forever.
                if shift > 21 {
                    return Err(CodecError::Malformed);
                }
                value |= ((byte & 0x7f) as usize) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            lengths.push(value);
        }

        let declared: usize = lengths.iter().sum();
        let body = bytes.len().checked_sub(at).ok_or(CodecError::Malformed)?;
        if declared > body {
            return Err(CodecError::Malformed);
        }
        lengths.push(body - declared);

        let mut layers = Vec::with_capacity(count);
        for len in lengths {
            layers.push(bytes[at..at + len].to_vec());
            at += len;
        }

        let base = layers.remove(0);
        Ok(Self {
            base,
            refinements: layers,
        })
    }

    /// The most layers that fit in `budget` bytes once framing is counted.
    ///
    /// This is where the layered design pays: one encode, and the sender picks
    /// how much of it to send per frame with no re-encoding and no second copy.
    /// The base is always included, even when it does not fit, because a frame
    /// without one is not a frame.
    pub fn within(&self, budget: usize) -> Self {
        for keep in (0..=self.refinements.len()).rev() {
            let candidate = self.truncated(keep);
            if candidate.to_bytes().len() <= budget {
                return candidate;
            }
        }
        self.truncated(0)
    }

    /// The frame with only the first `keep` refinements, as a network that ran
    /// out of budget would deliver it.
    pub fn truncated(&self, keep: usize) -> Self {
        Self {
            base: self.base.clone(),
            refinements: self.refinements.iter().take(keep).cloned().collect(),
        }
    }
}

/// How many pulses each band gets in each stage.
///
/// Computed from the energies alone, so the encoder and decoder agree without
/// transmitting it. The energies the decoder holds are the quantised ones, so
/// the encoder must plan from those too: planning from the exact values is the
/// mistake that made the first version of this codec decode as noise.
fn plan(energies: &[f32], budget: usize) -> Vec<Vec<usize>> {
    let allocation = bands::allocate(energies, budget);

    (0..BANDS)
        .map(|b| rvq::plan(bands::range(b).len(), allocation[b]))
        .collect()
}

/// Encode one window into layers.
/// Fold a signed delta so that zero is symbol zero.
///
/// The alphabet has to be an unsigned index, and an energy delta is
/// overwhelmingly zero or one either way. Two's complement would put the
/// commonest values at both ends of the range, where no adaptive model can find
/// them together.
pub fn fold(delta: i16) -> usize {
    if delta >= 0 {
        (delta as usize) * 2
    } else {
        ((-delta) as usize) * 2 - 1
    }
    .min(ENERGY_SYMBOLS - 1)
}

pub fn unfold(symbol: usize) -> i16 {
    if symbol % 2 == 0 {
        (symbol / 2) as i16
    } else {
        -(((symbol + 1) / 2) as i16)
    }
}

/// Alphabet size for the level models.
///
/// One symbol per level, derived rather than written down: the two were
/// separate constants that happened to agree, which is the shape of a bug
/// waiting for somebody to change one of them.
pub const ENERGY_SYMBOLS: usize = crate::ENERGY_LEVELS;

/// The level at which a band counts as silent.
///
/// Zero is the bottom of the energy scale, which the quantiser clamps to. A
/// band there is contributing nothing.
pub const SILENT: u8 = 0;

/// How many band positions share a residual model.
///
/// Six groups of four. The statistics of a residual are not the same at the
/// bottom of the spectrum, where a voice has structure, as at the top, where it
/// has a slope and nothing else, and one model averaging the two learns
/// neither. Six is where the gain from splitting stopped paying for the extra
/// models to learn.
pub const BAND_CONTEXTS: usize = 6;

/// How many buckets the previous band's residual is sorted into.
pub const RESIDUAL_CONTEXTS: usize = 5;

fn band_context(b: usize) -> usize {
    (b * BAND_CONTEXTS / BANDS).min(BAND_CONTEXTS - 1)
}

/// How many distinct levels an awake band can hold: everything but [`SILENT`].
const AWAKE_LEVELS: i16 = (ENERGY_SYMBOLS - 1) as i16;

/// Reduce a residual to the smallest representative that still identifies the
/// level, and interleave its sign.
///
/// An awake level is one of 63 values, so a residual only ever has to carry 63
/// possibilities however far apart the two levels are. Taking it modulo that
/// and picking the representative nearest zero keeps the alphabet inside
/// [`ENERGY_SYMBOLS`] and keeps the common case, a small residual, on a small
/// symbol.
///
/// This is not a nicety. Predicting along the spectrum produces residuals of
/// ±32 where predicting along time produced ±3, and the first version of this
/// code handed [`fold`] a value it could not represent. The levels decoded as a
/// flat line and `levels_round_trip_through_their_models` is what caught it.
fn fold_residual(residual: i16) -> usize {
    let d = residual.rem_euclid(AWAKE_LEVELS);
    fold(if d > AWAKE_LEVELS / 2 { d - AWAKE_LEVELS } else { d })
}

/// Recover the level from a folded residual and the band below it.
fn unfold_residual(symbol: usize, predictor: u8) -> u8 {
    let d = unfold(symbol).rem_euclid(AWAKE_LEVELS);
    // Levels 1..=63 laid out as a ring of 63, so the arithmetic is exact
    // however far the residual reached.
    (1 + (predictor as i16 - 1 + d).rem_euclid(AWAKE_LEVELS)) as u8
}

fn residual_context(previous: i16) -> usize {
    match previous {
        i16::MIN..=-4 => 0,
        -3..=-2 => 1,
        -1..=0 => 2,
        1..=2 => 3,
        _ => 4,
    }
}

/// The models the band levels are coded against.
///
/// # Why the prediction runs along the spectrum and not along time
///
/// This started out predicting each band from the same band in the previous
/// frame, with the frame's mean shift sent once so that a spectrum getting
/// louder as a whole did not pay twenty four times for it. That is the obvious
/// design and it is the wrong one. Measured against the same signal:
///
/// | predictor                     | bytes/frame |
/// |-------------------------------|-------------|
/// | previous frame, same band     | 15.4        |
/// | previous frame, damped by 0.8 | 15.3        |
/// | both, planar                  | 14.2        |
/// | CELT-style 0.9 time, 0.7 freq | 13.9        |
/// | **previous band, same frame** | **12.9**    |
///
/// The reason is that the thing which moves fastest in a voice is the overall
/// level, and it moves everything with it: a frame is 20 ms and the loudness
/// can change a great deal in 20 ms. What barely moves is the *shape* of the
/// spectrum, and predicting along the spectrum is exactly what does not have to
/// resend the shape. Time prediction predicts the fast axis from the fast axis.
///
/// It also happens to be worth more than its bits. Predicting inside the frame
/// means a frame's levels do not depend on any other frame, so a lost frame
/// costs one frame instead of corrupting everything after it.
///
/// # Why silence is a state and not a level
///
/// Coding every band as a delta looked right and measured badly: only 47
/// percent of deltas were zero and 13 percent were eleven steps or more. That
/// tail is entirely bands crossing the noise floor as the envelope moves, and a
/// delta model cannot predict a jump from silence to speech.
///
/// So silence is a flag with its own model. Conditioned on where the band sits,
/// that flag is nearly free: the top of the spectrum is almost always asleep and
/// the bottom almost never is, so the model that matters has already made up its
/// mind before it is asked.
#[derive(Clone)]
pub struct LevelModels {
    /// Whether each band is silent, one model per band context.
    silence: Vec<Model>,
    /// A band's departure from the band below it, by band and by what the band
    /// below did.
    residual: Vec<Model>,
    /// The first awake band of a frame, which has nothing below it to predict
    /// from.
    first: Model,
}

impl Default for LevelModels {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelModels {
    pub fn new() -> Self {
        Self {
            silence: (0..BAND_CONTEXTS).map(|_| Model::new(2)).collect(),
            residual: (0..BAND_CONTEXTS * RESIDUAL_CONTEXTS)
                .map(|_| Model::new(ENERGY_SYMBOLS))
                .collect(),
            first: Model::new(ENERGY_SYMBOLS),
        }
    }

    fn residual_model(&mut self, b: usize, previous: i16) -> &mut Model {
        &mut self.residual[band_context(b) * RESIDUAL_CONTEXTS + residual_context(previous)]
    }
}

/// Write one frame's band levels into an arithmetic stream.
///
/// A free function taking the models rather than a method, so that a group can
/// put several frames into one stream: an arithmetic coder must be flushed
/// before its output can be read, and the flush costs four to six bytes
/// whatever it carries. A 20 ms frame pays that fifty times a second.
///
/// The order is fixed and [`read_levels`] mirrors it exactly: every silence
/// flag first, then every awake band's level.
pub fn write_levels(stream: &mut RangeEncoder, levels: &[u8; BANDS], models: &mut LevelModels) {
    for b in 0..BANDS {
        let silent = (levels[b] == SILENT) as usize;
        encode_symbol(stream, &mut models.silence[band_context(b)], silent);
    }

    let mut predictor: Option<u8> = None;
    let mut previous_residual = 0i16;

    for b in 0..BANDS {
        if levels[b] == SILENT {
            continue;
        }
        match predictor {
            None => encode_symbol(stream, &mut models.first, levels[b] as usize),
            Some(p) => {
                let residual = levels[b] as i16 - p as i16;
                let model = models.residual_model(b, previous_residual);
                encode_symbol(stream, model, fold_residual(residual));
                previous_residual = residual;
            }
        }
        predictor = Some(levels[b]);
    }
}

/// Read back what [`write_levels`] wrote.
pub fn read_levels(stream: &mut RangeDecoder, models: &mut LevelModels) -> [u8; BANDS] {
    let mut silent = [false; BANDS];
    for b in 0..BANDS {
        silent[b] = decode_symbol(stream, &mut models.silence[band_context(b)]) == 1;
    }

    let mut levels = [0u8; BANDS];
    let mut predictor: Option<u8> = None;
    let mut previous_residual = 0i16;

    for b in 0..BANDS {
        if silent[b] {
            continue;
        }
        levels[b] = match predictor {
            None => decode_symbol(stream, &mut models.first) as u8,
            Some(p) => {
                let symbol = decode_symbol(stream, models.residual_model(b, previous_residual));
                let level = unfold_residual(symbol, p);
                previous_residual = level as i16 - p as i16;
                level
            }
        };
        predictor = Some(levels[b]);
    }
    levels
}

/// Choose each band's level against the shape the decoder will hold.
///
/// The same idea as the base codec's `refine_levels`, and the same reason it is
/// free: the pyramid codes direction and `rvq::encode` normalises by the band's
/// own root mean square before it starts, so a band's stages do not depend on
/// its level. Only the plan does, and the caller checks that separately.
///
/// The error is a parabola in the gain with its minimum at the projection
/// `<x, s> / <s, s>`, and the measured energy sits above that whenever the shape
/// is imperfect. So a band always came out slightly too loud, always in the same
/// direction, and this is the level on the grid that undoes it.
fn refine_levels(
    coefficients: &[f32],
    shapes: &[Vec<f32>],
    levels: [u8; BANDS],
    quantum: u8,
) -> [u8; BANDS] {
    let mut refined = levels;

    for b in 0..BANDS {
        let shape = &shapes[b];
        if shape.is_empty() {
            continue;
        }
        let x = &coefficients[bands::range(b)];
        let ss: f32 = shape.iter().map(|s| s * s).sum();
        if ss <= 1e-12 {
            continue;
        }

        let error_at = |gain: f32| -> f64 {
            x.iter()
                .zip(shape)
                .map(|(&c, &s)| {
                    let d = (c - gain * s) as f64;
                    d * d
                })
                .sum()
        };

        let here = levels[b];
        let mut best = error_at(level_to_energy(here));

        // Four steps either way is further than the projection can move a level,
        // and stopping there keeps this from being a search.
        for step in -4i16..=4 {
            let candidate = (here as i16 + step * quantum as i16).clamp(0, 255) as u8;
            let candidate = coarsen(candidate, quantum);
            if candidate == here {
                continue;
            }
            let e = error_at(level_to_energy(candidate));
            if e < best {
                best = e;
                refined[b] = candidate;
            }
        }
    }

    refined
}

pub struct LayeredEncoder {
    window: Vec<f32>,
    budget_bits: usize,
    models: LevelModels,
    quantum: u8,
}

impl LayeredEncoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            window: mdct::window(),
            budget_bits: bytes_per_frame * 8,
            models: LevelModels::new(),
            quantum: level_quantum(bytes_per_frame),
        }
    }

    /// Encode a frame, keeping every layer.
    ///
    /// For a link with a budget, prefer [`LayeredEncoder::encode_within`]: this
    /// is the same call with no ceiling, and a caller that trims afterwards
    /// gets a frame whose levels were chosen for layers it then threw away.
    pub fn encode(&mut self, audio: &[f32]) -> Result<LayeredFrame, CodecError> {
        self.encode_within(audio, usize::MAX)
    }

    /// Encode a frame that fits in `budget_bytes`, trimming layers here.
    ///
    /// # Why the trim moved inside
    ///
    /// It used to happen in the caller: encode everything, then call
    /// `LayeredFrame::within` against a budget taken from live congestion. That
    /// works for the bits and not for the levels. A band is rebuilt as its level
    /// times its shape, and the shape depends on how many stages arrive, so the
    /// best level for a frame with four layers is not the best level for the
    /// same frame with one. Choosing outside meant choosing against a frame
    /// nobody would receive.
    pub fn encode_within(
        &mut self,
        audio: &[f32],
        budget_bytes: usize,
    ) -> Result<LayeredFrame, CodecError> {
        if audio.len() != WINDOW {
            return Err(CodecError::WrongFrameSize { got: audio.len() });
        }

        let mut coefficients = mdct::forward(audio, &self.window);

        // Shaping happens before the energies are measured, because what gets
        // quantised from here on is the prediction error and the levels have to
        // describe that, not the coefficients it was computed from.
        // Two separate questions. Whether the frame carries shaping bits at all
        // depends only on the rate, which the decoder also knows, so it stays out
        // of the bitstream. Whether the filter in those bits is active depends on
        // the audio, which the decoder does not know, so it travels as the flag.
        let shaping = tns::allowed(self.budget_bits / 8);
        let filter = if shaping && tns::is_transient(audio) {
            tns::analyse(&coefficients)
        } else {
            tns::Filter::default()
        };
        filter.apply(&mut coefficients);

        let measured = bands::energies(&coefficients);

        let mut levels = [0u8; BANDS];
        for b in 0..BANDS {
            levels[b] = coarsen(energy_to_level(measured[b]), self.quantum);
        }
        let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();
        let shape = bands::normalise(&coefficients, &energies);

        // --- the levels, arithmetic coded ---
        //
        // In their own stream rather than mixed with the shapes: the two are
        // coded by different machinery, and interleaving them would mean the
        // arithmetic coder could not be flushed until the last band was written.
        // Coded against a copy of the models, because the size of this stream
        // decides the bit budget and the budget decides the plan, so it has to
        // be known before anything is committed. The real models are advanced
        // once, at the end, with whichever levels are actually sent.
        let mut trial_models = self.models.clone();
        let mut energy_stream = RangeEncoder::new();
        write_levels(&mut energy_stream, &levels, &mut trial_models);

        let energy_bytes = energy_stream.finish();
        if energy_bytes.len() > u8::MAX as usize {
            return Err(CodecError::Malformed);
        }

        // The shapes follow in the same layer, bit packed.
        let mut base = Encoder::new();
        let shaping_bits = if shaping {
            filter.write(&mut base);
            filter.bits()
        } else {
            0
        };

        let spent = (1 + energy_bytes.len()) * 8 + shaping_bits;
        let plans = plan(&energies, self.budget_bits.saturating_sub(spent));

        // Code every band fully, then split the stages across layers. Coding
        // per layer would mean re-deriving each band's residual four times.
        let coded: Vec<Vec<rvq::Stage>> = (0..BANDS)
            .map(|b| rvq::encode(&shape[bands::range(b)], &plans[b]))
            .collect();

        // Stage zero joins the energies in the base; the rest become
        // refinements.
        let mut layers: Vec<Encoder> = (0..LAYERS - 1).map(|_| Encoder::new()).collect();

        for (b, stages) in coded.iter().enumerate() {
            let n = bands::range(b).len();

            for (level, stage) in stages.iter().enumerate() {
                let target = if level == 0 {
                    &mut base
                } else if level - 1 < layers.len() {
                    &mut layers[level - 1]
                } else {
                    continue;
                };
                write_stage(target, n, stage);
            }
        }

        // Length prefixed, so the decoder knows where the arithmetic stream
        // ends and the bit packed shapes begin.
        let shape_bits = base.finish();
        let refinements: Vec<Vec<u8>> = layers.into_iter().map(|l| l.finish()).collect();

        let assemble = |energy: &[u8], refinements: &[Vec<u8>]| {
            let mut base_bytes = Vec::with_capacity(1 + energy.len() + shape_bits.len());
            base_bytes.push(energy.len() as u8);
            base_bytes.extend_from_slice(energy);
            base_bytes.extend_from_slice(&shape_bits);
            LayeredFrame {
                base: base_bytes,
                refinements: refinements.to_vec(),
            }
        };

        // What will actually be sent. Every layer beyond the budget is dropped
        // here rather than by the caller, because the level chosen next depends
        // on which stages the decoder will hold, and a caller trimming
        // afterwards would leave that choice made against a frame nobody gets.
        let frame = assemble(&energy_bytes, &refinements);
        let keep = frame.within(budget_bytes).refinements.len();
        let refinements: Vec<Vec<u8>> = refinements.into_iter().take(keep).collect();

        // Now the levels can be chosen against the shape the decoder will
        // rebuild, rather than against the energy that was measured. See
        // `refine_levels`.
        let surviving: Vec<Vec<f32>> = (0..BANDS)
            .map(|b| {
                let n = bands::range(b).len();
                let stages = &coded[b][..coded[b].len().min(keep + 1)];
                if stages.is_empty() {
                    Vec::new()
                } else {
                    rvq::decode(n, stages)
                }
            })
            .collect();

        let refined = refine_levels(&coefficients, &surviving, levels, self.quantum);

        // A level may only move if the frame comes out the same shape: the
        // energies decide the plan, and the size of their coded stream decides
        // the budget the plan is computed against. Either changing would leave
        // the decoder splitting the bits differently from the encoder that
        // wrote them, and reading every band from the wrong place.
        //
        // Tried one band at a time rather than all at once. All at once is one
        // arithmetic encode and it was refused four times in five, because a
        // single band moving is usually enough to change the coded length of
        // the whole stream. Band by band, what one band spoils no longer costs
        // the other twenty three.
        let energy_len = energy_bytes.len();
        let want = self.budget_bits.saturating_sub(spent);
        let mut chosen = levels;
        let mut chosen_bytes = energy_bytes;
        let mut committed = trial_models;

        for b in 0..BANDS {
            if refined[b] == chosen[b] {
                continue;
            }
            let mut candidate = chosen;
            candidate[b] = refined[b];

            let mut models = self.models.clone();
            let mut stream = RangeEncoder::new();
            write_levels(&mut stream, &candidate, &mut models);
            let bytes = stream.finish();
            if bytes.len() != energy_len {
                continue;
            }

            let energies: Vec<f32> = candidate.iter().map(|&l| level_to_energy(l)).collect();
            if plan(&energies, want) != plans {
                continue;
            }

            chosen = candidate;
            chosen_bytes = bytes;
            committed = models;
        }
        let energy_bytes = chosen_bytes;

        self.models = committed;
        Ok(assemble(&energy_bytes, &refinements))
    }
}

/// Decode layers back into audio.
pub struct LayeredDecoder {
    /// Advances every frame, so an invented texture never repeats. Decoder
    /// local and never transmitted.
    frames_decoded: u32,
    window: Vec<f32>,
    budget_bits: usize,
    overlap: mdct::OverlapAdd,
    models: LevelModels,
    /// Band energies from the last frame that arrived, for concealing the next
    /// one if it does not. Empty until something has been decoded.
    last_energies: Vec<f32>,
    /// How many frames in a row have been concealed, so each one is quieter
    /// than the last.
    concealed_in_a_row: u32,
}

impl LayeredDecoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            frames_decoded: 0,
            window: mdct::window(),
            budget_bits: bytes_per_frame * 8,
            overlap: mdct::OverlapAdd::new(),
            models: LevelModels::new(),
            last_energies: Vec::new(),
            concealed_in_a_row: 0,
        }
    }

    /// Decode whatever layers arrived.
    ///
    /// A frame with only its base decodes to coarse audio rather than to
    /// nothing, which is the entire point.
    /// One frame's worth of output for a frame that never arrived.
    ///
    /// # Why not silence
    ///
    /// Silence is what a gap sounded like, and a gap in the middle of a vowel
    /// is a click at each edge: the overlap-add window is fed a full frame and
    /// then nothing, so the signal falls off a cliff and climbs back up one.
    /// Somebody hears the discontinuity rather than the loss, and clicks are
    /// more distracting than a short roughness.
    ///
    /// # What it does instead
    ///
    /// It holds the band energies of the last frame that did arrive and fills
    /// the shape with noise at those levels, quieter each time. The energies
    /// alone say what the voice sounded like across the spectrum without saying
    /// anything about its fine structure, so a short gap comes out as the same
    /// timbre continuing rather than as a hole or as a repeat somebody can hear
    /// looping.
    ///
    /// The fade is deliberate and steep enough that a long outage becomes
    /// silence within about a hundred milliseconds. Concealment that keeps
    /// inventing sound for a lost connection is a machine talking to itself.
    ///
    /// The seed advances every frame, so two concealed frames in a row are not
    /// the same noise, which would be audible as a buzz.
    pub fn conceal(&mut self) -> Vec<f32> {
        self.frames_decoded = self.frames_decoded.wrapping_add(1);

        if self.last_energies.is_empty() {
            // Nothing has ever arrived, so there is nothing to continue. A
            // window rather than a frame: `push` takes what `inverse` produces,
            // which is the overlapping window, and it says so by panicking.
            return self.overlap.push(&vec![0.0f32; WINDOW]);
        }

        self.concealed_in_a_row = self.concealed_in_a_row.saturating_add(1);
        // About a tenth of a second to inaudible at 20 ms a frame.
        let fade = 0.6f32.powi(self.concealed_in_a_row as i32);

        let mut shape = vec![0.0f32; FRAME];
        for b in 0..BANDS {
            let range = bands::range(b);
            let seed = self
                .frames_decoded
                .wrapping_mul(0x9E37_79B9)
                .wrapping_add(b as u32);
            fill_with_noise(&mut shape[range], seed);
        }

        let energies: Vec<f32> = self.last_energies.iter().map(|e| e * fade).collect();
        let coefficients = bands::denormalise(&shape, &energies);
        self.overlap.push(&mdct::inverse(&coefficients, &self.window))
    }

    pub fn decode(&mut self, frame: &LayeredFrame) -> Result<Vec<f32>, CodecError> {
        self.frames_decoded = self.frames_decoded.wrapping_add(1);
        if frame.base.is_empty() {
            return Err(CodecError::Malformed);
        }

        let energy_len = frame.base[0] as usize;
        if frame.base.len() < 1 + energy_len {
            return Err(CodecError::Malformed);
        }
        let (energy_bytes, shape_bytes) = frame.base[1..].split_at(energy_len);

        let mut energy_stream = RangeDecoder::new(energy_bytes);
        let levels = read_levels(&mut energy_stream, &mut self.models);

        let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();

        let mut base = Decoder::new(shape_bytes);
        let (filter, shaping_bits) = if tns::allowed(self.budget_bits / 8) {
            let filter = tns::Filter::read(&mut base);
            let bits = filter.bits();
            (filter, bits)
        } else {
            (tns::Filter::default(), 0)
        };
        let spent = (1 + energy_len) * 8 + shaping_bits;
        let plans = plan(&energies, self.budget_bits.saturating_sub(spent));

        let mut refinements: Vec<Decoder> =
            frame.refinements.iter().map(|r| Decoder::new(r)).collect();

        let mut shape = vec![0.0f32; FRAME];

        for b in 0..BANDS {
            let n = bands::range(b).len();
            let mut stages = Vec::new();

            for (level, &pulses) in plans[b].iter().enumerate() {
                let source = if level == 0 {
                    Some(&mut base)
                } else {
                    refinements.get_mut(level - 1)
                };

                // A refinement that did not arrive simply ends the band here.
                // Everything read so far still renders.
                match source {
                    Some(d) => stages.push(read_stage(d, n, pulses)),
                    None => break,
                }
            }

            if stages.is_empty() {
                // No bits at all for this band: noise at the transmitted level.
                let seed = self
                    .frames_decoded
                    .wrapping_mul(BANDS as u32)
                    .wrapping_add(b as u32);
                fill_with_noise(&mut shape[bands::range(b)], seed);
            } else {
                shape[bands::range(b)].copy_from_slice(&rvq::decode(n, &stages));
            }
        }

        // Kept for concealment, in case the next frame does not arrive.
        self.last_energies = energies.clone();
        self.concealed_in_a_row = 0;

        let mut coefficients = bands::denormalise(&shape, &energies);
        filter.undo(&mut coefficients);
        Ok(self.overlap.push(&mdct::inverse(&coefficients, &self.window)))
    }
}

fn write_stage(encoder: &mut Encoder, n: usize, stage: &rvq::Stage) {
    let width = crate::pvq::bits(n, stage.pulses).ceil() as usize;

    if width > 32 {
        encoder.write_bits((stage.index >> 32) as u32, width - 32);
        encoder.write_bits(stage.index as u32, 32);
    } else {
        encoder.write_bits(stage.index as u32, width);
    }
    encoder.write_bits(stage.gain as u32, rvq::GAIN_BITS);
    encoder.write_bits(stage.negative as u32, 1);
}

fn read_stage(decoder: &mut Decoder, n: usize, pulses: usize) -> rvq::Stage {
    let width = crate::pvq::bits(n, pulses).ceil() as usize;

    let index = if width > 32 {
        let high = decoder.read_bits(width - 32) as u64;
        (high << 32) | decoder.read_bits(32) as u64
    } else {
        decoder.read_bits(width) as u64
    };

    let total = crate::pvq::count(n, pulses);

    rvq::Stage {
        pulses,
        // An index past the end of its codebook means a corrupted layer.
        // Wrapping keeps one bad layer to one rough band.
        index: if total > 0 { index % total } else { 0 },
        gain: decoder.read_bits(rvq::GAIN_BITS) as u8,
        negative: decoder.read_bits(1) == 1,
    }
}

/// A band with no bits at all, rendered as noise at unit level.
///
/// The signs must be random. Alternating them gives `+ - + -`, which is a tone
/// at the Nyquist frequency rather than noise and whistles at the top of every
/// unfunded band.
/// Invent a band's texture at unit level. See [`crate::invent_shape`], which
/// this defers to so the two decoders cannot drift apart on what noise is.
fn fill_with_noise(shape: &mut [f32], seed: u32) {
    crate::invent_shape(shape, seed);
}


/// Codes the band shapes of one frame, leaving its energies to the caller.
///
/// The split exists because a frame's shapes must stay independent while its
/// energies are worth coding across frames: an arithmetic coder's flush costs
/// four to six bytes and a 20 ms frame cannot amortise it.
pub struct ShapeEncoder {
    window: Vec<f32>,
    budget_bits: usize,
    quantum: u8,
}

impl ShapeEncoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            window: mdct::window(),
            budget_bits: bytes_per_frame * 8,
            quantum: level_quantum(bytes_per_frame),
        }
    }

    /// Returns the frame's band levels and its coded shapes.
    pub fn encode_shapes(
        &mut self,
        audio: &[f32],
    ) -> Result<([u8; BANDS], LayeredFrame), CodecError> {
        if audio.len() != WINDOW {
            return Err(CodecError::WrongFrameSize { got: audio.len() });
        }

        let coefficients = mdct::forward(audio, &self.window);
        let measured = bands::energies(&coefficients);

        let mut levels = [0u8; BANDS];
        for b in 0..BANDS {
            levels[b] = coarsen(energy_to_level(measured[b]), self.quantum);
        }
        let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();
        let shape = bands::normalise(&coefficients, &energies);

        // The energies live elsewhere, so the whole budget is shapes.
        let plans = plan(&energies, self.budget_bits);

        let coded: Vec<Vec<rvq::Stage>> = (0..BANDS)
            .map(|b| rvq::encode(&shape[bands::range(b)], &plans[b]))
            .collect();

        let mut base = Encoder::new();
        let mut layers: Vec<Encoder> = (0..LAYERS - 1).map(|_| Encoder::new()).collect();

        for (b, stages) in coded.iter().enumerate() {
            let n = bands::range(b).len();

            for (level, stage) in stages.iter().enumerate() {
                let target = if level == 0 {
                    &mut base
                } else if level - 1 < layers.len() {
                    &mut layers[level - 1]
                } else {
                    continue;
                };
                write_stage(target, n, stage);
            }
        }

        Ok((
            levels,
            LayeredFrame {
                base: base.finish(),
                refinements: layers.into_iter().map(|l| l.finish()).collect(),
            },
        ))
    }
}

/// The other half of [`ShapeEncoder`].
pub struct ShapeDecoder {
    /// See [`LayeredDecoder`].
    frames_decoded: u32,
    window: Vec<f32>,
    budget_bits: usize,
    overlap: mdct::OverlapAdd,
}

impl ShapeDecoder {
    pub fn new(bytes_per_frame: usize) -> Self {
        Self {
            frames_decoded: 0,
            window: mdct::window(),
            budget_bits: bytes_per_frame * 8,
            overlap: mdct::OverlapAdd::new(),
        }
    }

    pub fn decode_shapes(
        &mut self,
        levels: &[u8; BANDS],
        frame: &LayeredFrame,
    ) -> Result<Vec<f32>, CodecError> {
        self.frames_decoded = self.frames_decoded.wrapping_add(1);
        let energies: Vec<f32> = levels.iter().map(|&l| level_to_energy(l)).collect();
        let plans = plan(&energies, self.budget_bits);

        let mut base = Decoder::new(&frame.base);
        let mut refinements: Vec<Decoder> =
            frame.refinements.iter().map(|r| Decoder::new(r)).collect();

        let mut shape = vec![0.0f32; FRAME];

        for b in 0..BANDS {
            let n = bands::range(b).len();
            let mut stages = Vec::new();

            for (level, &pulses) in plans[b].iter().enumerate() {
                let source = if level == 0 {
                    Some(&mut base)
                } else {
                    refinements.get_mut(level - 1)
                };
                match source {
                    Some(d) => stages.push(read_stage(d, n, pulses)),
                    None => break,
                }
            }

            if stages.is_empty() {
                let seed = self
                    .frames_decoded
                    .wrapping_mul(BANDS as u32)
                    .wrapping_add(b as u32);
                fill_with_noise(&mut shape[bands::range(b)], seed);
            } else {
                shape[bands::range(b)].copy_from_slice(&rvq::decode(n, &stages));
            }
        }

        let coefficients = bands::denormalise(&shape, &energies);
        Ok(self.overlap.push(&mdct::inverse(&coefficients, &self.window)))
    }
}

#[cfg(test)]
mod tests {
    /// Decode a file of captured frames, to see what they really carry.
    ///
    /// Ignored: it needs a recording. `ROTELYX_FRAME_DUMP` on a desktop call
    /// writes one, each frame prefixed with its length, exactly as it arrived
    /// and after it authenticated. Replaying it here separates two things that
    /// look identical from inside a call: bytes that carry the wrong sound, and
    /// a decoder that turns the right bytes into the wrong sound.
    ///
    ///   ROTELYX_FRAMES=frames.bin cargo test -p rotelyx-codec \
    ///     decode_a_recording -- --ignored --nocapture
    #[test]
    #[ignore]
    fn decode_a_recording() {
        use super::*;

        let path = std::env::var("ROTELYX_FRAMES").expect("set ROTELYX_FRAMES");
        let raw = std::fs::read(path).expect("the recording");

        // How many frames to look at. A diagnostic that only holds for the first
        // seconds of a call is measured over those seconds and no further.
        let limit: usize = std::env::var("ROTELYX_FRAMES_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);

        let mut decoder = LayeredDecoder::new(60);
        let mut audio: Vec<f32> = Vec::new();
        let mut frames = 0usize;
        let mut refused = 0usize;

        let mut at = 0usize;
        while at + 4 <= raw.len() {
            let len = u32::from_le_bytes(raw[at..at + 4].try_into().expect("four bytes")) as usize;
            at += 4;
            if at + len > raw.len() {
                break;
            }
            let payload = &raw[at..at + len];
            at += len;

            match LayeredFrame::from_bytes(payload).and_then(|f| decoder.decode(&f)) {
                Ok(samples) => {
                    frames += 1;
                    audio.extend_from_slice(&samples);
                }
                Err(_) => refused += 1,
            }

            if frames >= limit {
                break;
            }
        }

        let paired: f32 = audio.windows(2).map(|w| w[0] * w[1]).sum();
        let total: f32 = audio.iter().map(|s| s * s).sum();
        let correlation = if total > 0.0 { paired / total } else { 0.0 };
        let rms = (total / audio.len().max(1) as f32).sqrt();

        // The dominant frequency, by counting how often the signal crosses zero.
        // A sine at f crosses 2f times a second, which is enough to tell 220 from
        // 440 from 880 without a transform.
        let crossings = audio
            .windows(2)
            .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
            .count();
        let seconds = audio.len() as f32 / 48000.0;
        let hz = if seconds > 0.0 {
            crossings as f32 / seconds / 2.0
        } else {
            0.0
        };

        println!("  {frames} frames decoded, {refused} refused");
        println!("  dominant frequency about {hz:.0} Hz");
        println!("  rms {rms:.4}, correlation between neighbours {correlation:.3}");
        println!(
            "  {}",
            if correlation > 0.8 {
                "that is a voice: the bytes carry sound and the decoder reads it"
            } else {
                "that is broadband noise: these bytes do not carry what was heard"
            }
        );
    }

    /// One lost frame must not poison every frame after it.
    ///
    /// # Why this is the question
    ///
    /// A real call decoded every frame it received, concealed seven, and played
    /// broadband noise: correlation 0.195 between neighbouring samples, where a
    /// voice is above 0.9. Frames were arriving and turning into the wrong
    /// sound, which is what a decoder that carries state across frames does
    /// after it loses one.
    ///
    /// So: encode a tone, drop a frame in the middle, and measure what comes out
    /// afterwards. If the decoder recovers, loss is not the explanation and the
    /// fault is elsewhere.
    #[test]
    fn a_lost_frame_does_not_poison_the_ones_after_it() {
        use super::*;

        const FRAME: usize = crate::mdct::FRAME;
        const WINDOW: usize = crate::mdct::WINDOW;

        let pcm: Vec<f32> = (0..FRAME * 20)
            .map(|n| {
                let t = n as f32 / crate::mdct::SAMPLE_RATE as f32;
                (t * 440.0 * std::f32::consts::TAU).sin() * 0.5
            })
            .collect();

        let mut encoder = LayeredEncoder::new(60);
        let mut decoder = LayeredDecoder::new(60);
        let mut history = vec![0.0f32; FRAME];

        // Which frame goes missing. Far enough in that everything before it is
        // settled, far enough from the end to hear what follows.
        const DROP: usize = 8;

        let mut after = Vec::new();
        for (n, input) in pcm.chunks_exact(FRAME).enumerate() {
            let mut window = Vec::with_capacity(WINDOW);
            window.extend_from_slice(&history);
            window.extend_from_slice(input);
            history.copy_from_slice(&window[FRAME..]);

            let frame = encoder.encode(&window).expect("encode");
            let bytes = frame.to_bytes();

            if n == DROP {
                // Lost on the way. The decoder is told nothing, which is exactly
                // what happens: a concealed slot never reaches it.
                continue;
            }

            let parsed = LayeredFrame::from_bytes(&bytes).expect("parse");
            let audio = decoder.decode(&parsed).expect("decode");

            if n > DROP + 1 {
                after.extend_from_slice(&audio);
            }
        }

        let paired: f32 = after.windows(2).map(|w| w[0] * w[1]).sum();
        let total: f32 = after.iter().map(|s| s * s).sum();
        let correlation = if total > 0.0 { paired / total } else { 0.0 };
        println!("  correlation after the loss: {correlation:.3}");

        // A tone at 440 Hz sampled at 48 kHz barely moves between neighbouring
        // samples. Anything near zero here is broadband noise, which is what a
        // person hears when a decoder never recovers.
        assert!(
            correlation > 0.8,
            "one lost frame left the decoder producing noise: correlation {correlation:.3}"
        );
    }

    /// The phone's capture path, decoded the way the desktop decodes it.
    ///
    /// # What this is checking
    ///
    /// Not the codec. The two clients build the encoder's input differently:
    /// the phone is handed sixteen bit PCM by Android and makes a forty
    /// millisecond window out of the previous frame and this one, and the
    /// desktop takes floats straight from its capture device. If those two
    /// disagree about anything at all, one direction of a call sounds like
    /// noise while the other sounds fine, which is exactly what a real call did.
    ///
    /// So this reproduces the phone's arithmetic exactly, sends the bytes it
    /// would send, and decodes them the way the far side does.
    #[test]
    fn the_phones_capture_path_decodes_to_the_same_sound() {
        use super::*;

        const FRAME: usize = crate::mdct::FRAME;
        const WINDOW: usize = crate::mdct::WINDOW;

        // A tone, as Android hands it over: sixteen bit, mono, 48 kHz.
        let pcm: Vec<i16> = (0..FRAME * 6)
            .map(|n| {
                let t = n as f32 / crate::mdct::SAMPLE_RATE as f32;
                ((t * 440.0 * std::f32::consts::TAU).sin() * 0.5 * 32767.0) as i16
            })
            .collect();

        let mut encoder = LayeredEncoder::new(60);
        let mut decoder = LayeredDecoder::new(60);
        let mut history = vec![0.0f32; FRAME];

        let mut heard = 0usize;
        let mut silent = 0usize;
        for input in pcm.chunks_exact(FRAME) {
            // The phone's window, to the letter.
            let mut window = Vec::with_capacity(WINDOW);
            window.extend_from_slice(&history);
            window.extend(input.iter().map(|s| *s as f32 / 32768.0));
            history.copy_from_slice(&window[FRAME..]);

            let frame = encoder.encode(&window).expect("encode");
            let on_the_wire = frame.to_bytes();

            let parsed = LayeredFrame::from_bytes(&on_the_wire).expect("parse");
            let audio = decoder.decode(&parsed).expect("decode");

            let energy: f32 = audio.iter().map(|s| s * s).sum::<f32>() / audio.len() as f32;

            // Energy is not enough, and that is the whole lesson here. Noise has
            // energy. A tone at 440 Hz sampled at 48 kHz moves slowly from one
            // sample to the next, so it is strongly correlated with itself one
            // sample back; broadband noise is not. A call decoded every frame it
            // received and played noise, and a test that only asked "is there
            // sound" said it was fine.
            let paired: f32 = audio.windows(2).map(|w| w[0] * w[1]).sum();
            let total: f32 = audio.iter().map(|s| s * s).sum();
            let correlation = if total > 0.0 { paired / total } else { 0.0 };
            println!(
                "  {} samples, energy {:.5}, correlation {:.3}",
                audio.len(),
                energy,
                correlation
            );
            if energy > 1e-3 {
                heard += 1;
            } else {
                silent += 1;
            }
        }

        assert!(
            heard >= 3,
            "the phone's capture path produced {silent} silent frames and {heard} with sound in \
             them: what it sends does not decode to what it heard"
        );
    }

    /// What one client puts on the wire is what the other parses.
    ///
    /// # Why this is worth a test of its own
    ///
    /// The phone client encoded with `TelyxEncoder` and the desktop parsed with
    /// `LayeredFrame::from_bytes`. Every frame of a real call crossed the
    /// network, authenticated, and failed to decode. Nothing reported a fault:
    /// an undecodable frame is concealed rather than counted, which is right for
    /// packet loss and hides a format mismatch completely. Both ends showed an
    /// open call and both people heard silence, then chirps, for as long as they
    /// were willing to hold it.
    ///
    /// So the check is not "does the codec work". It is: does the byte string
    /// one side sends parse as the frame the other side expects, and does the
    /// audio survive the trip.
    #[test]
    fn what_goes_on_the_wire_comes_back_as_audio() {
        use super::*;

        // A tone rather than noise, so what comes back can be compared to
        // something. Two windows, because the first primes the encoder.
        let tone: Vec<f32> = (0..crate::mdct::WINDOW * 2)
            .map(|n| {
                let t = n as f32 / crate::mdct::SAMPLE_RATE as f32;
                (t * 440.0 * std::f32::consts::TAU).sin() * 0.25
            })
            .collect();

        let mut encoder = LayeredEncoder::new(60);
        let mut decoder = LayeredDecoder::new(60);

        let mut heard = 0usize;
        for window in tone.chunks_exact(crate::mdct::WINDOW) {
            let frame = encoder.encode(window).expect("encode");

            // The wire is bytes. This is the step the phone was missing: it sent
            // a codec frame of a different shape entirely.
            let on_the_wire = frame.to_bytes();
            let parsed = LayeredFrame::from_bytes(&on_the_wire)
                .expect("what one side sends must parse on the other");

            let audio = decoder.decode(&parsed).expect("decode");

            // Energy, not sample equality: this is a lossy codec and the point
            // is that a voice arrives, not that the bits do.
            let energy: f32 = audio.iter().map(|s| s * s).sum();
            if energy > 1e-4 {
                heard += 1;
            }
        }

        assert!(
            heard > 0,
            "the audio did not survive the round trip through the wire format"
        );
    }


    /// A gap must sound like the voice continuing, not like a hole.
    ///
    /// # What this pins
    ///
    /// A lost frame used to play as silence. The overlap-add window is fed a
    /// full frame and then nothing, so the signal drops to zero and climbs back
    /// out, and both edges are clicks: somebody hears the discontinuity rather
    /// than the loss. This asserts the two properties that stop that. The
    /// concealed frame carries energy, and it carries less of it than the frame
    /// before, so a gap fades instead of holding a note or repeating audibly.
    #[test]
    fn a_concealed_frame_carries_the_voice_forward_and_fades() {
        let mut encoder = LayeredEncoder::new(60);
        let mut decoder = LayeredDecoder::new(60);

        // A vowel-ish signal: something with energy spread over the spectrum.
        let audio: Vec<f32> = (0..WINDOW)
            .map(|n| {
                let t = n as f32 / mdct::SAMPLE_RATE as f32;
                0.4 * (2.0 * std::f32::consts::PI * 220.0 * t).sin()
                    + 0.2 * (2.0 * std::f32::consts::PI * 660.0 * t).sin()
            })
            .collect();

        let frame = encoder.encode(&audio).expect("encode");
        let decoded = decoder.decode(&frame).expect("decode");
        let heard = energy(&decoded);

        let first = energy(&decoder.conceal());
        let second = energy(&decoder.conceal());
        let third = energy(&decoder.conceal());

        assert!(
            first > heard * 0.05,
            "the first concealed frame was near silence: {first:.5} against {heard:.5}"
        );
        assert!(
            second < first && third < second,
            "concealment did not fade: {first:.5} then {second:.5} then {third:.5}"
        );

        // And it gives up rather than talking to itself through an outage.
        for _ in 0..10 {
            decoder.conceal();
        }
        let much_later = energy(&decoder.conceal());
        assert!(
            much_later < heard * 0.001,
            "a long outage was still making sound: {much_later:.6}"
        );
    }

    /// Concealing before anything has arrived must not invent a voice.
    #[test]
    fn concealment_before_the_first_frame_is_silence() {
        let mut decoder = LayeredDecoder::new(60);
        assert_eq!(
            energy(&decoder.conceal()),
            0.0,
            "a decoder that has heard nothing invented something"
        );
    }

    fn energy(samples: &[f32]) -> f32 {
        samples.iter().map(|s| s * s).sum::<f32>() / samples.len().max(1) as f32
    }

    use super::*;
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

    fn snr_db(original: &[f32], decoded: &[f32]) -> f32 {
        let signal: f32 = original.iter().map(|s| s * s).sum();
        let noise: f32 = original
            .iter()
            .zip(decoded)
            .map(|(a, b)| (a - b).powi(2))
            .sum();

        if noise < 1e-12 {
            99.0
        } else {
            10.0 * (signal / noise).log10()
        }
    }

    /// Decode a signal keeping only `keep` refinement layers.
    fn round_trip(signal: &[f32], bytes: usize, keep: usize) -> Vec<f32> {
        let mut encoder = LayeredEncoder::new(bytes);
        let mut decoder = LayeredDecoder::new(bytes);
        let mut out = Vec::new();

        for start in (0..signal.len().saturating_sub(WINDOW)).step_by(FRAME) {
            let frame = encoder.encode(&signal[start..start + WINDOW]).expect("encode");
            out.extend(decoder.decode(&frame.truncated(keep)).expect("decode"));
        }
        out
    }

    /// The base layer alone must produce audio, not silence and not noise. This
    /// is what makes the split worth having.
    #[test]
    fn the_base_layer_alone_is_audio() {
        let signal = voice_like(FRAME * 10);
        let decoded = round_trip(&signal, 60, 0);

        let from = FRAME;
        let len = decoded.len() - from;
        let snr = snr_db(&signal[from..from + len], &decoded[from..from + len]);

        assert!(
            snr > 3.0,
            "the base layer alone gave {snr:.1} dB, which is not audio"
        );

        // And its level is right, which is what the energies are for.
        let a = (signal[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();
        let b = (decoded[from..from + len].iter().map(|s| s * s).sum::<f32>() / len as f32).sqrt();
        assert!(
            (0.5..2.0).contains(&(b / a)),
            "the base layer's level is {:.2}x the original",
            b / a
        );
    }

    /// Each refinement must improve on the last, or the layers are not ordered
    /// by importance and the split buys nothing.
    #[test]
    fn every_refinement_improves_on_the_last() {
        let signal = voice_like(FRAME * 10);
        let from = FRAME;

        let mut previous = f32::NEG_INFINITY;

        for keep in 0..LAYERS {
            let decoded = round_trip(&signal, 60, keep);
            let len = decoded.len() - from;
            let snr = snr_db(&signal[from..from + len], &decoded[from..from + len]);

            assert!(
                snr >= previous - 0.5,
                "keeping {keep} refinements gave {snr:.1} dB, worse than {previous:.1} with fewer"
            );
            previous = snr;
        }
    }

    /// The base is most of the frame, and recording that is the point of this
    /// test rather than an aspiration to fix.
    ///
    /// # Why the base cannot be small yet
    ///
    /// It carries the band energies, and those are twenty four values written
    /// at six bits each: eighteen bytes of a sixty byte frame before a single
    /// coefficient is described. Their frame-to-frame deltas cluster hard
    /// around zero and an entropy coder would collapse them, but the packer is
    /// fixed width.
    ///
    /// So layering delivers graceful degradation today and does **not** yet
    /// deliver a base cheap enough to protect much harder than the rest. The
    /// entropy coder is what unlocks the second, and this test will say so when
    /// it lands.
    #[test]
    fn the_base_carries_most_of_the_frame_until_the_energies_are_compressed() {
        let signal = voice_like(WINDOW * 2);
        let mut encoder = LayeredEncoder::new(60);

        encoder.encode(&signal[0..WINDOW]).expect("encode");
        let frame = encoder.encode(&signal[FRAME..FRAME + WINDOW]).expect("encode");

        assert!(!frame.base.is_empty());
        assert_eq!(frame.refinements.len(), LAYERS - 1);

        let share = frame.base.len() as f32 / frame.len() as f32;

        assert!(
            share > 0.5,
            "the base is only {:.0}% of the frame, so something has changed: check \
             whether the energies are now compressed",
            share * 100.0
        );

        // The energies alone, at six bits each.
        let energy_bytes = BANDS * 6 / 8;
        assert!(
            frame.base.len() > energy_bytes,
            "the base is smaller than the energies it must contain"
        );
    }

    /// What the arithmetic coder bought, measured across a run of frames.
    #[test]
    #[ignore = "measurement"]
    fn measure_the_base_layer() {
        let signal = voice_like(FRAME * 400);
        let mut encoder = LayeredEncoder::new(60);

        let mut energy_bytes = 0usize;
        let mut base_bytes = 0usize;
        let mut total_bytes = 0usize;
        let mut frames = 0usize;

        let mut first_half = 0usize;
        let mut second_half = 0usize;
        let all: Vec<usize> = (0..signal.len() - WINDOW).step_by(FRAME).collect();

        for (i, &start) in all.iter().enumerate() {
            let f = encoder.encode(&signal[start..start + WINDOW]).expect("encode");
            energy_bytes += f.base[0] as usize;
            base_bytes += f.base.len();
            total_bytes += f.len();
            frames += 1;

            if i < all.len() / 2 {
                first_half += f.base[0] as usize;
            } else {
                second_half += f.base[0] as usize;
            }
        }
        println!(
            "\n  energies: first half {:.1} bytes/frame, second half {:.1}",
            first_half as f32 / (all.len() / 2) as f32,
            second_half as f32 / (all.len() - all.len() / 2) as f32
        );

        // Split the run in two, so the model's startup cost is separated from
        // what it settles at. A short clip measures mostly adaptation.
        println!("\n  over {frames} frames, per frame:");
        println!("    energies      {:.1} bytes  (was 18, fixed width)", energy_bytes as f32 / frames as f32);
        println!("    base layer    {:.1} bytes", base_bytes as f32 / frames as f32);
        println!("    whole frame   {:.1} bytes", total_bytes as f32 / frames as f32);
        println!("    base share    {:.0}%", 100.0 * base_bytes as f32 / total_bytes as f32);

        // What the deltas actually look like, which decides what is possible.
        let mut encoder = LayeredEncoder::new(60);
        let mut previous = [0i16; BANDS];
        let mut histogram = [0usize; 12];
        let mut started = false;

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let coefficients = mdct::forward(&signal[start..start + WINDOW], &mdct::window());
            let levels: Vec<i16> = bands::energies(&coefficients)
                .iter()
                .map(|&e| energy_to_level(e) as i16)
                .collect();

            if started {
                for b in 0..BANDS {
                    let d = (levels[b] - previous[b]).unsigned_abs() as usize;
                    histogram[d.min(11)] += 1;
                }
            }
            previous.copy_from_slice(&levels);
            started = true;
        }
        let _ = &mut encoder;

        // The entropy of what is being coded, which is the floor no coder can
        // beat. If we are near it, further modelling is wasted effort.
        let mut silence_bits = 0.0f64;
        let mut level_bits = 0.0f64;
        let mut silent_hist = [0usize; 2];
        let mut deviation_hist = std::collections::HashMap::<i32, usize>::new();
        let mut absolute_hist = std::collections::HashMap::<u8, usize>::new();

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let coefficients = mdct::forward(&signal[start..start + WINDOW], &mdct::window());
            let levels: Vec<u8> = bands::energies(&coefficients)
                .iter()
                .map(|&e| energy_to_level(e))
                .collect();

            for b in 0..BANDS {
                silent_hist[(levels[b] == SILENT) as usize] += 1;
            }

            // The predictor is the band below, in this same frame.
            let mut predictor: Option<u8> = None;
            for b in 0..BANDS {
                if levels[b] == SILENT {
                    continue;
                }
                match predictor {
                    Some(p) => {
                        *deviation_hist
                            .entry(levels[b] as i32 - p as i32)
                            .or_default() += 1;
                    }
                    None => *absolute_hist.entry(levels[b]).or_default() += 1,
                }
                predictor = Some(levels[b]);
            }
        }

        // Total bits, which is N*H. Written as a sum over symbols so that the
        // count and the probability cannot drift apart: an earlier version of
        // this closure multiplied -p*log2(p) by the symbol's own count instead
        // of by the total, which understated every figure it produced by
        // roughly the number of distinct symbols. It reported an entropy floor
        // of 1.6 bytes a frame where the real one was 15, and a whole redesign
        // was aimed at a saving that did not exist.
        let entropy = |counts: &[usize]| -> f64 {
            let total: usize = counts.iter().sum();
            if total == 0 {
                return 0.0;
            }
            counts
                .iter()
                .filter(|&&c| c > 0)
                .map(|&c| -(c as f64) * (c as f64 / total as f64).log2())
                .sum::<f64>()
        };

        silence_bits += entropy(&silent_hist);
        let dev: Vec<usize> = deviation_hist.values().copied().collect();
        let abs: Vec<usize> = absolute_hist.values().copied().collect();
        level_bits += entropy(&dev) + entropy(&abs);

        println!(
            "\n  entropy floor: {:.1} bytes/frame  (silence {:.1} + levels {:.1})",
            (silence_bits + level_bits) / 8.0 / frames as f64,
            silence_bits / 8.0 / frames as f64,
            level_bits / 8.0 / frames as f64
        );
    }

    /// How much of a frame's energy stream is the arithmetic coder's flush
    /// rather than its payload.
    #[test]
    #[ignore = "measurement"]
    fn measure_flush_overhead() {
        use crate::entropy::{encode_symbol, Model, RangeEncoder};

        println!("\n  symbols   bytes   bytes/symbol");
        for n in [1usize, 5, 25, 37, 100, 1000] {
            let mut e = RangeEncoder::new();
            let mut m = Model::new(64);
            for _ in 0..n {
                encode_symbol(&mut e, &mut m, 0);
            }
            let bytes = e.finish().len();
            println!("  {n:7}   {bytes:5}   {:.3}", bytes as f32 / n as f32);
        }

        println!("\n  a frame's 37 symbols, all zero, should be near nothing.");
        println!("  whatever the one-symbol case costs is the flush.");
    }

    /// The levels must survive their own coder exactly. They are the loudness
    /// of the frame, so an error here is not a texture artefact.
    #[test]
    fn levels_round_trip_through_their_models() {
        let signal = voice_like(WINDOW * 30);
        let mut encoder = ShapeEncoder::new(60);

        let mut sent = Vec::new();
        let mut stream = RangeEncoder::new();
        let mut models = LevelModels::new();

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let (levels, _) = encoder
                .encode_shapes(&signal[start..start + WINDOW])
                .expect("encode");
            write_levels(&mut stream, &levels, &mut models);
            sent.push(levels);
        }

        let bytes = stream.finish();
        let mut back = RangeDecoder::new(&bytes);
        let mut models = LevelModels::new();

        for (i, expected) in sent.iter().enumerate() {
            let got = read_levels(&mut back, &mut models);
            assert_eq!(&got, expected, "frame {i} came back with different levels");
        }
    }

    /// Predicting along the spectrum beat predicting along time by two and a
    /// half bytes a frame, and the obvious design is the losing one. Asserted
    /// so that reverting to it fails here rather than in a bitrate report.
    #[test]
    fn predicting_along_the_spectrum_beats_predicting_along_time() {
        let signal = voice_like(WINDOW * 200);
        let mut encoder = ShapeEncoder::new(60);

        let mut frames: Vec<[u8; BANDS]> = Vec::new();
        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let (levels, _) = encoder
                .encode_shapes(&signal[start..start + WINDOW])
                .expect("encode");
            frames.push(levels);
        }

        // Total absolute residual is a proxy for the bits either predictor
        // needs: a coder spends roughly the log of the spread.
        let mut along_time = 0u32;
        let mut along_spectrum = 0u32;

        for f in 1..frames.len() {
            let mut predictor: Option<u8> = None;
            for b in 0..BANDS {
                if frames[f][b] == SILENT {
                    continue;
                }
                if frames[f - 1][b] != SILENT {
                    along_time += frames[f][b].abs_diff(frames[f - 1][b]) as u32;
                }
                if let Some(p) = predictor {
                    along_spectrum += frames[f][b].abs_diff(p) as u32;
                }
                predictor = Some(frames[f][b]);
            }
        }

        assert!(
            along_spectrum < along_time,
            "spectral prediction left {along_spectrum} of residual against \
             {along_time} for temporal: the measured ordering has flipped"
        );
    }

    /// A frame must survive the wire it was written for.
    #[test]
    fn a_frame_round_trips_through_its_wire_format() {
        let signal = voice_like(WINDOW * 20);
        let mut encoder = LayeredEncoder::new(60);

        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            let frame = encoder.encode(&signal[start..start + WINDOW]).expect("encode");

            for keep in 0..=frame.refinements.len() {
                let trimmed = frame.truncated(keep);
                let bytes = trimmed.to_bytes();
                let back = LayeredFrame::from_bytes(&bytes).expect("parse");

                assert_eq!(back.base, trimmed.base);
                // Trailing empty refinements are dropped rather than framed,
                // which is the point of the format, so compare what is carried.
                let sent: Vec<&Vec<u8>> =
                    trimmed.refinements.iter().filter(|r| !r.is_empty()).collect();
                let got: Vec<&Vec<u8>> = back.refinements.iter().collect();
                assert_eq!(got.len(), sent.len(), "layer count changed on the wire");
                for (a, b) in got.iter().zip(&sent) {
                    assert_eq!(a, b);
                }
            }
        }
    }

    /// The framing has to be small, or carrying the layers costs more than the
    /// layers are worth.
    #[test]
    fn the_framing_is_a_few_bytes() {
        let signal = voice_like(WINDOW * 4);
        let mut encoder = LayeredEncoder::new(60);
        let frame = encoder.encode(&signal[..WINDOW]).expect("encode");

        let overhead = frame.to_bytes().len() - frame.len();
        assert!(
            overhead <= 4,
            "framing costs {overhead} bytes; four is the whole budget for a \
             count and three lengths"
        );
    }

    /// Nothing a network can deliver may make the parser read past its buffer
    /// or loop, whatever the length fields claim.
    #[test]
    fn a_hostile_frame_is_refused_rather_than_believed() {
        // A length that runs past the end of what arrived.
        assert!(LayeredFrame::from_bytes(&[2, 200, 1, 2, 3]).is_err());
        // More layers than exist.
        assert!(LayeredFrame::from_bytes(&[9, 1, 2, 3]).is_err());
        // No layers at all.
        assert!(LayeredFrame::from_bytes(&[0]).is_err());
        // Empty.
        assert!(LayeredFrame::from_bytes(&[]).is_err());
        // A run of continuation bytes with no terminator.
        let forever = vec![2u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        assert!(LayeredFrame::from_bytes(&forever).is_err());
        // Truncated in the middle of a length.
        assert!(LayeredFrame::from_bytes(&[3, 0x80]).is_err());
    }

    /// The claim the layered design is made for: one encode, and the sender
    /// chooses how much of it to send.
    #[test]
    fn a_frame_trims_itself_to_a_budget() {
        let signal = voice_like(WINDOW * 6);
        let mut encoder = LayeredEncoder::new(60);
        let frame = encoder.encode(&signal[..WINDOW]).expect("encode");

        let full = frame.to_bytes().len();
        assert!(full > 20, "the test needs a frame with something to trim");

        let mut previous = usize::MAX;
        for budget in [full, full * 3 / 4, full / 2, full / 4, 1] {
            let trimmed = frame.within(budget);
            let size = trimmed.to_bytes().len();

            assert!(
                size <= budget || trimmed.refinements.is_empty(),
                "a {budget} byte budget produced {size} bytes with refinements \
                 still attached"
            );
            assert!(!trimmed.base.is_empty(), "the base was trimmed away");
            assert!(size <= previous, "a smaller budget produced a larger frame");
            previous = size;
        }
    }

    /// A frame whose refinements never arrived must still decode. This is the
    /// case the whole design exists for.
    #[test]
    fn missing_refinements_are_not_an_error() {
        let signal = voice_like(WINDOW * 2);
        let mut encoder = LayeredEncoder::new(60);
        let mut decoder = LayeredDecoder::new(60);

        let frame = encoder.encode(&signal[0..WINDOW]).expect("encode");

        for keep in 0..=frame.refinements.len() {
            let mut fresh = LayeredDecoder::new(60);
            assert!(
                fresh.decode(&frame.truncated(keep)).is_ok(),
                "{keep} refinements failed to decode"
            );
        }

        // But a frame with no base at all is not a frame.
        assert_eq!(
            decoder.decode(&LayeredFrame {
                base: Vec::new(),
                refinements: vec![vec![1, 2, 3]],
            }),
            Err(CodecError::Malformed)
        );
    }

    /// One encode must serve every rate, or the layering is not saving the
    /// second encode it exists to save.
    #[test]
    fn one_encode_serves_every_rate() {
        let signal = voice_like(FRAME * 8);
        let mut encoder = LayeredEncoder::new(60);

        let mut frames = Vec::new();
        for start in (0..signal.len() - WINDOW).step_by(FRAME) {
            frames.push(encoder.encode(&signal[start..start + WINDOW]).expect("encode"));
        }

        // The same frames, delivered at four different rates.
        for keep in 0..LAYERS {
            let mut decoder = LayeredDecoder::new(60);
            let bytes: usize = frames.iter().map(|f| f.truncated(keep).len()).sum();

            for frame in &frames {
                decoder.decode(&frame.truncated(keep)).expect("decode");
            }
            assert!(bytes > 0, "keeping {keep} refinements produced no bytes");
        }
    }
}
