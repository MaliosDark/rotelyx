//! Arithmetic coding, and a model of what the codec actually emits.
//!
//! # What a fixed width packer was costing
//!
//! The band energies are twenty four numbers per frame, written at six bits
//! each: eighteen bytes of a sixty byte frame before a single coefficient is
//! described. That is why the base layer is 85 percent of a frame and cannot be
//! protected any harder than the refinements it is supposed to outrank.
//!
//! Six bits each is the right size for a value that could be anything. These
//! cannot. A band's level moves slowly, so the frame-to-frame delta is almost
//! always zero or one, and six bits spends the same amount saying "unchanged"
//! as saying "thirty one louder".
//!
//! # Why arithmetic coding rather than a prefix code
//!
//! A Huffman code cannot spend less than one bit on a symbol. "Unchanged" is
//! common enough here that one bit is already too many, and there are twenty
//! four of them per frame. Arithmetic coding has no such floor: a symbol with
//! probability 0.7 costs 0.51 bits, and fractions accumulate across symbols
//! rather than rounding up at each one.
//!
//! # The model adapts and is never transmitted
//!
//! Counts start uniform and are updated after every symbol. The decoder makes
//! exactly the same updates from the symbols it has already decoded, so the two
//! stay in step without a table on the wire. The cost is that the first frames
//! of a stream are coded against a model that has not learned anything yet,
//! which is a few dozen bits once per conversation.

/// Range below which the coder renormalises.
const TOP: u32 = 1 << 24;

/// The largest total frequency a model may have.
///
/// Two things at once, and the second is the one that was nearly missed.
///
/// It bounds the range arithmetic's precision, which is why any value well
/// under 2^16 is safe.
///
/// It also sets **how entrenched a model may become**, and therefore how
/// quickly it can change its mind. Halving the counts preserves their ratios,
/// so it caps memory without making the model forget; what actually decides
/// adaptivity is how large a count can grow relative to the increment. Measured
/// on a source that switches symbol abruptly:
///
/// | Total | Cost of a switch | Cost of an incompressible source |
/// |---|---|---|
/// | 65536 | 500 bytes | 1.008 bits/symbol |
/// | 8192 | 82 bytes | 1.011 |
/// | **2048** | **29 bytes** | **1.024** |
/// | 512 | 30 bytes | 1.076 |
///
/// 2048 is seventeen times better on a change of character for 1.6 percent on
/// the case nothing can help. Speech changes character far faster than the
/// larger windows allow for.
pub const MAX_TOTAL: u32 = 2048;

/// Writes symbols as an arithmetic code.
pub struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl Default for RangeEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeEncoder {
    pub fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    /// Encode a symbol occupying `[cum, cum + freq)` out of `total`.
    pub fn encode(&mut self, cum: u32, freq: u32, total: u32) {
        debug_assert!(freq > 0, "a symbol with no probability cannot be encoded");
        debug_assert!(cum + freq <= total);
        debug_assert!(total <= MAX_TOTAL);

        let r = self.range / total;
        self.low += (r as u64) * (cum as u64);
        self.range = r * freq;

        while self.range < TOP {
            self.shift();
            self.range <<= 8;
        }
    }

    /// Push one byte out, resolving any pending carry.
    ///
    /// The carry is what makes a range coder fiddly: adding to `low` can
    /// overflow into bytes already emitted. Holding the last byte back, and
    /// counting how many `0xff` bytes are queued behind it, means a carry can
    /// still reach them.
    fn shift(&mut self) {
        let carry = (self.low >> 32) as u8;

        // A byte can leave only once it is certain no later addition will carry
        // into it. That is true when the low 32 bits are below 0xFF000000, or
        // when a carry has just happened and resolved everything queued behind
        // it.
        //
        // The condition was written as a range test on the whole 64 bit `low`
        // first, which is not the same thing: it let bytes out while a carry
        // was still possible and, worse, held them back when one was not, so
        // the encoder emitted far more than it needed to. Two constant runs of
        // three thousand symbols came to five hundred bytes instead of five.
        if carry != 0 || (self.low as u32) < 0xff00_0000 {
            self.out.push(self.cache.wrapping_add(carry));

            while self.cache_size > 1 {
                self.out.push(0xffu8.wrapping_add(carry));
                self.cache_size -= 1;
            }

            self.cache = (self.low >> 24) as u8;
            self.cache_size = 0;
        }
        self.cache_size += 1;
        self.low = ((self.low as u32) << 8) as u64;
    }

    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift();
        }
        // The first byte is the initial cache, which was never real output.
        if !self.out.is_empty() {
            self.out.remove(0);
        }
        self.out
    }

    /// Bytes emitted so far. Approximate while a symbol is in flight, which is
    /// all a rate controller needs.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }
}

/// Reads symbols back.
pub struct RangeDecoder<'a> {
    code: u32,
    range: u32,
    input: &'a [u8],
    position: usize,
}

impl<'a> RangeDecoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        let mut d = Self {
            code: 0,
            range: u32::MAX,
            input,
            position: 0,
        };
        for _ in 0..4 {
            d.code = (d.code << 8) | d.next() as u32;
        }
        d
    }

    /// Past the end reads as zero. A truncated frame then decodes to something
    /// rather than failing, which is what every other short-data path in this
    /// codec does.
    fn next(&mut self) -> u8 {
        let b = self.input.get(self.position).copied().unwrap_or(0);
        self.position += 1;
        b
    }

    /// Where in `total` the next symbol falls. The caller looks this up in its
    /// model and then calls [`RangeDecoder::update`].
    pub fn target(&mut self, total: u32) -> u32 {
        debug_assert!(total <= MAX_TOTAL);
        self.range /= total;
        (self.code / self.range).min(total - 1)
    }

    /// Consume the symbol found at `[cum, cum + freq)`.
    pub fn update(&mut self, cum: u32, freq: u32) {
        self.code -= cum * self.range;
        self.range *= freq;

        while self.range < TOP {
            self.code = (self.code << 8) | self.next() as u32;
            self.range <<= 8;
        }
    }
}

/// An adaptive frequency model over a small alphabet.
///
/// Counts start at one so nothing is impossible, which matters: a symbol the
/// model has never seen must still be codeable, and a zero frequency cannot be.
pub struct Model {
    counts: Vec<u32>,
    total: u32,
}

impl Model {
    pub fn new(symbols: usize) -> Self {
        Self {
            counts: vec![1; symbols],
            total: symbols as u32,
        }
    }

    /// Cumulative frequency below `symbol`, and its own frequency.
    pub fn range_of(&self, symbol: usize) -> (u32, u32) {
        let cum: u32 = self.counts[..symbol].iter().sum();
        (cum, self.counts[symbol])
    }

    /// Which symbol `target` falls in.
    pub fn symbol_at(&self, target: u32) -> (usize, u32, u32) {
        let mut cum = 0u32;

        for (symbol, &count) in self.counts.iter().enumerate() {
            if target < cum + count {
                return (symbol, cum, count);
            }
            cum += count;
        }
        let last = self.counts.len() - 1;
        (last, self.total - self.counts[last], self.counts[last])
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    /// Make `symbol` more likely next time.
    ///
    /// Halving when the total grows too large is what keeps the model
    /// responsive: without it, a thousand frames of history drown out the last
    /// ten, and speech changes character far faster than that.
    pub fn update(&mut self, symbol: usize) {
        self.counts[symbol] += 24;
        self.total += 24;

        if self.total >= MAX_TOTAL {
            self.total = 0;
            for c in self.counts.iter_mut() {
                *c = (*c >> 1).max(1);
                self.total += *c;
            }
        }
    }
}

/// Encode a symbol and adapt.
pub fn encode_symbol(encoder: &mut RangeEncoder, model: &mut Model, symbol: usize) {
    let (cum, freq) = model.range_of(symbol);
    encoder.encode(cum, freq, model.total());
    model.update(symbol);
}

/// Decode a symbol and adapt.
pub fn decode_symbol(decoder: &mut RangeDecoder, model: &mut Model) -> usize {
    let target = decoder.target(model.total());
    let (symbol, cum, freq) = model.symbol_at(target);

    decoder.update(cum, freq);
    model.update(symbol);
    symbol
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random sequence, so a failure is reproducible.
    fn sequence(n: usize, alphabet: usize, skew: bool) -> Vec<usize> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;

                if skew {
                    // Mostly zero, as an energy delta stream is. Clamped to the
                    // alphabet, because a generator that emits a symbol the
                    // model has no slot for tests the test rather than the
                    // coder.
                    let s = match state % 100 {
                        0..=59 => 0,
                        60..=79 => 1,
                        80..=89 => 2,
                        _ => (state % alphabet as u64) as usize,
                    };
                    s.min(alphabet - 1)
                } else {
                    (state % alphabet as u64) as usize
                }
            })
            .collect()
    }

    #[test]
    fn symbols_round_trip() {
        for alphabet in [2usize, 8, 64] {
            for skew in [false, true] {
                let symbols = sequence(2_000, alphabet, skew);

                let mut encoder = RangeEncoder::new();
                let mut model = Model::new(alphabet);
                for &s in &symbols {
                    encode_symbol(&mut encoder, &mut model, s);
                }
                let bytes = encoder.finish();

                let mut decoder = RangeDecoder::new(&bytes);
                let mut model = Model::new(alphabet);
                for (i, &expected) in symbols.iter().enumerate() {
                    assert_eq!(
                        decode_symbol(&mut decoder, &mut model),
                        expected,
                        "alphabet {alphabet}, skew {skew}: symbol {i}"
                    );
                }
            }
        }
    }

    /// The whole point: a skewed source must cost far less than its fixed
    /// width, and less than one bit per symbol where the symbol is common.
    #[test]
    fn a_skewed_source_costs_less_than_its_width() {
        let symbols = sequence(4_000, 64, true);

        let mut encoder = RangeEncoder::new();
        let mut model = Model::new(64);
        for &s in &symbols {
            encode_symbol(&mut encoder, &mut model, s);
        }
        let coded = encoder.finish().len();

        let fixed = symbols.len() * 6 / 8;

        assert!(
            coded < fixed / 2,
            "a source that is 60% zeroes took {coded} bytes against {fixed} fixed width, \
             which is not enough of a saving to be worth an arithmetic coder"
        );

        let bits_per_symbol = coded as f32 * 8.0 / symbols.len() as f32;
        assert!(
            bits_per_symbol < 2.5,
            "{bits_per_symbol:.2} bits per symbol on a heavily skewed source"
        );
    }

    /// A uniform source must not cost much more than its width, or the coder
    /// is losing on the case it cannot help.
    #[test]
    fn a_uniform_source_costs_about_its_width() {
        let symbols = sequence(4_000, 64, false);

        let mut encoder = RangeEncoder::new();
        let mut model = Model::new(64);
        for &s in &symbols {
            encode_symbol(&mut encoder, &mut model, s);
        }
        let coded = encoder.finish().len();
        let fixed = symbols.len() * 6 / 8;

        assert!(
            coded < fixed + fixed / 10,
            "a uniform source cost {coded} bytes against {fixed} fixed width"
        );
    }

    /// The model must follow a source that changes, or a long recording is
    /// coded against the statistics of its opening.
    #[test]
    fn the_model_follows_a_changing_source() {
        let mut symbols: Vec<usize> = vec![0; 3_000];
        symbols.extend(std::iter::repeat_n(7usize, 3_000));

        let mut encoder = RangeEncoder::new();
        let mut model = Model::new(8);
        for &s in &symbols {
            encode_symbol(&mut encoder, &mut model, s);
        }
        let coded = encoder.finish().len();

        // Two long runs of one symbol each cost almost nothing, and the switch
        // between them costs the model a moment to change its mind. Measured at
        // 29 bytes; the bound is loose enough to survive tuning and tight
        // enough to catch a model that stops adapting.
        assert!(
            coded < 60,
            "two constant runs cost {coded} bytes, so the model is not adapting"
        );

        let bytes = encoder_bytes(&symbols);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut model = Model::new(8);
        for (i, &expected) in symbols.iter().enumerate() {
            assert_eq!(decode_symbol(&mut decoder, &mut model), expected, "symbol {i}");
        }
    }

    fn encoder_bytes(symbols: &[usize]) -> Vec<u8> {
        let mut encoder = RangeEncoder::new();
        let mut model = Model::new(8);
        for &s in symbols {
            encode_symbol(&mut encoder, &mut model, s);
        }
        encoder.finish()
    }

    #[test]
    #[ignore = "measurement"]
    fn measure_adaptation() {
        for (name, symbols) in [
            ("3000 zeroes", vec![0usize; 3_000]),
            ("6000 zeroes", vec![0usize; 6_000]),
            ("3000 sevens alone", vec![7usize; 3_000]),
            ("100 zeroes then 3000 sevens", {
                let mut v = vec![0usize; 100];
                v.extend(std::iter::repeat_n(7usize, 3_000));
                v
            }),
            ("3000 zeroes then 3000 sevens", {
                let mut v = vec![0usize; 3_000];
                v.extend(std::iter::repeat_n(7usize, 3_000));
                v
            }),
            ("alternating 0 and 7", (0..6_000).map(|i| if i % 2 == 0 { 0usize } else { 7 }).collect()),
        ] {
            let bytes = encoder_bytes(&symbols).len();
            println!(
                "  {name:32}  {bytes:5} bytes  {:.3} bits/symbol",
                bytes as f32 * 8.0 / symbols.len() as f32
            );
        }
    }

    /// A truncated stream must decode to something rather than panic. A frame
    /// can arrive short and one rough band beats a dead decoder.
    #[test]
    fn a_truncated_stream_is_survivable() {
        let symbols = sequence(500, 8, true);
        let bytes = encoder_bytes(&symbols);

        for cut in [0usize, 1, 5, bytes.len() / 2] {
            let mut decoder = RangeDecoder::new(&bytes[..cut.min(bytes.len())]);
            let mut model = Model::new(8);

            for _ in 0..symbols.len() {
                let s = decode_symbol(&mut decoder, &mut model);
                assert!(s < 8, "a truncated stream produced symbol {s}");
            }
        }
    }

    /// Every symbol must remain codeable however lopsided the model becomes.
    #[test]
    fn no_symbol_ever_becomes_impossible() {
        let mut model = Model::new(16);

        for _ in 0..100_000 {
            model.update(3);
        }

        for symbol in 0..16 {
            let (_, freq) = model.range_of(symbol);
            assert!(freq > 0, "symbol {symbol} became impossible to code");
        }
        assert!(model.total() < MAX_TOTAL);
    }
}
