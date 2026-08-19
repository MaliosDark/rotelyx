//! Packing bits into a frame.
//!
//! # What this is, and what it is not yet
//!
//! A plain bit packer: values go in at a fixed width and come out the same way.
//! No entropy coding, no probability model, no arithmetic.
//!
//! That is a deliberate first step rather than an oversight. A codec's format
//! has to be settled before its entropy coder is worth writing, because every
//! change to what is coded changes what the model should be. Getting the
//! transform, the bands and the allocation right against measurable numbers
//! comes first; squeezing the last twenty percent out of the result comes after,
//! and it is the part that does not change how anything sounds.
//!
//! Where the twenty percent is: energy deltas between adjacent frames are
//! overwhelmingly small, and coefficient signs are near enough uniform that
//! they are already incompressible. An arithmetic coder over a model of those
//! deltas is the obvious next move, and it is arithmetic rather than design.

/// Writes values into a byte buffer, most significant bit first.
#[derive(Default)]
pub struct Encoder {
    bytes: Vec<u8>,
    /// Bits used in the byte currently being filled.
    partial: u8,
    partial_bits: u8,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write the low `count` bits of `value`.
    pub fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.partial = (self.partial << 1) | bit;
            self.partial_bits += 1;

            if self.partial_bits == 8 {
                self.bytes.push(self.partial);
                self.partial = 0;
                self.partial_bits = 0;
            }
        }
    }

    /// Write a signed value in `count` bits, centred so that zero is cheap.
    ///
    /// Zig-zag folded: 0, -1, 1, -2, 2 become 0, 1, 2, 3, 4. Energy deltas
    /// between adjacent frames cluster hard around zero, and a two's complement
    /// representation would put the most common values at both ends of the
    /// range where no model can exploit them.
    pub fn write_signed(&mut self, value: i16, count: usize) {
        let folded = if value >= 0 {
            (value as u32) * 2
        } else {
            ((-(value as i32)) as u32) * 2 - 1
        };

        let max = (1u32 << count) - 1;
        self.write_bits(folded.min(max), count);
    }

    /// Bits written so far, including the partly filled byte.
    pub fn len_bits(&self) -> usize {
        self.bytes.len() * 8 + self.partial_bits as usize
    }

    /// Finish, padding the last byte with zeroes.
    pub fn finish(mut self) -> Vec<u8> {
        if self.partial_bits > 0 {
            self.bytes.push(self.partial << (8 - self.partial_bits));
        }
        self.bytes
    }
}

/// Reads values back.
///
/// Reading past the end yields zeroes rather than failing. A frame is a fixed
/// size and the allocation decides how much of it is meaningful, so a decoder
/// that ran out has been handed a frame that disagrees with its own allocation:
/// returning zeroes degrades that band to noise at the right level, which is
/// what every other under-budget path here does.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn read_bits(&mut self, count: usize) -> u32 {
        let mut value = 0u32;

        for _ in 0..count {
            let byte = self.position / 8;
            let bit = 7 - (self.position % 8);

            let b = if byte < self.bytes.len() {
                (self.bytes[byte] >> bit) & 1
            } else {
                0
            };

            value = (value << 1) | b as u32;
            self.position += 1;
        }
        value
    }

    /// Read a value written by [`Encoder::write_signed`].
    pub fn read_signed(&mut self, count: usize) -> i16 {
        let folded = self.read_bits(count);

        if folded % 2 == 0 {
            (folded / 2) as i16
        } else {
            -(((folded + 1) / 2) as i16)
        }
    }

    pub fn position_bits(&self) -> usize {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        let mut encoder = Encoder::new();
        let values = [(5u32, 3usize), (0, 1), (1, 1), (63, 6), (1000, 12), (0, 8)];

        for &(value, bits) in &values {
            encoder.write_bits(value, bits);
        }

        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes);

        for &(value, bits) in &values {
            assert_eq!(decoder.read_bits(bits), value, "{value} in {bits} bits");
        }
    }

    /// Energy deltas are signed and cluster at zero, so the folding has to be
    /// exact in both directions.
    #[test]
    fn signed_values_round_trip() {
        let mut encoder = Encoder::new();
        let values: Vec<i16> = vec![0, -1, 1, -2, 2, -15, 15, -31, 31];

        for &v in &values {
            encoder.write_signed(v, 6);
        }

        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes);

        for &v in &values {
            assert_eq!(decoder.read_signed(6), v, "{v} did not survive folding");
        }
    }

    /// Zero must be the cheapest value to represent, since it is the common
    /// one. This is the whole reason for folding.
    #[test]
    fn zero_folds_to_zero() {
        let mut encoder = Encoder::new();
        encoder.write_signed(0, 6);
        assert_eq!(encoder.finish()[0] >> 2, 0);
    }

    /// Reading past the end must be quiet, because that path is reachable from
    /// a frame whose allocation disagrees with its contents.
    #[test]
    fn reading_past_the_end_yields_zeroes() {
        let mut decoder = Decoder::new(&[0xff, 0xff]);

        assert_eq!(decoder.read_bits(16), 0xffff);
        assert_eq!(decoder.read_bits(8), 0, "past the end must be zero, not a panic");
        assert_eq!(decoder.position_bits(), 24);
    }

    #[test]
    fn the_bit_count_is_accurate() {
        let mut encoder = Encoder::new();
        assert_eq!(encoder.len_bits(), 0);

        encoder.write_bits(1, 3);
        assert_eq!(encoder.len_bits(), 3);

        encoder.write_bits(1, 6);
        assert_eq!(encoder.len_bits(), 9);

        assert_eq!(encoder.finish().len(), 2, "9 bits is two bytes");
    }
}
