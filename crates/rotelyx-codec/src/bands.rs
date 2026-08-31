//! Splitting the spectrum the way hearing does.
//!
//! # Why not uniform bands
//!
//! The ear does not resolve frequency evenly. It separates 200 Hz from 300 Hz
//! easily and 8000 Hz from 8100 Hz not at all, so bits spent describing the top
//! of the spectrum precisely are bits nobody can hear. Every transform codec
//! worth using groups coefficients into bands that widen with frequency, and
//! this one is no exception.
//!
//! # What is kept per band, and why in two parts
//!
//! Each band is described as an **energy** and a **shape**: how loud, and how
//! that loudness is distributed inside the band.
//!
//! The split is what makes the codec robust rather than merely small. Energy is
//! cheap, perceptually dominant, and coded accurately. Shape is expensive and
//! perceptually forgiving, so it takes whatever bits are left. When bits run
//! out the result is a band with the right loudness and an approximate texture,
//! which sounds like a slightly rough version of the original. Coding a band as
//! one number and letting its level drift sounds like something else entirely.
//!
//! This separation is CELT's, and it is taken deliberately: it is a good idea
//! that is published, understood, and not improved by being reinvented.

use crate::mdct::{FRAME, SAMPLE_RATE};

/// Band edges in MDCT bins.
///
/// Roughly Bark spaced: narrow where hearing is sharp, wide where it is not.
/// At 25 Hz per bin, the first band is 0 to 300 Hz and the last spans several
/// kilohertz.
pub const EDGES: &[usize] = &[
    0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 68, 80, 96, 120, 152, 192, 240, 300, 380, 480,
    600, 760, 960,
];

/// How many bands there are.
pub const BANDS: usize = EDGES.len() - 1;

/// The bins in band `b`.
pub fn range(b: usize) -> std::ops::Range<usize> {
    EDGES[b]..EDGES[b + 1]
}

/// The frequency band `b` covers, in hertz. For documentation and tests.
pub fn hz(b: usize) -> (f32, f32) {
    let per_bin = SAMPLE_RATE as f32 / (2.0 * FRAME as f32);
    (EDGES[b] as f32 * per_bin, EDGES[b + 1] as f32 * per_bin)
}

/// The root-mean-square level of each band.
pub fn energies(coefficients: &[f32]) -> Vec<f32> {
    assert_eq!(coefficients.len(), FRAME);

    (0..BANDS)
        .map(|b| {
            let bins = &coefficients[range(b)];
            (bins.iter().map(|c| c * c).sum::<f32>() / bins.len() as f32).sqrt()
        })
        .collect()
}

/// Divide each band by its own level, leaving only shape.
///
/// A silent band has no shape to normalise and is left at zero rather than
/// divided by nothing.
pub fn normalise(coefficients: &[f32], energies: &[f32]) -> Vec<f32> {
    let mut out = coefficients.to_vec();

    for b in 0..BANDS {
        let e = energies[b];
        if e > 1e-9 {
            for c in &mut out[range(b)] {
                *c /= e;
            }
        } else {
            out[range(b)].fill(0.0);
        }
    }
    out
}

/// Put the levels back.
pub fn denormalise(shape: &[f32], energies: &[f32]) -> Vec<f32> {
    let mut out = shape.to_vec();

    for b in 0..BANDS {
        for c in &mut out[range(b)] {
            *c *= energies[b];
        }
    }
    out
}

/// How many bits each band's shape is worth.
///
/// # Reverse water-filling, not a proportional share
///
/// Two earlier versions were wrong in opposite directions and the second is
/// worth recording, because its failure was invisible.
///
/// The first spread the budget proportionally across every band. At a third of
/// a bit per coefficient no band reached even one bit each, every band fell
/// through to noise filling, and the entire budget bought nothing.
///
/// The second funded bands whole, best claim first. That produced audio, and a
/// rate/quality curve that **went backwards**: 32 kbit/s measured worse than
/// 24, because the extra budget was exactly enough to promote one wide
/// high-frequency band, which took its bits from the narrow ones where speech
/// is understood.
///
/// This one allocates in increments and chooses each increment by what it
/// actually buys. For a transform coder the distortion in a band falls roughly
/// as `E² · 4^-r` with `r` bits per coefficient, so the value of the next
/// increment is `E² · 4^-r`, and notably **not** scaled by the band's width,
/// because a wider band costs proportionally more bits for the same `r`. That
/// cancellation is the whole reason a wide band can no longer buy its way in
/// ahead of a narrow one.
///
/// The classical name for this is reverse water-filling. It is a known result
/// rather than something invented here, and the earlier versions are two ways
/// of getting it wrong that looked reasonable while being written.
pub fn allocate(energies: &[f32], total_bits: usize) -> Vec<usize> {
    // Bits per coefficient, per band.
    let mut rate = [0usize; BANDS];
    let mut left = total_bits;

    // Perceptual weight. Speech is understood below about three kilohertz, so
    // an error there costs more than the same error above it. A gentle slope
    // rather than a cliff: the top of the spectrum is timbre, not nothing.
    let weight: Vec<f32> = (0..BANDS)
        .map(|b| {
            let (_, top) = hz(b);
            if top <= 3_000.0 {
                1.0
            } else {
                (3_000.0 / top).powf(0.5)
            }
        })
        .collect();

    // What the next bit per coefficient is worth in band `b`.
    let value = |b: usize, rate: &[usize]| -> f32 {
        let e = energies[b];
        if e < 1e-5 {
            return 0.0;
        }
        // The ceiling exists because PVQ's pulse count is bounded, not because
        // extra bits stop helping. It was four while the shape quantiser was
        // scalar, and leaving it there after PVQ arrived capped quality at
        // 24 kbit/s: every higher rate measured identically, because the extra
        // budget had nowhere to go.
        if rate[b] >= 12 {
            return 0.0;
        }
        weight[b] * e * e * 4f32.powi(-(rate[b] as i32))
    };

    // The order of increments is decided **without reference to the budget**,
    // and the budget then takes a prefix of it.
    //
    // Skipping an increment that does not fit and carrying on to a cheaper one
    // is the obvious thing to write and it is what makes the result
    // non-monotonic: a larger budget affords an expensive increment early,
    // which consumes room a cheap one had at the smaller budget, and a band can
    // end up with fewer bits than it had before. Taking a strict prefix cannot
    // do that. It wastes at most one band's cost at the tail, which is the
    // price of the guarantee.
    let mut order = Vec::new();
    let mut planning = vec![0usize; BANDS];

    loop {
        let mut best = None;
        let mut best_value = 0.0f32;

        for b in 0..BANDS {
            let v = value(b, &planning);
            if v > best_value {
                best_value = v;
                best = Some(b);
            }
        }

        match best {
            Some(b) => {
                planning[b] += 1;
                order.push(b);
            }
            None => break,
        }
    }

    // Walk the order and take what fits, passing over what does not.
    //
    // Stopping at the first unaffordable increment would make the allocation
    // monotone band by band, and it stalls: one wide band standing at the head
    // of the queue with no room for it wastes the whole remaining budget. What
    // has to be monotone is the **quality**, not the bits in any particular
    // band, and that is asserted end to end in `lib.rs` rather than assumed
    // here.
    for b in order {
        let cost = range(b).len();
        if cost <= left {
            rate[b] += 1;
            left -= cost;
        }
    }

    (0..BANDS).map(|b| rate[b] * range(b).len()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bands_cover_the_spectrum_without_gaps() {
        assert_eq!(EDGES[0], 0);
        assert_eq!(*EDGES.last().expect("non-empty"), FRAME);

        for pair in EDGES.windows(2) {
            assert!(pair[1] > pair[0], "band edges must increase: {pair:?}");
        }
    }

    /// Bands must widen with frequency, or the split is not doing the one thing
    /// it exists for.
    #[test]
    fn bands_widen_with_frequency() {
        let low = range(0).len();
        let high = range(BANDS - 1).len();

        assert!(
            high > low * 20,
            "the top band is {high} bins against {low} at the bottom, which is not \
             following hearing at all"
        );

        // And the first band covers the frequencies speech lives in.
        let (start, end) = hz(0);
        assert_eq!(start, 0.0);
        assert!(
            end <= 150.0,
            "the first band reaches {end} Hz, too coarse for pitch"
        );
    }

    /// Normalising and putting the levels back must return the signal, or the
    /// split has lost information before any quantiser has touched it.
    #[test]
    fn normalising_round_trips() {
        let coefficients: Vec<f32> = (0..FRAME)
            .map(|n| ((n * 7919) % 1000) as f32 / 500.0 - 1.0)
            .collect();

        let e = energies(&coefficients);
        let back = denormalise(&normalise(&coefficients, &e), &e);

        for (i, (a, b)) in coefficients.iter().zip(&back).enumerate() {
            assert!((a - b).abs() < 1e-4, "bin {i}: {a} came back as {b}");
        }
    }

    /// A silent band must not produce infinities.
    #[test]
    fn silence_does_not_divide_by_nothing() {
        let mut coefficients = vec![0.0f32; FRAME];
        coefficients[500] = 1.0; // one band has content, the rest are silent

        let e = energies(&coefficients);
        let shape = normalise(&coefficients, &e);

        assert!(
            shape.iter().all(|c| c.is_finite()),
            "a silent band produced a non-finite shape"
        );
    }

    /// A band that gets bits must get enough to be worth anything: at least a
    /// sign per coefficient. This is the failure the first allocator had.
    #[test]
    fn a_funded_band_gets_at_least_a_sign_per_coefficient() {
        let e = vec![0.5f32; BANDS];
        let bits = allocate(&e, 336); // what 24 kbit/s actually leaves

        let mut funded = 0;
        for (b, &given) in bits.iter().enumerate() {
            if given > 0 {
                assert!(
                    given >= range(b).len(),
                    "band {b} got {given} bits for {} coefficients, which buys nothing",
                    range(b).len()
                );
                funded += 1;
            }
        }
        assert!(funded > 8, "only {funded} bands were funded at all");
    }

    /// The budget must not be exceeded, or frames overflow their size.
    #[test]
    fn allocation_never_exceeds_the_budget() {
        for budget in [0usize, 1, 50, 336, 1000, 10_000] {
            let e: Vec<f32> = (0..BANDS).map(|b| 1.0 / (b + 1) as f32).collect();
            let total: usize = allocate(&e, budget).iter().sum();

            assert!(
                total <= budget,
                "budget {budget} produced an allocation of {total}"
            );
        }
    }

    /// Low frequencies come first, because that is where speech is understood.
    #[test]
    fn the_low_bands_are_served_first() {
        let e = vec![0.5f32; BANDS];
        let bits = allocate(&e, 336);

        assert!(
            bits[0] > 0 && bits[1] > 0 && bits[2] > 0,
            "the bottom went unfunded"
        );
        assert_eq!(
            bits[BANDS - 1],
            0,
            "the top band was funded ahead of the speech band"
        );
    }

    /// More budget must buy more description overall.
    ///
    /// Not band by band: a larger budget can legitimately move an increment
    /// from a narrow band to a wider one that was previously unaffordable, and
    /// insisting otherwise is what makes the allocator stall. What must hold is
    /// that the total keeps rising, and that the quality does. The second is
    /// asserted end to end where it can actually be measured.
    #[test]
    fn more_budget_buys_more_description() {
        let e: Vec<f32> = (0..BANDS)
            .map(|b| if b < 14 { 1.0 / (b + 1) as f32 } else { 0.01 })
            .collect();

        let mut previous = 0usize;

        for budget in (100..1600).step_by(50) {
            let total: usize = allocate(&e, budget).iter().sum();
            assert!(
                total >= previous,
                "budget {budget} allocated {total} bits, down from {previous}"
            );
            assert!(total <= budget, "budget {budget} allocated {total}");
            previous = total;
        }
    }

    /// A silent band must never be funded, however much budget there is.
    #[test]
    fn silence_is_never_funded() {
        let mut e = vec![1.0f32; BANDS];
        e[7] = 0.0;
        e[18] = 0.0;

        for budget in [200usize, 500, 2000, 10_000] {
            let bits = allocate(&e, budget);
            assert_eq!(bits[7], 0, "a silent band was funded at budget {budget}");
            assert_eq!(bits[18], 0);
        }
    }

    /// A wide band must not be able to buy its way in ahead of a narrow one
    /// that still has room to improve. This is the cancellation the design
    /// rests on: value does not scale with width, but cost does.
    #[test]
    fn width_does_not_buy_priority() {
        let mut e = vec![0.0f32; BANDS];
        e[2] = 1.0; // 4 bins, low
        e[22] = 1.0; // 160 bins, high

        // Not enough for the wide band at any rate, so everything affordable
        // goes to the narrow one.
        let bits = allocate(&e, 16);

        assert_eq!(
            bits[2], 16,
            "the narrow band should have taken every affordable rate"
        );
        assert_eq!(
            bits[22], 0,
            "the wide band does not fit and must not be funded"
        );

        // With room for both, the narrow band is still served far past the
        // point where the wide one could have taken the budget instead.
        let bits = allocate(&e, 200);
        assert!(
            bits[2] >= 16,
            "the narrow band lost ground when the budget grew: {} bits",
            bits[2]
        );
        assert!(
            bits[2] / range(2).len() > 4,
            "the narrow band should be described finely before a wide one is funded at all"
        );
    }

    /// A tiny budget must produce something rather than dividing by zero.
    #[test]
    fn a_starved_budget_still_allocates() {
        let e = vec![0.5f32; BANDS];

        for budget in [0usize, 1, 10] {
            let bits = allocate(&e, budget);
            assert_eq!(bits.len(), BANDS);
            assert!(bits.iter().sum::<usize>() <= budget);
        }
    }
}
