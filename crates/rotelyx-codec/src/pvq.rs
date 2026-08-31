//! Pyramid vector quantisation.
//!
//! # The problem it solves, which nothing else does
//!
//! A band of `N` coefficients has to be described in a budget that is often
//! well under one bit per coefficient. Scalar quantisation cannot do that: the
//! cheapest thing it can say about a coefficient is one bit, so at a third of a
//! bit each it says nothing about any of them. Telyx spent its first working
//! version in exactly that state, filling every band with noise while its whole
//! budget went unspent.
//!
//! PVQ describes the band as a **whole vector** instead. The codebook is every
//! way of placing `K` signed unit pulses across `N` positions, normalised onto
//! the unit sphere. Choosing `K` chooses the rate, continuously and at any
//! fraction of a bit per coefficient:
//!
//! | N | K | Bits | Bits per coefficient |
//! |---|---|---|---|
//! | 32 | 1 | 6.0 | 0.19 |
//! | 32 | 3 | 15.4 | 0.48 |
//! | 32 | 8 | 32.6 | 1.02 |
//!
//! # Why the codebook is never stored
//!
//! `V(32, 8)` is over six billion entries. What makes PVQ usable is that the
//! codebook is *enumerable*: every vector has a position in a canonical
//! ordering that can be computed arithmetically, so encoding produces an index
//! directly and decoding reconstructs the vector from it. Nothing is looked up
//! and nothing is held in memory.
//!
//! This is Fischer's construction, and it is what CELT uses. It is taken
//! wholesale because it is exactly right and there is nothing to improve about
//! counting.
//!
//! # The property that matters for speech
//!
//! Every codeword has the same norm. A band's loudness is therefore carried
//! entirely by its separately transmitted energy and cannot be disturbed by how
//! coarsely its shape was coded. Starve a band of bits and it becomes a rough
//! version of itself at exactly the right level, which is the failure mode a
//! listener forgives.

/// The largest band the codebook is computed for.
const MAX_N: usize = 256;

/// The most pulses. Past this the index exceeds what 64 bits can hold for wide
/// bands, and no band needs finer description than this buys.
const MAX_K: usize = 32;

/// The largest pulse count any caller may ask for.
pub const MAX_K_FOR: usize = MAX_K;

/// `V(n, k)`: how many vectors of `n` integers have an L1 norm of exactly `k`.
///
/// `V(n,k) = V(n-1,k) + V(n,k-1) + V(n-1,k-1)`, which counts the three ways a
/// vector can be built: leave the first position at zero, take a pulse from the
/// budget, or do both.
pub fn count(n: usize, k: usize) -> u64 {
    thread_local! {
        static TABLE: Vec<Vec<u64>> = build_table();
    }
    TABLE.with(|t| {
        if n < t.len() && k < t[n].len() {
            t[n][k]
        } else {
            0
        }
    })
}

fn build_table() -> Vec<Vec<u64>> {
    let mut v = vec![vec![0u64; MAX_K + 1]; MAX_N + 1];

    for row in v.iter_mut() {
        row[0] = 1; // one vector has norm zero: all zeroes
    }
    // No positions, no pulses.
    v[0][1..=MAX_K].fill(0);

    for n in 1..=MAX_N {
        for k in 1..=MAX_K {
            v[n][k] = v[n - 1][k]
                .saturating_add(v[n][k - 1])
                .saturating_add(v[n - 1][k - 1]);
        }
    }
    v
}

/// The widest index that may be used.
///
/// An index is carried in a `u64`, and the arithmetic that builds it adds
/// several codebook counts together. Leaving two bits of headroom keeps that
/// arithmetic inside the type.
///
/// Without this bound a wide band with many pulses names a codebook larger than
/// `u64` can count, and the index overflows. In release that wrapped silently
/// and produced a plausible wrong vector; only a debug build said so. The
/// ceiling is here rather than at the call sites so there is one place it can
/// be got wrong.
pub const MAX_INDEX_BITS: usize = 62;

/// How many bits an `(n, k)` codebook costs.
///
/// Infinite when the codebook is too large to index, so a caller searching for
/// the largest affordable `k` stops rather than choosing one it cannot address.
pub fn bits(n: usize, k: usize) -> f32 {
    let c = count(n, k);
    if c <= 1 {
        0.0
    } else if c >= (1u64 << MAX_INDEX_BITS) {
        f32::INFINITY
    } else {
        (c as f32).log2()
    }
}

/// The largest `k` whose codebook fits in `budget` bits.
pub fn pulses_for(n: usize, budget: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut best = 0;
    for k in 1..=MAX_K {
        if count(n, k) == 0 {
            break;
        }
        let cost = bits(n, k);
        if cost.is_finite() && cost <= budget as f32 {
            best = k;
        } else {
            break;
        }
    }
    best
}

/// Find the `k`-pulse vector closest in direction to `target`.
///
/// # Why projection alone is not enough
///
/// Scaling the target so its L1 norm is `k` and rounding gives a vector whose
/// norm is usually wrong, because rounding does not preserve a sum. The
/// remaining pulses are then placed one at a time, each going wherever it most
/// improves the match.
///
/// The measure being improved is the correlation with the target divided by the
/// norm of the result, which is the cosine between them: PVQ codes direction
/// only, and the length is the energy's job.
pub fn search(target: &[f32], k: usize) -> Vec<i32> {
    let n = target.len();
    let mut y = vec![0i32; n];

    if n == 0 || k == 0 {
        return y;
    }

    // Projection: get most of the pulses into roughly the right places at once.
    let l1: f32 = target.iter().map(|t| t.abs()).sum();
    let mut placed = 0i64;

    if l1 > 1e-9 {
        // Deliberately under-shoot. Overshooting means taking pulses away, and
        // removing one that is already well placed is more damaging than
        // placing a spare one greedily.
        let scale = (k as f32 - 0.5) / l1;
        for i in 0..n {
            y[i] = (target[i].abs() * scale).floor() as i32 * target[i].signum() as i32;
            placed += y[i].unsigned_abs() as i64;
        }
    }

    // Running sums, so each candidate placement is O(1) rather than O(n).
    let mut xy: f32 = target.iter().zip(&y).map(|(t, &q)| t * q as f32).sum();
    let mut yy: f32 = y.iter().map(|&q| (q * q) as f32).sum();

    while placed < k as i64 {
        let mut best = 0usize;
        let mut best_score = f32::NEG_INFINITY;

        for i in 0..n {
            let s = target[i].signum();
            // Adding a pulse at i changes the sums by these amounts.
            let new_xy = xy + s * target[i];
            let new_yy = yy + 2.0 * (y[i] as f32 * s) + 1.0;

            // Cosine, squared and sign-preserved: maximising this maximises the
            // match without a square root in the inner loop.
            let score = if new_yy > 0.0 {
                new_xy * new_xy.abs() / new_yy
            } else {
                0.0
            };

            if score > best_score {
                best_score = score;
                best = i;
            }
        }

        let s = target[best].signum();
        xy += s * target[best];
        yy += 2.0 * (y[best] as f32 * s) + 1.0;
        y[best] += s as i32;
        placed += 1;
    }

    y
}

/// The position of `y` in the canonical ordering of the `(n, k)` codebook.
pub fn index(y: &[i32]) -> u64 {
    let mut k: usize = y.iter().map(|v| v.unsigned_abs() as usize).sum();
    let mut i = 0u64;

    for (position, &value) in y.iter().enumerate() {
        let remaining = y.len() - position - 1;
        let magnitude = value.unsigned_abs() as usize;

        // Skip past every vector whose magnitude here is smaller.
        for smaller in 0..magnitude {
            let ways = count(remaining, k - smaller);
            i += if smaller == 0 { ways } else { 2 * ways };
        }

        // Within this magnitude, negative comes before positive.
        if magnitude > 0 && value > 0 {
            i += count(remaining, k - magnitude);
        }

        k -= magnitude;
    }
    i
}

/// The vector at position `i` in the `(n, k)` codebook.
pub fn deindex(n: usize, k: usize, mut i: u64) -> Vec<i32> {
    let mut y = vec![0i32; n];
    let mut k = k;

    for (position, slot) in y.iter_mut().enumerate() {
        let remaining = n - position - 1;

        let mut magnitude = 0usize;
        loop {
            let ways = count(remaining, k - magnitude);
            let block = if magnitude == 0 { ways } else { 2 * ways };

            if i < block {
                if magnitude == 0 {
                    *slot = 0;
                } else if i < ways {
                    *slot = -(magnitude as i32);
                } else {
                    *slot = magnitude as i32;
                    // The positive half sits after the negative one, and
                    // `index` adds that offset. Failing to take it back here
                    // leaves the index misaligned for every position after
                    // this one, which shows up as vectors of the wrong norm.
                    i -= ways;
                }
                break;
            }

            i -= block;
            magnitude += 1;

            if magnitude > k {
                // Only reachable from an index outside the codebook, which
                // means a corrupted frame. Stop rather than run off the end.
                break;
            }
        }

        k -= slot.unsigned_abs() as usize;
    }
    y
}

/// Turn a codebook vector back into a unit-norm shape.
pub fn to_shape(y: &[i32]) -> Vec<f32> {
    let norm: f32 = y.iter().map(|&v| (v * v) as f32).sum::<f32>().sqrt();

    if norm < 1e-9 {
        return vec![0.0; y.len()];
    }
    // Scaled so the result has unit RMS rather than unit L2, which is what the
    // band energy stage expects.
    let scale = (y.len() as f32).sqrt() / norm;
    y.iter().map(|&v| v as f32 * scale).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_matches_its_recursion() {
        assert_eq!(count(1, 1), 2, "one position, one pulse: plus or minus");
        assert_eq!(count(2, 1), 4, "two positions, one pulse, either sign");
        assert_eq!(count(4, 0), 1, "no pulses is one vector, all zeroes");

        for n in 1..=20 {
            for k in 1..=10 {
                assert_eq!(
                    count(n, k),
                    count(n - 1, k) + count(n, k - 1) + count(n - 1, k - 1),
                    "V({n},{k}) does not satisfy its own recursion"
                );
            }
        }
    }

    /// The rate table in the module documentation, asserted so it cannot drift.
    #[test]
    fn the_rates_are_what_the_documentation_claims() {
        for (n, k, expected, per_coefficient) in [
            (32usize, 1usize, 6.0f32, 0.19f32),
            (32, 3, 15.4, 0.48),
            (32, 8, 32.6, 1.02),
        ] {
            let b = bits(n, k);
            assert!(
                (b - expected).abs() < 0.15,
                "V({n},{k}) costs {b:.1} bits, documented as {expected}"
            );
            assert!((b / n as f32 - per_coefficient).abs() < 0.02);
        }
    }

    /// The property scalar quantisation cannot offer: a rate below one bit per
    /// coefficient that still describes the whole band.
    #[test]
    fn a_band_can_be_coded_below_one_bit_per_coefficient() {
        for n in [16usize, 32, 64, 120] {
            let k = pulses_for(n, n / 2); // half a bit each
            assert!(
                k > 0,
                "a {n} coefficient band could not be coded in {} bits at all",
                n / 2
            );
            assert!(bits(n, k) <= (n / 2) as f32);
        }
    }

    /// Every index must map to exactly one vector and back.
    #[test]
    fn indexing_round_trips_exhaustively() {
        for n in 1..=6usize {
            for k in 1..=5usize {
                let total = count(n, k);

                for i in 0..total {
                    let y = deindex(n, k, i);

                    let norm: usize = y.iter().map(|v| v.unsigned_abs() as usize).sum();
                    assert_eq!(norm, k, "V({n},{k}) index {i} produced norm {norm}");

                    assert_eq!(index(&y), i, "V({n},{k}) index {i} did not come back");
                }
            }
        }
    }

    /// Distinct indices must give distinct vectors, or the codebook wastes rate
    /// on duplicates.
    #[test]
    fn the_codebook_has_no_duplicates() {
        for (n, k) in [(4usize, 3usize), (6, 4), (8, 3)] {
            let mut seen = std::collections::HashSet::new();

            for i in 0..count(n, k) {
                assert!(
                    seen.insert(deindex(n, k, i)),
                    "V({n},{k}) index {i} repeats an earlier vector"
                );
            }
            assert_eq!(seen.len() as u64, count(n, k));
        }
    }

    /// The search must produce a vector of exactly the requested norm, or the
    /// index will not fit the codebook it was sized for.
    #[test]
    fn the_search_hits_the_requested_norm() {
        let targets: Vec<Vec<f32>> = vec![
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.5, -0.5, 0.5, -0.5],
            vec![3.0, 0.1, -0.2, 0.05, 0.0, 0.0, 0.0, 1.5],
            vec![0.0; 16],
            (0..32)
                .map(|i| ((i * 37 % 19) as f32 - 9.0) / 9.0)
                .collect(),
        ];

        for target in &targets {
            for k in 1..=8usize {
                let y = search(target, k);
                let norm: usize = y.iter().map(|v| v.unsigned_abs() as usize).sum();

                assert_eq!(
                    norm,
                    k,
                    "search for {k} pulses in {} dimensions produced norm {norm}",
                    target.len()
                );
                assert!(
                    index(&y) < count(target.len(), k),
                    "the index is outside its codebook"
                );
            }
        }
    }

    /// More pulses must describe the target better, or the rate control is
    /// buying nothing.
    #[test]
    fn more_pulses_track_the_target_more_closely() {
        let target: Vec<f32> = (0..32)
            .map(|i| ((i as f32 * 0.7).sin() * 2.0).powi(3))
            .collect();

        let norm: f32 = target.iter().map(|t| t * t).sum::<f32>().sqrt();
        let unit: Vec<f32> = target.iter().map(|t| t / norm).collect();

        let mut previous = -1.0f32;

        for k in [1usize, 2, 4, 8, 16, 24] {
            let shape = to_shape(&search(&target, k));
            let shape_norm: f32 = shape.iter().map(|s| s * s).sum::<f32>().sqrt();

            // Cosine between the coded direction and the true one.
            let cosine: f32 = unit
                .iter()
                .zip(&shape)
                .map(|(u, s)| u * s / shape_norm)
                .sum();

            assert!(
                cosine >= previous - 0.02,
                "{k} pulses matched worse than the previous rate: {cosine:.3} after {previous:.3}"
            );
            previous = cosine;
        }

        assert!(
            previous > 0.9,
            "even at 24 pulses the direction is only {previous:.3} right"
        );
    }

    /// Every codeword has the same length, which is what lets the band's
    /// loudness be carried entirely by its energy.
    #[test]
    fn every_codeword_has_the_same_norm() {
        let n = 16;

        for k in [1usize, 3, 7] {
            for i in (0..count(n, k)).step_by(97) {
                let shape = to_shape(&deindex(n, k, i));
                let rms = (shape.iter().map(|s| s * s).sum::<f32>() / n as f32).sqrt();

                assert!(
                    (rms - 1.0).abs() < 1e-4,
                    "V({n},{k}) index {i} has RMS {rms}, so the band's level would drift"
                );
            }
        }
    }

    /// Every codebook a caller can select must be small enough to index. This
    /// is the bound whose absence overflowed in debug and wrapped in release.
    #[test]
    fn no_reachable_codebook_overflows_its_index() {
        for n in [4usize, 16, 32, 64, 120, 200, 256] {
            for budget in [8usize, 32, 100, 500, 5_000] {
                let k = pulses_for(n, budget);
                if k == 0 {
                    continue;
                }

                let cost = bits(n, k);
                assert!(cost.is_finite(), "V({n},{k}) is not indexable");
                assert!(
                    cost <= MAX_INDEX_BITS as f32,
                    "V({n},{k}) needs {cost} bits, past the {MAX_INDEX_BITS} an index holds"
                );
                assert!(count(n, k) < (1u64 << MAX_INDEX_BITS));

                // And the arithmetic that builds an index stays inside a u64.
                let y = search(&vec![1.0; n], k);
                assert!(index(&y) < count(n, k));
            }
        }
    }

    /// A silent target must not produce pulses out of nothing.
    #[test]
    fn silence_stays_silent() {
        let y = search(&[0.0; 16], 0);
        assert!(y.iter().all(|&v| v == 0));
        assert!(to_shape(&y).iter().all(|&s| s == 0.0));
    }

    /// An index from a corrupted frame must not run off the end.
    #[test]
    fn an_index_outside_the_codebook_is_survivable() {
        let y = deindex(8, 4, u64::MAX);
        assert_eq!(y.len(), 8);
        assert!(y.iter().all(|v| v.abs() <= 4));
    }
}
