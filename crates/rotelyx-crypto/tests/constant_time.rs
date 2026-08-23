//! Do the primitive libraries actually take the same time on secret data?
//!
//! §6 of the threat model reviewed every comparison in the first-party crates
//! and said plainly that it had not measured the libraries underneath. This
//! measures them, for the two operations everything else rests on: the
//! constant-time byte comparison that all four first-party checks call, and the
//! AEAD tag check that decides whether a sealed file or an envelope is genuine.
//!
//! # Why a measurement and not a reading
//!
//! Reading says what the author intended. A compiler decides what runs, and it
//! is allowed to turn a branchless comparison into a branch if it can prove the
//! result is the same, which it can, because the result *is* the same. The only
//! statement worth making is about the machine.
//!
//! Two advisories reviewed in `docs/UPSTREAM.md` are exactly this failure in
//! somebody else's crate: a non-constant-time GCM tag comparison, and a
//! constant-time select that compared the wrong width of register on aarch64.
//! Neither reaches Rotelyx. That is luck about which backend got selected, not a
//! property of the code we chose, and it is a poor reason to skip measuring.
//!
//! # The method, and what it can conclude
//!
//! This is dudect (Reparaz, Balasch and Verbauwhede, 2016). Time the operation
//! over two classes of input chosen so that a leak separates them, and apply
//! Welch's t-test. Above |t| = 10 the difference is not noise. Below it, with
//! enough samples, there is no evidence of a leak, which is a weaker statement
//! and the only honest one: absence of evidence on one machine, one compiler and
//! one microarchitecture.
//!
//! # Which binary this is about
//!
//! The compiler is the thing being watched, so the profile matters: a
//! measurement of an unoptimised build says nothing about the one that ships.
//! The run prints which profile it was built under, and `--release` is the one
//! that answers the question. A debug run is still worth having, because the
//! control proves the harness works either way.
//!
//! # The negative control, which is the part that matters
//!
//! A timing harness that reports "no leak" for everything is indistinguishable
//! from a broken one, and on a loaded desktop it is the likely outcome. So the
//! first thing measured is a comparison written to leak: a byte loop that
//! returns on the first difference. If the harness cannot see that, the machine
//! is too noisy to conclude anything and the run says so instead of reporting an
//! all-clear it did not earn.

use std::hint::black_box;
use std::time::Instant;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;

/// Operations timed together as one sample.
///
/// A single 32 byte comparison is a few nanoseconds, which is under the noise
/// of reading the clock twice. Timing a batch lifts the signal above the clock
/// without changing what is being compared.
/// An unoptimised build spends most of its time inside the AEAD rather than on
/// the difference being measured, so it does less work for the same answer. The
/// control says whether the smaller run was still enough.
const BATCH: usize = if cfg!(debug_assertions) { 128 } else { 512 };

/// Samples per class. dudect keeps going until the statistic settles; a test
/// has to stop, and this is enough to see a first-byte-versus-last-byte leak by
/// several orders of magnitude.
const SAMPLES: usize = if cfg!(debug_assertions) { 400 } else { 1200 };

/// The fastest fraction of samples kept.
///
/// A sample interrupted by the scheduler measures the scheduler. Every such
/// event makes a sample slower, never faster, so cropping the slow tail removes
/// interference without removing signal.
const KEEP: f64 = 0.85;

/// dudect's threshold. Below this, no evidence; above it, not noise.
const THRESHOLD: f64 = 10.0;

/// A tiny deterministic generator, to interleave the two classes.
///
/// Which class runs first has to vary, or a drift in machine speed across the
/// run is attributed to whichever class ran second.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).expect("seed");
        Self(u64::from_le_bytes(seed) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Welch's t statistic between two sets of timings, slow tail cropped.
fn welch(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    a.sort_by(|x, y| x.partial_cmp(y).unwrap());
    b.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let keep = |v: &mut Vec<f64>| v.truncate((v.len() as f64 * KEEP) as usize);
    keep(&mut a);
    keep(&mut b);

    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let mean = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var, n)
    };
    let (ma, va, na) = stats(&a);
    let (mb, vb, nb) = stats(&b);
    let denominator = (va / na + vb / nb).sqrt();
    if denominator == 0.0 {
        return 0.0;
    }
    (ma - mb) / denominator
}

/// Time one operation over two classes, where a class is which byte of the
/// input is wrong.
///
/// Both classes read the **same buffer** at the same address. An earlier
/// version gave each class its own array and reported a leak in
/// `subtle::ConstantTimeEq` at t = 65, reproducibly. It was not a leak. Two
/// arrays sit at two addresses, and the difference between those addresses was
/// worth more than the difference between the operations: handing both classes
/// data that differed in the same byte, out of two buffers, produced t = -26 on
/// its own. The buffer is flipped and restored outside the timed region, so the
/// only thing that changes between the two classes is which byte is wrong.
fn t_statistic(base: &mut [u8], class_a: (usize, u8), class_b: (usize, u8), mut op: impl FnMut(&[u8])) -> f64 {
    for _ in 0..BATCH {
        op(base);
    }

    let mut rng = Rng::new();
    let (mut ta, mut tb) = (Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES));

    for _ in 0..SAMPLES {
        let a_first = rng.next() & 1 == 0;
        let order = if a_first { [class_a, class_b] } else { [class_b, class_a] };
        let mut timed = [0.0f64; 2];

        for (slot, &(position, mask)) in order.iter().enumerate() {
            base[position] ^= mask;
            let start = Instant::now();
            for _ in 0..BATCH {
                op(base);
            }
            timed[slot] = start.elapsed().as_nanos() as f64;
            base[position] ^= mask;
        }

        if a_first {
            ta.push(timed[0]);
            tb.push(timed[1]);
        } else {
            tb.push(timed[0]);
            ta.push(timed[1]);
        }
    }
    welch(ta, tb)
}

/// A comparison written to leak, as the control.
///
/// `#[inline(never)]` so the optimiser cannot dissolve it into the caller and
/// prove the loop away.
#[inline(never)]
fn leaky_eq(x: &[u8], y: &[u8]) -> bool {
    for i in 0..x.len() {
        if x[i] != y[i] {
            return false;
        }
    }
    true
}

#[test]
fn the_primitives_do_not_leak_where_they_are_compared() {
    const LEN: usize = 32;
    let mut truth = [0u8; LEN];
    getrandom::fill(&mut truth).expect("random");

    // Wrong in the first byte, against wrong in the last. Anything that stops
    // at the first difference separates them.
    let early = (0usize, 0xffu8);
    let late = (LEN - 1, 0xffu8);
    // Wrong in the first byte both times, two different wrong values. Nothing
    // can legitimately separate these, so a reading here is the harness lying.
    let null_a = (0usize, 0xffu8);
    let null_b = (0usize, 0x0fu8);

    println!(
        "\n  profile: {}",
        if cfg!(debug_assertions) {
            "debug, which is not what ships. Run with --release to answer the question"
        } else {
            "release, which is what ships"
        }
    );

    // ---- the control ------------------------------------------------------
    let mut buffer = truth;
    let control = t_statistic(&mut buffer, early, late, |candidate| {
        black_box(leaky_eq(black_box(&truth[..]), black_box(candidate)));
    });
    println!("  control, a comparison written to leak: t = {control:.1}");

    if control.abs() < THRESHOLD {
        println!(
            "  the harness cannot see a leak it was handed, so this machine is too\n  \
             noisy to conclude anything. Nothing below is a result. Run it again on\n  \
             an idle machine."
        );
        return;
    }

    // ---- the null ---------------------------------------------------------
    let mut buffer = truth;
    let null = t_statistic(&mut buffer, null_a, null_b, |candidate| {
        black_box(bool::from(black_box(&truth[..]).ct_eq(black_box(candidate))));
    });
    println!("  null, two wrong values in the same byte: t = {null:.1}");
    assert!(
        null.abs() < THRESHOLD,
        "the harness separated two inputs that differ only in which wrong value \
         sits in the same byte, t = {null:.1}. Nothing real can do that, so every \
         other number this run produced is measuring the harness"
    );

    // ---- subtle::ConstantTimeEq ------------------------------------------
    let mut buffer = truth;
    let subtle_t = t_statistic(&mut buffer, early, late, |candidate| {
        black_box(bool::from(black_box(&truth[..]).ct_eq(black_box(candidate))));
    });
    println!("  subtle::ConstantTimeEq on 32 bytes:    t = {subtle_t:.1}");

    // ---- the AEAD tag check ----------------------------------------------
    //
    // The same question one layer up: does rejecting a forged envelope take a
    // different time depending on where the tag is wrong. This is the shape of
    // RUSTSEC-2026-0211 in another crate.
    let cipher = XChaCha20Poly1305::new_from_slice(&[7u8; 32]).expect("key");
    let nonce = XNonce::try_from(&[9u8; 24][..]).expect("nonce");
    let mut sealed = cipher
        .encrypt(&nonce, Payload { msg: b"a message of no importance", aad: b"" })
        .expect("seal");

    let tag_first = (sealed.len() - 16, 0xffu8);
    let tag_last = (sealed.len() - 1, 0xffu8);
    let aead_t = t_statistic(&mut sealed, tag_first, tag_last, |candidate| {
        black_box(
            cipher
                .decrypt(&nonce, Payload { msg: black_box(candidate), aad: b"" })
                .is_ok(),
        );
    });
    println!("  XChaCha20-Poly1305 tag rejection:      t = {aead_t:.1}");

    println!(
        "\n  Above |t| = {THRESHOLD:.0} is a leak. Below it is no evidence of one, on this\n  \
         machine, this compiler and this microarchitecture, and nothing more."
    );

    assert!(
        subtle_t.abs() < THRESHOLD,
        "subtle::ConstantTimeEq separated first-byte from last-byte differences \
         at t = {subtle_t:.1}, while the control leaked at t = {control:.1} and the \
         null read {null:.1}. Every first-party secret comparison calls this"
    );
    assert!(
        aead_t.abs() < THRESHOLD,
        "rejecting a forged tag took a measurably different time depending on \
         where the tag was wrong, t = {aead_t:.1}. That is a forgery oracle"
    );
}
