//! DudeCT constant-time check for Rotelyx's Tag equality (subtle::ct_eq).
//!
//! The Tag PartialEq is constant-time by design (subtle). This proves it
//! empirically: a variable-time compare would let an attacker learn a tag by
//! timing, breaking mailbox addressing. DudeCT feeds two input classes and runs
//! Welch's t-test on the timings; |t| staying small (< ~10) => no leak detected.

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rotelyx_mailbox::Tag;

fn tag_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    let reference = Tag::from_bytes(&[0x42u8; 32]).unwrap();

    let mut inputs = Vec::new();
    let mut classes = Vec::new();
    for _ in 0..100_000 {
        let mut b = [0u8; 32];
        rng.fill(&mut b[..]);
        if b[0] & 1 == 0 {
            // LEFT: equal to the reference (worst case for a leaky compare).
            inputs.push(Tag::from_bytes(&[0x42u8; 32]).unwrap());
            classes.push(Class::Left);
        } else {
            // RIGHT: a random tag.
            inputs.push(Tag::from_bytes(&b).unwrap());
            classes.push(Class::Right);
        }
    }

    for (input, class) in inputs.into_iter().zip(classes.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(input == reference);
        });
    }
}

ctbench_main!(tag_eq);
