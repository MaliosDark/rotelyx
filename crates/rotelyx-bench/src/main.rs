//! What each part of Rotelyx costs, measured rather than asserted.
//!
//! # Why this exists
//!
//! The paper quotes sizes throughout and timings almost nowhere, and the two
//! are not equally checkable: a size can be recomputed by reading the code, and
//! a timing cannot be recomputed by anybody who does not run it. An external
//! reader asked for the second kind, and they were right to.
//!
//! # What a number here means
//!
//! The median of `SAMPLES` runs after a warm-up, on the machine that ran it,
//! in a release build. Not a best case: a best case is the number a machine
//! produces when nothing else is happening, which is not the condition any of
//! this runs in. Not a mean either, because one scheduling stall drags a mean
//! and leaves a median alone.
//!
//! Every figure is therefore a property of a machine as much as of the code.
//! Two runs on different hardware will differ, which is why the output carries
//! no claim about what is fast, only what it took.
//!
//! # What is deliberately not here
//!
//! Anything that needs a network. Establishing a direct path, reaching a relay,
//! depositing to a mailbox over a socket: those are dominated by the network
//! and measuring them here would produce a number that says more about this
//! room's wifi than about Rotelyx. They belong in a field test, and the paper
//! says so.

use std::time::{Duration, Instant};

use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder};
use rotelyx_codec::mdct::{FRAME, WINDOW};
use rotelyx_crypto::hybrid::HybridKem;
use rotelyx_crypto::{Conversation, Member};
use rotelyx_mailbox::envelope::{Envelope, TagKey};
use rotelyx_media::{CallBinding, Receiver, Sender, SenderKeys};

/// Runs per measurement. Enough that a median means something, few enough that
/// the whole suite finishes while somebody is still watching it.
const SAMPLES: usize = 64;

/// Fewer than this and no figure is printed at all.
const MINIMUM: usize = 3;

fn main() {
    println!("Rotelyx benchmarks");
    println!("median of {SAMPLES} runs, release build\n");

    heading("Post-quantum key agreement");
    x_wing();

    heading("Message layer");
    messages();

    heading("Groups");
    groups();

    heading("Blind mailbox");
    mailbox();

    heading("Media");
    media();

    heading("Voice codec");
    codec();

    heading("At the door");
    identity();

    println!("\nNothing here touches a network. See the module comment.");
}

fn heading(name: &str) {
    println!("\n{name}");
    println!("{}", "-".repeat(name.len()));
}

/// Time `body` `SAMPLES` times and report the median.
fn bench(label: &str, mut body: impl FnMut()) {
    // One untimed run, so a first-call allocation or a lazily built table is
    // not charged to the first sample.
    body();

    let mut taken = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        body();
        taken.push(start.elapsed());
    }
    report(label, &mut taken, None);
}

/// The same, for something too slow to run `SAMPLES` times.
fn bench_few(label: &str, runs: usize, mut body: impl FnMut()) {
    let mut taken = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        body();
        taken.push(start.elapsed());
    }
    report(label, &mut taken, Some(runs));
}

fn report(label: &str, taken: &mut Vec<Duration>, runs: Option<usize>) {
    if taken.len() < MINIMUM {
        println!("  {label:<42} too few samples to say");
        return;
    }
    taken.sort_unstable();
    let median = taken[taken.len() / 2];
    let note = match runs {
        Some(n) if n < SAMPLES => format!("  ({n} runs)"),
        _ => String::new(),
    };
    println!("  {label:<42} {}{note}", human(median));
}

/// A duration in whatever unit keeps it readable.
fn human(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 10_000 {
        format!("{ns:>8} ns")
    } else if ns < 10_000_000 {
        format!("{:>8.1} us", ns as f64 / 1_000.0)
    } else {
        format!("{:>8.1} ms", ns as f64 / 1_000_000.0)
    }
}

/// A size, for the rows that are about bytes rather than time.
fn size(label: &str, bytes: usize) {
    println!("  {label:<42} {bytes:>8} bytes");
}

fn x_wing() {
    let (sk, pk) = HybridKem::generate();

    bench("encapsulate", || {
        let _ = pk.encapsulate();
    });

    let (ct, _) = pk.encapsulate();
    bench("decapsulate", || {
        let _ = sk.decapsulate(&ct);
    });

    size("encapsulation key", pk.to_bytes().len());
    size("ciphertext", ct.to_bytes().len());
}

fn messages() {
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");
    let mut group = Conversation::create(&alice).expect("create");
    let bundle = bob.key_package().expect("kp");
    let (_commit, welcome) = group.invite(&alice, bundle.key_package()).expect("invite");
    let tree = group.ratchet_tree().expect("tree");
    let mut theirs = Conversation::join(&bob, &welcome, &tree).expect("join");

    let short = b"ok";
    let long = vec![b'x'; 4096];

    bench("encrypt, 2 bytes", || {
        let _ = group.send(&alice, short).expect("send");
    });
    bench("encrypt, 4 KiB", || {
        let _ = group.send(&alice, &long).expect("send");
    });

    // Decryption is measured one message at a time, each freshly produced,
    // because a ratchet only moves forward and replaying one would measure the
    // replay check instead.
    let mut prepared: Vec<Vec<u8>> = (0..SAMPLES + 1)
        .map(|_| group.send(&alice, short).expect("send"))
        .collect();
    let mut taken = Vec::with_capacity(SAMPLES);
    for ct in prepared.drain(..).take(SAMPLES) {
        let start = Instant::now();
        let _ = theirs.receive(&bob, &ct).expect("receive");
        taken.push(start.elapsed());
    }
    report("decrypt, 2 bytes", &mut taken, None);

    size("ciphertext for 2 bytes", group.send(&alice, short).expect("send").len());
    size("ciphertext for 4 KiB", group.send(&alice, &long).expect("send").len());
}

fn groups() {
    for members in [8usize, 100, 1000] {
        let founder = Member::new(b"founder").expect("identity");
        let mut group = Conversation::create(&founder).expect("create");

        // Filling the group is not what is being measured, so it is not timed.
        let mut last = 0usize;
        for i in 1..members {
            let joiner = Member::new(format!("member-{i}").as_bytes()).expect("identity");
            let bundle = joiner.key_package().expect("kp");
            let (commit, _welcome) = group.invite(&founder, bundle.key_package()).expect("invite");
            last = commit.len();
        }

        let label = format!("commit at {members} members");
        size(&label, last);

        bench(&format!("export the tag key at {members}"), || {
            let _ = group.mailbox_tag_key(&founder).expect("export");
        });
    }
}

fn mailbox() {
    let tag_key = TagKey::new([7u8; 32]);
    let payload_key = tag_key.payload_key();
    let tag = tag_key.tag_for_epoch(1);

    bench("derive a tag for one hour", || {
        let _ = tag_key.tag_for_epoch(1);
    });

    let message = vec![b'm'; 900];
    bench("seal a payload", || {
        let _ = payload_key.seal(Some(tag), &message).expect("seal");
    });

    let sealed = payload_key.seal(Some(tag), &message).expect("seal");
    bench("open a payload", || {
        let _ = payload_key.open(Some(tag), &sealed).expect("open");
    });

    bench("envelope, seal into a bucket", || {
        let _ = Envelope::seal(tag, &sealed).expect("envelope");
    });

    size("sealed payload for 900 bytes", sealed.len());
    size(
        "envelope on the wire",
        Envelope::seal(tag, &sealed).expect("envelope").to_bytes().len(),
    );
}

fn media() {
    let call = CallBinding::new(b"a-benchmark-call").expect("binding");
    let keys = SenderKeys::derive(&[3u8; 32], 1, &call);
    let mut sender = Sender::new(keys).expect("sender");
    let mut receiver =
        Receiver::new(SenderKeys::derive(&[3u8; 32], 1, &call)).expect("receiver");

    // Sixty bytes is one frame at 24 kbit/s, which is what a call sends.
    let frame = vec![0xA5u8; 60];

    bench("protect one frame", || {
        let _ = sender.protect(&frame).expect("protect");
    });

    // Unprotect needs a frame the replay window has not seen, so each sample
    // gets its own.
    let mut prepared: Vec<Vec<u8>> = (0..SAMPLES)
        .map(|_| sender.protect(&frame).expect("protect"))
        .collect();
    let mut taken = Vec::with_capacity(SAMPLES);
    for f in prepared.drain(..) {
        let start = Instant::now();
        let _ = receiver.unprotect(&f).expect("unprotect");
        taken.push(start.elapsed());
    }
    report("unprotect one frame", &mut taken, None);

    size(
        "frame on the wire, 60 byte payload",
        sender.protect(&frame).expect("protect").len(),
    );
}

fn codec() {
    // Twenty milliseconds of something with structure, so the coder is not
    // being handed silence.
    let audio: Vec<f32> = (0..WINDOW)
        .map(|i| {
            let t = i as f32 / 48_000.0;
            0.3 * (2.0 * std::f32::consts::PI * 220.0 * t).sin()
                + 0.15 * (2.0 * std::f32::consts::PI * 1_400.0 * t).sin()
        })
        .collect();

    for bytes in [30usize, 40, 60] {
        let kbit = bytes * 8 * 50 / 1000;
        let mut encoder = LayeredEncoder::new(bytes);
        let mut decoder = LayeredDecoder::new(bytes);

        let label = format!("encode one frame, {kbit} kbit/s");
        bench(&label, || {
            let _ = encoder.encode(&audio).expect("encode");
        });

        let frame = encoder.encode(&audio).expect("encode");
        let label = format!("decode one frame, {kbit} kbit/s");
        bench(&label, || {
            let _ = decoder.decode(&frame).expect("decode");
        });

        size(&format!("frame at {kbit} kbit/s"), frame.to_bytes().len());
    }

    // What matters for a call is not the microseconds but the fraction of the
    // twenty milliseconds each frame is allowed.
    let mut encoder = LayeredEncoder::new(60);
    let mut decoder = LayeredDecoder::new(60);
    let start = Instant::now();
    const ROUNDS: usize = 200;
    for _ in 0..ROUNDS {
        let frame = encoder.encode(&audio).expect("encode");
        let _ = decoder.decode(&frame).expect("decode");
    }
    let spent = start.elapsed().as_secs_f64();
    let audio_seconds = ROUNDS as f64 * FRAME as f64 / 48_000.0;
    println!(
        "  {:<42} {:>8.2} % of real time, one core",
        "encode and decode together",
        spent / audio_seconds * 100.0
    );
}

fn identity() {
    bench("safety number, two identities", || {
        let a = rotelyx_core::Identity::generate();
        let b = rotelyx_core::Identity::generate();
        let _ = rotelyx_core::safety_number(&a.id(), &b.id());
    });

    bench("mint a meeting code", || {
        let _ = rotelyx_wasm::new_meeting_code().expect("code");
    });

    bench("derive a rendezvous tag", || {
        let _ = rotelyx_wasm::rendezvous_tag("a meeting code long enough").expect("tag");
    });

    // The one that is slow on purpose. Everything above is microseconds because
    // it runs per message; this runs once, when somebody types a passphrase,
    // and 64 MiB with three passes is what makes guessing it expensive.
    bench_few("unlock the vault (Argon2id, 64 MiB)", 5, || {
        let _ = rotelyx_wasm::SessionKey::create("a passphrase long enough to be accepted")
            .expect("key");
    });
}
