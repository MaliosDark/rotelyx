//! How large a Rotelyx group can actually be, measured rather than assumed.
//!
//! Three things grow with member count and each one has a different ceiling:
//! the ratchet tree a joiner needs, the welcome that carries the group secrets,
//! and the commit every existing member must process. Each is padded to a
//! mailbox bucket before it travels, and the padded size is what a member
//! actually downloads.

use rotelyx_crypto::{Conversation, Member};
use rotelyx_mailbox::Bucket;

const MAX_BUCKET: usize = 8 * 1024 * 1024;

/// Ask the real ladder rather than keeping a copy of it here. A duplicate
/// table drifts, and this one did: it kept reporting the old five bucket
/// ladder after the real one was made finer, so the measurement overstated
/// what a large group costs.
fn padded(len: usize) -> String {
    match Bucket::for_len(len) {
        Ok(b) if b.size() >= 1_048_576 => format!("{} MiB", b.size() / 1_048_576),
        Ok(b) => format!("{} KiB", b.size() / 1_024),
        Err(_) => "TOO BIG".to_string(),
    }
}

#[test]
#[ignore = "measurement, not an assertion: cargo test -- --ignored --nocapture"]
fn measure_how_group_material_grows() {
    let founder = Member::new(b"founder").expect("identity");
    let mut group = Conversation::create(&founder).expect("create");

    println!(
        "\n{:>7} {:>12} {:>10} {:>12} {:>10} {:>10}",
        "members", "tree", "bucket", "welcome", "bucket", "commit"
    );

    let checkpoints = [2usize, 32, 64, 128, 256, 384, 512, 768, 1024];
    let mut next = 0;

    for n in 2..=1024 {
        let joiner = Member::new(format!("member-{n}").as_bytes()).expect("identity");
        let kp = joiner.key_package().expect("key package");

        let (commit, welcome) = group
            .invite(&founder, kp.key_package())
            .expect("invite");
        let tree = group.ratchet_tree().expect("tree");

        if checkpoints.get(next) == Some(&n) {
            next += 1;
            println!(
                "{:>7} {:>12} {:>10} {:>12} {:>10} {:>10}",
                n,
                tree.len(),
                padded(tree.len()),
                welcome.len(),
                padded(welcome.len()),
                commit.len(),
            );
            if tree.len() > MAX_BUCKET || welcome.len() > MAX_BUCKET {
                println!("  ^ past the largest bucket: undeliverable");
                break;
            }
        }
    }
    println!();
}
