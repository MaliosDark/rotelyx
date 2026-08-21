//! MLS message handling, given bytes from somebody already in the conversation.
//!
//! A member is not trusted to be honest, only to be a member. `receive` parses
//! and then decrypts, and everything before the decryption is attacker chosen.
//!
//! The conversation is built once for the process rather than per case. Building
//! one costs more than a fuzzing iteration should, and a case that is rejected
//! must not advance the group anyway: if a rejected message can move the state,
//! that is itself the defect worth finding, and it shows up here as a later case
//! behaving differently for no reason a reader can see.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rotelyx_crypto::{Conversation, Member};
use std::sync::{Mutex, OnceLock};

struct Pair {
    bob: Member,
    b: Conversation,
}

fn pair() -> &'static Mutex<Pair> {
    static PAIR: OnceLock<Mutex<Pair>> = OnceLock::new();
    PAIR.get_or_init(|| {
        let alice = Member::new(b"alice-device-1").expect("alice");
        let bob = Member::new(b"bob-device-1").expect("bob");

        let mut a = Conversation::create(&alice).expect("create");
        let (_commit, welcome) = a
            .invite(&alice, bob.key_package().expect("kp").key_package())
            .expect("invite");
        let tree = a.ratchet_tree().expect("tree");
        let b = Conversation::join(&bob, &welcome, &tree).expect("join");

        Mutex::new(Pair { bob, b })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut guard = pair().lock().expect("the conversation is not poisoned");
    let Pair { bob, b } = &mut *guard;
    let _ = b.receive(bob, data);
});
