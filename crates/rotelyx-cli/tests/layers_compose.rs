//! End-to-end: do the layers actually compose?
//!
//! Every crate is tested in isolation. Nothing until now checked that a message
//! survives the whole path: MLS encryption, envelope padding, a blind mailbox
//! round trip, and decryption on the far side, or that the guarantees each
//! layer claims still hold once they are stacked.
//!
//! These tests deliberately assert *properties*, not just that the code runs.
//! "It didn't panic" is not evidence of confidentiality.

use rotelyx_core::{safety_number, Identity};
use rotelyx_crypto::{Conversation, Member};
use rotelyx_mailbox::{Envelope, Mailbox, TagKey};

/// A conversation of two, plus the mailbox tag key both sides derived from it.
///
/// The tag key is pinned here, at the epoch both members share right after the
/// join, and reused for the rest of the test. Deriving it lazily per message
/// would break the moment either side committed: see
/// `the_tag_key_changes_with_the_epoch_so_it_must_be_pinned` in rotelyx-crypto.
fn conversation_of_two() -> (Member, Member, Conversation, Conversation, TagKey, TagKey) {
    let alice = Member::new(b"alice-device").expect("alice");
    let bob = Member::new(b"bob-device").expect("bob");

    let mut a = Conversation::create(&alice).expect("create");
    let bob_kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, bob_kp.key_package()).expect("invite");
    let tree = a.ratchet_tree().expect("ratchet tree");
    let b = Conversation::join(&bob, &welcome, &tree).expect("join");

    let ka = a.mailbox_tag_key(&alice).expect("alice tag key");
    let kb = b.mailbox_tag_key(&bob).expect("bob tag key");
    assert_eq!(ka, kb, "both members must address the same mailbox slot");

    (alice, bob, a, b, TagKey::new(ka), TagKey::new(kb))
}

/// The whole path: Alice encrypts, pads, deposits; Bob polls, collects,
/// decrypts. Neither peer is online at the same moment.
#[test]
fn a_message_survives_the_offline_path() {
    let (alice, bob, mut a, mut b, sender_tags, recipient_tags) = conversation_of_two();
    let mut mailbox = Mailbox::with_default_ttl();

    let plaintext = b"solo bob puede leer esto";

    // Alice: encrypt at L2, pad and address at L3, deposit.
    let ciphertext = a.send(&alice, plaintext).expect("send");
    let envelope = Envelope::seal(sender_tags.tag_for_epoch(100), &ciphertext).expect("seal");
    mailbox.deposit(envelope, 0).expect("deposit");

    // Bob comes online later and polls his window, using the tag key he derived
    // independently from the group: nothing about addressing was transmitted.
    let collected = mailbox.collect_many(&recipient_tags.polling_tags(100, 3), 60);
    assert_eq!(collected.len(), 1, "Bob must find exactly his envelope");

    // Decrypt. The MLS message is self-delimiting, so the zero padding is
    // simply ignored: this is what makes a cleartext length field unnecessary.
    let recovered = b
        .receive(&bob, collected[0].payload())
        .expect("receive")
        .message()
        .expect("application message");

    assert_eq!(recovered, plaintext);
}

/// The mailbox operator's view. This is the test that has to keep passing for
/// any privacy claim about the mailbox to be honest.
#[test]
fn the_operator_learns_nothing_it_should_not() {
    let (alice, _bob, mut a, _b, tags, _kb) = conversation_of_two();

    let plaintext = b"unmistakable-secret-marker";
    let ciphertext = a.send(&alice, plaintext).expect("send");
    let envelope = Envelope::seal(tags.tag_for_epoch(7), &ciphertext).expect("seal");

    let on_the_wire = envelope.to_bytes();

    // No plaintext.
    assert!(
        !on_the_wire
            .windows(plaintext.len())
            .any(|w| w == plaintext),
        "plaintext reached the operator"
    );

    // No sender identity. Alice's MLS credential identity must not appear.
    let alice_identity = b"alice-device";
    assert!(
        !on_the_wire
            .windows(alice_identity.len())
            .any(|w| w == alice_identity),
        "sender identity reached the operator"
    );

    // No recipient identity: the routing information is a tag derived from a
    // key the operator does not hold.
    let bob_identity = b"bob-device";
    assert!(
        !on_the_wire
            .windows(bob_identity.len())
            .any(|w| w == bob_identity),
        "recipient identity reached the operator"
    );
}

/// Length hiding has to survive the stack, not just the envelope unit test: two
/// wildly different messages must be the same size on the operator's disk.
#[test]
fn message_length_is_hidden_end_to_end() {
    let (alice, _bob, mut a, _b, tags, _kb) = conversation_of_two();
    let tag = tags.tag_for_epoch(1);

    let short = a.send(&alice, b"si").expect("send");
    let long = a.send(&alice, &vec![b'x'; 150]).expect("send");

    let e_short = Envelope::seal(tag, &short).expect("seal");
    let e_long = Envelope::seal(tag, &long).expect("seal");

    assert_eq!(
        e_short.to_bytes().len(),
        e_long.to_bytes().len(),
        "a 2-byte and a 150-byte message must be indistinguishable on the wire"
    );
}

/// Post-quantum material must still reach the key schedule when the commit
/// travels through the mailbox rather than a live connection.
#[test]
fn the_post_quantum_commit_survives_the_mailbox() {
    let (alice, bob, mut a, mut b, sender_tags, recipient_tags) = conversation_of_two();
    let mut mailbox = Mailbox::with_default_ttl();

    let epoch_before = a.epoch();

    // Alice encapsulates to Bob's published hybrid key; Bob recovers it and
    // stages it before the commit arrives.
    let (ct, alice_secret) = bob.hybrid_public_key().encapsulate();
    let bob_secret = bob.open_pq(&ct);
    b.stage_pq_secret(&bob, &bob_secret).expect("stage");

    // The commit goes through the mailbox like any other message.
    let commit = a.commit_pq_secret(&alice, &alice_secret).expect("commit");
    let envelope = Envelope::seal(sender_tags.tag_for_epoch(5), &commit).expect("seal");
    mailbox.deposit(envelope, 0).expect("deposit");

    let collected = mailbox.collect_many(&recipient_tags.polling_tags(5, 1), 1);
    assert_eq!(collected.len(), 1);

    // A rekey is not a membership change, and must not be announced as one.
    //
    // This commit mixes in a post-quantum secret. Nobody joined and nobody
    // left. It used to return the same value as a commit that adds a member,
    // so every client said "the group changed" here, and a warning that fires
    // on routine traffic is a warning people learn to dismiss. See ADV-7 in the
    // threat model: surfacing membership changes is a security control, and a
    // control that cries wolf is not one.
    let outcome = b
        .receive(&bob, collected[0].payload())
        .expect("process commit");
    assert_eq!(
        outcome,
        rotelyx_crypto::Received::Nothing,
        "a rekey was reported as something a person needs told about"
    );

    assert!(a.epoch() > epoch_before);
    assert_eq!(a.epoch(), b.epoch(), "both sides land on the same epoch");

    // And the conversation continues, now post-quantum protected.
    let msg = a.send(&alice, b"after the commit").expect("send");
    let got = b.receive(&bob, &msg).expect("receive").message().expect("application");
    assert_eq!(got, b"after the commit");
}

/// Somebody holding the mailbox contents but not the tag key cannot even tell
/// which envelopes belong together.
#[test]
fn envelopes_from_one_pair_are_unlinkable_without_the_key() {
    let (_alice, _bob, _a, _b, tags, _kb) = conversation_of_two();

    let t1 = tags.tag_for_epoch(1);
    let t2 = tags.tag_for_epoch(2);
    let other = TagKey::new([0x5A; 32]).tag_for_epoch(1);

    assert_ne!(t1, t2);
    assert_ne!(t1, other);

    // Shared prefixes would let an operator cluster envelopes; there must be
    // none beyond what chance allows.
    let shared_prefix = t1
        .as_bytes()
        .iter()
        .zip(t2.as_bytes())
        .take_while(|(a, b)| a == b)
        .count();
    assert!(
        shared_prefix < 4,
        "tags from consecutive epochs share {shared_prefix} leading bytes"
    );
}

/// The transport identity and the safety number that guards first contact.
#[test]
fn safety_numbers_agree_between_two_identities() {
    let a = Identity::generate();
    let b = Identity::generate();

    let from_a = a.safety_number(&b.id());
    let from_b = b.safety_number(&a.id());

    assert_eq!(from_a, from_b, "both sides must display the same digits");
    assert_eq!(from_a, safety_number(&a.id(), &b.id()));
    assert_eq!(from_a.split(' ').count(), 12);
}
