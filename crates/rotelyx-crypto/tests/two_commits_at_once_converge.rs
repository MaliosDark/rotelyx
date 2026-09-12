//! Two members commit at one epoch, and the conversation survives it.
//!
//! This is the defect that cost a week in the field. Two copies that changed
//! the group at the same moment each applied their own change and neither
//! could ever process the other's, because a commit names the epoch it was
//! built at and both had left it. Not a dropped message: two conversations
//! where there was one, with no way back, and nothing anywhere saying so.
//!
//! Every other system answers this with a server that orders commits and
//! rejects the losers. There is no such server here on purpose: the mailbox
//! cannot see epochs, and one that could would be one that knows which of its
//! deposits belong to the same conversation.
//!
//! So the answer is that a commit is not applied the moment it is made. While
//! it is held, the member is still at the epoch everybody else is at, and can
//! still take somebody else's commit instead of its own. Both sides compare
//! the same two commits and reach the same answer about which stands.

use rotelyx_crypto::{Conversation, Member, Received};

/// Alice and Bob, both settled at one epoch.
fn pair() -> (Member, Member, Conversation, Conversation) {
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite");
    a.settle(&alice).expect("settle the founding commit");

    let b = Conversation::join(&bob, &welcome, &a.ratchet_tree().expect("tree")).expect("join");

    (alice, bob, a, b)
}

/// Both sides rekey at the same instant, which is the plainest form of it.
#[test]
fn two_rekeys_at_one_epoch_end_at_one_epoch() {
    let (alice, bob, mut a, mut b) = pair();
    let started = a.epoch();
    assert_eq!(started, b.epoch(), "they did not start together");

    let from_alice = a.rekey_after_restore(&alice).expect("alice rekeys");
    let from_bob = b.rekey_after_restore(&bob).expect("bob rekeys");

    // Neither has applied its own, so each can still weigh the other's.
    assert!(a.is_holding_a_commit());
    assert!(b.is_holding_a_commit());

    let at_alice = a.receive(&alice, &from_bob).expect("alice weighs bob's");
    let at_bob = b.receive(&bob, &from_alice).expect("bob weighs alice's");

    // Exactly one of them lost, and they agree about which.
    let alice_lost = matches!(at_alice, Received::OurCommitLost { .. });
    let bob_lost = matches!(at_bob, Received::OurCommitLost { .. });
    assert!(
        alice_lost != bob_lost,
        "they did not agree: alice {at_alice:?}, bob {at_bob:?}"
    );

    assert_eq!(
        a.epoch(),
        b.epoch(),
        "two commits at one epoch left them at two"
    );
    assert!(a.epoch() > started, "nothing moved at all");

    // And they can still talk, which is the only thing that actually matters.
    let ciphertext = a.send(&alice, b"still here").expect("alice sends");
    assert_eq!(
        b.receive(&bob, &ciphertext).expect("bob reads").message(),
        Some(b"still here".to_vec()),
        "they ended at one epoch and still could not talk"
    );
}

/// The same race, where both commits change who is in the group.
///
/// Two people removing the same lost device at the same moment is not a
/// contrived case: it is what happens when somebody says "I left my phone on
/// the train" in a group and two people reach for the same button.
///
/// The loser is told its change did not happen, and told what happened
/// instead, so an interface can say so rather than falling silent.
#[test]
fn the_loser_is_told_its_change_did_not_happen() {
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");
    let carol = Member::new(b"carol").expect("identity");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("kp");
    let (_c, welcome) = a.invite(&alice, kp.key_package()).expect("invite bob");
    a.settle(&alice).expect("settle");
    let mut b =
        Conversation::join(&bob, &welcome, &a.ratchet_tree().expect("tree")).expect("bob joins");

    // Carol joins the way anybody does: one asks, another agrees.
    let kp = carol.key_package().expect("kp");
    let proposal = a.propose_invite(&alice, kp.key_package()).expect("propose");
    b.receive(&bob, &proposal).expect("bob hears it");
    let (commit, _welcome) = b.confirm_additions(&bob).expect("bob confirms");
    b.settle(&bob).expect("settle");
    a.receive(&alice, &commit).expect("alice applies it");
    assert_eq!(a.member_count(), 3);

    // Carol's device is gone, and both of them reach for the button.
    let carols_leaf = a
        .roster()
        .into_iter()
        .find(|p| p.identity == b"carol")
        .expect("carol is in the roster")
        .signature_key;

    let from_alice = a.remove(&alice, &carols_leaf).expect("alice removes carol");
    let from_bob = b.remove(&bob, &carols_leaf).expect("bob removes carol");

    let at_alice = a.receive(&alice, &from_bob).expect("alice weighs bob's");
    let at_bob = b.receive(&bob, &from_alice).expect("bob weighs alice's");

    assert_eq!(a.epoch(), b.epoch(), "they ended at two epochs");
    assert_eq!(
        a.member_count(),
        2,
        "carol is still here, or somebody went missing"
    );
    assert_eq!(a.member_count(), b.member_count());

    // Exactly one lost, and that one is told what happened instead.
    let mut told = 0;
    for outcome in [at_alice, at_bob] {
        if let Received::OurCommitLost { instead } = outcome {
            let change = instead
                .membership_change()
                .expect("the winning commit removed somebody and said nothing");
            assert_eq!(change.removed.len(), 1, "the departure was not reported");
            assert_eq!(change.removed[0].identity, b"carol");
            told += 1;
        }
    }
    assert_eq!(told, 1, "either nobody lost or both did");
}

/// A member on its own is not racing anybody, and nothing here may slow that
/// down or leave it holding a commit for ever.
#[test]
fn a_commit_nobody_raced_still_applies() {
    let (alice, bob, mut a, mut b) = pair();
    let started = a.epoch();

    let commit = a.rekey_after_restore(&alice).expect("alice rekeys");
    assert!(a.is_holding_a_commit(), "it was applied immediately");
    assert_eq!(a.epoch(), started, "the epoch moved before it was settled");

    b.receive(&bob, &commit).expect("bob applies it");
    assert!(a.settle(&alice).expect("settle"), "there was nothing to settle");
    assert_eq!(a.epoch(), b.epoch(), "they ended apart");
    assert!(!a.is_holding_a_commit());
    assert!(!a.settle(&alice).expect("settle again"), "it settled twice");
}

/// The rule has to be the same on both sides and has to not always favour the
/// same person, or one member could keep a group to itself by committing
/// whenever anybody else did.
#[test]
fn the_winner_is_not_always_the_same_member() {
    let mut alice_won = 0;
    let mut bob_won = 0;

    for _ in 0..24 {
        let (alice, bob, mut a, mut b) = pair();
        let _from_alice = a.rekey_after_restore(&alice).expect("alice rekeys");
        let from_bob = b.rekey_after_restore(&bob).expect("bob rekeys");

        match a.receive(&alice, &from_bob).expect("alice weighs") {
            Received::OurCommitLost { .. } => bob_won += 1,
            Received::TheirCommitLost => alice_won += 1,
            other => panic!("no tie was broken at all: {other:?}"),
        }
    }

    assert!(
        alice_won > 0 && bob_won > 0,
        "one member won every race: alice {alice_won}, bob {bob_won}"
    );
}
