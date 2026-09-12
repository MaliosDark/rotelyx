//! Admitting somebody takes two members, and the group is what enforces it.
//!
//! The worry this answers is not hypothetical and it is not about bots. A
//! member holds the group key, so a member can add anybody, and everybody else
//! merges the commit because MLS says it is valid. One careless device, one
//! borrowed phone, one compromised account, and a participant nobody chose is
//! in the conversation reading everything said from then on.
//!
//! It cannot be a rule about bots, because "is a bot" is not a property
//! anything can check. A program joins with the same kind of key package a
//! person does, and a program written to get around a rule would simply not
//! declare itself. So the rule is about additions, and it applies to everybody.
//!
//! What makes it worth anything is where it is enforced. A sender that decides
//! not to follow it is not asking permission, so the check that counts is the
//! one every **receiver** runs: a commit that admits somebody on the authority
//! of the member that sent it is refused, and the epoch does not move.

use rotelyx_crypto::{Conversation, GroupError, Member, Received};

/// Alice and Bob, already talking.
fn pair() -> (Member, Member, Conversation, Conversation) {
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite bob");
    let tree = a.ratchet_tree().expect("tree");
    let b = Conversation::join(&bob, &welcome, &tree).expect("bob joins");

    (alice, bob, a, b)
}

#[test]
fn a_member_cannot_admit_somebody_alone() {
    let (alice, bob, mut a, mut b) = pair();

    // Alice adds Carol the old way, on nobody's authority but her own.
    let carol = Member::new(b"carol").expect("identity");
    let kp = carol.key_package().expect("key package");
    let (commit, _welcome) = a.invite(&alice, kp.key_package()).expect("alice commits");

    let refused = b.receive(&bob, &commit).expect_err("Bob merged it anyway");
    assert!(
        matches!(refused, GroupError::AddedWithoutASecondMember),
        "refused for the wrong reason: {refused:?}"
    );

    // And the refusal has to leave Bob where he was. A check that rejects the
    // commit but advances the epoch would be worse than no check: Bob would be
    // unable to read anything afterwards while Carol sat in the group.
    assert_eq!(b.member_count(), 2, "Bob's group changed anyway");
}

#[test]
fn two_members_between_them_can() {
    let (alice, bob, mut a, mut b) = pair();

    let carol = Member::new(b"carol").expect("identity");
    let kp = carol.key_package().expect("key package");

    // Alice asks.
    let proposal = a
        .propose_invite(&alice, kp.key_package())
        .expect("alice proposes");
    assert_eq!(a.member_count(), 2, "proposing changed the group by itself");

    // Bob is told, by name, who wants to admit whom. This is the half that is
    // still a decision, so it is the half a person has to be able to see.
    let heard = b.receive(&bob, &proposal).expect("bob hears it");
    let Received::AdditionProposed { by, joining } = heard else {
        panic!("Bob was not told that somebody wants in: {heard:?}");
    };
    assert_eq!(
        by.expect("unattributed").identity,
        b"alice",
        "the request did not say who made it"
    );
    assert_eq!(joining.len(), 1);
    assert_eq!(joining[0].identity, b"carol");
    assert_eq!(b.member_count(), 2, "hearing a request changed the group");

    // Bob confirms, and now it happens.
    let (commit, welcome) = b.confirm_additions(&bob).expect("bob confirms");
    let welcome = welcome.expect("a welcome for carol");
    let change = a
        .receive(&alice, &commit)
        .expect("alice applies it")
        .membership_change()
        .expect("alice was not told")
        .clone();

    assert_eq!(change.added.len(), 1);
    assert_eq!(change.added[0].identity, b"carol");
    assert_eq!(
        change.by.expect("unattributed").identity,
        b"bob",
        "the arrival did not say who let them in"
    );

    let tree = b.ratchet_tree().expect("tree");
    let c = Conversation::join(&carol, &welcome, &tree).expect("carol joins");
    assert_eq!(c.member_count(), 3);
}

#[test]
fn the_proposer_cannot_be_the_second_pair_of_eyes() {
    let (alice, bob, mut a, mut b) = pair();

    let carol = Member::new(b"carol").expect("identity");
    let kp = carol.key_package().expect("key package");

    // Alice proposes, broadcasts it like an honest client, and then races to
    // commit her own proposal before Bob can. Bob has the proposal, so MLS is
    // perfectly happy with the commit: there is nothing malformed about it,
    // and this is exactly why the check cannot be left to MLS.
    let proposal = a
        .propose_invite(&alice, kp.key_package())
        .expect("alice proposes");
    b.receive(&bob, &proposal).expect("bob hears the request");
    let (commit, _welcome) = a.confirm_additions(&alice).expect("alice commits her own");

    let refused = b.receive(&bob, &commit).expect_err("Bob merged it anyway");
    assert!(
        matches!(refused, GroupError::AddedWithoutASecondMember),
        "refused for the wrong reason: {refused:?}"
    );
    assert_eq!(b.member_count(), 2);
}

#[test]
fn first_contact_is_exempt_because_there_is_nobody_else_yet() {
    // A group of one admitting its first member is the reason the conversation
    // exists. Asking for a second member there asks for somebody who by
    // definition has not arrived.
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite");
    let tree = a.ratchet_tree().expect("tree");

    let b = Conversation::join(&bob, &welcome, &tree).expect("bob joins");
    assert_eq!(b.member_count(), 2);
}

#[test]
fn a_person_adding_their_own_device_is_not_admitting_anybody() {
    // A leaf per device means a person's laptop is a second leaf for the same
    // person. Making that wait on somebody else's attention would cost a
    // person the use of their own machine and buy nothing: they are already in
    // the room.
    let alice = Member::new(b"alice").expect("identity");
    let alice_laptop = Member::for_device(b"alice", b"laptop").expect("device");
    let bob = Member::new(b"bob").expect("identity");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite bob");
    let tree = a.ratchet_tree().expect("tree");
    let mut b = Conversation::join(&bob, &welcome, &tree).expect("bob joins");

    let laptop_kp = alice_laptop.key_package().expect("key package");
    let (commit, _welcome) = a
        .invite(&alice, laptop_kp.key_package())
        .expect("alice adds her laptop");

    let change = b
        .receive(&bob, &commit)
        .expect("bob accepts her own device")
        .membership_change()
        .expect("bob was not told")
        .clone();

    assert_eq!(change.added.len(), 1);
    assert_eq!(
        change.added[0].device, b"laptop",
        "the device that arrived was not the one added"
    );
    assert_eq!(b.member_count(), 3);
}

#[test]
fn somebody_elses_device_is_not_your_device() {
    // The exemption is "the same person", and it is compared against what MLS
    // authenticated as the committer rather than against what the joining leaf
    // claims. Otherwise anybody could be admitted alone by claiming to be the
    // person doing the admitting.
    let alice = Member::new(b"alice").expect("identity");
    let bob = Member::new(b"bob").expect("identity");
    let impostor = Member::for_device(b"alice", b"not-really").expect("device");

    let mut a = Conversation::create(&alice).expect("create");
    let kp = bob.key_package().expect("key package");
    let (_commit, welcome) = a.invite(&alice, kp.key_package()).expect("invite bob");
    let tree = a.ratchet_tree().expect("tree");
    let mut b = Conversation::join(&bob, &welcome, &tree).expect("bob joins");

    // Bob tries to admit a leaf claiming to be one of Alice's devices. Bob is
    // not Alice, so this is an addition like any other and takes two.
    let kp = impostor.key_package().expect("key package");
    let (commit, _welcome) = b.invite(&bob, kp.key_package()).expect("bob commits");

    let refused = a.receive(&alice, &commit).expect_err("Alice merged it");
    assert!(
        matches!(refused, GroupError::AddedWithoutASecondMember),
        "refused for the wrong reason: {refused:?}"
    );
    assert_eq!(a.member_count(), 2);
}

/// A group can narrow who turns a request into a member.
///
/// Two members are the floor, not the ceiling. A group that wants a smaller
/// set of people deciding can name them, and the reason it is in the group
/// context rather than in a message is that a rule about who may do something
/// is worth exactly as much as the agreement about who that is. In the group
/// context it is hashed into the key schedule, so every member at an epoch
/// holds bit for bit the same list.
mod admins {
    use super::*;

    /// Alice, Bob and Carol, with Alice named as the only admin.
    fn three_with_alice_in_charge() -> (
        Member,
        Member,
        Member,
        Conversation,
        Conversation,
        Conversation,
    ) {
        let alice = Member::new(b"alice").expect("identity");
        let bob = Member::new(b"bob").expect("identity");
        let carol = Member::new(b"carol").expect("identity");

        let mut a = Conversation::create(&alice).expect("create");
        let kp = bob.key_package().expect("kp");
        let (_c, welcome) = a.invite(&alice, kp.key_package()).expect("invite bob");
        let mut b =
            Conversation::join(&bob, &welcome, &a.ratchet_tree().expect("tree")).expect("bob joins");

        let kp = carol.key_package().expect("kp");
        let proposal = a.propose_invite(&alice, kp.key_package()).expect("propose");
        b.receive(&bob, &proposal).expect("bob hears it");
        let (commit, welcome) = b.confirm_additions(&bob).expect("bob confirms");
        a.receive(&alice, &commit).expect("alice applies");
        let mut c = Conversation::join(
            &carol,
            &welcome.expect("welcome"),
            &b.ratchet_tree().expect("tree"),
        )
        .expect("carol joins");

        let commit = a
            .set_admins(&alice, &[b"alice".to_vec()])
            .expect("name the admins");
        b.receive(&bob, &commit).expect("bob applies");
        c.receive(&carol, &commit).expect("carol applies");

        (alice, bob, carol, a, b, c)
    }

    #[test]
    fn everybody_holds_the_same_list() {
        let (_alice, _bob, _carol, a, b, c) = three_with_alice_in_charge();
        assert_eq!(a.admins(), vec![b"alice".to_vec()]);
        assert_eq!(b.admins(), a.admins(), "bob holds a different list");
        assert_eq!(c.admins(), a.admins(), "carol holds a different list");
    }

    #[test]
    fn a_member_who_is_not_an_admin_cannot_let_anybody_in() {
        let (alice, bob, carol, mut a, mut b, mut c) = three_with_alice_in_charge();

        // Carol asks, which she is allowed to do, and Bob confirms, which he
        // is not. Two members agreed, so the rule underneath is satisfied and
        // this tests the one above it.
        let dan = Member::new(b"dan").expect("identity");
        let kp = dan.key_package().expect("kp");
        let proposal = c.propose_invite(&carol, kp.key_package()).expect("propose");
        a.receive(&alice, &proposal).expect("alice hears it");
        b.receive(&bob, &proposal).expect("bob hears it");

        let (commit, _welcome) = b.confirm_additions(&bob).expect("bob commits");

        let refused = a.receive(&alice, &commit).expect_err("alice merged it");
        assert!(
            matches!(refused, GroupError::AddedBySomebodyWhoIsNotAnAdmin),
            "refused for the wrong reason: {refused:?}"
        );
        assert_eq!(a.member_count(), 3, "the group changed anyway");
    }

    #[test]
    fn an_admin_can() {
        let (alice, bob, carol, mut a, mut b, mut c) = three_with_alice_in_charge();

        let dan = Member::new(b"dan").expect("identity");
        let kp = dan.key_package().expect("kp");

        // Carol asks. She is an ordinary member, and asking is what a request
        // to join looks like from inside the group.
        let proposal = c.propose_invite(&carol, kp.key_package()).expect("propose");
        a.receive(&alice, &proposal).expect("alice hears it");
        b.receive(&bob, &proposal).expect("bob hears it");

        let (commit, welcome) = a.confirm_additions(&alice).expect("alice commits");
        let change = b
            .receive(&bob, &commit)
            .expect("bob applies it")
            .membership_change()
            .expect("bob was not told")
            .clone();
        assert_eq!(change.added[0].identity, b"dan");
        assert_eq!(
            change.by.expect("unattributed").identity,
            b"alice",
            "the arrival did not say who let them in"
        );

        c.receive(&carol, &commit).expect("carol applies it");
        let dans = Conversation::join(
            &dan,
            &welcome.expect("welcome"),
            &a.ratchet_tree().expect("tree"),
        )
        .expect("dan joins");
        assert_eq!(dans.member_count(), 4);
    }

    #[test]
    fn a_group_that_loses_every_admin_is_not_locked_shut() {
        // The failure this avoids is worse than the one it protects against.
        // A rule that outlives the people it named leaves a conversation that
        // can never admit anybody again, and there is no server here to be
        // asked to fix it.
        let (alice, bob, carol, mut a, mut b, mut c) = three_with_alice_in_charge();

        let alices_leaf = a
            .roster()
            .into_iter()
            .find(|p| p.identity == b"alice")
            .expect("alice is in her own roster")
            .signature_key;
        let commit = b
            .remove(&bob, &alices_leaf)
            .expect("bob removes alice");
        c.receive(&carol, &commit).expect("carol applies");
        let _ = a.receive(&alice, &commit);

        // The list still names her and she is not here, so the rule stands
        // down. The two member rule underneath does not.
        assert_eq!(b.admins(), vec![b"alice".to_vec()]);

        let dan = Member::new(b"dan").expect("identity");
        let kp = dan.key_package().expect("kp");
        let proposal = b.propose_invite(&bob, kp.key_package()).expect("propose");
        c.receive(&carol, &proposal).expect("carol hears it");
        let (commit, _welcome) = c.confirm_additions(&carol).expect("carol commits");

        b.receive(&bob, &commit).expect("bob applies it");
        assert_eq!(b.member_count(), 3, "the group could not admit anybody");
    }

    #[test]
    fn two_members_are_still_needed_even_between_admins() {
        // Naming admins narrows who may decide. It does not remove the rule
        // underneath, or a group with one admin would be a group where one
        // person admits whoever they like, which is what this started as.
        let (alice, bob, _carol, mut a, mut b, _c) = three_with_alice_in_charge();

        let dan = Member::new(b"dan").expect("identity");
        let kp = dan.key_package().expect("kp");
        let (commit, _welcome) = a.invite(&alice, kp.key_package()).expect("alice alone");

        let refused = b.receive(&bob, &commit).expect_err("bob merged it");
        assert!(
            matches!(refused, GroupError::AddedWithoutASecondMember),
            "refused for the wrong reason: {refused:?}"
        );
    }
}
