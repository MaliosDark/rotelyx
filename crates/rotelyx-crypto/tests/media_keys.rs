//! Media keys come from the group, so a call is as end to end as a message.
//!
//! The frame format is tested in `rotelyx-media`. What is tested here is the
//! join between the two: that the key a call is encrypted under is the group's,
//! that every member derives the same one, and that it changes when the
//! membership does.

use rotelyx_crypto::{Conversation, Member};
use rotelyx_media::{MediaError, Receiver, Sender, SenderKeys};

/// A group of `n`, everyone up to date.
fn group(n: usize) -> (Vec<Member>, Vec<Conversation>) {
    let members: Vec<Member> = (0..n)
        .map(|i| Member::new(format!("member{i}").as_bytes()).expect("identity"))
        .collect();

    let mut founder = Conversation::create(&members[0]).expect("create");
    let mut joined: Vec<Conversation> = Vec::new();

    for i in 1..n {
        let kp = members[i].key_package().expect("key package");
        let (commit, welcome) = founder.invite(&members[0], kp.key_package()).expect("invite");
        let tree = founder.ratchet_tree().expect("tree");

        for (offset, existing) in joined.iter_mut().enumerate() {
            existing
                .receive(&members[offset + 1], &commit)
                .expect("apply commit");
        }

        joined.push(Conversation::join(&members[i], &welcome, &tree).expect("join"));
    }

    let mut all = vec![founder];
    all.extend(joined);
    (members, all)
}

/// Every member must derive the same base key, or a call is silence.
#[test]
fn every_member_derives_the_same_media_key() {
    let (members, conversations) = group(4);

    let keys: Vec<[u8; 32]> = conversations
        .iter()
        .zip(&members)
        .map(|(c, m)| c.media_base_key(m).expect("export"))
        .collect();

    for (i, key) in keys.iter().enumerate() {
        assert_eq!(
            key, &keys[0],
            "member {i} derived a different media key from the same epoch"
        );
    }
}

/// A media key must not be the same bytes as the mailbox tag key, even though
/// both come from the same exporter at the same epoch.
#[test]
fn the_media_key_is_not_the_mailbox_key() {
    let (members, conversations) = group(2);

    assert_ne!(
        conversations[0].media_base_key(&members[0]).expect("media"),
        conversations[0].mailbox_tag_key(&members[0]).expect("mailbox"),
        "one label separates them, and it has to"
    );
}

/// A real call between two members of a real group.
#[test]
fn two_members_hold_an_encrypted_call() {
    let (members, conversations) = group(2);
    let base = conversations[0].media_base_key(&members[0]).expect("export");

    let mut alice = Sender::new(SenderKeys::derive(&base, 0)).expect("sender");
    let mut bob_hears_alice = Receiver::new(SenderKeys::derive(&base, 0)).expect("receiver");

    for n in 0..50u32 {
        let frame = format!("20ms of audio, frame {n}").into_bytes();
        let protected = alice.protect(&frame).expect("protect");

        assert!(
            !protected.windows(frame.len()).any(|w| w == frame),
            "the audio is in the clear on the wire"
        );
        assert_eq!(bob_hears_alice.unprotect(&protected).expect("unprotect"), frame);
    }
}

/// The point of tying media to the group: a membership change rekeys the call.
///
/// Without this a removed member keeps decrypting until the call ends, which
/// makes removal a suggestion rather than a boundary.
#[test]
fn a_membership_change_rekeys_the_call() {
    let (members, mut conversations) = group(2);

    let before = conversations[0].media_base_key(&members[0]).expect("export");

    // A third person joins.
    let carol = Member::new(b"carol").expect("identity");
    let kp = carol.key_package().expect("key package");
    let (commit, welcome) = conversations[0]
        .invite(&members[0], kp.key_package())
        .expect("invite");
    let tree = conversations[0].ratchet_tree().expect("tree");

    conversations[1]
        .receive(&members[1], &commit)
        .expect("apply commit");
    let carols = Conversation::join(&carol, &welcome, &tree).expect("join");

    let after = conversations[0].media_base_key(&members[0]).expect("export");
    assert_ne!(before, after, "the epoch moved and the media key did not");

    // Everyone, the newcomer included, is on the new key.
    for (c, m) in [
        (&conversations[0], &members[0]),
        (&conversations[1], &members[1]),
        (&carols, &carol),
    ] {
        assert_eq!(c.media_base_key(m).expect("export"), after);
    }

    // And the old key no longer opens anything current.
    let mut speaking = Sender::new(SenderKeys::derive(&after, 0)).expect("sender");
    let mut listening_with_old = Receiver::new(SenderKeys::derive(&before, 0)).expect("receiver");

    let frame = speaking.protect(b"said after carol joined").expect("protect");
    assert_eq!(
        listening_with_old.unprotect(&frame),
        Err(MediaError::BadTag),
        "a key from before the change still decrypts the call"
    );
}

/// One member must not be able to produce another member's stream, or a call
/// is a place where words can be put in somebody's mouth.
#[test]
fn a_member_cannot_speak_as_another() {
    let (members, conversations) = group(3);
    let base = conversations[0].media_base_key(&members[0]).expect("export");

    let mut alice = Sender::new(SenderKeys::derive(&base, 0)).expect("sender");
    let mut listening_for_bob = Receiver::new(SenderKeys::derive(&base, 1)).expect("receiver");

    let from_alice = alice.protect(b"this is bob speaking").expect("protect");

    assert_eq!(
        listening_for_bob.unprotect(&from_alice),
        Err(MediaError::WrongSender {
            expected: 1,
            got: 0
        })
    );

    let mut relabelled = from_alice;
    relabelled[0] = 1;
    assert_eq!(
        listening_for_bob.unprotect(&relabelled),
        Err(MediaError::BadTag),
        "relabelling the header must not make the frame Bob's"
    );
}

/// A call between two different groups must share nothing, even with the same
/// sender numbering.
#[test]
fn two_groups_do_not_share_media_keys() {
    let (a_members, a) = group(2);
    let (b_members, b) = group(2);

    let a_base = a[0].media_base_key(&a_members[0]).expect("export");
    let b_base = b[0].media_base_key(&b_members[0]).expect("export");
    assert_ne!(a_base, b_base);

    let mut speaking = Sender::new(SenderKeys::derive(&a_base, 0)).expect("sender");
    let mut eavesdropping = Receiver::new(SenderKeys::derive(&b_base, 0)).expect("receiver");

    let frame = speaking.protect(b"a private call").expect("protect");
    assert_eq!(eavesdropping.unprotect(&frame), Err(MediaError::BadTag));
}
