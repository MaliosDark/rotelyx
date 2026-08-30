//! The circuit frames, and the constant two crates have to agree on.
//!
//! # Why this file is in the relay and not beside either constant
//!
//! `rotelyx_relay_proto::protos::relay::SEALED_HOP_LEN` and
//! `rotelyx_crypto::circuit::SEALED_HOP_LEN` are the same number written twice,
//! and they are written twice on purpose: the vendored transport must not
//! depend on the message-layer crypto, because that inverts the layering the
//! design rests on. L0 does not know what L2 is.
//!
//! Two constants that must agree and nothing checking them is the defect this
//! project keeps finding. So the check lives where both are visible, in a crate
//! that reaches the crypto only as a **dev-dependency**: the shipped relay
//! still cannot open anything.

use rotelyx_crypto::circuit::{Hop, SealedHop};
use rotelyx_crypto::hybrid::HybridKem;

/// The relay's idea of a descriptor's size must be the crypto's.
///
/// If it is not, a real descriptor is refused as malformed and no circuit ever
/// opens, on a path that is otherwise correct end to end.
#[test]
fn the_two_crates_agree_on_the_size_of_a_descriptor() {
    assert_eq!(
        rotelyx_relay_proto::protos::relay::SEALED_HOP_LEN,
        rotelyx_crypto::circuit::SEALED_HOP_LEN,
        "the relay and the crypto disagree about how long a sealed circuit \
         descriptor is, so every real one would be refused as malformed"
    );
}

/// And the number is what a descriptor actually measures, not just a shared
/// belief.
///
/// Both constants agreeing on a wrong value would pass the test above and fail
/// everywhere else, which is the failure a shared constant invites.
#[test]
fn a_real_descriptor_is_that_many_bytes() {
    let (_, public) = HybridKem::generate();
    let sealed = SealedHop::seal(
        &public,
        &[7u8; 32],
        &Hop {
            destination: [9u8; 32],
            return_key: [137u8; 32],
            next_relay: None,
            hour: 400_000,
        },
    )
    .expect("seal");

    assert_eq!(
        sealed.to_bytes().len(),
        rotelyx_relay_proto::protos::relay::SEALED_HOP_LEN,
        "the constant both crates share is not the length a descriptor has"
    );
}
