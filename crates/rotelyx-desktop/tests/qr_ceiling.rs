//! What fits in the invitation QR, measured rather than assumed.
//!
//! An invitation is handed over by being scanned, so its size is not a detail:
//! past a certain number of bytes there is no QR that a phone camera will read,
//! and the failure is not a smaller code, it is no code.
//!
//! The desktop draws its codes at `EcLevel::H` because a logo covers part of
//! them, and error correction is what pays for that. H is the least roomy
//! level, so it is the one that decides what an invitation may carry.
//!
//! This test exists because `docs/RELAY-CHAINING-PLAN.md` phase 4 would add the
//! exit relay's key to the invitation, and the plan says to measure the ceiling
//! before designing against it.

use qrcode::{EcLevel, QrCode};

/// An invitation today: a 32 byte secret and a 32 byte address.
const INVITATION_LEN: usize = 64;

/// What chaining would add: the exit relay's endpoint id and its X-Wing public
/// key.
const EXIT_RELAY_LEN: usize = 32 + 1216;

/// Whether a payload of this many bytes can be drawn at `EcLevel::H`.
///
/// The filler matters. A QR encoder picks the narrowest mode the data allows,
/// and its alphanumeric mode holds far more than its byte mode: filling with
/// `b'A'` measures a capacity an invitation can never have, since an invitation
/// is either raw key material or base64url, and base64url has lowercase in it.
/// So the filler cycles every byte value, which forces byte mode, which is what
/// an invitation actually costs.
fn fits_at_h(bytes: usize) -> bool {
    let payload: Vec<u8> = (0..bytes).map(|i| (i % 256) as u8).collect();
    QrCode::with_error_correction_level(payload, EcLevel::H).is_ok()
}

/// The same question for text that is base64url, which is how the applications
/// hand an invitation over.
fn fits_at_h_encoded(raw_bytes: usize) -> bool {
    let payload: String = (0..raw_bytes.div_ceil(3) * 4)
        .map(|i| {
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            ALPHABET[i % ALPHABET.len()] as char
        })
        .collect();
    QrCode::with_error_correction_level(payload, EcLevel::H).is_ok()
}

/// Today's invitation fits with room to spare, in either encoding.
#[test]
fn todays_invitation_fits() {
    assert!(fits_at_h(INVITATION_LEN), "a bare invitation does not fit");

    // The applications hand it over base64url encoded, which is what actually
    // goes in the code.
    assert!(
        fits_at_h_encoded(INVITATION_LEN),
        "an encoded invitation does not fit"
    );
}

/// An invitation carrying the exit relay's key does not fit, and this is the
/// number that says so.
///
/// Recorded as a test rather than a note because the conclusion is load
/// bearing: phase 4 of relay chaining cannot put the exit relay's public key in
/// the QR, and any design that assumes it can is designing against a ceiling
/// that is not there. If a future change makes this pass, the ceiling moved and
/// the plan should be reread, not the test deleted.
#[test]
fn an_invitation_carrying_the_exit_relay_key_does_not_fit() {
    let raw = INVITATION_LEN + EXIT_RELAY_LEN;
    assert!(
        !fits_at_h(raw),
        "the exit relay key now fits raw in a QR at H: {raw} bytes"
    );

    assert!(
        !fits_at_h_encoded(raw),
        "the exit relay key now fits base64url in a QR at H"
    );
}

/// The largest payload the predicate still accepts.
fn largest_that_fits(fits: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (1usize, 3000usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Where the ceiling actually is, so a design has a number to work against.
///
/// Printed rather than asserted to a constant: the answer belongs to the QR
/// standard and the crate that implements it, and pinning it here would be
/// repeating somebody else's number in a third place.
#[test]
fn the_ceiling_is_where_this_says_it_is() {
    // Binary searched rather than scanned: capacity only ever decreases as the
    // payload grows, and a linear walk to two thousand costs a minute of every
    // future test run to answer the same question.
    let largest = largest_that_fits(fits_at_h);
    let largest_encoded = largest_that_fits(fits_at_h_encoded);
    println!("at EcLevel::H: {largest} raw bytes, or {largest_encoded} bytes base64url encoded");

    assert!(
        largest > INVITATION_LEN,
        "an invitation no longer fits at all"
    );
    assert!(
        largest < INVITATION_LEN + EXIT_RELAY_LEN,
        "the exit relay key would now fit, and the plan should be reread"
    );
}
