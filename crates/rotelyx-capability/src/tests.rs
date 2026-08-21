//! Tiers, tokens and metering, checked against tokens the tests mint and
//! against tokens frozen from the real issuer.
//!
//! See `vectors::mint` for why a minter exists here when the issuer does not.

use crate::*;

use std::fs;
use data_encoding::BASE64URL_NOPAD;

use crate::{testing, vectors};

/// The key the tests mint with. Not an issuer: see `vectors::mint`.
const SECRET: &str = "abababababababababababababababababababababababababababababababab";
/// A different key, for the forgery cases.
const OTHER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn verifier() -> Verifier {
    Verifier::from_public_hex(&testing::public_hex(SECRET)).expect("verifier")
}

#[test]
fn a_minted_token_verifies_and_carries_its_tier() {
            let token = testing::mint(SECRET, [1u8; 16], Tier::Plus, 1000, 0);

    let cap = verifier().verify(&token, 999).expect("verify");
    assert_eq!(cap.tier, Tier::Plus);
    assert_eq!(cap.limits.max_fanout, Tier::Plus.limits().max_fanout);
    assert_eq!(cap.id, [1u8; 16]);
}

/// A token signed by anyone else must be refused, or the tier is free to
/// take rather than to buy.
#[test]
fn a_token_from_another_issuer_is_refused() {
    let forged = testing::mint(OTHER, [2u8; 16], Tier::Plus, 1000, 0);
    assert!(matches!(
        verifier().verify(&forged, 999),
        Err(TokenError::BadSignature)
    ));
}

/// Flipping a byte of the claims must invalidate the token, or a holder
/// could promote a free token to plus.
#[test]
fn a_tampered_token_is_refused() {
            let token = testing::mint(SECRET, [3u8; 16], Tier::Free, 1000, 0);

    let mut raw = BASE64URL_NOPAD.decode(token.as_bytes()).expect("b64");
    raw[0] ^= 0xff;
    let tampered = BASE64URL_NOPAD.encode(&raw);

    assert!(verifier().verify(&tampered, 999).is_err());
}

#[test]
fn an_expired_token_is_refused() {
            let token = testing::mint(SECRET, [4u8; 16], Tier::Plus, 100, 0);

    assert!(matches!(
        verifier().verify(&token, 100),
        Err(TokenError::Expired)
    ));
    assert!(verifier().verify(&token, 99).is_ok());
}

/// The quota lives in the token and the meter counts against its id, so
/// sharing a token shares its allowance. This is what stops one purchase
/// from serving a thousand people.
#[test]
fn sharing_a_token_shares_its_quota() {
            let token = testing::mint(SECRET, [5u8; 16], Tier::Plus, 1000, 1_000);
    let cap = verifier().verify(&token, 999).expect("verify");

    let mut meter = Meter::default();

    // Three different people, one token.
    assert!(matches!(meter.charge(&cap, 400, 0), Charge::Allowed { .. }));
    assert!(matches!(meter.charge(&cap, 400, 0), Charge::Allowed { .. }));
    assert_eq!(
        meter.charge(&cap, 400, 0),
        Charge::OverQuota {
            limit: 1_000,
            used: 800
        },
        "the third spender must find the shared allowance gone"
    );
}

/// Two different tokens must not draw from one another's allowance.
#[test]
fn separate_tokens_are_metered_separately() {
            let a = verifier()
        .verify(&testing::mint(SECRET, [6u8; 16], Tier::Plus, 1000, 500), 1)
        .expect("verify");
    let b = verifier()
        .verify(&testing::mint(SECRET, [7u8; 16], Tier::Plus, 1000, 500), 1)
        .expect("verify");

    let mut meter = Meter::default();
    assert!(matches!(meter.charge(&a, 500, 0), Charge::Allowed { .. }));
    assert!(
        matches!(meter.charge(&b, 500, 0), Charge::Allowed { .. }),
        "one token's spending must not consume another's"
    );
    assert!(matches!(meter.charge(&a, 1, 0), Charge::OverQuota { .. }));
}

/// One free caller must not be able to spend another one's allowance.
///
/// # The hole this closes
///
/// The meter counts against a capability's id, and the free capability used a
/// constant one. Every unauthenticated client on a mailbox therefore shared a
/// single 64 MiB bucket that resets once a day. Filling it took no token, no
/// payment and no identity: connect, deposit 64 MiB, and every other free user
/// is refused until the period rolls over. At the free fanout of 25 and 64 KiB
/// an envelope, that is 41 deposits.
///
/// The tests above cover two *bought* tokens, which have different ids by
/// construction, so none of them ever reached the free path. The machinery that
/// exists to stop abuse was the cheapest way to commit it.
#[test]
fn one_free_caller_cannot_spend_another_ones_quota() {
    let (a, b) = (Capability::free(), Capability::free());
    assert_ne!(a.id, b.id, "two free callers were given one meter bucket");

    let limit = Tier::Free.limits().bytes_per_period;
    let mut meter = Meter::default();

    // The first spends everything it is allowed, and no more.
    assert!(matches!(meter.charge(&a, limit, 0), Charge::Allowed { .. }));
    assert!(
        matches!(meter.charge(&a, 1, 0), Charge::OverQuota { .. }),
        "a free caller kept spending past its own limit"
    );

    // The second has spent nothing, and must be unaffected by the first.
    assert!(
        matches!(meter.charge(&b, limit, 0), Charge::Allowed { .. }),
        "one free caller filling its bucket refused an unrelated one"
    );
}

/// A quota that only resets on restart is not a subscription.
#[test]
fn the_allowance_returns_next_period() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [8u8; 16], Tier::Plus, 10_000, 100), 1)
        .expect("verify");

    let mut meter = Meter::default();
    assert!(matches!(meter.charge(&cap, 100, 0), Charge::Allowed { .. }));
    assert!(matches!(meter.charge(&cap, 1, 0), Charge::OverQuota { .. }));

    assert!(
        matches!(meter.charge(&cap, 100, PERIOD_HOURS), Charge::Allowed { .. }),
        "the allowance must return when the period rolls over"
    );
}

/// Refusing before spending, rather than after, is what makes it a limit.
#[test]
fn an_overshoot_is_refused_rather_than_recorded() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [9u8; 16], Tier::Free, 10_000, 100), 1)
        .expect("verify");

    let mut meter = Meter::default();
    assert!(matches!(meter.charge(&cap, 90, 0), Charge::Allowed { .. }));
    assert!(matches!(meter.charge(&cap, 20, 0), Charge::OverQuota { .. }));

    // The refused charge must not have been counted.
    assert!(
        matches!(meter.charge(&cap, 10, 0), Charge::Allowed { remaining: 0 }),
        "a refused charge must leave the counter untouched"
    );
}

/// Every limit a tier advertises must actually be reachable.
///
/// This exists because it was not. Plus was sold 256 pending envelopes per
/// recipient while the store clamped every depositor to 64, so the paid
/// tier delivered exactly what the free one did and said otherwise.
#[test]
fn every_advertised_limit_is_reachable() {
    for tier in [Tier::Free, Tier::Plus, Tier::PlusPlus] {
        let limits = tier.limits();
        assert!(
            limits.max_per_tag <= rotelyx_mailbox::MAX_PER_TAG,
            "the {} tier advertises {} envelopes per tag but the store clamps at {}",
            tier.name(),
            limits.max_per_tag,
            rotelyx_mailbox::MAX_PER_TAG
        );
        assert!(
            rotelyx_mailbox::Bucket::from_size(limits.max_payload).is_some(),
            "the {} tier's max payload of {} is not a padding bucket, so no \
             well formed envelope can ever be that size",
            tier.name(),
            limits.max_payload
        );
    }
}

/// The free tier must not be able to do the things that are sold.
#[test]
fn the_free_tier_cannot_reach_the_paid_limits() {
    let free = Tier::Free.limits();
    let plus = Tier::Plus.limits();

    assert!(free.max_payload < plus.max_payload, "attachment size is a paid limit");
    assert!(free.ttl_seconds < plus.ttl_seconds, "retention is a paid limit");
    assert!(free.max_per_tag < plus.max_per_tag, "backlog depth is a paid limit");
    assert!(free.bytes_per_period < plus.bytes_per_period, "volume is a paid limit");

    // Group size is a paid lever, in three steps.
    let more = Tier::PlusPlus.limits();
    assert!(free.max_fanout < plus.max_fanout);
    assert!(plus.max_fanout < more.max_fanout);
    assert!(plus.ttl_seconds < more.ttl_seconds);
    assert!(plus.bytes_per_period < more.bytes_per_period);

    // The free tier must still hold an ordinary conversation. A messenger
    // that charges to talk to your family is not a messenger.
    assert!(
        free.max_fanout >= 25,
        "the free tier must hold a family or a team"
    );
}

/// The meter must forget. It holds no identity, but an unbounded table is
/// still a liability and a leak.
#[test]
fn the_meter_forgets_old_periods() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [10u8; 16], Tier::Plus, 10_000, 100), 1)
        .expect("verify");

    let mut meter = Meter::default();
    meter.charge(&cap, 10, 0);
    assert_eq!(meter.tracked(), 1);

    assert_eq!(meter.sweep(PERIOD_HOURS), 1);
    assert_eq!(meter.tracked(), 0);
}

/// A restart must not hand out a fresh allowance. This is the whole point.
#[test]
fn spending_survives_a_restart() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [20u8; 16], Tier::Plus, 10_000, 1_000), 1)
        .expect("verify");

    let dir = std::env::temp_dir().join(format!("rotelyx-meter-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("meter");

    let mut meter = Meter::default();
    assert!(matches!(meter.charge(&cap, 900, 0), Charge::Allowed { .. }));
    meter.save(&path).expect("save");

    let mut restarted = Meter::load(&path, 0).expect("load");
    assert!(
        matches!(restarted.charge(&cap, 200, 0), Charge::OverQuota { used: 900, .. }),
        "a restart must not reset what was already spent"
    );
    assert!(matches!(restarted.charge(&cap, 100, 0), Charge::Allowed { .. }));

    let _ = fs::remove_dir_all(&dir);
}

/// A first start has no file, and that is not a failure.
#[test]
fn a_missing_snapshot_is_a_first_start() {
    let path = std::env::temp_dir().join("rotelyx-meter-does-not-exist");
    let _ = fs::remove_file(&path);
    assert_eq!(Meter::load(&path, 0).expect("load").tracked(), 0);
}

/// Counters from a period that has passed must not come back.
#[test]
fn a_stale_snapshot_does_not_resurrect_old_spending() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [21u8; 16], Tier::Plus, 100_000, 1_000), 1)
        .expect("verify");

    let dir = std::env::temp_dir().join(format!("rotelyx-stale-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("meter");

    let mut meter = Meter::default();
    meter.charge(&cap, 1_000, 0);
    meter.save(&path).expect("save");

    // A day later.
    let restarted = Meter::load(&path, PERIOD_HOURS).expect("load");
    assert_eq!(
        restarted.tracked(),
        0,
        "yesterday's counters must not follow the token into today"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// The snapshot must contain no identity. This is asserted rather than
/// assumed, because it is the claim that makes the file safe to keep.
#[test]
fn the_snapshot_holds_nothing_but_ids_and_counts() {
            let cap = verifier()
        .verify(&testing::mint(SECRET, [22u8; 16], Tier::Plus, 10_000, 1_000), 1)
        .expect("verify");

    let dir = std::env::temp_dir().join(format!("rotelyx-shape-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("meter");

    let mut meter = Meter::default();
    meter.charge(&cap, 500, 0);
    meter.save(&path).expect("save");

    let raw = fs::read(&path).expect("read");
    assert!(
        raw.len() < 64,
        "one token's record is {} bytes: too large to be only an id and two \
         integers, so something else got in",
        raw.len()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the snapshot must not be world readable");
    }

    let _ = fs::remove_dir_all(&dir);
}

/// The secret half round-trips in the issuer's own crate, which is not
/// here. What this checks is the half a server holds.
#[test]
fn a_public_key_round_trips_through_hex() {
    let hex = testing::public_hex(SECRET);
    assert!(Verifier::from_public_hex(&hex).is_some());

    assert!(Verifier::from_public_hex("too short").is_none());
    assert!(Verifier::from_public_hex(&"zz".repeat(32)).is_none());
}

/// The frozen vectors still verify.
///
/// These were produced by the real issuer before it left this repository.
/// If this fails, the wire format moved and every token already sold has
/// stopped working.
#[test]
fn the_frozen_vectors_still_verify() {
    let v = Verifier::from_public_hex(vectors::ED25519_PUBLIC_HEX).expect("verifier");

    for (token, tier) in [
        (vectors::ED25519_TOKEN_FREE, Tier::Free),
        (vectors::ED25519_TOKEN_PLUS, Tier::Plus),
        (vectors::ED25519_TOKEN_PLUSPLUS, Tier::PlusPlus),
    ] {
        let cap = v.verify(token, 999_999).expect("a frozen vector must verify");
        assert_eq!(cap.tier, tier);
        assert_eq!(cap.id, [7u8; 16]);
    }

    let cap = v.verify(vectors::ED25519_TOKEN_QUOTA, 999_999).expect("verify");
    assert_eq!(cap.limits.bytes_per_period, 12_345, "the quota override was lost");
}
