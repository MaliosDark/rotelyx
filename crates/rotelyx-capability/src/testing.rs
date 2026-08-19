//! A minter, for tests. Behind a feature, and never in a shipped binary.
//!
//! This is not the issuer. The issuer is a program that holds a key in a vault,
//! decides what to sell, and talks to a payment processor; it lives in a
//! separate crate that is not in this repository.
//!
//! What is here is the twenty lines of signature the *format* requires, so that
//! this crate's tests, and the mailbox server's, can ask what happens to an
//! expired token, a token carrying a quota, or a token signed by a key the
//! server has never heard of. The frozen vectors in `vectors` cannot express
//! those, and rewriting the tests to do without would have meant testing less.
//!
//! Enabled with `features = ["testing"]`, which nothing but a dev-dependency
//! should ever do.

/// Mint a token with the given key. Signs; decides nothing.
pub fn mint(
    secret_hex: &str,
    id: [u8; 16],
    tier: crate::Tier,
    expires_hour: u64,
    quota_bytes: u64,
) -> String {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::{Signer, SigningKey};

    let bytes = crate::decode_hex(secret_hex, 32).expect("32 byte secret");
    let key = SigningKey::from_bytes(&bytes.try_into().expect("32 bytes"));

    let claims = crate::Claims {
        id,
        tier,
        expires_hour,
        quota_bytes,
    };
    let body = postcard::to_allocvec(&claims).expect("claims encode");

    let mut signed = Vec::new();
    signed.extend_from_slice(crate::TOKEN_CONTEXT);
    signed.extend_from_slice(&body);

    let mut out = body;
    out.extend_from_slice(&key.sign(&signed).to_bytes());
    BASE64URL_NOPAD.encode(&out)
}

/// The public key matching the secret the tests mint with.
pub fn public_hex(secret_hex: &str) -> String {
    use ed25519_dalek::SigningKey;
    let bytes = crate::decode_hex(secret_hex, 32).expect("32 byte secret");
    let key = SigningKey::from_bytes(&bytes.try_into().expect("32 bytes"));
    crate::encode_hex(key.verifying_key().as_bytes())
}
