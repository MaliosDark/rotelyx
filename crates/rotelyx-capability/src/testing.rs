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

/// A blind issuer, for tests. Generates a key, signs what it is given, and
/// decides nothing.
///
/// The real issuer is a program that holds this key in a vault, takes a
/// payment, and refuses to sign twice for one of them. The contract it serves
/// is in `docs/ISSUER.md`. What is here is only the signing, so a test can walk
/// the whole purchase without that program existing.
///
/// **It signs whatever it is handed.** That is the correct behaviour for a
/// blind issuer and it is the reason the payment check has to happen before
/// this call rather than inside it: by the time there is a blinded message to
/// sign, there is nothing left to inspect.
pub struct BlindIssuer {
    public_der: Vec<u8>,
    secret: blind_rsa_signatures::SecretKey<
        blind_rsa_signatures::Sha384,
        blind_rsa_signatures::PSS,
        blind_rsa_signatures::Randomized,
    >,
}

impl BlindIssuer {
    /// A fresh 2048 bit key, the shape `Redeemer` expects.
    pub fn generate() -> Self {
        use blind_rsa_signatures::reexports::rand::rngs::ThreadRng;
        use blind_rsa_signatures::{KeyPair, Randomized, Sha384, PSS};

        let mut rng = ThreadRng::default();
        let KeyPair { pk, sk } =
            KeyPair::<Sha384, PSS, Randomized>::generate(&mut rng, 2048).expect("keypair");
        Self {
            public_der: pk.to_der().expect("der"),
            secret: sk,
        }
    }

    /// The DER a client blinds against, and a mailbox verifies with.
    pub fn public_der(&self) -> &[u8] {
        &self.public_der
    }

    /// Sign one blinded message, base64url in and base64url out.
    ///
    /// Returns `None` for input that is not base64url, which is the 400 in the
    /// contract rather than a panic, so a test can exercise that path.
    pub fn blind_sign(&self, blinded_b64: &str) -> Option<String> {
        use data_encoding::BASE64URL_NOPAD;

        let blinded = BASE64URL_NOPAD.decode(blinded_b64.as_bytes()).ok()?;
        let signature = self.secret.blind_sign(&blinded).ok()?;
        Some(BASE64URL_NOPAD.encode(&signature))
    }
}
