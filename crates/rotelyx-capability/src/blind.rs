//! Issuing capability tokens without learning which purchase produced them.
//!
//! # What the Ed25519 tokens could not do
//!
//! The signed tokens in [`crate::access`] identify nobody, and that is already
//! most of the way there. What they cannot do is hide the *link between a
//! purchase and a token*: the issuer sees the exact bytes it signed, and if it
//! keeps a record of the sale alongside them, every later use of that token is
//! attributable. Nothing forces an operator to keep that record, and no
//! customer can check that it did not.
//!
//! Blind signatures remove the choice. The issuer signs a message it cannot
//! read and never sees the finished token, so the record it would need to keep
//! does not exist to be kept.
//!
//! # RFC 9474, not something invented here
//!
//! Blind RSA, which is what Privacy Pass uses for publicly verifiable tokens.
//! Publicly verifiable matters: the mailbox holds only a public key, exactly as
//! it does today. The alternative construction, a VOPRF, requires the verifier
//! to hold the issuing secret, which would put the key that mints paid access
//! on the machine most exposed to the internet.
//!
//! # Why the tier is the key, not a field
//!
//! The client chooses the message being blinded. If the tier lived inside that
//! message the client would simply write `Plus` into it, and the issuer, being
//! blind, could not object.
//!
//! So **each tier has its own key pair**. The blinded message carries nothing
//! but a random id. What a token grants is decided by which key verifies it,
//! and that is chosen by the issuer at the moment of sale. This is how Privacy
//! Pass separates token types, and it is the piece that makes blindness safe
//! rather than a hole.
//!
//! # What is still visible
//!
//! | | Visible |
//! |---|---|
//! | Who paid | To the payment processor. Never to the mailbox |
//! | Which purchase produced a token | **No longer**, and not by policy: by construction |
//! | Which tier a token grants | Yes, from the key that signs it |
//! | That one token's traffic belongs together | Yes. Inherent to metering |
//!
//! The third row is worth stating plainly: buying the only Plus subscription
//! sold that week narrows the anonymity set to one, whatever the mathematics
//! does. Blindness protects a token among its peers, never a lone purchaser.

use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, PublicKey, Randomized,
    Sha384, Signature, PSS,
};

/// RSABSSA-SHA384-PSS-Randomized, the variant RFC 9474 recommends. Randomized
/// rather than deterministic: a deterministic signature over the same id is the
/// same bytes every time, which hands an issuer a way to recognise a token it
/// has already seen.
type Public = PublicKey<Sha384, PSS, Randomized>;
use data_encoding::BASE64URL_NOPAD;

use crate::{Capability, Tier};

/// The blinded message is a random id and nothing else. Sixteen bytes, matching
/// what the meter counts against.
pub const ID_BYTES: usize = 16;

/// The randomized variant prepends 32 bytes to the message before hashing, and
/// a verifier needs those bytes back. They travel inside the token, between the
/// id and the signature.
pub const RANDOMIZER_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum BlindError {
    #[error("key material is malformed")]
    BadKey,
    #[error("not valid base64url")]
    Encoding,
    #[error("token is malformed")]
    Malformed,
    #[error("signature does not verify against the {0} key")]
    BadSignature(&'static str),
    #[error("generating a key: {0}")]
    Generate(String),
    #[error("blinding: {0}")]
    Blinding(String),
}

/// The client's half. Generates an id, blinds it, and later unblinds.
pub struct Redeemer {
    id: [u8; ID_BYTES],
    blinding: BlindingResult,
}

impl Redeemer {
    /// Write the in-flight state out, so blinding and unblinding can happen in
    /// two separate invocations with a payment in between.
    ///
    /// This is secret while it lives: whoever holds it can finish the token.
    /// It is deleted once redeemed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id);
        out.extend_from_slice(
            &self
                .blinding
                .msg_randomizer
                .map(|r| r.0)
                .unwrap_or([0u8; RANDOMIZER_BYTES]),
        );
        out.extend_from_slice(&self.blinding.secret.0);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlindError> {
        if bytes.len() <= ID_BYTES + RANDOMIZER_BYTES {
            return Err(BlindError::Malformed);
        }
        let (id, rest) = bytes.split_at(ID_BYTES);
        let (randomizer, secret) = rest.split_at(RANDOMIZER_BYTES);

        Ok(Self {
            id: id.try_into().map_err(|_| BlindError::Malformed)?,
            blinding: BlindingResult {
                blind_message: blind_rsa_signatures::BlindMessage(Vec::new()),
                secret: blind_rsa_signatures::Secret(secret.to_vec()),
                msg_randomizer: Some(MessageRandomizer(
                    randomizer.try_into().map_err(|_| BlindError::Malformed)?,
                )),
            },
        })
    }

    /// Pick an id and blind it under the tier's public key.
    ///
    /// The id never leaves this side unblinded until the token is spent, which
    /// is what breaks the link to the purchase.
    pub fn begin(public_der: &[u8]) -> Result<(Self, String), BlindError> {
        let pk = Public::from_der(public_der).map_err(|_| BlindError::BadKey)?;

        let mut id = [0u8; ID_BYTES];
        getrandom::fill(&mut id).map_err(|e| BlindError::Generate(e.to_string()))?;

        let blinding = pk
            .blind(&mut DefaultRng, id)
            .map_err(|e| BlindError::Blinding(e.to_string()))?;

        let blinded = BASE64URL_NOPAD.encode(&blinding.blind_message);
        Ok((Self { id, blinding }, blinded))
    }

    /// Unblind the issuer's signature into a usable token.
    pub fn finish(self, public_der: &[u8], blind_sig_b64: &str) -> Result<String, BlindError> {
        let pk = Public::from_der(public_der).map_err(|_| BlindError::BadKey)?;

        let raw = BASE64URL_NOPAD
            .decode(blind_sig_b64.trim().as_bytes())
            .map_err(|_| BlindError::Encoding)?;

        let signature = pk
            .finalize(&BlindSignature(raw), &self.blinding, self.id)
            .map_err(|e| BlindError::Blinding(e.to_string()))?;

        // The randomizer is not secret and is useless without the signature it
        // belongs to, so carrying it in the token costs nothing but 32 bytes.
        let randomizer = self
            .blinding
            .msg_randomizer
            .ok_or(BlindError::Malformed)?;

        let mut token = Vec::with_capacity(ID_BYTES + RANDOMIZER_BYTES + signature.len());
        token.extend_from_slice(&self.id);
        token.extend_from_slice(&randomizer.0);
        token.extend_from_slice(&signature);
        Ok(BASE64URL_NOPAD.encode(&token))
    }
}

/// Verifies blind tokens. This is what the mailbox holds: one public key per
/// tier and nothing else.
pub struct BlindVerifier {
    keys: Vec<(Tier, Public)>,
}

impl BlindVerifier {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn with_tier(mut self, tier: Tier, public_der: &[u8]) -> Result<Self, BlindError> {
        let pk = Public::from_der(public_der).map_err(|_| BlindError::BadKey)?;
        self.keys.push((tier, pk));
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check a token against every configured key.
    ///
    /// The tier is whichever key verifies, so a holder cannot promote a token
    /// by editing it: a Free token is a Free token because the Free key signed
    /// it, and nothing in the bytes says otherwise.
    ///
    /// Keys are tried highest tier first only so the common paid case is one
    /// operation. A token verifies under exactly one key regardless of order.
    pub fn verify(&self, token: &str) -> Result<Capability, BlindError> {
        let raw = BASE64URL_NOPAD
            .decode(token.trim().as_bytes())
            .map_err(|_| BlindError::Encoding)?;

        if raw.len() <= ID_BYTES + RANDOMIZER_BYTES {
            return Err(BlindError::Malformed);
        }
        let (id_bytes, rest) = raw.split_at(ID_BYTES);
        let (randomizer_bytes, sig) = rest.split_at(RANDOMIZER_BYTES);

        let id: [u8; ID_BYTES] = id_bytes.try_into().map_err(|_| BlindError::Malformed)?;
        let randomizer = MessageRandomizer(
            randomizer_bytes.try_into().map_err(|_| BlindError::Malformed)?,
        );

        for (tier, pk) in &self.keys {
            if pk
                .verify(&Signature(sig.to_vec()), Some(randomizer), id)
                .is_ok()
            {
                return Ok(Capability {
                    id,
                    tier: *tier,
                    limits: tier.limits(),
                });
            }
        }

        Err(BlindError::BadSignature(
            self.keys.first().map(|(t, _)| t.name()).unwrap_or("any"),
        ))
    }
}

impl Default for BlindVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn plus_der() -> Vec<u8> {
        unhex(vectors::BLIND_PLUS_PUBLIC_DER_HEX)
    }

    fn plusplus_der() -> Vec<u8> {
        unhex(vectors::BLIND_PLUSPLUS_PUBLIC_DER_HEX)
    }

    fn both() -> BlindVerifier {
        BlindVerifier::new()
            .with_tier(Tier::Plus, &plus_der())
            .expect("plus key")
            .with_tier(Tier::PlusPlus, &plusplus_der())
            .expect("plus++ key")
    }

    /// Tokens produced by a real blind issuance, frozen before that code left
    /// this repository.
    #[test]
    fn frozen_blind_tokens_verify_and_carry_their_tier() {
        let v = both();

        let cap = v.verify(vectors::BLIND_PLUS_TOKEN).expect("plus token verifies");
        assert_eq!(cap.tier, Tier::Plus);
        assert_eq!(cap.limits.max_fanout, Tier::Plus.limits().max_fanout);

        let cap = v
            .verify(vectors::BLIND_PLUSPLUS_TOKEN)
            .expect("plus++ token verifies");
        assert_eq!(cap.tier, Tier::PlusPlus);
    }

    /// The tier is the key, so a token signed under one key must not be
    /// accepted as the other. This is the property that makes blindness safe:
    /// the client picks the message, the issuer picks the key.
    #[test]
    fn a_token_is_not_accepted_under_another_tier_key() {
        let only_plusplus = BlindVerifier::new()
            .with_tier(Tier::PlusPlus, &plusplus_der())
            .expect("plus++ key");

        assert!(
            only_plusplus.verify(vectors::BLIND_PLUS_TOKEN).is_err(),
            "a plus token verified against the plus++ key"
        );
    }

    /// A server configured with no blind keys accepts nothing.
    #[test]
    fn an_empty_verifier_grants_nothing() {
        let v = BlindVerifier::new();
        assert!(v.is_empty());
        assert!(v.verify(vectors::BLIND_PLUS_TOKEN).is_err());
        assert!(v.verify(vectors::BLIND_PLUSPLUS_TOKEN).is_err());
    }

    /// Every single byte of a valid token, altered.
    #[test]
    fn editing_a_token_invalidates_it() {
        let v = both();
        let token = vectors::BLIND_PLUS_TOKEN;

        for position in 0..token.len() {
            let mut bytes = token.as_bytes().to_vec();
            bytes[position] ^= 0x01;
            let Ok(edited) = std::str::from_utf8(&bytes) else {
                continue;
            };
            assert!(
                v.verify(edited).is_err(),
                "a token with byte {position} altered still verified"
            );
        }
    }

    /// Garbage, and the shapes a parser walks off the end on.
    #[test]
    fn nothing_else_is_accepted() {
        let v = both();
        for junk in ["", "not a token", "AAAA", &"A".repeat(4096)] {
            assert!(v.verify(junk).is_err(), "accepted {junk:?}");
        }
    }

    /// The client's half still works: blinding needs only the public key, which
    /// is why the redeemer stays in the open even though the signer does not.
    #[test]
    fn the_in_flight_state_survives_being_written_down() {
        let der = plus_der();
        let (redeemer, blinded) = Redeemer::begin(&der).expect("begin");

        let bytes = redeemer.to_bytes();
        let restored = Redeemer::from_bytes(&bytes).expect("restore");

        assert_eq!(restored.to_bytes(), bytes, "the round trip changed the state");
        assert!(!blinded.is_empty());
    }

    /// Two blindings of two fresh ids share nothing an issuer could correlate.
    #[test]
    fn two_blindings_share_nothing() {
        let der = plus_der();
        let (_, first) = Redeemer::begin(&der).expect("begin");
        let (_, second) = Redeemer::begin(&der).expect("begin");
        assert_ne!(first, second, "two blinded messages came out identical");
    }
}
