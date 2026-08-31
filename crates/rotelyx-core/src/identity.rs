//! Rotelyx identity: an Ed25519 keypair, and nothing else.
//!
//! There is deliberately no phone number, email, or account here. An identity
//! *is* a public key. Everything a peer needs to reach and encrypt to this
//! identity is derived from it or published under it.

use std::fmt;
use std::str::FromStr;

// Taken from the transport's key crate rather than from the transport
// itself, so that identity works in a browser build where the transport
// cannot be compiled.
use rotelyx_transport_base::{EndpointId, SecretKey};
use zeroize::Zeroizing;

/// A public Rotelyx identity. Thin newtype over the iroh endpoint id so that the
/// rest of the codebase never depends on iroh's naming directly, if the
/// transport is ever swapped, this is the only type that has to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RotelyxId(EndpointId);

impl RotelyxId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.0
    }

    /// Short human-comparable form for UI. **Not** a security check: use
    /// [`Identity::safety_number`] for out-of-band verification.
    pub fn short(&self) -> String {
        let hex = self.0.to_string();
        format!("{}…{}", &hex[..6], &hex[hex.len() - 6..])
    }
}

impl From<EndpointId> for RotelyxId {
    fn from(id: EndpointId) -> Self {
        Self(id)
    }
}

impl fmt::Display for RotelyxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RotelyxId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(EndpointId::from_str(s)?))
    }
}

/// A local identity, including secret key material.
///
/// The secret is held in a [`Zeroizing`] buffer and only handed to iroh at
/// endpoint construction. Never log, serialise, or `Debug`-print this type,
/// the `Debug` impl below deliberately redacts.
pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    public: RotelyxId,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    ///
    /// Panics if the OS entropy source is unavailable. That is the correct
    /// behaviour: there is no safe degraded mode for generating a long-term
    /// identity key, and silently falling back to a weaker source is exactly
    /// the failure that is invisible until it matters.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable; refusing to generate a key");
        Self::from_bytes(bytes)
    }

    /// Restore an identity from stored key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_secret_key(SecretKey::from_bytes(&bytes))
    }

    fn from_secret_key(secret: SecretKey) -> Self {
        let public = RotelyxId(secret.public());
        Self {
            secret: Zeroizing::new(secret.to_bytes()),
            public,
        }
    }

    pub fn id(&self) -> RotelyxId {
        self.public
    }

    /// Hand the secret to the transport. Kept crate-visible so no application
    /// code can pull raw key material out of an `Identity`.
    // Only the transport needs the raw key; a browser build has no transport.
    #[cfg(feature = "transport")]
    pub(crate) fn secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.secret)
    }

    /// The name this identity presents inside one conversation.
    ///
    /// # Why not the identity itself
    ///
    /// A client that puts its long-lived identity in every conversation hands
    /// every contact the same value. Two people you invited separately can then
    /// compare what their screens show and learn they are talking to the same
    /// person, which is the linkage per-invitation addresses remove from the
    /// network and then hand straight back to the contacts.
    ///
    /// `shared` is something both sides of one conversation know and nobody else
    /// does: the invitation secret. The result is stable for that conversation,
    /// so a peer sees one consistent name across reconnections, and unrelated
    /// between conversations, so two peers see nothing in common.
    ///
    /// # What this costs, and what it does not
    ///
    /// It does not cost authentication. The value goes into an MLS credential,
    /// which is a label the member chooses: nothing ever proved it corresponded
    /// to a real identity, and the safety number authenticates by having both
    /// sides contribute and be compared out of band, which still works.
    ///
    /// What it costs is recognition. Somebody who verified you in one
    /// conversation cannot recognise you in another, and cannot vouch for you to
    /// anybody else. That is the same trade SimpleX makes, and it is the point
    /// rather than a side effect.
    pub fn in_conversation(&self, shared: &[u8]) -> RotelyxId {
        let mut hasher = blake3::Hasher::new_derive_key("rotelyx per-conversation name v1");
        hasher.update(&*self.secret);
        hasher.update(&(shared.len() as u64).to_be_bytes());
        hasher.update(shared);
        // Through a key rather than straight out of the hash: a `RotelyxId` is a
        // public key, and thirty two arbitrary bytes are not one. Deriving the
        // secret and taking its public half is deterministic, always valid, and
        // leaves room for this name to sign for itself later.
        RotelyxId::from(SecretKey::from_bytes(hasher.finalize().as_bytes()).public())
    }

    /// Export for encrypted at-rest storage. The caller is responsible for
    /// sealing this before it touches a disk.
    pub fn to_storage_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.clone()
    }

    /// Out-of-band verification string for two identities.
    ///
    /// Order-independent so both sides display the same digits, and derived
    /// from a domain-separated BLAKE3 of both public keys. Users compare this
    /// over a channel Rotelyx does not control: that comparison is the only
    /// thing that rules out a machine-in-the-middle at first contact.
    pub fn safety_number(&self, other: &RotelyxId) -> String {
        safety_number(&self.public, other)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Sixty decimal digits in twelve groups of five, matching the shape users
/// already know from other messengers.
pub fn safety_number(a: &RotelyxId, b: &RotelyxId) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };

    const GROUPS: usize = 12;

    let mut hasher = blake3::Hasher::new_derive_key("rotelyx safety-number v1");
    hasher.update(lo.as_bytes());
    hasher.update(hi.as_bytes());

    // A plain BLAKE3 digest is 32 bytes, which is only eight 4-byte groups.
    // Take the extendable output instead so the digit count is a display
    // decision rather than a hash-width accident.
    let mut bytes = [0u8; GROUPS * 4];
    hasher.finalize_xof().fill(&mut bytes);

    let mut groups = Vec::with_capacity(GROUPS);
    for chunk in bytes.chunks_exact(4) {
        let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        groups.push(format!("{:05}", v % 100_000));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {

    /// Two contacts must not be shown the same name.
    ///
    /// # What this is for
    ///
    /// It is the whole point of deriving a name per conversation. Per-invitation
    /// addresses stop the network seeing one name for all of somebody's
    /// contacts, and then a client that puts its long-lived identity in every
    /// MLS credential hands that name to the contacts instead, where they can
    /// compare it.
    #[test]
    fn two_conversations_show_two_different_names() {
        let me = Identity::generate();
        let (with_bob, with_carol) = ([1u8; 32], [2u8; 32]);

        let to_bob = me.in_conversation(&with_bob);
        let to_carol = me.in_conversation(&with_carol);

        assert_ne!(
            to_bob, to_carol,
            "two people invited separately were shown the same name and can link them"
        );
        assert_ne!(
            to_bob,
            me.id(),
            "the long-lived identity reached a conversation"
        );
        assert_ne!(to_carol, me.id());
    }

    /// The same conversation must show the same name every time.
    ///
    /// A name that changed between reconnections would be a new stranger every
    /// time, and the safety number somebody read out loud would stop matching.
    #[test]
    fn one_conversation_shows_one_name() {
        let me = Identity::generate();
        let shared = b"the invitation secret both sides hold";
        assert_eq!(me.in_conversation(shared), me.in_conversation(shared));
    }

    /// Two identities must not derive the same name from one conversation.
    #[test]
    fn two_identities_are_not_one_name() {
        let (a, b) = (Identity::generate(), Identity::generate());
        let shared = b"the same conversation";
        assert_ne!(a.in_conversation(shared), b.in_conversation(shared));
    }

    /// The length of `shared` is part of the derivation.
    ///
    /// Without it, two different secrets that concatenate to the same bytes
    /// would derive the same name.
    #[test]
    fn the_shared_secret_cannot_be_split_two_ways() {
        let me = Identity::generate();
        assert_ne!(me.in_conversation(b"abc"), me.in_conversation(b"ab"));
        assert_ne!(me.in_conversation(b"ab"), me.in_conversation(b"a"));
    }
    use super::*;

    #[test]
    fn identity_roundtrips_through_storage() {
        let id = Identity::generate();
        let restored = Identity::from_bytes(*id.to_storage_bytes());
        assert_eq!(id.id(), restored.id());
    }

    #[test]
    fn safety_number_is_order_independent() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(a.safety_number(&b.id()), b.safety_number(&a.id()));
    }

    #[test]
    fn safety_number_differs_per_pair() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        assert_ne!(a.safety_number(&b.id()), a.safety_number(&c.id()));
    }

    #[test]
    fn safety_number_is_twelve_groups_of_five() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sn = a.safety_number(&b.id());
        let groups: Vec<_> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let id = Identity::generate();
        let rendered = format!("{id:?}");
        assert!(rendered.contains("<redacted>"));
        let secret_hex = data_encoding::HEXLOWER.encode(&*id.to_storage_bytes());
        assert!(!rendered.contains(&secret_hex));
    }
}
