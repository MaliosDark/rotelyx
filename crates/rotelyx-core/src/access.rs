//! Reachability: who is allowed to open a session with you.
//!
//! Rotelyx identities are keypairs, so they are free and unlimited. That is the
//! property that removes phone numbers from the design, and it is the same
//! property that made Kik a haven for unsolicited contact: an identity that
//! costs nothing can be discarded and replaced the moment it is blocked.
//!
//! Cryptography does not fix this. Scarcity does, and there are only two kinds
//! available here:
//!
//! - **Authorisation.** You are reachable only by someone holding an invitation
//!   you issued. This is the default, and it makes unsolicited contact
//!   impossible rather than merely expensive.
//! - **Cost.** For identities that *do* want to be reachable by strangers: a
//!   support account, a public figure: a proof of work makes first contact
//!   cost the sender real time while costing the recipient microseconds.
//!
//! Neither stops a determined individual attacker. Both destroy the economics
//! of bulk unsolicited contact, which is the actual threat. See
//! `docs/THREAT-MODEL.md` ADV-10.

use std::time::Duration;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use rotelyx_transport_base::SecretKey;

use crate::identity::RotelyxId;

const POW_CONTEXT: &str = "rotelyx contact proof-of-work v1";
const INVITE_CONTEXT: &str = "rotelyx invitation proof v1";

/// Length of a coarse time bucket used by both mechanisms, in seconds.
///
/// One hour. Long enough that clock skew between two phones is irrelevant,
/// short enough that a solved proof or a captured invitation proof stops being
/// useful the same day.
pub const EPOCH_SECONDS: u64 = 3600;

/// Convert a wall-clock timestamp to an epoch.
///
/// Callers pass time in rather than this module reading a clock, which keeps it
/// deterministic and makes skew an explicit concern rather than a hidden one.
pub fn epoch_at(unix_seconds: u64) -> u64 {
    unix_seconds / EPOCH_SECONDS
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("proof of work is for a different recipient")]
    WrongTarget,

    #[error("proof of work is for epoch {got}, current window is {want}±{tolerance}")]
    StaleProof {
        got: u64,
        want: u64,
        tolerance: u64,
    },

    #[error("proof of work does not meet difficulty {required}")]
    InsufficientWork { required: u8 },

    #[error("invitation proof did not verify")]
    BadInvitation,

    #[error("invitation expired at epoch {expired_at}")]
    ExpiredInvitation { expired_at: u64 },


    /// A code that is not the right length, or whose address half is not a
    /// point on the curve. Said the same way for both, because telling a caller
    /// which half they got wrong is telling them something about the other.
    #[error("invitation code is malformed")]
    Malformed,

    #[error("admission evidence is malformed")]
    MalformedAdmission,
}

// ---------------------------------------------------------------------------
// Proof of work
// ---------------------------------------------------------------------------

/// A solved proof of work for one (sender, recipient, epoch) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactProof {
    pub nonce: u64,
    pub epoch: u64,
}

fn pow_digest(sender: &RotelyxId, target: &RotelyxId, epoch: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(POW_CONTEXT);
    hasher.update(sender.as_bytes());
    hasher.update(target.as_bytes());
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&nonce.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        let z = byte.leading_zeros();
        bits += z;
        if z != 8 {
            break;
        }
    }
    bits
}

/// Search for a proof of work.
///
/// Cost doubles with every point of difficulty. The work is bound to **both**
/// identities and to the epoch, which is what makes it non-transferable:
///
/// - Binding the target means work done to reach one person cannot be spent on
///   another, so a bulk sender pays per recipient.
/// - Binding the sender means a spammer cannot solve once and reuse it across a
///   fleet of throwaway identities: each identity pays again.
/// - Binding the epoch means proofs cannot be stockpiled years in advance, and
///   expire on their own.
///
/// Together those force a bulk sender to choose: reuse one identity and be
/// blocked, or pay the work for every identity.
pub fn solve(sender: &RotelyxId, target: &RotelyxId, epoch: u64, difficulty: u8) -> ContactProof {
    let mut nonce = 0u64;
    loop {
        let digest = pow_digest(sender, target, epoch, nonce);
        if leading_zero_bits(&digest) >= u32::from(difficulty) {
            return ContactProof { nonce, epoch };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Verify a proof of work.
///
/// `tolerance` is how many epochs either side of `current_epoch` to accept,
/// covering clock skew and a proof solved just before an epoch boundary.
pub fn verify_proof(
    proof: &ContactProof,
    sender: &RotelyxId,
    target: &RotelyxId,
    current_epoch: u64,
    difficulty: u8,
    tolerance: u64,
) -> Result<(), AccessError> {
    if proof.epoch.abs_diff(current_epoch) > tolerance {
        return Err(AccessError::StaleProof {
            got: proof.epoch,
            want: current_epoch,
            tolerance,
        });
    }

    let digest = pow_digest(sender, target, proof.epoch, proof.nonce);
    if leading_zero_bits(&digest) < u32::from(difficulty) {
        return Err(AccessError::InsufficientWork {
            required: difficulty,
        });
    }
    Ok(())
}

/// Rough time to solve at a given difficulty, for choosing a setting.
///
/// Assumes one million hashes per second, which is conservative for a phone.
/// Difficulty 20 is about a second; 24 about sixteen; 28 about four minutes.
pub fn estimated_cost(difficulty: u8) -> Duration {
    let hashes = 2f64.powi(i32::from(difficulty));
    Duration::from_secs_f64(hashes / 1_000_000.0)
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

/// The identity a group authenticated, as opposed to the key a transport did.
///
/// # Why these are two different values
///
/// An endpoint bound under its identity authenticates that identity, and a
/// transport peer and a person were the same thing. An endpoint bound under an
/// invitation's own key authenticates that key, which belongs to one
/// conversation and says nothing about who is behind it.
///
/// A safety number over the second verifies that nobody swapped a single-use
/// key. Nobody reads digits out loud for that. This is the value to compare.
pub fn peer_identity(roster: &[Vec<u8>], me: RotelyxId) -> Option<RotelyxId> {
    roster
        .iter()
        .filter_map(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
        .filter_map(|b| rotelyx_transport_base::EndpointId::from_bytes(&b).ok())
        .map(RotelyxId::from)
        .find(|id| *id != me)
}

/// The address a transport key is answered at.
fn address_of(transport: &[u8; 32]) -> RotelyxId {
    RotelyxId::from(SecretKey::from_bytes(transport).public())
}

/// Where a circuit through two relays should come out.
///
/// Carried in an invitation because the recipient picks their own relay, and
/// the sender has to learn which one without asking a directory. See
/// `docs/RELAY-CHAINING.md` section 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRelay {
    /// The relay's endpoint id, which is what a circuit descriptor is sealed
    /// to.
    pub relay: RotelyxId,
    /// BLAKE3 of that relay's circuit key.
    ///
    /// # Why a hash and not the key
    ///
    /// The key is 1216 bytes and an invitation is scanned. Measured rather than
    /// guessed: at the error correction level the mark needs, a QR holds 1292
    /// raw bytes, and an invitation carrying the key outright would be 1312.
    /// `crates/rotelyx-desktop/tests/qr_ceiling.rs` holds the measurement.
    ///
    /// So the key is fetched, and **through the sender's own relay**, never
    /// from the exit relay: asking it directly would hand it the sender's
    /// address before any circuit exists. This hash is what makes that safe.
    /// The relay doing the fetching cannot substitute a key of its own.
    pub key_hash: [u8; 32],
    /// Where that relay is, because a relay is reached by address and not by
    /// endpoint id.
    pub url: String,
}

/// The context a circuit key's fingerprint is derived under.
///
/// Domain separated so that this hash cannot be mistaken for, or replayed as,
/// any other hash of the same bytes in this system.
const CIRCUIT_KEY_FINGERPRINT_CONTEXT: &str = "rotelyx relay circuit key fingerprint v1";

impl ExitRelay {
    /// The fingerprint of a relay's circuit key, as an invitation carries it.
    ///
    /// Over the key's raw bytes rather than its base64, so that two spellings
    /// of the same key give the same answer.
    pub fn fingerprint(key: &[u8]) -> [u8; 32] {
        blake3::derive_key(CIRCUIT_KEY_FINGERPRINT_CONTEXT, key)
    }

    /// The two sealed layers that open a circuit to this relay.
    ///
    /// # What goes in each
    ///
    /// The outer one is sealed to the **first** relay, the caller's own, and
    /// says only where to carry this and under what name to answer. The inner
    /// one is sealed to the exit relay and says where the circuit ends. Neither
    /// relay can read the other's, which is the whole arrangement.
    ///
    /// `return_key` is the name the destination sees as the sender, and it is
    /// the caller's own per-call transport key. The destination replies to it
    /// and the reply comes back along the circuit.
    ///
    /// `exit_key` must be checked with [`Self::accepts`] first. It was fetched
    /// through the first relay and that relay could have substituted one of its
    /// own; sealing to an unchecked key hands it every circuit.
    pub fn seal_circuit(
        &self,
        first_relay: &RotelyxId,
        first_relay_key: &rotelyx_crypto::hybrid::HybridPublicKey,
        exit_key: &rotelyx_crypto::hybrid::HybridPublicKey,
        destination: &RotelyxId,
        return_key: &RotelyxId,
        hour: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), AccessError> {
        use rotelyx_crypto::circuit::{Hop, SealedHop};

        let inner = SealedHop::seal(
            exit_key,
            self.relay.as_bytes(),
            &Hop {
                destination: *destination.as_bytes(),
                return_key: *return_key.as_bytes(),
                // Ends at a person, so there is nowhere further to carry it.
                next_relay: None,
                hour,
            },
        )
        .map_err(|_| AccessError::Malformed)?;

        let outer = SealedHop::seal(
            first_relay_key,
            first_relay.as_bytes(),
            &Hop {
                // The first relay's circuit ends at the second one.
                destination: *self.relay.as_bytes(),
                // What the exit relay sees as the sender on the link. Not the
                // caller's own key: this hop's return name is between these two
                // relays and says nothing about anybody.
                return_key: *return_key.as_bytes(),
                next_relay: Some(self.url.clone()),
                hour,
            },
        )
        .map_err(|_| AccessError::Malformed)?;

        Ok((outer.to_bytes(), inner.to_bytes()))
    }

    /// Whether this is the key the invitation named.
    ///
    /// # Why this is the whole safety of fetching a key
    ///
    /// The key does not travel in the invitation, so it is fetched, and it is
    /// fetched **through the sender's own relay** rather than from the exit
    /// relay. That relay could answer with a key of its own and read every
    /// circuit sealed to it. It cannot, because the invitation carried this
    /// hash, and the person who issued the invitation is the person whose relay
    /// it names.
    ///
    /// A caller that skips this check has a chain that protects nothing.
    pub fn accepts(&self, key: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        Self::fingerprint(key).ct_eq(&self.key_hash).into()
    }
}

/// What a code says, once read.
#[derive(Debug, Clone)]
pub struct ReadCode {
    /// The secret that authorises.
    pub secret: [u8; 32],
    /// The address to call.
    pub address: RotelyxId,
    /// The exit relay, when the code carries one.
    pub exit: Option<ExitRelay>,
}

/// A capability issued by one identity so another can reach it.
///
/// Shared out of band: a QR code, a link, a spoken string. Possession is the
/// authorisation; the secret itself never travels over the wire, only a MAC
/// derived from it.
pub struct Invitation {
    secret: Zeroizing<[u8; 32]>,
    expires_at_epoch: u64,
    /// The public half of `transport`, worked out once.
    ///
    /// Deriving it costs a scalar multiplication, and admission consults every
    /// live invitation's address on every attempt to connect, which anybody may
    /// make. Left to be recomputed, the work an unadmitted caller can ask for
    /// would grow with the number of invitations the identity holds.
    address: RotelyxId,
    /// The address this invitation is answered on.
    ///
    /// # Why an invitation carries an address at all
    ///
    /// An identity that listens under its own key is reachable at one address
    /// for everybody, and a relay carrying that traffic learns which endpoint
    /// talks to which however little it can read. That disclosure exists only
    /// because the transport key and the identity key are the same key.
    ///
    /// Giving each invitation a key of its own removes it. Every contact
    /// reaches a different address, none of which is the identity, and a relay
    /// sees values that say nothing about who is behind them.
    ///
    /// It also replaces blocking with something stronger. A blocklist refuses a
    /// caller who still reached you; **discarding an invitation's key means the
    /// address stops existing.** There is nothing to refuse and nothing to
    /// probe.
    ///
    /// # Why the secret half is not derived from the invitation secret
    ///
    /// Deriving it would be tidier: the holder of the code could work out the
    /// address without being told. It would also hand the holder the private
    /// key of the endpoint they are calling, which is an impersonation of the
    /// host to its own relay. The public half travels in the code; the private
    /// half never leaves the issuer.
    transport: Zeroizing<[u8; 32]>,
}

impl Invitation {
    /// Issue an invitation valid until `expires_at_epoch`.
    ///
    /// Generates both halves: the secret that authorises, and the transport key
    /// this invitation will be answered on.
    pub fn issue(expires_at_epoch: u64) -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("OS CSPRNG unavailable");
        let mut transport = [0u8; 32];
        getrandom::fill(&mut transport).expect("OS CSPRNG unavailable");
        Self {
            address: address_of(&transport),
            secret: Zeroizing::new(secret),
            expires_at_epoch,
            transport: Zeroizing::new(transport),
        }
    }

    /// Rebuild one that was stored.
    pub fn from_parts(secret: [u8; 32], transport: [u8; 32], expires_at_epoch: u64) -> Self {
        Self {
            address: address_of(&transport),
            secret: Zeroizing::new(secret),
            expires_at_epoch,
            transport: Zeroizing::new(transport),
        }
    }

    /// Rebuild one stored before invitations had an address of their own.
    ///
    /// The transport key is generated fresh, which is correct rather than a
    /// fallback: an invitation that had no address was answered on the
    /// identity's, and giving it one now is the whole improvement. The holder
    /// of the old code needs the new one, and that is a real migration cost
    /// rather than something to paper over.
    pub fn from_secret(secret: [u8; 32], expires_at_epoch: u64) -> Self {
        let mut transport = [0u8; 32];
        getrandom::fill(&mut transport).expect("OS CSPRNG unavailable");
        Self {
            address: address_of(&transport),
            secret: Zeroizing::new(secret),
            expires_at_epoch,
            transport: Zeroizing::new(transport),
        }
    }

    /// The transport key this invitation is answered on. Issuer only.
    pub fn transport_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.transport.clone()
    }

    /// The address a holder of this invitation should call.
    ///
    /// Derived from the transport key, so it is the same value the issuer will
    /// be listening on and nothing has to be carried alongside the code.
    pub fn address(&self) -> RotelyxId {
        self.address
    }

    /// The whole thing as one string to hand over: the secret that authorises,
    /// and the address to call.
    ///
    /// # Why both travel together
    ///
    /// Before this, reaching somebody took two strings: an address and an
    /// invitation code, and the address was the identity, the same one for
    /// everybody. One string now, and the address in it belongs to this
    /// invitation alone. Handing somebody a way in stopped being the same as
    /// handing them your name.
    ///
    /// The secret half is a password. The address half is not, and is useless
    /// without it: calling that address without the proof is refused like any
    /// other stranger.
    pub fn code(&self) -> Zeroizing<[u8; 64]> {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.secret[..]);
        out[32..].copy_from_slice(self.address().as_bytes());
        Zeroizing::new(out)
    }

    /// Read a code handed over by an issuer: the secret, and where to call.
    ///
    /// Returns the two halves rather than an `Invitation`, because a caller
    /// holds neither the transport secret nor the expiry and must not be able
    /// to pretend it does.
    pub fn read_code(code: &[u8]) -> Result<([u8; 32], RotelyxId), AccessError> {
        let read = Self::read_code_full(code)?;
        Ok((read.secret, read.address))
    }

    /// The same code, including the exit relay when one travels with it.
    ///
    /// # Why length says which form this is, and not a version byte
    ///
    /// A code is 64 bytes or it is longer. Sixty four is the form that has been
    /// handed out since before chaining and it keeps working untouched; longer
    /// carries an exit relay after it. Nothing has to be decided about a
    /// version number nobody has written yet, and an old code stays valid
    /// rather than becoming version zero of something.
    pub fn read_code_full(code: &[u8]) -> Result<ReadCode, AccessError> {
        if code.len() < 64 {
            return Err(AccessError::Malformed);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&code[..32]);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&code[32..64]);
        let id = rotelyx_transport_base::EndpointId::from_bytes(&addr)
            .map_err(|_| AccessError::Malformed)?;

        let exit = match code.len() {
            64 => None,
            // An exit relay is its endpoint id, a hash of its circuit key, and
            // the address to reach it at. The address is what is left, so it
            // needs no length of its own.
            len if len > 128 => {
                let mut relay = [0u8; 32];
                relay.copy_from_slice(&code[64..96]);
                let relay = rotelyx_transport_base::EndpointId::from_bytes(&relay)
                    .map_err(|_| AccessError::Malformed)?;
                let mut key_hash = [0u8; 32];
                key_hash.copy_from_slice(&code[96..128]);
                let url = core::str::from_utf8(&code[128..])
                    .map_err(|_| AccessError::Malformed)?
                    .to_owned();
                Some(ExitRelay {
                    relay: RotelyxId::from(relay),
                    key_hash,
                    url,
                })
            }
            // Between the two: an exit relay with something missing. Refused
            // rather than half read.
            _ => return Err(AccessError::Malformed),
        };

        Ok(ReadCode {
            secret,
            address: RotelyxId::from(id),
            exit,
        })
    }

    /// The code with an exit relay named after it.
    ///
    /// The recipient chooses their own relay, so the invitation is where they
    /// say which one. See `docs/RELAY-CHAINING.md`.
    pub fn code_with_exit(&self, exit: &ExitRelay) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(128 + exit.url.len());
        out.extend_from_slice(&self.code()[..]);
        out.extend_from_slice(exit.relay.as_bytes());
        out.extend_from_slice(&exit.key_hash);
        out.extend_from_slice(exit.url.as_bytes());
        Zeroizing::new(out)
    }

    /// The bytes to encode into a QR code or link. Treat as a password.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.clone()
    }

    pub fn expires_at_epoch(&self) -> u64 {
        self.expires_at_epoch
    }

    /// Prove possession, as the caller.
    ///
    /// Binding the caller's identity is what stops a captured proof being
    /// replayed by somebody else who saw it: the issuer checks the MAC against
    /// the identity that the QUIC handshake already authenticated, so a stolen
    /// proof is useless without also stealing the caller's private key.
    pub fn prove(&self, caller: &RotelyxId, epoch: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret);
        hasher.update(INVITE_CONTEXT.as_bytes());
        hasher.update(caller.as_bytes());
        hasher.update(&epoch.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify a caller's proof, as the issuer.
    pub fn verify(
        &self,
        proof: &[u8; 32],
        caller: &RotelyxId,
        epoch: u64,
        current_epoch: u64,
    ) -> Result<(), AccessError> {
        if current_epoch > self.expires_at_epoch {
            return Err(AccessError::ExpiredInvitation {
                expired_at: self.expires_at_epoch,
            });
        }

        let expected = self.prove(caller, epoch);
        // Constant time: a byte-by-byte comparison that returns early leaks how
        // much of a forged proof was correct, which is enough to forge the rest.
        if expected.ct_eq(proof).into() {
            Ok(())
        } else {
            Err(AccessError::BadInvitation)
        }
    }
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invitation")
            .field("secret", &"<redacted>")
            .field("expires_at_epoch", &self.expires_at_epoch)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// How an identity decides who may open a session with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityPolicy {
    /// Invitation required. Unsolicited contact is impossible, not merely
    /// expensive. The correct default for a person.
    InvitationOnly,

    /// Open to strangers who pay a proof of work.
    ///
    /// For identities that must be publicly reachable. `difficulty` is leading
    /// zero bits; see [`estimated_cost`].
    ProofOfWork { difficulty: u8 },

    /// Anyone may connect.
    ///
    /// Provided because some deployments genuinely want it: a public relay
    /// endpoint, a test rig, and because pretending it does not exist would
    /// just mean people reimplement it worse. Never a sensible default for a
    /// human's device.
    Open,
}

impl ReachabilityPolicy {
    /// Whether an unknown identity can reach this one without authorisation.
    pub fn admits_strangers(&self) -> bool {
        !matches!(self, Self::InvitationOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;


    /// Two invitations from one identity are answered at two addresses, and
    /// neither is the identity.
    ///
    /// This is the property the whole change exists for. A relay carrying both
    /// conversations sees two unrelated values, and nothing that ties either to
    /// the person behind them.
    #[test]
    fn every_invitation_has_an_address_of_its_own() {
        let me = Identity::generate();
        let a = Invitation::issue(100);
        let b = Invitation::issue(100);

        assert_ne!(a.address(), b.address(), "two invitations share an address");
        assert_ne!(a.address(), me.id(), "an invitation is answered on the identity");
        assert_ne!(b.address(), me.id(), "an invitation is answered on the identity");
    }

    /// The code carries both halves and survives the round trip.
    #[test]
    fn a_code_carries_the_secret_and_the_address() {
        let inv = Invitation::issue(100);
        let code = inv.code();

        let (secret, addr) = Invitation::read_code(&code[..]).expect("a code we just made");
        assert_eq!(secret, *inv.secret_bytes(), "the secret did not survive");
        assert_eq!(addr, inv.address(), "the address did not survive");
    }

    /// A code with an exit relay carries it, and the short form still reads.
    #[test]
    fn a_code_can_carry_an_exit_relay_and_the_old_form_still_reads() {
        let inv = Invitation::issue(100);
        let exit = ExitRelay {
            relay: address_of(&[7u8; 32]),
            key_hash: [9u8; 32],
            url: "https://relay.example.invalid".to_owned(),
        };

        let long = inv.code_with_exit(&exit);
        let read = Invitation::read_code_full(&long[..]).expect("a code we just made");
        assert_eq!(read.secret, *inv.secret_bytes(), "the secret did not survive");
        assert_eq!(read.address, inv.address(), "the address did not survive");
        assert_eq!(read.exit.as_ref(), Some(&exit), "the exit relay did not survive");

        // The form handed out before chaining is still a code, and says it
        // carries no exit relay rather than failing.
        let short = inv.code();
        let read = Invitation::read_code_full(&short[..]).expect("the old form should still read");
        assert_eq!(read.secret, *inv.secret_bytes());
        assert!(read.exit.is_none(), "an exit relay appeared from nowhere");

        // And the reader everything else uses is unchanged by any of it.
        let (secret, addr) = Invitation::read_code(&long[..]).expect("the long form");
        assert_eq!(secret, *inv.secret_bytes());
        assert_eq!(addr, inv.address());
    }

    /// The fingerprint accepts the key it was made from and nothing else.
    #[test]
    fn a_fingerprint_accepts_only_the_key_it_names() {
        let key = vec![0x41u8; 1216];
        let exit = ExitRelay {
            relay: address_of(&[7u8; 32]),
            key_hash: ExitRelay::fingerprint(&key),
            url: "https://relay.example.invalid".to_owned(),
        };

        assert!(exit.accepts(&key), "the key it names was refused");

        // One bit, anywhere.
        for at in [0usize, 7, 600, 1215] {
            let mut other = key.clone();
            other[at] ^= 1;
            assert!(
                !exit.accepts(&other),
                "a key differing at byte {at} was accepted"
            );
        }

        // And a key of a different length, which is what a relay answering
        // with something else would most likely be.
        assert!(!exit.accepts(&[]), "an empty key was accepted");
        assert!(!exit.accepts(&vec![0x41u8; 1215]), "a short key was accepted");
    }

    /// The fingerprint is not a bare hash of the key.
    ///
    /// Domain separation, so this value cannot be replayed as some other hash
    /// of the same bytes elsewhere in the system.
    #[test]
    fn the_fingerprint_is_domain_separated() {
        let key = vec![0x41u8; 1216];
        assert_ne!(
            ExitRelay::fingerprint(&key),
            *blake3::hash(&key).as_bytes(),
            "the fingerprint is a plain hash of the key"
        );
    }

    /// Each relay opens its own layer and neither opens the other's.
    ///
    /// This is the property the whole chain rests on, so it is asserted rather
    /// than described: the first relay learns where to carry this and not where
    /// it ends, and the exit relay learns where it ends and nothing about the
    /// caller beyond a key made for one call.
    #[test]
    fn each_relay_opens_its_own_layer_and_not_the_other() {
        use rotelyx_crypto::circuit::SealedHop;
        use rotelyx_crypto::hybrid::HybridKem;

        let (first_secret, first_public) = HybridKem::generate();
        let (exit_secret, exit_public) = HybridKem::generate();

        let first_relay = address_of(&[1u8; 32]);
        let exit = ExitRelay {
            relay: address_of(&[2u8; 32]),
            key_hash: ExitRelay::fingerprint(&exit_public.to_bytes()),
            url: "https://exit.example.invalid".to_owned(),
        };
        let destination = address_of(&[3u8; 32]);
        let return_key = address_of(&[4u8; 32]);
        let hour = 400_000;

        let (outer, inner) = exit
            .seal_circuit(
                &first_relay,
                &first_public,
                &exit_public,
                &destination,
                &return_key,
                hour,
            )
            .expect("sealing");

        // The first relay reads where to carry it, and where that relay is.
        let hop = SealedHop::from_bytes(&outer)
            .expect("the outer layer is a descriptor")
            .open(&first_secret, first_relay.as_bytes(), hour)
            .expect("the first relay opens its own layer");
        assert_eq!(hop.destination, *exit.relay.as_bytes());
        assert_eq!(hop.next_relay.as_deref(), Some(exit.url.as_str()));

        // And cannot read the other one.
        assert!(
            SealedHop::from_bytes(&inner)
                .expect("a descriptor")
                .open(&first_secret, first_relay.as_bytes(), hour)
                .is_err(),
            "the first relay opened the layer meant for the exit relay"
        );

        // The exit relay reads where it ends, and what name to wear.
        let hop = SealedHop::from_bytes(&inner)
            .expect("the inner layer is a descriptor")
            .open(&exit_secret, exit.relay.as_bytes(), hour)
            .expect("the exit relay opens its own layer");
        assert_eq!(hop.destination, *destination.as_bytes());
        assert_eq!(hop.return_key, *return_key.as_bytes());
        assert!(hop.next_relay.is_none(), "the circuit was told to go further");

        // And cannot read the first relay's, so it never learns which relay
        // carried this to it from the descriptor.
        assert!(
            SealedHop::from_bytes(&outer)
                .expect("a descriptor")
                .open(&exit_secret, exit.relay.as_bytes(), hour)
                .is_err(),
            "the exit relay opened the layer meant for the first relay"
        );

        // Neither address is readable in what travels.
        for wire in [&outer, &inner] {
            assert!(
                !wire
                    .windows(32)
                    .any(|w| w == destination.as_bytes()),
                "the destination is readable in a descriptor"
            );
        }
    }

    /// A code between the two forms is refused rather than half read.
    ///
    /// Sixty five bytes through a hundred and twenty eight is an exit relay
    /// with something missing. Reading what is there and inventing the rest
    /// would produce a relay nobody named.
    #[test]
    fn a_code_that_is_neither_form_is_refused() {
        let inv = Invitation::issue(100);
        let full = inv.code_with_exit(&ExitRelay {
            relay: address_of(&[7u8; 32]),
            key_hash: [9u8; 32],
            url: "https://relay.example.invalid".to_owned(),
        });

        for len in [0usize, 1, 63, 65, 96, 127, 128] {
            let truncated = &full[..len.min(full.len())];
            assert!(
                Invitation::read_code_full(truncated).is_err(),
                "a code of {len} bytes was accepted"
            );
        }
    }

    /// An address that is not text is refused.
    #[test]
    fn an_exit_relay_address_that_is_not_text_is_refused() {
        let inv = Invitation::issue(100);
        let mut code = inv.code_with_exit(&ExitRelay {
            relay: address_of(&[7u8; 32]),
            key_hash: [9u8; 32],
            url: "https://relay.example.invalid".to_owned(),
        })
        .to_vec();
        // A byte no UTF-8 sequence may begin with.
        code.truncate(128);
        code.push(0xFF);
        assert!(
            Invitation::read_code_full(&code).is_err(),
            "an address that is not text was accepted"
        );
    }

    /// The address in a code is the public half, never the private one.
    ///
    /// Deriving the transport key from the invitation secret would have been
    /// tidier and would have handed every holder the private key of the
    /// endpoint they are calling. This pins that it did not happen: the code
    /// contains the address and the transport secret is not recoverable from
    /// anything in it.
    #[test]
    fn a_code_does_not_carry_the_private_half() {
        let inv = Invitation::issue(100);
        let code = inv.code();
        let transport = inv.transport_bytes();

        assert!(
            !code.windows(32).any(|w| w == &transport[..]),
            "the transport secret is inside the code that gets handed out"
        );
    }

    /// A malformed code is an error, never a panic.
    ///
    /// This parser is fed by whatever somebody pasted, so the contract is the
    /// same as every other parser in this project: reject anything, panic at
    /// nothing.
    ///
    /// Note what is **not** claimed. Most 32-byte values decompress to a valid
    /// curve point, so a wrong address half usually parses and then fails at
    /// the handshake instead. The length check is the only structural one there
    /// is, and pretending otherwise would be a test that reads stronger than it
    /// is.
    #[test]
    fn a_malformed_code_is_refused_and_never_panics() {
        for len in [0usize, 1, 31, 32, 63, 65, 128, 4096] {
            assert!(Invitation::read_code(&vec![0x41; len]).is_err(), "accepted {len} bytes");
        }

        // Exhaustive over one byte at every position of a real code, which is
        // where a parser that indexes without checking is found.
        let code = Invitation::issue(100).code();
        for position in 0..code.len() {
            for byte in 0u16..=255 {
                let mut mutated = *code;
                mutated[position] = byte as u8;
                let _ = Invitation::read_code(&mutated);
            }
        }
    }

    fn ids() -> (RotelyxId, RotelyxId) {
        (Identity::generate().id(), Identity::generate().id())
    }

    // --- proof of work ---

    #[test]
    fn a_solved_proof_verifies() {
        let (sender, target) = ids();
        let proof = solve(&sender, &target, 100, 8);
        assert!(verify_proof(&proof, &sender, &target, 100, 8, 1).is_ok());
    }

    /// Work done to reach one person must not be spendable on another,
    /// otherwise a bulk sender pays once for a whole address book.
    #[test]
    fn work_is_not_transferable_between_recipients() {
        let (sender, target) = ids();
        let (_, other_target) = ids();

        let proof = solve(&sender, &target, 100, 12);
        assert!(matches!(
            verify_proof(&proof, &sender, &other_target, 100, 12, 1),
            Err(AccessError::InsufficientWork { .. })
        ));
    }

    /// A spammer must not solve once and reuse it across throwaway identities.
    #[test]
    fn work_is_not_transferable_between_senders() {
        let (sender, target) = ids();
        let (other_sender, _) = ids();

        let proof = solve(&sender, &target, 100, 12);
        assert!(matches!(
            verify_proof(&proof, &other_sender, &target, 100, 12, 1),
            Err(AccessError::InsufficientWork { .. })
        ));
    }

    /// Proofs must not be stockpiled in advance or replayed indefinitely.
    #[test]
    fn proofs_expire_outside_the_tolerance_window() {
        let (sender, target) = ids();
        let proof = solve(&sender, &target, 100, 8);

        assert!(verify_proof(&proof, &sender, &target, 101, 8, 1).is_ok());
        assert!(matches!(
            verify_proof(&proof, &sender, &target, 105, 8, 1),
            Err(AccessError::StaleProof { .. })
        ));
    }

    /// Tolerance must work in both directions: a sender whose clock is fast
    /// solves for an epoch the recipient has not reached yet.
    #[test]
    fn tolerance_covers_clock_skew_in_both_directions() {
        let (sender, target) = ids();
        let proof = solve(&sender, &target, 100, 8);

        assert!(verify_proof(&proof, &sender, &target, 99, 8, 1).is_ok());
        assert!(verify_proof(&proof, &sender, &target, 101, 8, 1).is_ok());
    }

    #[test]
    fn a_proof_below_the_required_difficulty_is_rejected() {
        let (sender, target) = ids();
        let weak = solve(&sender, &target, 100, 4);
        // Solving for 4 bits will rarely satisfy 20.
        if verify_proof(&weak, &sender, &target, 100, 20, 1).is_ok() {
            // 1-in-65536 chance the weak solution happens to be strong enough.
            return;
        }
        assert!(matches!(
            verify_proof(&weak, &sender, &target, 100, 20, 1),
            Err(AccessError::InsufficientWork { .. })
        ));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0xFF; 32]), 0);
        assert_eq!(leading_zero_bits(&[0x7F; 32]), 1);
        let mut d = [0u8; 32];
        d[2] = 0x80;
        assert_eq!(leading_zero_bits(&d), 16);
    }

    #[test]
    fn cost_doubles_with_each_difficulty_point() {
        assert!(estimated_cost(21) >= estimated_cost(20) * 2);
    }

    // --- invitations ---

    #[test]
    fn a_valid_invitation_proof_is_accepted() {
        let (caller, _) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);
        assert!(inv.verify(&proof, &caller, 100, 100).is_ok());
    }

    /// The replay defence: somebody who observes a proof cannot present it as
    /// themselves, because the MAC commits to the caller the transport already
    /// authenticated.
    #[test]
    fn an_invitation_proof_cannot_be_replayed_by_another_identity() {
        let (caller, thief) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        assert!(matches!(
            inv.verify(&proof, &thief, 100, 100),
            Err(AccessError::BadInvitation)
        ));
    }

    #[test]
    fn an_expired_invitation_is_refused() {
        let (caller, _) = ids();
        let inv = Invitation::issue(100);
        let proof = inv.prove(&caller, 101);

        assert!(matches!(
            inv.verify(&proof, &caller, 101, 101),
            Err(AccessError::ExpiredInvitation { .. })
        ));
    }

    #[test]
    fn a_forged_proof_is_refused() {
        let (caller, _) = ids();
        let inv = Invitation::issue(200);
        assert!(matches!(
            inv.verify(&[0u8; 32], &caller, 100, 100),
            Err(AccessError::BadInvitation)
        ));
    }

    #[test]
    fn two_invitations_never_share_a_secret() {
        let a = Invitation::issue(200);
        let b = Invitation::issue(200);
        assert_ne!(*a.secret_bytes(), *b.secret_bytes());
    }

    #[test]
    fn invitation_debug_never_leaks() {
        let inv = Invitation::issue(200);
        assert!(format!("{inv:?}").contains("<redacted>"));
    }

    // --- policy ---

    #[test]
    fn only_invitation_only_shuts_strangers_out_entirely() {
        assert!(!ReachabilityPolicy::InvitationOnly.admits_strangers());
        assert!(ReachabilityPolicy::ProofOfWork { difficulty: 20 }.admits_strangers());
        assert!(ReachabilityPolicy::Open.admits_strangers());
    }

    // --- the gate ---

    #[test]
    fn an_invitation_only_gate_admits_a_valid_holder() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(inv);

        let evidence = Admission::Invitation { proof, epoch: 100 };
        assert!(gate.admit(&caller, &me, &evidence, 100, None).is_ok());
    }

    /// The default posture: a stranger with no evidence gets nowhere.
    #[test]
    fn an_invitation_only_gate_refuses_a_stranger() {
        let (caller, me) = ids();
        let gate = Gate::invitation_only();
        assert!(matches!(
            gate.admit(&caller, &me, &Admission::None, 100, None),
            Err(AccessError::BadInvitation)
        ));
    }


    /// A permission is for one address, and worthless at any other.
    ///
    /// # The hole this closes
    ///
    /// Each invitation is answered at an address of its own precisely so that
    /// two people invited by the same identity are never handed a name in
    /// common. Checking the proof and ignoring the address would give that back
    /// with one extra step: a holder who came across an address it suspected
    /// belonged to the same host could call it, present its own invitation, and
    /// read the answer. Being let in would confirm the guess. Refusal has to be
    /// what an address you were not given returns, whoever you are.
    #[test]
    fn a_proof_for_one_address_is_refused_at_another() {
        let (caller, me) = ids();
        let mine = Invitation::issue(200);
        let someone_elses = Invitation::issue(200);
        let proof = mine.prove(&caller, 100);

        let (at_mine, at_theirs) = (mine.address(), someone_elses.address());
        assert_ne!(at_mine, at_theirs, "two invitations must differ in address");

        let mut gate = Gate::invitation_only();
        gate.add_invitation(mine);
        gate.add_invitation(someone_elses);

        let evidence = Admission::Invitation { proof, epoch: 100 };

        assert!(
            gate.admit(&caller, &me, &evidence, 100, Some(at_mine)).is_ok(),
            "the address this invitation is answered at must admit its holder",
        );
        assert!(
            matches!(
                gate.admit(&caller, &me, &evidence, 100, Some(at_theirs)),
                Err(AccessError::BadInvitation)
            ),
            "another invitation's address must refuse this holder, or the \
             address tells them the two invitations share a host",
        );
    }

    /// An identity listening under its own key still admits every holder.
    ///
    /// The desktop and browser clients bind the identity, so the address a
    /// caller reaches is one it could have derived from the identity itself.
    /// There is no per-address claim to enforce there, and enforcing one anyway
    /// would refuse everybody.
    #[test]
    fn an_address_that_is_no_invitations_admits_any_of_them() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(inv);

        let evidence = Admission::Invitation { proof, epoch: 100 };
        assert!(gate.admit(&caller, &me, &evidence, 100, Some(me)).is_ok());
        assert!(gate.admit(&caller, &me, &evidence, 100, None).is_ok());
    }


    /// Revocation is the answer to a leaked invitation. Expiry is a promise
    /// about the future; a leak is a problem now.
    #[test]
    fn revoking_an_invitation_shuts_out_holders_immediately() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let secret = *inv.secret_bytes();
        let proof = inv.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(inv);
        assert!(gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100, None)
            .is_ok());

        assert_eq!(gate.revoke(&secret), 1);
        assert!(gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100, None)
            .is_err());
    }

    /// Revoking one invitation must not shut out holders of the others.
    #[test]
    fn revocation_is_surgical() {
        let (caller, me) = ids();
        let keep = Invitation::issue(200);
        let drop = Invitation::issue(200);
        let drop_secret = *drop.secret_bytes();
        let proof = keep.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(keep);
        gate.add_invitation(drop);

        assert_eq!(gate.revoke(&drop_secret), 1);
        assert_eq!(gate.invitation_count(), 1);
        assert!(gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100, None)
            .is_ok());
    }

    #[test]
    fn pruning_drops_only_expired_invitations() {
        let mut gate = Gate::invitation_only();
        gate.add_invitation(Invitation::issue(100));
        gate.add_invitation(Invitation::issue(300));

        assert_eq!(gate.prune(200), 1);
        assert_eq!(gate.invitation_count(), 1);
    }

    #[test]
    fn a_proof_of_work_gate_admits_a_solved_proof() {
        let (caller, me) = ids();
        let gate = Gate::new(ReachabilityPolicy::ProofOfWork { difficulty: 8 });
        let proof = solve(&caller, &me, 100, 8);

        assert!(gate
            .admit(&caller, &me, &Admission::ProofOfWork(proof), 100, None)
            .is_ok());
    }

    /// Presenting the wrong *kind* of evidence must not slip through.
    #[test]
    fn evidence_of_the_wrong_kind_is_refused() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        let pow_gate = Gate::new(ReachabilityPolicy::ProofOfWork { difficulty: 8 });
        assert!(pow_gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100, None)
            .is_err());

        let mut inv_gate = Gate::invitation_only();
        inv_gate.add_invitation(Invitation::issue(200));
        let work = solve(&caller, &me, 100, 4);
        assert!(inv_gate
            .admit(&caller, &me, &Admission::ProofOfWork(work), 100, None)
            .is_err());
    }


    // --- admission wire format ---

    #[test]
    fn admission_encodings_roundtrip() {
        for evidence in [
            Admission::None,
            Admission::Invitation { proof: [7u8; 32], epoch: 42 },
            Admission::ProofOfWork(ContactProof { nonce: 99, epoch: 42 }),
        ] {
            let bytes = evidence.to_bytes();
            assert_eq!(Admission::from_bytes(&bytes).expect("decode"), evidence);
        }
    }

    /// Every malformed input must be an error, never a panic: this parser runs
    /// on the first bytes an unauthenticated stranger sends.
    #[test]
    fn malformed_admission_is_rejected_rather_than_panicking() {
        assert!(Admission::from_bytes(&[]).is_err());
        assert!(Admission::from_bytes(&[9]).is_err());
        assert!(Admission::from_bytes(&[1]).is_err());
        assert!(Admission::from_bytes(&[1, 2, 3]).is_err());
        assert!(Admission::from_bytes(&[2; 16]).is_err());
        assert!(Admission::from_bytes(&[0, 0]).is_err());

        // Every prefix of a valid encoding.
        let valid = Admission::Invitation { proof: [1u8; 32], epoch: 5 }.to_bytes();
        for cut in 0..valid.len() {
            let _ = Admission::from_bytes(&valid[..cut]);
        }
    }

    #[test]
    fn epochs_bucket_time_by_the_hour() {
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(3599), 0);
        assert_eq!(epoch_at(3600), 1);
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Everything an endpoint consults before admitting a caller.
///
/// One object so the decision has one place to be read and audited, rather than
/// being spread across the accept path where a missing check is invisible.
#[derive(Debug)]
pub struct Gate {
    policy: ReachabilityPolicy,
    /// Invitations this identity has issued and not yet retired.
    invitations: Vec<Invitation>,
    /// Identities refused outright.
    /// Epochs of tolerance for clock skew on proofs.
    tolerance: u64,
}

impl Gate {
    pub fn new(policy: ReachabilityPolicy) -> Self {
        Self {
            policy,
            invitations: Vec::new(),
            tolerance: 1,
        }
    }

    /// The safe default for a person's device.
    pub fn invitation_only() -> Self {
        Self::new(ReachabilityPolicy::InvitationOnly)
    }

    pub fn policy(&self) -> &ReachabilityPolicy {
        &self.policy
    }

    pub fn add_invitation(&mut self, invitation: Invitation) {
        self.invitations.push(invitation);
    }

    /// Retire every invitation whose secret matches.
    ///
    /// Revocation, for the case that matters: an invitation shared more widely
    /// than intended. Expiry alone is not enough: it is a promise about the
    /// future, and a leak is a problem right now.
    pub fn revoke(&mut self, secret: &[u8; 32]) -> usize {
        let before = self.invitations.len();
        self.invitations
            .retain(|inv| !bool::from(inv.secret_bytes().ct_eq(secret)));
        before - self.invitations.len()
    }

    /// Drop invitations that have expired, so the list does not grow forever.
    pub fn prune(&mut self, current_epoch: u64) -> usize {
        let before = self.invitations.len();
        self.invitations
            .retain(|inv| inv.expires_at_epoch() >= current_epoch);
        before - self.invitations.len()
    }

    pub fn invitation_count(&self) -> usize {
        self.invitations.len()
    }


    /// Decide whether `caller` may open a session.
    ///
    /// The blocklist is checked **first**, before any verification work. A
    /// blocked identity must cost us nothing: otherwise blocking someone hands
    /// them a way to keep spending our CPU.
    /// `dialled` is the address the caller actually called, from the transport.
    ///
    /// # Why the address is part of admission
    ///
    /// Each invitation is answered at an address of its own so that two people
    /// invited by the same identity are never given a name in common. Checking
    /// the proof alone would undo that: a holder of any live invitation would be
    /// admitted at *every* address this identity answers, so it could take an
    /// address it suspects belongs to the same host, call it, and learn from
    /// being let in that the suspicion was right. Requiring the permission to
    /// match the address turns that test into an ordinary refusal.
    ///
    /// # It must be the address that answered
    ///
    /// Not the one the caller asked for. The caller writes an address into the
    /// TLS server name, and a name the endpoint does not hold is answered by
    /// the key it was bound with anyway. Reading the caller's own word would
    /// hand it the choice: name an address nobody answers at, land in the
    /// branch below where every invitation is eligible, and the check is gone.
    /// [`rotelyx_net::NetEndpoint::answered_at`] is the value to pass.
    ///
    /// An address that is no invitation's leaves every invitation eligible.
    /// That covers an identity listening under its own key, which gives nothing
    /// away: a caller could derive that address from the identity on its own.
    /// `None` is accepted for tests and means the same.
    pub fn admit(
        &self,
        caller: &RotelyxId,
        me: &RotelyxId,
        evidence: &Admission,
        current_epoch: u64,
        dialled: Option<RotelyxId>,
    ) -> Result<(), AccessError> {
        match (&self.policy, evidence) {
            (ReachabilityPolicy::Open, _) => Ok(()),

            (ReachabilityPolicy::InvitationOnly, Admission::Invitation { proof, epoch }) => {
                // Which invitation matched is not reported, so a caller
                // cannot probe for which ones an identity currently holds.
                //
                // When the caller named an address that belongs to one of these
                // invitations, only that invitation's proof will do. A proof
                // for one address is then worthless at another, which is what
                // stops a holder from calling an address it suspects and
                // learning from being let in that it guessed right.
                //
                // When the caller named something else, or said nothing, every
                // invitation is eligible. That is the identity's own address,
                // which is how the desktop and browser clients listen: an
                // address the caller could have derived from the identity
                // anyway, so admitting there reveals nothing it did not have.
                let named_an_invitation = dialled
                    .is_some_and(|at| self.invitations.iter().any(|inv| inv.address() == at));

                for inv in &self.invitations {
                    if named_an_invitation && dialled != Some(inv.address()) {
                        continue;
                    }
                    if inv.verify(proof, caller, *epoch, current_epoch).is_ok() {
                        return Ok(());
                    }
                }
                Err(AccessError::BadInvitation)
            }
            (ReachabilityPolicy::InvitationOnly, _) => Err(AccessError::BadInvitation),

            (ReachabilityPolicy::ProofOfWork { difficulty }, Admission::ProofOfWork(proof)) => {
                verify_proof(proof, caller, me, current_epoch, *difficulty, self.tolerance)
            }
            (ReachabilityPolicy::ProofOfWork { difficulty }, _) => {
                Err(AccessError::InsufficientWork {
                    required: *difficulty,
                })
            }
        }
    }
}

/// What a caller presents to be admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Proof of holding an invitation the recipient issued.
    Invitation { proof: [u8; 32], epoch: u64 },
    /// A solved proof of work.
    ProofOfWork(ContactProof),
    /// Nothing. Only ever admitted by [`ReachabilityPolicy::Open`].
    None,
}

impl Admission {
    /// Encode for the wire. Fixed layout, no length fields: every variant has
    /// a known size, so there is nothing for a parser to get wrong.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Invitation { proof, epoch } => {
                let mut out = Vec::with_capacity(41);
                out.push(1);
                out.extend_from_slice(proof);
                out.extend_from_slice(&epoch.to_be_bytes());
                out
            }
            Self::ProofOfWork(p) => {
                let mut out = Vec::with_capacity(17);
                out.push(2);
                out.extend_from_slice(&p.nonce.to_be_bytes());
                out.extend_from_slice(&p.epoch.to_be_bytes());
                out
            }
            Self::None => vec![0],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccessError> {
        match bytes.first() {
            Some(0) if bytes.len() == 1 => Ok(Self::None),
            Some(1) if bytes.len() == 41 => {
                let mut proof = [0u8; 32];
                proof.copy_from_slice(&bytes[1..33]);
                let epoch = u64::from_be_bytes(bytes[33..41].try_into().expect("checked length"));
                Ok(Self::Invitation { proof, epoch })
            }
            Some(2) if bytes.len() == 17 => {
                let nonce = u64::from_be_bytes(bytes[1..9].try_into().expect("checked length"));
                let epoch = u64::from_be_bytes(bytes[9..17].try_into().expect("checked length"));
                Ok(Self::ProofOfWork(ContactProof { nonce, epoch }))
            }
            _ => Err(AccessError::MalformedAdmission),
        }
    }
}
