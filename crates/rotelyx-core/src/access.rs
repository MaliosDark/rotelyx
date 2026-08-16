//! Reachability: who is allowed to open a session with you.
//!
//! Rotelyx identities are keypairs, so they are free and unlimited. That is the
//! property that removes phone numbers from the design, and it is the same
//! property that made Kik a haven for unsolicited contact — an identity that
//! costs nothing can be discarded and replaced the moment it is blocked.
//!
//! Cryptography does not fix this. Scarcity does, and there are only two kinds
//! available here:
//!
//! - **Authorisation.** You are reachable only by someone holding an invitation
//!   you issued. This is the default, and it makes unsolicited contact
//!   impossible rather than merely expensive.
//! - **Cost.** For identities that *do* want to be reachable by strangers — a
//!   support account, a public figure — a proof of work makes first contact
//!   cost the sender real time while costing the recipient microseconds.
//!
//! Neither stops a determined individual attacker. Both destroy the economics
//! of bulk unsolicited contact, which is the actual threat. See
//! `docs/THREAT-MODEL.md` ADV-10.

use std::time::Duration;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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

    #[error("caller is blocked")]
    Blocked,

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
///   fleet of throwaway identities — each identity pays again.
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

/// A capability issued by one identity so another can reach it.
///
/// Shared out of band — a QR code, a link, a spoken string. Possession is the
/// authorisation; the secret itself never travels over the wire, only a MAC
/// derived from it.
pub struct Invitation {
    secret: Zeroizing<[u8; 32]>,
    expires_at_epoch: u64,
}

impl Invitation {
    /// Issue an invitation valid until `expires_at_epoch`.
    pub fn issue(expires_at_epoch: u64) -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("OS CSPRNG unavailable");
        Self {
            secret: Zeroizing::new(secret),
            expires_at_epoch,
        }
    }

    pub fn from_secret(secret: [u8; 32], expires_at_epoch: u64) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            expires_at_epoch,
        }
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
    /// Provided because some deployments genuinely want it — a public relay
    /// endpoint, a test rig — and because pretending it does not exist would
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
        assert!(gate.admit(&caller, &me, &evidence, 100).is_ok());
    }

    /// The default posture: a stranger with no evidence gets nowhere.
    #[test]
    fn an_invitation_only_gate_refuses_a_stranger() {
        let (caller, me) = ids();
        let gate = Gate::invitation_only();
        assert!(matches!(
            gate.admit(&caller, &me, &Admission::None, 100),
            Err(AccessError::BadInvitation)
        ));
    }

    /// A blocked identity must be refused before any verification runs — a
    /// block that still costs us CPU is a block the blocked party can abuse.
    #[test]
    fn a_blocked_identity_is_refused_even_with_a_valid_invitation() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(inv);
        gate.block(caller);

        assert!(matches!(
            gate.admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100),
            Err(AccessError::Blocked)
        ));
    }

    #[test]
    fn unblocking_restores_access() {
        let (caller, me) = ids();
        let inv = Invitation::issue(200);
        let proof = inv.prove(&caller, 100);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(inv);
        gate.block(caller);
        assert!(gate.unblock(&caller));

        assert!(gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100)
            .is_ok());
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
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100)
            .is_ok());

        assert_eq!(gate.revoke(&secret), 1);
        assert!(gate
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100)
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
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100)
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
            .admit(&caller, &me, &Admission::ProofOfWork(proof), 100)
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
            .admit(&caller, &me, &Admission::Invitation { proof, epoch: 100 }, 100)
            .is_err());

        let mut inv_gate = Gate::invitation_only();
        inv_gate.add_invitation(Invitation::issue(200));
        let work = solve(&caller, &me, 100, 4);
        assert!(inv_gate
            .admit(&caller, &me, &Admission::ProofOfWork(work), 100)
            .is_err());
    }

    #[test]
    fn an_open_gate_admits_anyone_but_still_honours_blocks() {
        let (caller, me) = ids();
        let mut gate = Gate::new(ReachabilityPolicy::Open);
        assert!(gate.admit(&caller, &me, &Admission::None, 100).is_ok());

        gate.block(caller);
        assert!(matches!(
            gate.admit(&caller, &me, &Admission::None, 100),
            Err(AccessError::Blocked)
        ));
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

    /// Every malformed input must be an error, never a panic — this parser runs
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
    blocked: std::collections::HashSet<RotelyxId>,
    /// Epochs of tolerance for clock skew on proofs.
    tolerance: u64,
}

impl Gate {
    pub fn new(policy: ReachabilityPolicy) -> Self {
        Self {
            policy,
            invitations: Vec::new(),
            blocked: std::collections::HashSet::new(),
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
    /// than intended. Expiry alone is not enough — it is a promise about the
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

    pub fn block(&mut self, id: RotelyxId) {
        self.blocked.insert(id);
    }

    pub fn unblock(&mut self, id: &RotelyxId) -> bool {
        self.blocked.remove(id)
    }

    pub fn is_blocked(&self, id: &RotelyxId) -> bool {
        self.blocked.contains(id)
    }

    /// Decide whether `caller` may open a session.
    ///
    /// The blocklist is checked **first**, before any verification work. A
    /// blocked identity must cost us nothing — otherwise blocking someone hands
    /// them a way to keep spending our CPU.
    pub fn admit(
        &self,
        caller: &RotelyxId,
        me: &RotelyxId,
        evidence: &Admission,
        current_epoch: u64,
    ) -> Result<(), AccessError> {
        if self.is_blocked(caller) {
            return Err(AccessError::Blocked);
        }

        match (&self.policy, evidence) {
            (ReachabilityPolicy::Open, _) => Ok(()),

            (ReachabilityPolicy::InvitationOnly, Admission::Invitation { proof, epoch }) => {
                // Any live invitation matching is enough; which one it was is
                // not reported, so a caller cannot probe for which invitations
                // an identity currently holds.
                for inv in &self.invitations {
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
    /// Encode for the wire. Fixed layout, no length fields — every variant has
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
