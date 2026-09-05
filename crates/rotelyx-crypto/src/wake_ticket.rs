//! Waking a phone in real time without anybody holding the link.
//!
//! # The problem
//!
//! A push token is stable for months. A mailbox tag rotates every hour,
//! precisely so two tags from one member cannot be tied together. Store
//! `token -> tag` anywhere and that stable token re-links every rotation, and
//! the party holding the table is the mailbox operator, which is us.
//!
//! Waking everybody on a schedule avoids the table by never asking the
//! question, and pays for it in latency: nothing arrives until the next sweep.
//! That is the right trade for a message and the wrong one for an emergency.
//!
//! # What a ticket is
//!
//! The device's push token, sealed to the **notifier's** public key, with fresh
//! randomness every time. The device leaves one under each tag it listens on.
//!
//! - The mailbox stores `tag -> ticket`. It cannot read a ticket, and because
//!   every one is freshly randomised it cannot tell two tickets belong to one
//!   device. There is no identifier in the row to follow.
//! - When something arrives at a tag, the mailbox hands that ticket to the
//!   notifier and nothing else. The notifier opens it, pushes, and keeps
//!   nothing. **It never learns which tag the ticket came from.**
//!
//! So the mailbox knows the tag and not the device, the notifier knows the
//! device and not the tag, and neither writes down a mapping that could be
//! read later. Compare SimpleX, which reaches the same separation through a
//! persistent `notifierId` its notification server stores against the token,
//! and which therefore learns how many queues a device has and how often each
//! one delivers. A ticket is one use and rotates with the tag it sits under.
//!
//! # What this does not hide
//!
//! The notifier learns that some device was pushed at some moment, and Apple
//! learns the same. No push scheme avoids that. It is blunted by decoys: the
//! mailbox hands over several tickets for every real arrival, only one of
//! which is the one that matters, and since every wake this system sends is
//! contentless and every device already wakes and finds nothing, a decoy is
//! indistinguishable from the real thing at both the notifier and Apple. The
//! mailbox knows which was real and cannot read any of them; the notifier can
//! read them all and does not know which was real.
//!
//! A stolen ticket is a spurious wake and nothing else: it carries no tag, no
//! content, and no way to ask for any. [`TICKET_MAX_AGE_HOURS`] bounds even
//! that.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::hybrid::{
    HybridCiphertext, HybridError, HybridPublicKey, HybridSecretKey, PqSecret, CIPHERTEXT_LEN,
};

/// Domain separator. Versioned, so an implementation of this construction and
/// one of a later construction cannot silently agree on a key.
const TICKET_CONTEXT: &str = "rotelyx wake ticket v1";
const TICKET_LABEL: &[u8] = b"rotelyx wake ticket v1";

/// Room for a push token, zero padded.
///
/// Fixed rather than length prefixed on the wire, so that every ticket is the
/// same size. A ticket whose length followed the token inside it would say
/// which push service a device uses to anybody holding the row: an APNs token
/// is 64 characters and a Firebase one is around 160, which is not a detail
/// worth leaking to distinguish an iPhone from an Android.
const TOKEN_ROOM: usize = 256;

/// Kind, token length, token, minted hour.
const TICKET_BODY_LEN: usize = 1 + 2 + TOKEN_ROOM + 8;

/// Bytes on the wire: the KEM ciphertext, the nonce, the sealed body, the tag.
pub const SEALED_TICKET_LEN: usize = CIPHERTEXT_LEN + 24 + TICKET_BODY_LEN + 16;

/// How long after minting a ticket is still honoured.
///
/// Long enough to cover the window a client polls its own tags across, so a
/// ticket does not expire under a tag that is still live and leave a device
/// quietly unwakeable. Short enough that one taken from a compromised mailbox
/// stops being usable, which costs an attacker nothing to lose: the worst a
/// ticket buys is a contentless wake.
pub const TICKET_MAX_AGE_HOURS: u64 = 48;

/// Which push service a token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketKind {
    Apns,
    Fcm,
}

impl TicketKind {
    fn code(self) -> u8 {
        match self {
            Self::Apns => 1,
            Self::Fcm => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Apns),
            2 => Some(Self::Fcm),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }
}

/// What opening a ticket yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Woken {
    pub kind: TicketKind,
    pub token: String,
}

/// A push token sealed to the notifier, opaque to everybody else.
#[derive(Clone)]
pub struct WakeTicket {
    kem: HybridCiphertext,
    nonce: [u8; 24],
    sealed: Vec<u8>,
}

impl std::fmt::Debug for WakeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WakeTicket({SEALED_TICKET_LEN} bytes, opaque)")
    }
}

/// The AEAD key for one ticket, from the encapsulated secret.
fn ticket_key(secret: &PqSecret) -> Zeroizing<[u8; 32]> {
    crate::hybrid::derive_key(secret, TICKET_CONTEXT)
}

impl WakeTicket {
    /// Seal a push token to the notifier.
    ///
    /// `minted_hour` is hours since the epoch, and is carried inside rather
    /// than bound as associated data: the notifier has to read it to decide
    /// whether the ticket is too old, and it must not have to be told anything
    /// from outside to open one. Being told a tag is exactly what it must not
    /// be told.
    pub fn seal(
        notifier: &HybridPublicKey,
        kind: TicketKind,
        token: &str,
        minted_hour: u64,
    ) -> Result<Self, HybridError> {
        // Refused rather than truncated. A truncated token is a different
        // token, and pushing to a different token is worse than not pushing.
        if token.is_empty() || token.len() > TOKEN_ROOM {
            return Err(HybridError::BadCiphertext);
        }

        let (kem, kem_secret) = notifier.encapsulate();
        let key = ticket_key(&kem_secret);

        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| HybridError::Entropy)?;

        let mut room = [0u8; TOKEN_ROOM];
        room[..token.len()].copy_from_slice(token.as_bytes());

        let mut body = Vec::with_capacity(TICKET_BODY_LEN);
        body.push(kind.code());
        body.extend_from_slice(&(token.len() as u16).to_be_bytes());
        body.extend_from_slice(&room);
        body.extend_from_slice(&minted_hour.to_be_bytes());

        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &body,
                    aad: TICKET_LABEL,
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;

        Ok(Self { kem, nonce, sealed })
    }

    /// Open a ticket, as the notifier.
    ///
    /// `now_hour` is the hour the notifier believes it is. One hour of slack
    /// forward, because two machines disagree about the time and refusing a
    /// wake over clock skew is an outage rather than a defence.
    pub fn open(
        &self,
        notifier: &HybridSecretKey,
        now_hour: u64,
    ) -> Result<Woken, HybridError> {
        let kem_secret = notifier.decapsulate(&self.kem);
        let key = ticket_key(&kem_secret);

        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;
        let body = cipher
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.sealed,
                    aad: TICKET_LABEL,
                },
            )
            .map_err(|_| HybridError::Decapsulation)?;

        if body.len() != TICKET_BODY_LEN {
            return Err(HybridError::BadCiphertext);
        }

        let kind = TicketKind::from_code(body[0]).ok_or(HybridError::BadCiphertext)?;

        let len = u16::from_be_bytes([body[1], body[2]]) as usize;
        if len == 0 || len > TOKEN_ROOM {
            return Err(HybridError::BadCiphertext);
        }

        let minted = u64::from_be_bytes(
            body[3 + TOKEN_ROOM..].try_into().expect("eight bytes, checked above"),
        );

        // Too old, or minted in a future further off than clock skew explains.
        if now_hour.saturating_sub(minted) > TICKET_MAX_AGE_HOURS || minted > now_hour + 1 {
            return Err(HybridError::BadCiphertext);
        }

        let token = std::str::from_utf8(&body[3..3 + len])
            .map_err(|_| HybridError::BadCiphertext)?
            .to_owned();

        Ok(Woken { kind, token })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_TICKET_LEN);
        out.extend_from_slice(&self.kem.to_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != SEALED_TICKET_LEN {
            return Err(HybridError::BadCiphertext);
        }
        let kem = HybridCiphertext::from_bytes(&bytes[..CIPHERTEXT_LEN])?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[CIPHERTEXT_LEN..CIPHERTEXT_LEN + 24]);
        Ok(Self {
            kem,
            nonce,
            sealed: bytes[CIPHERTEXT_LEN + 24..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKem;

    const APNS: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

    fn notifier() -> HybridSecretKey {
        HybridKem::generate().0
    }

    #[test]
    fn a_ticket_round_trips() {
        let key = notifier();
        let ticket = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 100).expect("seal");

        let woken = ticket.open(&key, 100).expect("open");
        assert_eq!(woken.kind, TicketKind::Apns);
        assert_eq!(woken.token, APNS);
    }

    /// The property the whole design rests on.
    ///
    /// The mailbox holds one ticket per tag, and a tag rotates every hour. If
    /// two tickets for one device were the same bytes, that repeated value
    /// would be an identifier sitting in the rows, and following it across the
    /// rotations would re-link exactly what the rotation is for. The operator
    /// holding those rows is us, which is why this is asserted rather than
    /// assumed.
    #[test]
    fn two_tickets_for_one_device_share_nothing() {
        let key = notifier();
        let one = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 100).expect("seal");
        let two = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 100).expect("seal");

        assert_ne!(one.to_bytes(), two.to_bytes(), "two tickets were identical");

        // And not merely different: no run of bytes is shared beyond what
        // chance gives, so there is nothing to match on. Checked at the
        // coarsest useful granularity, eight bytes, because a shared eight
        // byte run is what an operator would index on.
        let a = one.to_bytes();
        let b = two.to_bytes();
        let shared = a
            .windows(8)
            .filter(|w| b.windows(8).any(|x| x == *w))
            .count();
        assert_eq!(shared, 0, "{shared} eight byte runs were common to both");

        // Both still open to the same device.
        assert_eq!(one.open(&key, 100).expect("open").token, APNS);
        assert_eq!(two.open(&key, 100).expect("open").token, APNS);
    }

    /// A ticket must not say which push service the device uses.
    ///
    /// An APNs token is 64 characters and a Firebase one is around 160. A
    /// ticket whose length followed the token would separate iPhones from
    /// Android phones for anybody holding the rows, which is a population
    /// split nobody needs to be handed.
    #[test]
    fn every_ticket_is_the_same_size() {
        let key = notifier();
        let short = WakeTicket::seal(&key.public(), TicketKind::Apns, "ab", 100).expect("seal");
        let long = WakeTicket::seal(
            &key.public(),
            TicketKind::Fcm,
            &"f".repeat(TOKEN_ROOM),
            100,
        )
        .expect("seal");

        assert_eq!(short.to_bytes().len(), SEALED_TICKET_LEN);
        assert_eq!(long.to_bytes().len(), SEALED_TICKET_LEN);
    }

    /// The mailbox holds these and must not be able to read one.
    #[test]
    fn another_key_does_not_open_it() {
        let real = notifier();
        let other = notifier();
        let ticket = WakeTicket::seal(&real.public(), TicketKind::Apns, APNS, 100).expect("seal");

        assert!(ticket.open(&other, 100).is_err(), "the wrong key opened it");
    }

    /// A ticket taken from a mailbox stops working.
    ///
    /// The worst it buys is a contentless wake, which is why the window is
    /// generous rather than tight, but a ticket that never expired would stay
    /// useful for as long as the token behind it, which is months.
    #[test]
    fn a_ticket_past_its_window_is_refused() {
        let key = notifier();
        let ticket = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 100).expect("seal");

        assert!(
            ticket.open(&key, 100 + TICKET_MAX_AGE_HOURS).is_ok(),
            "refused inside its own window"
        );
        assert!(
            ticket.open(&key, 100 + TICKET_MAX_AGE_HOURS + 1).is_err(),
            "an expired ticket was honoured"
        );
    }

    /// Clock skew is an outage, not a defence, so a little slack forward is
    /// allowed and a lot is not.
    #[test]
    fn a_ticket_from_the_future_is_refused_beyond_skew() {
        let key = notifier();
        let ticket = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 101).expect("seal");

        assert!(ticket.open(&key, 100).is_ok(), "one hour of skew was refused");
        assert!(
            WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 105)
                .expect("seal")
                .open(&key, 100)
                .is_err(),
            "a ticket from five hours ahead was honoured"
        );
    }

    /// Every byte is covered, so a mailbox cannot edit one it cannot read.
    #[test]
    fn a_changed_byte_is_refused() {
        let key = notifier();
        let ticket = WakeTicket::seal(&key.public(), TicketKind::Apns, APNS, 100).expect("seal");
        let good = ticket.to_bytes();

        for at in [0usize, CIPHERTEXT_LEN, CIPHERTEXT_LEN + 10, good.len() - 1] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            let refused = match WakeTicket::from_bytes(&bad) {
                Err(_) => true,
                Ok(t) => t.open(&key, 100).is_err(),
            };
            assert!(refused, "a ticket with byte {at} flipped was honoured");
        }
    }

    #[test]
    fn a_token_too_long_is_refused_rather_than_cut() {
        let key = notifier();
        assert!(
            WakeTicket::seal(
                &key.public(),
                TicketKind::Apns,
                &"f".repeat(TOKEN_ROOM + 1),
                100
            )
            .is_err(),
            "an oversized token was accepted and would have been truncated"
        );
    }
}
