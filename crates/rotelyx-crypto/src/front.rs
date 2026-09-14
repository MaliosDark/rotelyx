//! A sealed session between a phone and the mailbox, carried by a front.
//!
//! # What a front is for
//!
//! The mailbox is blind to content and not to shape. One connection asking for
//! the tags of every conversation a device is in would hand the mailbox that
//! device's whole social graph, so the application opens one connection per
//! conversation and the mailbox sees connections that share nothing. That is
//! the strictest position of any messenger in this space, and it costs nine
//! sockets per phone and a per-address ceiling that fills the mailbox at a few
//! hundred people.
//!
//! A **front** is a relay between phones and the mailbox that can read neither
//! side's secret. The phone opens one connection, to the front, and runs any
//! number of sessions inside it, one per conversation, each sealed to the
//! mailbox's own key. The front sees the phone's address and opaque blobs; the
//! mailbox sees sessions arriving from the front with no way to tell which
//! belong to one phone, and tags but never an address. Neither can put a
//! device and a conversation together. See `docs/FRONT.md`.
//!
//! # What this module is
//!
//! The cryptographic session and nothing else: the hello a phone sends, the
//! two keys both ends derive from it, and sealing and opening a frame under
//! them. No network, no framing beyond the sealed bytes, so it can be reviewed
//! on its own. It is shaped like [`crate::circuit`] on purpose, for the reason
//! that module gives: a second sealing construction in one codebase is a second
//! thing to get right.
//!
//! # The construction
//!
//! ```text
//! hello  = kem_ct || session_id (8 bytes, chosen by the phone)
//! shared = decapsulate(kem_ct)                       both ends hold this
//! k_up   = derive(shared, "…up v1"   || session_id)  phone  -> mailbox
//! k_down = derive(shared, "…down v1" || session_id)  mailbox -> phone
//! frame  = XChaCha20-Poly1305(k_dir, nonce, aad = session_id, plaintext)
//! nonce  = 16 zero bytes || counter (u64 be)
//! ```
//!
//! The counter starts at zero in each direction and is the next expected value
//! for every frame; one out of order ends the session. The nonce is derived
//! from the counter rather than drawn at random so that a repeat is a bug a
//! test catches rather than a probability nobody sees. Post-quantum, because
//! what a recording of this reveals -- that a device fetched a set of tags --
//! is worth as much in fifteen years as today, the same harvest-now argument
//! the message layer makes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::hybrid::{
    derive_key, HybridCiphertext, HybridError, HybridPublicKey, HybridSecretKey, CIPHERTEXT_LEN,
};

/// How the two directions are separated. Versioned: a change to the
/// construction takes new context strings rather than reusing these, so an
/// implementation of one version cannot silently agree a key with another.
const UP_CONTEXT: &str = "rotelyx front session up v1";
const DOWN_CONTEXT: &str = "rotelyx front session down v1";

/// The session id the phone chooses, so it can name its own sessions inside
/// one connection. Eight bytes is enough that a phone's own sessions do not
/// collide; the front namespaces per upstream connection so two phones cannot
/// either.
pub const SESSION_ID_LEN: usize = 8;

/// Bytes of a hello on the wire: the KEM ciphertext then the session id.
pub const HELLO_LEN: usize = CIPHERTEXT_LEN + SESSION_ID_LEN;

/// Which end of a session a key belongs to. A key derived for one direction
/// cannot open a frame sealed for the other, so a frame the phone sent cannot
/// be replayed back at it as though the mailbox had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Up,
    Down,
}

impl Direction {
    fn context(self) -> &'static str {
        match self {
            Direction::Up => UP_CONTEXT,
            Direction::Down => DOWN_CONTEXT,
        }
    }
}

/// The phone's opening message: enough for the mailbox to derive the same two
/// keys, and the id the phone will name this session by.
#[derive(Clone, Debug)]
pub struct Hello {
    kem: HybridCiphertext,
    session_id: [u8; SESSION_ID_LEN],
}

impl Hello {
    /// The id the phone chose. The front reads this to route; it means nothing
    /// to the mailbox but the label of a session.
    pub fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }

    pub fn to_bytes(&self) -> [u8; HELLO_LEN] {
        let mut out = [0u8; HELLO_LEN];
        out[..CIPHERTEXT_LEN].copy_from_slice(&self.kem.to_bytes());
        out[CIPHERTEXT_LEN..].copy_from_slice(&self.session_id);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != HELLO_LEN {
            return Err(HybridError::BadCiphertext);
        }
        let kem = HybridCiphertext::from_bytes(&bytes[..CIPHERTEXT_LEN])?;
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&bytes[CIPHERTEXT_LEN..]);
        Ok(Self { kem, session_id })
    }
}

/// One end of a session: the two keys, and a counter per direction.
///
/// The phone builds one with [`Session::open_to`], which also produces the
/// hello; the mailbox builds the matching one with [`Session::accept`]. From
/// there the two are symmetric except for which counter each advances when it
/// seals: the phone seals up and opens down, the mailbox the reverse.
#[derive(Debug)]
pub struct Session {
    up: Zeroizing<[u8; 32]>,
    down: Zeroizing<[u8; 32]>,
    session_id: [u8; SESSION_ID_LEN],
    seal_dir: Direction,
    seal_counter: u64,
    open_counter: u64,
}

impl Session {
    /// The phone side. Encapsulates to the mailbox's key, derives the two
    /// keys, and returns the hello to send alongside.
    pub fn open_to(
        mailbox_key: &HybridPublicKey,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<(Self, Hello), HybridError> {
        let (kem, secret) = mailbox_key.encapsulate();
        let up = derive_key(&secret, &binding(Direction::Up, &session_id));
        let down = derive_key(&secret, &binding(Direction::Down, &session_id));
        let hello = Hello {
            kem: kem.clone(),
            session_id,
        };
        Ok((
            Self {
                up,
                down,
                session_id,
                // The phone sends up and receives down.
                seal_dir: Direction::Up,
                seal_counter: 0,
                open_counter: 0,
            },
            hello,
        ))
    }

    /// The mailbox side. Decapsulates the hello and derives the same two keys.
    pub fn accept(
        mailbox_secret: &HybridSecretKey,
        hello: &Hello,
    ) -> Result<Self, HybridError> {
        let secret = mailbox_secret.decapsulate(&hello.kem);
        let up = derive_key(&secret, &binding(Direction::Up, &hello.session_id));
        let down = derive_key(&secret, &binding(Direction::Down, &hello.session_id));
        Ok(Self {
            up,
            down,
            session_id: hello.session_id,
            // The mailbox sends down and receives up.
            seal_dir: Direction::Down,
            seal_counter: 0,
            open_counter: 0,
        })
    }

    /// Seal one frame for the other end. Advances this end's seal counter, so
    /// two frames never share a nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HybridError> {
        let key = match self.seal_dir {
            Direction::Up => &self.up,
            Direction::Down => &self.down,
        };
        let nonce = nonce_for(self.seal_counter);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.session_id,
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;
        self.seal_counter = self
            .seal_counter
            .checked_add(1)
            .ok_or(HybridError::BadCiphertext)?;
        Ok(sealed)
    }

    /// Open one frame from the other end, in order. A frame whose counter is
    /// not the next expected one is refused, which the caller must treat as
    /// the end of the session rather than a frame to skip: a gap means either
    /// loss, which this transport does not have, or tampering.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, HybridError> {
        // The opposite direction to seal.
        let key = match self.seal_dir {
            Direction::Up => &self.down,
            Direction::Down => &self.up,
        };
        let nonce = nonce_for(self.open_counter);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HybridError::BadCiphertext)?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &self.session_id,
                },
            )
            .map_err(|_| HybridError::BadCiphertext)?;
        self.open_counter = self
            .open_counter
            .checked_add(1)
            .ok_or(HybridError::BadCiphertext)?;
        Ok(plaintext)
    }

    pub fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }
}

/// The nonce for a counter: sixteen zero bytes then the counter, big-endian.
/// XChaCha's nonce is 24 bytes, and a counter that starts at zero and never
/// repeats inside a session is all the uniqueness a single key needs.
fn nonce_for(counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[16..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// What a key is derived over: the direction's context and the session id,
/// so two sessions under one mailbox key never share a key and the two
/// directions of one session never do either.
fn binding(direction: Direction, session_id: &[u8; SESSION_ID_LEN]) -> String {
    // A context string for `derive_key`, which hashes it as the domain of a
    // key-derivation. The session id is hex so the whole thing stays a string,
    // which is what `blake3::new_derive_key` takes.
    let mut out = String::with_capacity(direction.context().len() + 1 + SESSION_ID_LEN * 2);
    out.push_str(direction.context());
    out.push(' ');
    for byte in session_id {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKem;

    fn pair() -> (HybridSecretKey, HybridPublicKey) {
        HybridKem::generate()
    }

    #[test]
    fn a_frame_sealed_by_the_phone_opens_at_the_mailbox() {
        let (secret, public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [1; SESSION_ID_LEN]).expect("open");
        let mut mailbox = Session::accept(&secret, &hello).expect("accept");

        let sealed = phone.seal(b"subscribe").expect("seal");
        assert_ne!(sealed, b"subscribe");
        assert_eq!(mailbox.open(&sealed).expect("open"), b"subscribe");
    }

    #[test]
    fn a_frame_sealed_by_the_mailbox_opens_at_the_phone() {
        let (secret, public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [2; SESSION_ID_LEN]).expect("open");
        let mut mailbox = Session::accept(&secret, &hello).expect("accept");

        let sealed = mailbox.seal(b"an envelope").expect("seal");
        assert_eq!(phone.open(&sealed).expect("open"), b"an envelope");
    }

    #[test]
    fn each_direction_flows_on_its_own_counter() {
        let (secret, public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [3; SESSION_ID_LEN]).expect("open");
        let mut mailbox = Session::accept(&secret, &hello).expect("accept");

        // Interleaved, both ways, several each. The counters are independent,
        // so a busy direction does not disturb a quiet one.
        for i in 0..5u8 {
            let up = phone.seal(&[i]).expect("seal up");
            assert_eq!(mailbox.open(&up).expect("open up"), &[i]);
        }
        for i in 0..3u8 {
            let down = mailbox.seal(&[i, i]).expect("seal down");
            assert_eq!(phone.open(&down).expect("open down"), &[i, i]);
        }
        let up = phone.seal(b"still fine").expect("seal");
        assert_eq!(mailbox.open(&up).expect("open"), b"still fine");
    }

    #[test]
    fn a_frame_out_of_order_is_refused() {
        let (secret, public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [4; SESSION_ID_LEN]).expect("open");
        let mut mailbox = Session::accept(&secret, &hello).expect("accept");

        let first = phone.seal(b"one").expect("seal");
        let second = phone.seal(b"two").expect("seal");

        // The mailbox expects `first` next. Handed `second`, it refuses: the
        // counters have diverged and there is no skipping back.
        assert!(mailbox.open(&second).is_err());
        // And it has not advanced, so `first` was not silently consumed.
        assert_eq!(mailbox.open(&first).expect("open"), b"one");
    }

    #[test]
    fn two_sessions_under_one_key_do_not_share_a_key() {
        let (secret, public) = pair();
        let (mut phone_a, hello_a) = Session::open_to(&public, [5; SESSION_ID_LEN]).expect("a");
        let (_phone_b, hello_b) = Session::open_to(&public, [6; SESSION_ID_LEN]).expect("b");
        let _mailbox_a = Session::accept(&secret, &hello_a).expect("accept a");
        let mut mailbox_b = Session::accept(&secret, &hello_b).expect("accept b");

        let sealed = phone_a.seal(b"for a").expect("seal");
        // Session b's key must not open session a's frame, or the session id
        // would be doing nothing and the mailbox could confuse two phones.
        assert!(mailbox_b.open(&sealed).is_err());
    }

    #[test]
    fn the_mailbox_cannot_open_with_the_wrong_secret() {
        let (_secret, public) = pair();
        let (other_secret, _other_public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [7; SESSION_ID_LEN]).expect("open");
        // Accepting with a key that is not the one the hello was sealed to
        // yields a different shared secret, and the first frame will not open.
        let mut wrong = Session::accept(&other_secret, &hello).expect("accept");
        let sealed = phone.seal(b"secret").expect("seal");
        assert!(wrong.open(&sealed).is_err());
    }

    #[test]
    fn a_hello_survives_the_wire() {
        let (_secret, public) = pair();
        let (_phone, hello) = Session::open_to(&public, [8; SESSION_ID_LEN]).expect("open");
        let bytes = hello.to_bytes();
        assert_eq!(bytes.len(), HELLO_LEN);
        let back = Hello::from_bytes(&bytes).expect("parse");
        assert_eq!(back.session_id(), [8; SESSION_ID_LEN]);
        assert_eq!(back.to_bytes(), bytes);
    }

    #[test]
    fn a_hello_of_the_wrong_length_is_refused() {
        assert!(Hello::from_bytes(b"short").is_err());
        assert!(Hello::from_bytes(&[0u8; HELLO_LEN + 1]).is_err());
    }

    #[test]
    fn tampering_with_a_frame_is_caught() {
        let (secret, public) = pair();
        let (mut phone, hello) = Session::open_to(&public, [9; SESSION_ID_LEN]).expect("open");
        let mut mailbox = Session::accept(&secret, &hello).expect("accept");
        let mut sealed = phone.seal(b"deposit this").expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(mailbox.open(&sealed).is_err());
    }
}
