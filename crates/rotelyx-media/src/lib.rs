//! Frame encryption for calls.
//!
//! # What this is, and what it deliberately is not
//!
//! This crate encrypts and decrypts individual media frames. It does **not**
//! encode audio, manage a jitter buffer, cancel echo or estimate bandwidth.
//! Those are the long part of building calls and they need real devices to get
//! right. This is the part that decides whether a call is as end to end as a
//! message, and it can be built and checked without a microphone in the room.
//!
//! # Why media cannot simply reuse the message layer
//!
//! An MLS application message is the wrong shape for audio. It is ordered,
//! reliable and ratcheted: every message advances a chain, and a message that
//! arrives out of order or not at all is a problem to be solved. Audio is the
//! opposite. Frames arrive every twenty milliseconds, some never arrive at all,
//! and a frame that is late is worthless rather than worth waiting for. Running
//! fifty ratchet steps a second per speaker, and stalling on every lost packet,
//! would produce a call that breaks whenever the network does.
//!
//! So media takes a **key** from MLS and does its own framing:
//!
//! - One key per sender per epoch, exported from the group. Nothing new is
//!   agreed, and nothing weakens: the media key is as strong as the epoch it
//!   came from, and it dies with that epoch.
//! - A per frame counter, carried in the clear, so a receiver can decrypt any
//!   frame on arrival without having seen the ones before it.
//! - A replay window, because a counter in the clear is a counter an attacker
//!   can repeat.
//!
//! This is the structure of SFrame (RFC 9605), and it is followed rather than
//! reinvented for the usual reason: a forwarding unit for group calls has to be
//! able to route frames it cannot read, and that only works if the header is a
//! shape other implementations already agree on.
//!
//! # Two modes, because a call and a recording are not the same thing
//!
//! Every real-time media stack optimises latency and accepts loss, because a
//! telephone call needs it: two people interrupting each other cannot be doing
//! it half a second apart.
//!
//! Rotelyx offers that, and offers the opposite. In **fidelity** mode the
//! buffer runs seconds deep, missing frames are asked for again, and a slot
//! waits rather than being concealed. Measured, it loses nothing on a network
//! dropping **one packet in two**, with the retransmissions dropping at the
//! same rate.
//!
//! What makes it possible is the delay itself. A deep buffer is time, and time
//! is enough round trips to get back what the network threw away. Nobody else
//! builds this because nobody else starts from "delay does not matter", and for
//! a briefing, a recording or anything one person says to others, it does not.
//!
//! # Calls are always relayed
//!
//! Rotelyx prefers any direct path over any relayed one for messages, because a
//! relay learns who talks to whom and the alternative exposure is to an
//! operator.
//!
//! **Calls invert that and the inversion is deliberate.** On a direct path the
//! other party learns your address, and in a group call every participant does.
//! A messenger whose call feature hands your address to whoever rings you is
//! not one that can claim to protect its users, so the exposure that matters
//! here is to the other party rather than to an operator.
//!
//! SimpleX reaches the same default and says so plainly: turning the relay off
//! means "your IP address will be known to your contacts". The difference is
//! that we do not offer the switch.
//!
//! # What a forwarding unit can see
//!
//! Group calls above a handful of participants need a server that forwards
//! streams. That server sees frame sizes, timing, and which sender a frame came
//! from. It cannot see content. That is the same bargain the blind mailbox
//! makes, and it is worth stating before anybody builds on it: **a call routed
//! through a forwarding unit leaks who is speaking and when**, and over a
//! conversation that is its rhythm.
//!
//! Half of that is now optional rather than inherent. [`Sender::pad_to`] makes
//! every datagram come out the same size, so the sizes stop being a voice
//! activity detector anybody on the path can run. It is off by default because
//! it costs the difference between the average frame and the largest one, from
//! everybody, including the people saying nothing, and on a two-party direct
//! call there is no forwarder to hide from.
//!
//! The other half is not optional: the forwarder knows which connection a
//! datagram arrived on, so it knows who sent it. Hiding that needs onion routing
//! or a group small enough not to need a forwarder, and saying so is better than
//! implying a property this does not have. See [`forward`].

pub mod forward;
pub mod jitter;
pub mod transport;

pub use forward::{ForwardError, Forwarder, Routed};
pub use jitter::{JitterBuffer, Mode, Playout};
pub use transport::{MediaIn, MediaOut, TransportError, MAX_FRAME};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separation for the media key exported from MLS. Distinct from every
/// other label this project exports under, so a media key can never be the same
/// bytes as a mailbox tag key.
pub const MEDIA_KEY_LABEL: &str = "rotelyx media base key v1";

/// Separates the two values derived from one base key.
const KEY_INFO: &[u8] = b"rotelyx media key v1";
const SALT_INFO: &[u8] = b"rotelyx media salt v1";

/// Authentication tag length, in bytes.
///
/// # Why this is sixteen and not eight
///
/// Eight would take frame overhead from 22 percent to 14, and SFrame permits
/// it, so it was tried. The `aes-gcm` crate gates an eight byte tag behind a
/// feature named `hazmat`, and the reason is specific rather than cautious.
///
/// A truncated **polynomial** MAC is not a truncated HMAC. GCM and Poly1305
/// both authenticate with a polynomial over a secret subkey, and Ferguson
/// showed in 2005 that short GCM tags leak information about that subkey across
/// repeated forgery attempts. Security therefore degrades faster than the
/// 2^-64 a naive reading suggests, which is why NIST SP 800-38D constrains
/// packet size and invocation count when short tags are used at all.
///
/// SFrame's other cipher suite, AES-CTR with a truncated HMAC-SHA256, has no
/// such problem: truncating an HMAC is ordinary and safe. Taking that route
/// means composing encrypt-then-MAC by hand, which is exactly the kind of
/// construction this project does not write.
///
/// So the eight bytes stay spent, and the note stays here so nobody re-derives
/// the idea and reaches for the `hazmat` flag.
pub const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// How far out of order a frame may arrive and still be accepted, in frames.
///
/// # Why this is not sixty four
///
/// It was, which is over a second of audio and generous for a conversation
/// where a late frame is worthless anyway.
///
/// Then recovery arrived. A retransmitted frame carries the **same counter** as
/// the one that was lost, so the replay window is not only an anti-replay
/// measure, it is the ceiling on how far back a frame can be rescued. A window
/// of 64 frames would silently cap recovery at 1.28 seconds no matter how deep
/// the buffer was told to be, and the failure would look like the recovery
/// simply not working.
///
/// 256 frames is 5.12 seconds at fifty frames a second, comfortably past any
/// buffer depth worth configuring. The cost is 32 bytes of bitmap per sender.
const REPLAY_WINDOW: u64 = 256;

/// The bitmap holding it, in 64 bit words.
const REPLAY_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// The most senders one call may have.
///
/// Five bits of the config byte, which is what leaves three for the counter
/// length. Thirty two simultaneous speakers is far past the point where a call
/// needs a forwarding unit anyway, and the alternative is spending a whole byte
/// on a field that is almost always zero or one.
pub const MAX_SENDERS: usize = 32;

/// The smallest: config byte plus one counter byte.
const MIN_HEADER_LEN: usize = 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("frame is too short to contain a header")]
    Truncated,
    #[error("frame did not authenticate")]
    BadTag,
    #[error("frame is from sender {got}, not {expected}")]
    WrongSender { expected: u8, got: u8 },
    #[error("frame {counter} was already seen, or is too old to accept")]
    Replay { counter: u64 },
    #[error("this sender has used every counter and must rekey")]
    CounterExhausted,
    #[error("sender {id} cannot be carried in a frame header, which holds 0 to 31")]
    SenderOutOfRange { id: u8 },
    #[error("a call binding must be at least {min} bytes, and this one is {got}")]
    CallBindingTooShort { min: usize, got: usize },
}

/// The value that makes one call's keys different from the next one's.
///
/// # Why this type exists rather than another argument
///
/// Because the argument was missing and nobody noticed for months. Media keys
/// were derived from the group's exported secret and the speaker's position in
/// the roster, both of which are fixed for an entire MLS epoch, and the frame
/// counter starts at zero. Ordinary messages do not advance an epoch; only a
/// commit does. So hanging up and calling again reused the key **and** the
/// nonce, frame for frame, from the first frame onwards.
///
/// Under ChaCha20-Poly1305 that is not a weakness, it is the end of the
/// guarantee. Two ciphertexts under one nonce give the exclusive-or of the two
/// plaintexts, and speech is structured enough to separate. Worse, two
/// authenticated messages under one nonce recover the Poly1305 one-time key,
/// after which anything can be forged with a valid tag: the per speaker key
/// exists precisely so that nobody can put words in somebody else's mouth, and
/// a repeated nonce hands that back.
///
/// A plain `&[u8]` argument would have been enough to fix it and not enough to
/// keep it fixed. A named type with no default and no way to build an empty one
/// means the next person to write a call has to answer the question.
#[derive(Clone, PartialEq, Eq)]
pub struct CallBinding(Vec<u8>);

impl CallBinding {
    /// Shorter than this is not worth having.
    ///
    /// Sixty four bits of a value chosen fresh per call puts a repeat far past
    /// the number of calls two people will place inside one epoch, and the only
    /// collision that costs anything is between two calls of the same pair at
    /// the same epoch.
    pub const MIN_BYTES: usize = 8;

    /// Both ends must pass the same bytes, and neither may reuse them.
    ///
    /// In practice this is the identifier the call signalling already carries:
    /// the side that rings mints it, the side that answers echoes it, and both
    /// derive from it.
    pub fn new(bytes: &[u8]) -> Result<Self, MediaError> {
        if bytes.len() < Self::MIN_BYTES {
            return Err(MediaError::CallBindingTooShort {
                min: Self::MIN_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Deliberately says nothing. A call identifier is not secret, but it is a
/// linkage between two ends of one conversation and a log is a poor place for
/// it.
impl std::fmt::Debug for CallBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallBinding(..)")
    }
}

/// The key material for one sender in one epoch.
///
/// # Why per sender
///
/// Every participant encrypts with a different key, derived from the same group
/// secret and that participant's identity. Two reasons, and the second is the
/// one that matters:
///
/// 1. Counters cannot collide, so no nonce is ever reused. A shared key with
///    independent counters per sender is a nonce reuse waiting for two people
///    to speak at once.
/// 2. A frame that claims to be from Alice can only be produced by Alice. With
///    a shared key any member could forge any other member's stream, which in a
///    call means putting words in somebody's mouth.
pub struct SenderKeys {
    id: u8,
    key: Zeroizing<[u8; 32]>,
    salt: Zeroizing<[u8; NONCE_LEN]>,
}

impl std::fmt::Debug for SenderKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderKeys")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SenderKeys {
    /// Derive from a group secret exported at the current MLS epoch.
    ///
    /// `base` is what `Conversation::media_base_key` exports: the same bytes
    /// for every member, tied to one epoch. `sender` distinguishes the streams
    /// within it and must be the same value both ends use to address that
    /// participant.
    /// `call` is what stops one call from reusing the previous call's nonces.
    /// See [`CallBinding`]. It is mixed into both expansions rather than only
    /// into the key, so that two calls differ in their salts as well: if a
    /// derivation ever went wrong and produced the same key twice, different
    /// salts would still keep the nonces apart.
    pub fn derive(base: &[u8; 32], sender: u8, call: &CallBinding) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(&[sender]), base);

        let mut key = Zeroizing::new([0u8; 32]);
        let mut salt = Zeroizing::new([0u8; NONCE_LEN]);

        let mut key_info = KEY_INFO.to_vec();
        key_info.extend_from_slice(call.as_bytes());
        let mut salt_info = SALT_INFO.to_vec();
        salt_info.extend_from_slice(call.as_bytes());

        // Infallible for these lengths: HKDF only fails past 255 hash blocks.
        hkdf.expand(&key_info, &mut key[..]).expect("32 bytes");
        hkdf.expand(&salt_info, &mut salt[..]).expect("12 bytes");

        Self {
            id: sender,
            key,
            salt,
        }
    }

    pub fn sender(&self) -> u8 {
        self.id
    }

    /// The nonce for a frame.
    ///
    /// Salt exclusive-ored with the counter, which is how SFrame avoids
    /// transmitting a nonce while guaranteeing it never repeats: the salt is
    /// fixed per key and the counter never reuses a value under one key.
    fn nonce(&self, counter: u64) -> [u8; NONCE_LEN] {
        let mut nonce = *self.salt;
        let counter = counter.to_be_bytes();
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter) {
            *n ^= c;
        }
        nonce
    }

    /// The header for a frame: one config byte, then the counter in as few
    /// bytes as it fits.
    ///
    /// # Why the counter is not a fixed eight bytes
    ///
    /// It was, and eight bytes on an eighty byte Opus frame is ten percent of
    /// the packet spent on a number that is almost always small. At fifty
    /// frames a second, three bytes carry ninety three hours of continuous
    /// speech. The length lives in the config byte so a receiver knows how much
    /// to read without a delimiter.
    ///
    /// The counter is still a full 64 bit value everywhere it matters: the
    /// nonce is derived from all of it, and only its *encoding* is short.
    fn header(&self, counter: u64) -> Vec<u8> {
        let significant = counter.to_be_bytes();
        let first = significant
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(significant.len() - 1);
        let bytes = &significant[first..];

        let mut header = Vec::with_capacity(1 + bytes.len());
        header.push(((bytes.len() as u8 - 1) << 5) | self.id);
        header.extend_from_slice(bytes);
        header
    }

    /// Read a header back. Returns the counter and how many bytes it occupied.
    pub fn parse_header(frame: &[u8]) -> Result<(u8, u64, usize), MediaError> {
        if frame.len() < MIN_HEADER_LEN {
            return Err(MediaError::Truncated);
        }

        let config = frame[0];
        let sender = config & 0b0001_1111;
        let counter_len = ((config >> 5) as usize) + 1;

        let header_len = 1 + counter_len;
        if frame.len() < header_len {
            return Err(MediaError::Truncated);
        }

        let mut counter = 0u64;
        for byte in &frame[1..header_len] {
            counter = (counter << 8) | *byte as u64;
        }

        Ok((sender, counter, header_len))
    }
}

/// One byte, always, marking where the frame ends and the padding begins.
pub const PAD_MARKER_LEN: usize = 1;

/// The marker. ISO/IEC 7816-4: a single `0x80`, then zeros.
const PAD_MARKER: u8 = 0x80;

/// Grow a frame to `to` bytes of plaintext, unambiguously.
///
/// The marker is written **whether or not** anything is padded, so a receiver
/// has one rule rather than two and there is no flag in the header saying which
/// was used. A flag would have to travel in the clear, and a clear flag saying
/// "this one is padded" is most of what padding was hiding.
///
/// Scanning back from the end over zeros to the first non-zero byte finds the
/// marker unambiguously, whatever the frame itself ends with, because the frame
/// always ends before the marker.
fn pad(frame: &[u8], to: Option<usize>) -> Vec<u8> {
    let target = to.unwrap_or(0).max(frame.len() + PAD_MARKER_LEN);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(frame);
    out.push(PAD_MARKER);
    out.resize(target, 0);
    out
}

/// Take the padding back off.
fn unpad(plain: &[u8]) -> Result<Vec<u8>, MediaError> {
    let end = plain
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(MediaError::Truncated)?;
    if plain[end] != PAD_MARKER {
        return Err(MediaError::Truncated);
    }
    Ok(plain[..end].to_vec())
}

/// Which participant a datagram claims to come from.
///
/// # Why this is readable before anything is authenticated
///
/// It has to be. The sender id selects the key the tag is checked with, so it
/// is read first by construction, and a receiver with several participants
/// cannot route a datagram without it. The value is therefore **a claim, not a
/// fact**: anybody can write any sender id into a datagram they made up. What
/// makes it trustworthy is that a frame claiming to be from a participant and
/// failing that participant's tag is discarded, so a lie routes a packet to the
/// place that rejects it.
///
/// Exposed so a caller holding one `Receiver` per participant can pick the
/// right one instead of trying all of them.
pub fn claimed_sender(frame: &[u8]) -> Result<u8, MediaError> {
    SenderKeys::parse_header(frame).map(|(sender, _, _)| sender)
}

/// Encrypts one participant's outgoing frames.
pub struct Sender {
    keys: SenderKeys,
    counter: u64,
    /// Set once the last counter has been used.
    ///
    /// A separate flag rather than stopping one short, because "the counter
    /// cannot advance" and "the counter has been spent" are different states
    /// and conflating them silently wastes the final value.
    exhausted: bool,
    /// Size every protected frame is grown to, before encryption. See
    /// [`Sender::pad_to`].
    pad_to: Option<usize>,
}

impl Sender {
    /// Refuses a sender id the header cannot carry, rather than silently
    /// truncating it into somebody else's stream.
    pub fn new(keys: SenderKeys) -> Result<Self, MediaError> {
        if usize::from(keys.id) >= MAX_SENDERS {
            return Err(MediaError::SenderOutOfRange { id: keys.id });
        }
        Ok(Self {
            keys,
            counter: 0,
            exhausted: false,
            pad_to: None,
        })
    }

    /// How many frames this key has protected. An operator rotating keys on a
    /// schedule reads this rather than guessing.
    pub fn frames_sent(&self) -> u64 {
        self.counter
    }

    /// Encrypt one frame.
    ///
    /// The header is authenticated but not encrypted, so a forwarding unit can
    /// route by sender without being able to read or alter anything: changing
    /// a byte of the header invalidates the tag.
    /// Bytes this sender will add to the next frame it protects.
    ///
    /// The header grows by a byte whenever the counter needs another one, so
    /// this is a function of where the call has got to rather than a constant.
    /// Exposed because a layered encoder has to know how much of a datagram is
    /// left for it before it decides how many layers to send, and guessing 18
    /// would be wrong for the last seven minutes of a very long call.
    pub fn overhead(&self) -> usize {
        self.keys.header(self.counter).len() + TAG_LEN + PAD_MARKER_LEN
    }

    /// Make every frame this sender protects come out the same size.
    ///
    /// # What this is for
    ///
    /// A group call above a handful of people needs a forwarding unit, and a
    /// forwarding unit sees the size of every datagram it routes. Speech is not
    /// a constant bit rate: a coded frame of silence is smaller than a coded
    /// frame of a vowel, and the rate control moves the size again. So the sizes
    /// alone say who is talking and when, which over a conversation is its
    /// rhythm, and the rhythm is most of what a transcript would tell you about
    /// who was arguing with whom.
    ///
    /// Padding to a fixed size takes that away. It costs the difference between
    /// the average frame and the largest one, every frame, from everybody,
    /// including the people saying nothing. That is the trade and it is the
    /// caller's to make: on a two-party direct call there is no forwarder to
    /// hide from and this should stay off.
    ///
    /// A size smaller than a frame turns out to be does not truncate it. The
    /// frame goes out at its own size, because dropping audio to keep a size
    /// constant would be a worse failure than the one being prevented, and
    /// the caller sets the size from `payload_budget` anyway.
    pub fn pad_to(&mut self, bytes: Option<usize>) {
        self.pad_to = bytes;
    }

    /// How many plaintext bytes fit in a datagram of `datagram_bytes`.
    ///
    /// Saturating rather than erroring: a budget smaller than the overhead is a
    /// budget for nothing, which is a true answer and one the caller can act on.
    pub fn payload_budget(&self, datagram_bytes: usize) -> usize {
        datagram_bytes.saturating_sub(self.overhead())
    }

    pub fn protect(&mut self, frame: &[u8]) -> Result<Vec<u8>, MediaError> {
        // Refuse rather than wrap. A wrapped counter repeats a nonce under the
        // same key, which loses confidentiality outright, and the caller can
        // always rekey.
        if self.exhausted {
            return Err(MediaError::CounterExhausted);
        }
        let counter = self.counter;
        match counter.checked_add(1) {
            Some(next) => self.counter = next,
            None => self.exhausted = true,
        }

        let header = self.keys.header(counter);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.keys.key[..]).expect("32 byte key");

        // Padded **inside** the encryption, which is the only place it helps. A
        // datagram padded after the tag tells anybody counting bytes exactly how
        // much of it is padding, so the real length is still there to read.
        let padded = pad(frame, self.pad_to);

        let sealed = cipher
            .encrypt(
                &Nonce::from(self.keys.nonce(counter)),
                Payload {
                    msg: &padded,
                    aad: &header,
                },
            )
            .map_err(|_| MediaError::BadTag)?;

        let mut out = Vec::with_capacity(header.len() + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

/// Decrypts one participant's incoming frames, refusing replays.
pub struct Receiver {
    keys: SenderKeys,
    /// Highest counter accepted so far.
    highest: u64,
    /// Bitmap of the counters below `highest` that have been seen. Bit `n`,
    /// counting across the whole array, is the counter `highest - 1 - n`.
    seen: [u64; REPLAY_WORDS],
    started: bool,
}

impl Receiver {
    pub fn new(keys: SenderKeys) -> Result<Self, MediaError> {
        if usize::from(keys.id) >= MAX_SENDERS {
            return Err(MediaError::SenderOutOfRange { id: keys.id });
        }
        Ok(Self {
            keys,
            highest: 0,
            seen: [0; REPLAY_WORDS],
            started: false,
        })
    }

    /// Decrypt one frame.
    ///
    /// Out of order arrival within the replay window is accepted, because that
    /// is normal on any real network. Anything already seen, or older than the
    /// window, is refused.
    pub fn unprotect(&mut self, frame: &[u8]) -> Result<Vec<u8>, MediaError> {
        let (sender, counter, header_len) = SenderKeys::parse_header(frame)?;
        let (header, body) = frame.split_at(header_len);

        if sender != self.keys.id {
            return Err(MediaError::WrongSender {
                expected: self.keys.id,
                got: sender,
            });
        }

        self.check_replay(counter)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.keys.key[..]).expect("32 byte key");
        let plain = cipher
            .decrypt(
                &Nonce::from(self.keys.nonce(counter)),
                Payload {
                    msg: body,
                    aad: header,
                },
            )
            .map_err(|_| MediaError::BadTag)?;

        // Recorded only after the tag verifies. Marking a counter used on an
        // unauthenticated header would let anyone lock out a frame they cannot
        // even read, by sending garbage that claims its number.
        self.record(counter);
        unpad(&plain)
    }

    /// The highest counter accepted so far, and whether anything has been.
    ///
    /// Exposed so a caller can tell a gap from a quiet moment. The replay
    /// window already holds this: it is what "is this frame older than the ones
    /// I have" is decided against.
    pub fn highest_accepted(&self) -> Option<u64> {
        self.started.then_some(self.highest)
    }

    fn check_replay(&self, counter: u64) -> Result<(), MediaError> {
        if !self.started {
            return Ok(());
        }
        if counter > self.highest {
            return Ok(());
        }

        let behind = self.highest - counter;
        if behind >= REPLAY_WINDOW {
            return Err(MediaError::Replay { counter });
        }
        if behind == 0 || self.was_seen(behind) {
            return Err(MediaError::Replay { counter });
        }
        Ok(())
    }

    /// Whether the counter `behind` positions below `highest` has been seen.
    fn was_seen(&self, behind: u64) -> bool {
        let bit = behind - 1;
        self.seen[(bit / 64) as usize] & (1 << (bit % 64)) != 0
    }

    fn mark_seen(&mut self, behind: u64) {
        let bit = behind - 1;
        self.seen[(bit / 64) as usize] |= 1 << (bit % 64);
    }

    /// Slide the window forward by `step` counters.
    fn slide(&mut self, step: u64) {
        if step >= REPLAY_WINDOW {
            self.seen = [0; REPLAY_WORDS];
            return;
        }

        let words = (step / 64) as usize;
        let bits = step % 64;

        // Shift the whole array left, most significant word first so a word is
        // read before it is overwritten.
        for i in (0..REPLAY_WORDS).rev() {
            let mut value = if i >= words { self.seen[i - words] } else { 0 };
            if bits > 0 {
                value <<= bits;
                if i >= words + 1 {
                    value |= self.seen[i - words - 1] >> (64 - bits);
                }
            }
            self.seen[i] = value;
        }

        // The counter that was `highest` is now `step` behind.
        self.mark_seen(step);
    }

    fn record(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.seen = [0; REPLAY_WORDS];
            return;
        }

        if counter > self.highest {
            // Everything the window slides past is forgotten, which is what
            // bounds the memory: the window is a fixed size regardless of how
            // long a call runs.
            self.slide(counter - self.highest);
            self.highest = counter;
        } else {
            let behind = self.highest - counter;
            if behind >= 1 && behind < REPLAY_WINDOW {
                self.mark_seen(behind);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    /// A fixed binding for tests that are not about the binding.
    ///
    /// Named rather than inlined so that a test which needs two different calls
    /// has to say so, which is the whole point of the type.
    fn test_call() -> CallBinding {
        CallBinding::new(b"a-test-call-0001").expect("long enough")
    }

    fn pair(sender_id: u8) -> (Sender, Receiver) {
        let base = [7u8; 32];
        (
            Sender::new(SenderKeys::derive(&base, sender_id, &test_call())).expect("sender"),
            Receiver::new(SenderKeys::derive(&base, sender_id, &test_call())).expect("receiver"),
        )
    }

    #[test]
    fn a_frame_round_trips() {
        let (mut sender, mut receiver) = pair(1);

        for n in 0..100u32 {
            let frame = format!("audio frame {n}").into_bytes();
            let protected = sender.protect(&frame).expect("protect");
            assert_eq!(receiver.unprotect(&protected).expect("unprotect"), frame);
        }
    }

    /// The whole point: a frame must be unreadable without the key.
    #[test]
    fn the_payload_is_not_in_the_clear() {
        let (mut sender, _) = pair(1);
        let secret = b"what was actually said";

        let protected = sender.protect(secret).expect("protect");
        assert!(
            !protected.windows(secret.len()).any(|w| w == secret),
            "the frame is sitting in the packet"
        );
    }

    /// Changing a byte anywhere must fail, header included. A forwarding unit
    /// routes by the header, so a header it could rewrite is a header it could
    /// use to misattribute speech.
    #[test]
    fn tampering_is_refused_everywhere() {
        let (mut sender, mut receiver) = pair(3);
        let protected = sender.protect(b"hello").expect("protect");

        for byte in 0..protected.len() {
            let mut tampered = protected.clone();
            tampered[byte] ^= 0xff;

            let mut fresh = Receiver::new(SenderKeys::derive(&[7u8; 32], 3, &test_call())).expect("receiver");
            assert!(
                fresh.unprotect(&tampered).is_err(),
                "flipping byte {byte} was accepted"
            );
        }

        assert!(receiver.unprotect(&protected).is_ok(), "the original still works");
    }

    /// Packets arrive out of order on every real network. Refusing them would
    /// make the call worse than the network is.
    #[test]
    fn out_of_order_within_the_window_is_accepted() {
        let (mut sender, mut receiver) = pair(1);

        let frames: Vec<Vec<u8>> = (0..8)
            .map(|n| sender.protect(format!("{n}").as_bytes()).expect("protect"))
            .collect();

        // Delivered backwards.
        for (n, frame) in frames.iter().enumerate().rev() {
            assert_eq!(
                receiver.unprotect(frame).expect("out of order"),
                n.to_string().as_bytes(),
                "frame {n} was refused"
            );
        }
    }

    /// A counter travels in the clear, so it is a counter an attacker can
    /// repeat.
    #[test]
    fn a_repeated_frame_is_refused() {
        let (mut sender, mut receiver) = pair(1);
        let frame = sender.protect(b"once").expect("protect");

        assert!(receiver.unprotect(&frame).is_ok());
        assert_eq!(
            receiver.unprotect(&frame),
            Err(MediaError::Replay { counter: 0 }),
            "the same frame must not be accepted twice"
        );
    }

    /// A frame older than the window is refused rather than accepted, because
    /// the window is what bounds how far back a replay can reach.
    #[test]
    fn a_frame_older_than_the_window_is_refused() {
        let (mut sender, mut receiver) = pair(1);

        let old = sender.protect(b"old").expect("protect");
        for _ in 0..REPLAY_WINDOW + 1 {
            let f = sender.protect(b"filler").expect("protect");
            receiver.unprotect(&f).expect("in order");
        }

        assert!(
            matches!(receiver.unprotect(&old), Err(MediaError::Replay { .. })),
            "a frame from before the window must not be accepted"
        );
    }

    /// Two calls inside one MLS epoch must not share a keystream.
    ///
    /// This is the regression test for the worst defect this crate has had. The
    /// exported group secret and the sender index are both fixed for an epoch,
    /// ordinary messages do not advance an epoch, and the frame counter starts
    /// at zero every time a sender is constructed. So before the call binding
    /// existed, hanging up and dialling again encrypted the second call's first
    /// frame under the first call's first key and nonce.
    ///
    /// The assertion is on the exclusive-or of two ciphertexts, because that is
    /// exactly what an eavesdropper computes: under a repeated nonce it equals
    /// the exclusive-or of the two plaintexts and the ciphertexts stop hiding
    /// anything.
    #[test]
    fn two_calls_in_one_epoch_do_not_repeat_a_nonce() {
        let base = [7u8; 32];
        let plaintext = b"the same words spoken twice";

        let first = CallBinding::new(b"call-one-0001").expect("long enough");
        let second = CallBinding::new(b"call-two-0002").expect("long enough");

        let mut one = Sender::new(SenderKeys::derive(&base, 1, &first)).expect("sender");
        let mut two = Sender::new(SenderKeys::derive(&base, 1, &second)).expect("sender");

        let a = one.protect(plaintext).expect("protect");
        let b = two.protect(plaintext).expect("protect");

        // Same header: same sender, same counter zero. That part is expected and
        // is not the problem.
        assert_eq!(a[..MIN_HEADER_LEN], b[..MIN_HEADER_LEN]);

        // The bodies must not be equal, and more than that, their exclusive-or
        // must not be the exclusive-or of the plaintexts, which for identical
        // plaintexts is all zeroes.
        let body_a = &a[MIN_HEADER_LEN..MIN_HEADER_LEN + plaintext.len()];
        let body_b = &b[MIN_HEADER_LEN..MIN_HEADER_LEN + plaintext.len()];
        assert_ne!(body_a, body_b, "two calls produced the same ciphertext");
        assert!(
            body_a.iter().zip(body_b).any(|(x, y)| x ^ y != 0),
            "the two keystreams cancelled, which is nonce reuse"
        );

        // And the second call's receiver must not accept the first call's audio,
        // because accepting it is what makes a captured stream replayable into a
        // later conversation.
        let mut listening = Receiver::new(SenderKeys::derive(&base, 1, &second)).expect("receiver");
        assert_eq!(listening.unprotect(&a), Err(MediaError::BadTag));
    }

    /// A binding too short to be worth having is refused rather than accepted
    /// and quietly weakened.
    #[test]
    fn a_short_call_binding_is_refused() {
        assert_eq!(
            CallBinding::new(b"short"),
            Err(MediaError::CallBindingTooShort { min: 8, got: 5 })
        );
        assert_eq!(
            CallBinding::new(b""),
            Err(MediaError::CallBindingTooShort { min: 8, got: 0 })
        );
    }

    /// Every sender has its own key, so one member cannot produce another
    /// member's stream. In a call that is the difference between overhearing
    /// somebody and impersonating them.
    #[test]
    fn one_sender_cannot_forge_another() {
        let base = [7u8; 32];
        let mut alice = Sender::new(SenderKeys::derive(&base, 1, &test_call())).expect("sender");
        let mut listening_for_bob = Receiver::new(SenderKeys::derive(&base, 2, &test_call())).expect("receiver");

        let from_alice = alice.protect(b"pretending to be bob").expect("protect");

        assert_eq!(
            listening_for_bob.unprotect(&from_alice),
            Err(MediaError::WrongSender {
                expected: 2,
                got: 1
            })
        );

        // And relabelling the header does not help, because the header is
        // authenticated and the key is different anyway.
        let mut relabelled = from_alice.clone();
        relabelled[0] = 2;
        assert_eq!(
            listening_for_bob.unprotect(&relabelled),
            Err(MediaError::BadTag)
        );
    }

    /// A sender id the header cannot carry must be refused, not truncated into
    /// somebody else's stream.
    #[test]
    fn a_sender_beyond_the_header_is_refused() {
        let base = [7u8; 32];

        assert!(Sender::new(SenderKeys::derive(&base, MAX_SENDERS as u8 - 1, &test_call())).is_ok());
        assert!(matches!(
            Sender::new(SenderKeys::derive(&base, MAX_SENDERS as u8, &test_call())),
            Err(MediaError::SenderOutOfRange { id }) if id == MAX_SENDERS as u8
        ));
        assert!(Receiver::new(SenderKeys::derive(&base, 200, &test_call())).is_err());
    }

    /// The counter is encoded short but is a full 64 bit value everywhere it
    /// matters. A frame written with a one byte counter must still be readable
    /// after the counter has grown past it.
    #[test]
    fn a_short_counter_and_a_long_one_are_the_same_number() {
        let (mut sender, mut receiver) = pair(1);

        for counter in [0u64, 1, 255, 256, 65_535, 65_536, 1 << 32, u64::MAX - 1] {
            sender.counter = counter;
            sender.exhausted = false;

            let protected = sender.protect(b"hello").expect("protect");
            let (id, read_back, _) = SenderKeys::parse_header(&protected).expect("parse");

            assert_eq!(id, 1);
            assert_eq!(read_back, counter, "the counter did not survive encoding");

            let mut fresh = Receiver::new(SenderKeys::derive(&[7u8; 32], 1, &test_call())).expect("receiver");
            assert_eq!(fresh.unprotect(&protected).expect("unprotect"), b"hello");
        }
        let _ = &mut receiver;
    }

    /// Two senders must never derive the same key or the same nonce stream.
    #[test]
    fn senders_derive_independent_keys() {
        let base = [7u8; 32];
        let a = SenderKeys::derive(&base, 1, &test_call());
        let b = SenderKeys::derive(&base, 2, &test_call());

        assert_ne!(a.key[..], b.key[..], "two senders share a key");
        assert_ne!(a.salt[..], b.salt[..], "two senders share a nonce stream");
        assert_ne!(a.nonce(0), b.nonce(0));
    }

    /// A key from another epoch must not decrypt this epoch's frames. This is
    /// what makes a media key die with the epoch it came from.
    #[test]
    fn a_key_from_another_epoch_does_not_work() {
        let mut sender = Sender::new(SenderKeys::derive(&[7u8; 32], 1, &test_call())).expect("sender");
        let mut next_epoch = Receiver::new(SenderKeys::derive(&[8u8; 32], 1, &test_call())).expect("receiver");

        let frame = sender.protect(b"this epoch only").expect("protect");
        assert_eq!(next_epoch.unprotect(&frame), Err(MediaError::BadTag));
    }

    /// No nonce may repeat under one key, ever. This is the property whose
    /// failure loses confidentiality outright rather than degrading it.
    #[test]
    fn no_nonce_repeats_under_one_key() {
        let keys = SenderKeys::derive(&[7u8; 32], 1, &test_call());

        let mut seen = std::collections::HashSet::new();
        for counter in 0..10_000u64 {
            assert!(
                seen.insert(keys.nonce(counter)),
                "counter {counter} reused a nonce"
            );
        }

        // And far apart, where a naive construction would wrap.
        for counter in [u64::MAX, u64::MAX - 1, 1 << 40, 1 << 63] {
            assert!(seen.insert(keys.nonce(counter)), "counter {counter} collided");
        }
    }

    /// Running out of counters must stop the sender rather than wrap it.
    #[test]
    fn an_exhausted_counter_refuses_to_wrap() {
        let mut sender = Sender::new(SenderKeys::derive(&[7u8; 32], 1, &test_call())).expect("sender");
        sender.counter = u64::MAX;

        assert!(sender.protect(b"last").is_ok(), "the final counter is usable");
        assert_eq!(
            sender.protect(b"one too many"),
            Err(MediaError::CounterExhausted),
            "wrapping would repeat a nonce under the same key"
        );
    }

    /// A garbage frame must not be able to lock out the real one that carries
    /// the same number.
    #[test]
    fn a_forged_frame_cannot_burn_a_counter() {
        let (mut sender, mut receiver) = pair(1);

        let real = sender.protect(b"the real frame").expect("protect");

        let mut forged = real.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;

        assert_eq!(receiver.unprotect(&forged), Err(MediaError::BadTag));
        assert_eq!(
            receiver.unprotect(&real).expect("the real frame still works"),
            b"the real frame"
        );
    }

    /// A short frame must be refused rather than indexed into.
    #[test]
    fn a_truncated_frame_is_refused() {
        let (mut sender, mut receiver) = pair(1);
        let protected = sender.protect(b"hello").expect("protect");

        for len in 0..MIN_HEADER_LEN {
            assert_eq!(
                receiver.unprotect(&protected[..len]),
                Err(MediaError::Truncated)
            );
        }

        // And a header claiming more counter bytes than the frame holds.
        assert_eq!(
            receiver.unprotect(&[0b1110_0001, 1, 2]),
            Err(MediaError::Truncated)
        );
    }

    #[test]
    fn a_frame_survives_being_padded() {
        for pad_to in [None, Some(0usize), Some(1), Some(200), Some(1000)] {
            let (mut sender, mut receiver) = pair(1);
            sender.pad_to(pad_to);

            for len in [0usize, 1, 60, 199] {
                let frame: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let protected = sender.protect(&frame).expect("protect");
                assert_eq!(
                    receiver.unprotect(&protected).expect("unprotect"),
                    frame,
                    "a {len} byte frame padded to {pad_to:?} did not come back"
                );
            }
        }
    }

    /// A frame ending in the marker byte, or in zeros, must still come back
    /// whole. This is what an ambiguous padding scheme gets wrong.
    #[test]
    fn a_frame_that_looks_like_padding_still_comes_back() {
        let (mut sender, mut receiver) = pair(1);
        sender.pad_to(Some(200));

        for frame in [
            vec![0x80u8],
            vec![0x00u8; 40],
            vec![0x80u8; 40],
            [vec![7u8; 10], vec![0u8; 30]].concat(),
            [vec![7u8; 10], vec![0x80u8], vec![0u8; 5]].concat(),
        ] {
            let protected = sender.protect(&frame).expect("protect");
            assert_eq!(
                receiver.unprotect(&protected).expect("unprotect"),
                frame,
                "a frame that ends like padding was truncated"
            );
        }
    }

    /// The property padding exists for.
    ///
    /// A forwarding unit sees the size of every datagram it routes and nothing
    /// else. Speech is not a constant bit rate, so without this those sizes are
    /// who is talking and when. This is the check that they stop being.
    #[test]
    fn a_forwarder_cannot_tell_speech_from_silence_by_size() {
        let (mut sender, _) = pair(1);
        sender.pad_to(Some(200));

        // What the codec produces for a vowel, for a consonant, and for a room
        // with nobody in it.
        let speech = vec![9u8; 120];
        let quiet = vec![3u8; 24];
        let nothing = vec![];

        let sizes: Vec<usize> = [speech, quiet, nothing]
            .iter()
            .map(|f| sender.protect(f).expect("protect").len())
            .collect();

        assert_eq!(
            sizes.iter().collect::<std::collections::HashSet<_>>().len(),
            1,
            "the datagrams came out at {sizes:?}, so their sizes still say who is speaking"
        );
    }

    /// And with it off, they do say. Stated as a test so the cost of turning it
    /// on is not mistaken for the cost of having it at all.
    #[test]
    fn without_padding_the_sizes_say_everything() {
        let (mut sender, _) = pair(1);

        let loud = sender.protect(&vec![9u8; 120]).expect("protect").len();
        let quiet = sender.protect(&vec![3u8; 24]).expect("protect").len();
        assert!(
            loud > quiet,
            "this test no longer measures what it claims to"
        );
    }

    /// The overhead is what a call pays on every frame, so it is measured
    /// rather than assumed.
    #[test]
    fn the_overhead_is_what_we_think_it_is() {
        let (mut sender, _) = pair(1);

        // A 20 ms Opus frame at 32 kbit/s is about 80 bytes.
        let frame = vec![0u8; 80];
        let protected = sender.protect(&frame).expect("protect");

        let overhead = protected.len() - frame.len();
        assert_eq!(
            overhead,
            2 + 16 + PAD_MARKER_LEN,
            "1 config byte, 1 counter byte, 16 byte tag, 1 padding marker"
        );
        assert_eq!(overhead, 19);

        // The marker is written on every frame whether or not anything is
        // padded, so that a receiver has one rule and no flag has to travel in
        // the clear saying which frames were padded. That flag would have been
        // most of what the padding was hiding.

        // And it grows only as the counter does. At fifty frames a second these
        // are the whole life of a call.
        for (counter, expected) in [(0u64, 19usize), (255, 19), (256, 20), (65_536, 21), (1 << 24, 22)] {
            sender.counter = counter;
            let protected = sender.protect(&frame).expect("protect");
            assert_eq!(
                protected.len() - frame.len(),
                expected,
                "counter {counter} produced the wrong overhead"
            );
        }

        // 18 bytes on 80 is 22%, down from 31% when the counter was a fixed
        // eight bytes. The remaining sixteen are the authentication tag. SFrame
        // permits truncating it to eight, which would take this to 14%, and
        // that needs an AEAD whose tag length is configurable:
        // ChaCha20-Poly1305 fixes it at sixteen. Recorded so the number is
        // known rather than discovered on somebody's metered connection.
    }
}
