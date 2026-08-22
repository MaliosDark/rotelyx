//! Devices and one call in progress.
//!
//! Split out of the terminal client the moment a second program wanted it. The
//! desktop window and the terminal both make calls, and a call is the same
//! thing in both: a microphone, a codec, a key per sender, and datagrams.
//!
//! What is deliberately **not** here is anything that knows what a conversation
//! is. [`Call::start`] takes a key and a sender index that the caller has
//! already worked out, because how those are derived is the caller's business
//! and every caller does it from something different.

pub mod device;

pub mod echo;

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder, LayeredFrame};
use rotelyx_codec::mdct::{FRAME, SAMPLE_RATE, WINDOW};

use rotelyx_media::transport::{MediaIn, MediaOut};
use rotelyx_media::SenderKeys;
use rotelyx_net::PathPolicy;

/// Bytes of codec payload per 20 ms frame.
///
/// 60 is what the layered encoder is tuned around elsewhere in this repository,
/// and at 50 frames a second it is 24 kbit/s before framing. Chosen to match the
/// measurements rather than reopened here.
pub const BYTES_PER_FRAME: usize = 60;

/// A call in progress.
///
/// Everything a call needs lives here so that ending one is a `drop`: the
/// devices close, the codec state goes, and the keys are zeroed by the types
/// that hold them. A call that ends by setting a boolean tends to leave a
/// microphone open.
pub struct Call {
    capture: device::Capture,
    playback: device::Playback,
    out: MediaOut,
    encoder: LayeredEncoder,
    decoder: LayeredDecoder,
    /// One receiver per sender, because a frame is keyed per sender and a single
    /// receiver keyed with the wrong index authenticates nothing. This was got
    /// wrong once already and a loopback test did not catch it.
    inbound: HashMap<u8, MediaIn>,
    base: [u8; 32],
    /// The encoder needs `WINDOW` samples and advances `FRAME`, so half of every
    /// window is the tail of the last one and has to be kept.
    window: Vec<f32>,
    frames_out: u64,
    frames_in: u64,
    /// Takes the loudspeaker back out of the microphone.
    ///
    /// # What it is aligned against, and what that costs
    ///
    /// The filter needs to know which played sample sat under which captured
    /// one. Two devices with two clocks do not offer that, and this does not
    /// have the timestamps that would settle it, so the two streams are matched
    /// a frame at a time: whatever was queued for the loudspeaker this tick is
    /// the reference for whatever the microphone produced this tick, and
    /// silence stands in when nothing was played.
    ///
    /// A constant offset between them is exactly what an adaptive filter is
    /// for: it finds the delay itself, which is why the filter covers 128 ms
    /// rather than the few it would need if the alignment were exact. An offset
    /// that *drifts*, because the two devices run at slightly different rates,
    /// is a different matter and would need resampling against a common clock.
    /// This is the part that needs a real microphone and a real room to judge,
    /// and it has not had one.
    echo: echo::EchoCanceller,

    /// Frames invented to cover ones that never arrived. What a call quality
    /// indicator should show beside the loss rate: it is the loss somebody
    /// actually heard smoothed over.
    frames_concealed: u64,

    /// Microphone samples thrown away because the call could not keep up.
    dropped_samples: u64,
}

impl Call {
    /// Start a call, given the key material the caller has already derived.
    ///
    /// Takes a base key and a sender index rather than a group, so that the
    /// terminal client, the desktop window and anything later all reach this
    /// through whatever they already hold. Deriving those two is the caller's
    /// job because only the caller knows what a conversation is.
    pub fn start(base: [u8; 32], index: u8, paths: PathPolicy) -> Result<Self> {
        // Refused before a device is opened, so a user on a direct session does
        // not get a microphone light and then an error.
        if paths.permits_direct() {
            bail!(
                "this session may take a direct path, and a direct path shows the \
                 other side your address. Start both ends with --relay <url> to call"
            );
        }

        let out = MediaOut::new(paths, SenderKeys::derive(&base, index))
            .context("preparing to send audio")?;

        // The devices last, so a configuration error costs nothing.
        let capture = device::Capture::open()?;
        let playback = device::Playback::open()?;

        Ok(Self {
            capture,
            playback,
            out,
            encoder: LayeredEncoder::new(BYTES_PER_FRAME),
            decoder: LayeredDecoder::new(BYTES_PER_FRAME),
            inbound: HashMap::new(),
            base,
            window: Vec::with_capacity(WINDOW),
            frames_out: 0,
            frames_in: 0,
            frames_concealed: 0,
            echo: echo::EchoCanceller::new(),
            dropped_samples: 0,
        })
    }

    /// Encode and send every whole frame the microphone has ready.
    ///
    /// # Why this drains rather than sending one
    ///
    /// A tick every 20 ms and one frame per tick is exactly the right rate on
    /// paper and wrong in practice: a timer that fires late never fires twice to
    /// make up for it, so every late tick leaves 20 ms in the buffer that nothing
    /// removes. Measured on the first real call, that reached **360 ms of
    /// microphone waiting** and stayed there, which is delay the person on the
    /// other end hears for the rest of the conversation.
    ///
    /// Draining means a late tick catches up. The bound stops a pathological
    /// case from turning catching up into a stall of its own: past it the
    /// backlog is dropped rather than sent, because audio that late is worth
    /// less than the delay of sending it.
    pub fn send_all_ready(&mut self, conn: &rotelyx_net::Connection) -> Result<()> {
        /// At most this many frames in one tick. Five is 100 ms, enough to
        /// absorb an ordinary scheduling hiccup and not enough to spend a tick
        /// encoding.
        const MAX_PER_TICK: usize = 5;

        for _ in 0..MAX_PER_TICK {
            if !self.send_one(conn)? {
                return Ok(());
            }
        }

        // Still behind after draining what a tick allows: the excess is old
        // audio and keeping it only moves the delay forward.
        let keep = WINDOW + FRAME * MAX_PER_TICK;
        if self.capture.backlog() > keep {
            let dropped = self.capture.backlog() - keep;
            self.capture.discard(dropped);
            self.dropped_samples += dropped as u64;
        }
        Ok(())
    }

    /// One frame. `false` when the microphone has not produced a whole one.
    fn send_one(&mut self, conn: &rotelyx_net::Connection) -> Result<bool> {
        // Top the window up to a full one before encoding anything.
        while self.window.len() < WINDOW {
            let Some(more) = self.capture.take(FRAME) else {
                return Ok(false);
            };
            // Make up whatever the loudspeaker did not play.
            //
            // The reference is the audio queued for playback, added as it
            // arrives. When the other end is quiet none arrives, and a
            // canceller with less reference than microphone holds the
            // microphone back waiting for audio that is never coming: the call
            // would go silent in this direction whenever it went silent in the
            // other. The shortfall is silence, because that is what the
            // loudspeaker was doing. Only the shortfall: padding
            // unconditionally would put twice as much reference as microphone
            // through and align the filter against nothing.
            let deficit = more.len().saturating_sub(self.echo.reference_available());
            if deficit > 0 {
                self.echo.played(&vec![0.0f32; deficit]);
            }
            let cleaned = self.echo.capture(&more);
            self.window.extend_from_slice(&cleaned);
        }

        let frame = self
            .encoder
            .encode(&self.window[..WINDOW])
            .context("encoding")?;

        // Half the window is the next window's history.
        self.window.drain(..FRAME);

        // What the network will carry, which the transport reports rather than
        // this guessing. A frame trimmed to the budget still decodes; it just
        // decodes rougher.
        let budget = self
            .out
            .payload_budget(conn.max_datagram_size().unwrap_or(1200));
        let datagram = self
            .out
            .frame(&frame.within(budget).to_bytes())
            .context("protecting the frame")?;

        // Dropped rather than queued when the connection is congested. A late
        // voice frame is worth nothing, and waiting for it delays every frame
        // behind it.
        if conn.send_datagram(datagram.into()).is_ok() {
            self.frames_out += 1;
        }
        Ok(true)
    }

    /// Authenticate, decode and play one datagram.
    pub fn receive_one(&mut self, datagram: &[u8]) {
        // Which sender, from the header, before any key is used.
        let Ok(sender) = rotelyx_media::claimed_sender(datagram) else {
            return;
        };

        let inbound = self.inbound.entry(sender).or_insert_with(|| {
            MediaIn::new(PathPolicy::RelayOnly, SenderKeys::derive(&self.base, sender))
                .expect("RelayOnly is the policy this call refused to start without")
        });

        // `None` is a frame that failed to authenticate, was replayed, or was
        // too late. All three are the same answer: it is not played.
        let Some(payload) = inbound.frame(datagram) else {
            return;
        };
        let Ok(parsed) = LayeredFrame::from_bytes(&payload) else {
            return;
        };
        // Fill what never arrived before playing what did.
        //
        // A lost frame used to leave a hole, and a hole in the middle of a
        // vowel is heard as a click at each edge rather than as a loss. The
        // decoder carries the last frame's band energies forward as noise at
        // those levels, quieter each time, so a short gap sounds like the voice
        // continuing and a long one fades out instead of holding a note.
        //
        // Bounded, because concealment is worth having for a stumble and not
        // for an outage: past this it is a machine talking to itself, and the
        // fade has taken it to nothing anyway.
        const MOST_CONCEALED_IN_A_ROW: u64 = 8;
        let missing = inbound.skipped().min(MOST_CONCEALED_IN_A_ROW);
        for _ in 0..missing {
            let filled = self.decoder.conceal();
            self.echo.played(&filled);
            self.playback.queue(&filled);
            self.frames_concealed += 1;
        }

        let Ok(audio) = self.decoder.decode(&parsed) else {
            return;
        };

        // The reference for the canceller: what the loudspeaker is about to
        // play is what the microphone is about to hear.
        self.echo.played(&audio);
        self.playback.queue(&audio);
        self.frames_in += 1;
    }
}

/// What a call has done so far, for a caller that wants to report it.
impl Call {
    pub fn frames_sent(&self) -> u64 {
        self.frames_out
    }

    /// Frames invented to cover ones that never arrived.
    pub fn frames_concealed(&self) -> u64 {
        self.frames_concealed
    }

    /// How much of the loudspeaker is being taken back out of the microphone,
    /// in decibels. Zero means none of it: on a speakerphone that is the number
    /// that decides whether the other end can bear the call.
    pub fn echo_loss_db(&self) -> f32 {
        self.echo.loss_db()
    }

    pub fn frames_received(&self) -> u64 {
        self.frames_in
    }

    /// Whether the microphone is mono, or stereo being averaged.
    pub fn microphone_is_mono(&self) -> bool {
        self.capture.channels() == 1
    }

    /// Audio waiting to be played, in milliseconds.
    ///
    /// This is delay the listener is hearing right now. A number that keeps
    /// climbing is the call falling behind, and it is the one figure worth
    /// putting in front of a user during a call rather than after it.
    pub fn queued_ms(&self) -> usize {
        self.playback.backlog() * 1000 / SAMPLE_RATE as usize
    }

    /// Microphone audio thrown away because the call could not keep up, in
    /// milliseconds.
    pub fn dropped_ms(&self) -> usize {
        self.dropped_samples as usize * 1000 / SAMPLE_RATE as usize
    }

    /// The rate this call sends at, in kbit/s, before framing.
    pub fn kbit_per_second(&self) -> usize {
        BYTES_PER_FRAME * 50 * 8 / 1000
    }
}
