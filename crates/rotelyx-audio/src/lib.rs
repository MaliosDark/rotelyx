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

pub mod align;
pub mod device;

pub mod denoise;
pub mod echo;
pub mod pace;

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder, LayeredFrame};
use rotelyx_codec::mdct::{FRAME, SAMPLE_RATE, WINDOW};

use rotelyx_media::jitter::Playout;
use rotelyx_media::transport::{MediaIn, MediaOut};
use rotelyx_media::{CallBinding, SenderKeys};

/// Re-exported because every caller of [`Call::start`] has to name one, and
/// making them all depend on the media crate to do it is friction that ends in
/// somebody finding a way around the argument.
pub use rotelyx_media::CallBinding as Binding;
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
    /// One decoder per sender, kept beside that sender's receiver.
    ///
    /// # Why it cannot be shared
    ///
    /// A decoder carries state that belongs to one stream: half of every window
    /// is the tail of the previous one, waiting to be added to the next, and
    /// the band energies it holds for concealment are the last thing *that*
    /// voice said. Two people speaking through one decoder each get half of the
    /// other's tail folded into their own output, and a gap in one is concealed
    /// with the timbre of the other. With two participants only one of them
    /// ever sends, so nothing showed; with three it would have sounded like
    /// interference nobody could place.
    decoders: HashMap<u8, LayeredDecoder>,
    /// One receiver per sender, because a frame is keyed per sender and a single
    /// receiver keyed with the wrong index authenticates nothing. This was got
    /// wrong once already and a loopback test did not catch it.
    inbound: HashMap<u8, MediaIn>,
    base: [u8; 32],
    /// What separates this call's keys from the last one's. Held because every
    /// receiver built later in the call has to derive from the same value.
    call: CallBinding,
    /// The encoder needs `WINDOW` samples and advances `FRAME`, so half of every
    /// window is the tail of the last one and has to be kept.
    window: Vec<f32>,
    frames_out: u64,
    frames_in: u64,
    /// When this call started, which is the clock the buffers follow jitter
    /// against. A monotonic instant rather than a wall clock: a call should not
    /// stutter because somebody's machine synchronised its time.
    started: std::time::Instant,

    /// Everyone who is speaking, added together, waiting to be played.
    ///
    /// # Why this is not just queued as it arrives
    ///
    /// The playback device takes a queue and plays it in order. Handing it one
    /// person's frame and then another's plays them one after the other, so two
    /// people talking at once come out taking turns at twice the speed and the
    /// call drifts further behind with every frame. Sound does not queue: it
    /// adds. Two voices in a room are the sum of two pressures, and that is
    /// what a mixer has to reproduce.
    ///
    /// # What this does and does not do
    ///
    /// Frames that arrive in the same tick are summed at the same position, so
    /// people talking over each other are heard over each other. A frame that
    /// arrives a tick late is summed a tick late, which is a small
    /// misalignment nobody can hear but is not the same as being right: doing
    /// it properly needs a jitter buffer for each speaker and one playout clock
    /// to hang them all on. That is the piece this is short of, and it is worth
    /// building when a call has three people in it to test with.
    mix: Vec<f32>,

    /// Decides how many bytes a frame may be, from what the link is doing.
    ///
    /// A call cannot slow down and arrive later, so congestion is invisible in
    /// the ordinary way: nothing backs up, the sender keeps producing, and what
    /// a listener hears is holes. The rate has to come down on purpose, and the
    /// layered codec is what makes that possible without renegotiating
    /// anything.
    pace: pace::Pace,

    /// Takes the room out of the voice, before the codec spends bits on it.
    ///
    /// A codec at 12 kbit/s spends its bits on whatever is loudest, which in a
    /// kitchen is the fan. Removing steady noise first gives those bits back to
    /// the person talking.
    ///
    /// After the echo canceller, not before: the canceller is trying to predict
    /// what the loudspeaker did to the microphone, and a suppressor in front of
    /// it changes the microphone in ways the loudspeaker did not, which is the
    /// one thing that makes the prediction impossible.
    denoise: denoise::Denoiser,

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
    /// `call` is the value both ends agreed on for **this** call and no other.
    /// Without it the keys would be a function of the MLS epoch alone, and two
    /// calls inside one epoch would repeat every nonce. See
    /// [`rotelyx_media::CallBinding`].
    pub fn start(base: [u8; 32], index: u8, call: CallBinding, paths: PathPolicy) -> Result<Self> {
        // Refused before a device is opened, so a user on a direct session does
        // not get a microphone light and then an error.
        if paths.permits_direct() {
            bail!(
                "this session may take a direct path, and a direct path shows the \
                 other side your address. Start both ends with --relay <url> to call"
            );
        }

        let out = MediaOut::new(paths, SenderKeys::derive(&base, index, &call))
            .context("preparing to send audio")?;

        // The devices last, so a configuration error costs nothing.
        let capture = device::Capture::open()?;
        let playback = device::Playback::open()?;

        Ok(Self {
            capture,
            playback,
            out,
            call,
            encoder: LayeredEncoder::new(BYTES_PER_FRAME),
            decoders: HashMap::new(),
            inbound: HashMap::new(),
            base,
            window: Vec::with_capacity(WINDOW),
            frames_out: 0,
            frames_in: 0,
            frames_concealed: 0,
            echo: echo::EchoCanceller::new(),
            denoise: denoise::Denoiser::new(),
            pace: pace::Pace::new(),
            mix: Vec::new(),
            started: std::time::Instant::now(),
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
    /// Hand the mixed audio to the loudspeaker.
    ///
    /// Called once a tick, after whatever arrived in that tick has been added.
    /// Everything complete goes out together, which is what makes two people
    /// talking at once sound like two people talking at once.
    fn play_mixed(&mut self) {
        if self.mix.is_empty() {
            return;
        }
        let mut out = std::mem::take(&mut self.mix);
        without_clipping(&mut out);

        // What the loudspeaker is about to play, written down when asked for.
        //
        // Counting frames says a call is delivering and says nothing about what
        // it sounds like, and the two came apart: a call decoded every frame it
        // received and a person heard noise. Nothing short of the samples
        // themselves settles that, and a person on the other end of a terminal
        // cannot listen. Off unless `ROTELYX_CALL_DUMP` names a file.
        if let Some(path) = std::env::var_os("ROTELYX_CALL_DUMP") {
            use std::io::Write as _;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let bytes: Vec<u8> = out.iter().flat_map(|s| s.to_le_bytes()).collect();
                let _ = file.write_all(&bytes);
            }
        }
        // The reference for the canceller is what the loudspeaker is about to
        // play, which is the sum rather than any one voice in it.
        self.echo.played(&out);
        self.playback.queue(&out);
    }

    pub fn send_all_ready(&mut self, conn: &rotelyx_net::Connection) -> Result<()> {
        // One slot from every speaker, on this clock, before anything is sent.
        self.play_one_slot();
        self.play_mixed();

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
            let quieter = self.denoise.process(&cleaned);
            self.window.extend_from_slice(&quieter);
        }

        // What the link will carry, and what the path will bear. Both are
        // decided *before* encoding now, because the encoder needs them: a band
        // is rebuilt as its level times its shape, and how many layers survive
        // decides the shape, so a frame trimmed after the fact carries levels
        // chosen for stages nobody receives.
        //
        // The first is a hard limit: a datagram larger than the path allows is
        // not sent at all. The second is a choice, taken from the loss and the
        // round trip the transport already tracks, and it is the one that stops
        // a call punching holes in itself on a link that cannot hold it.
        let stats = conn.stats();
        let allowed = self
            .pace
            .observe(stats.lost_packets, conn.rtt(rotelyx_net::PathId::ZERO));
        let budget = self
            .out
            .payload_budget(conn.max_datagram_size().unwrap_or(1200))
            .min(allowed);

        let frame = self
            .encoder
            .encode_within(&self.window[..WINDOW], budget)
            .context("encoding")?;

        // Half the window is the next window's history.
        self.window.drain(..FRAME);

        let datagram = self
            .out
            .frame(&frame.to_bytes())
            .context("protecting the frame")?;

        // Dropped rather than queued when the connection is congested. A late
        // voice frame is worth nothing, and waiting for it delays every frame
        // behind it.
        if conn.send_datagram(datagram.into()).is_ok() {
            self.frames_out += 1;
        }
        Ok(true)
    }

    /// Authenticate one datagram and put it in this speaker's buffer.
    ///
    /// # Why it is not played here
    ///
    /// It used to be: decode on arrival and hand the result to the loudspeaker.
    /// That plays audio on the network's clock rather than the device's, so
    /// every wobble in arrival time is a wobble somebody hears, and two people
    /// speaking arrive interleaved and come out interleaved.
    ///
    /// `MediaIn` has carried a jitter buffer for exactly this the whole time,
    /// and said so: `frame` is documented as being for tests and for a caller
    /// doing its own buffering, and a real call using `accept` and `play`. The
    /// call was using `frame`.
    pub fn receive_one(&mut self, datagram: &[u8]) {
        // Which sender, from the header, before any key is used.
        let Ok(sender) = rotelyx_media::claimed_sender(datagram) else {
            return;
        };

        let inbound = self.inbound.entry(sender).or_insert_with(|| {
            MediaIn::new(
                PathPolicy::RelayOnly,
                // The same binding this call was started with. A receiver built
                // from a different one hears nothing, which is the point.
                SenderKeys::derive(&self.base, sender, &self.call),
            )
            .expect("RelayOnly is the policy this call refused to start without")
        });

        // Arrival time on the local clock, which is what the buffer follows the
        // network's jitter with.
        let now_ms = self.started.elapsed().as_millis() as u64;
        inbound.accept(datagram, now_ms);
    }

    /// Take one slot from every speaker, mix them, and hand the sum over.
    ///
    /// Called once a tick, which is the playout clock: one clock for everybody,
    /// so people talking at once are heard at once and a frame that arrived
    /// early waits for its slot rather than jumping the queue.
    fn play_one_slot(&mut self) {
        let senders: Vec<u8> = self.inbound.keys().copied().collect();
        for sender in senders {
            let Some(inbound) = self.inbound.get_mut(&sender) else {
                continue;
            };
            let decoder = self
                .decoders
                .entry(sender)
                .or_insert_with(|| LayeredDecoder::new(BYTES_PER_FRAME));

            let audio = match inbound.play() {
                Playout::Frame(payload) => {
                    // The authenticated payload, exactly as it arrived, so the
                    // same bytes can be decoded again away from the call. A
                    // frame that authenticates and turns into noise is either
                    // these bytes or this decoder, and nothing but replaying
                    // them separates the two. Off unless asked for.
                    if let Some(path) = std::env::var_os("ROTELYX_FRAME_DUMP") {
                        use std::io::Write as _;

                        // One file per speaker. Written to a single file first,
                        // and two calls in one process then interleaved their
                        // records and made the recording unreadable: the control
                        // that was meant to prove the instrument works read 7
                        // frames out of 59 kilobytes. An instrument that lies
                        // this way is worse than none.
                        let mut path = path;
                        path.push(format!(".{sender}"));

                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                        {
                            let _ = file.write_all(&(payload.len() as u32).to_le_bytes());
                            let _ = file.write_all(&payload);
                        }
                    }

                    match LayeredFrame::from_bytes(&payload) {
                        Ok(parsed) => match decoder.decode(&parsed) {
                            Ok(audio) => {
                                self.frames_in += 1;
                                audio
                            }
                            // Authenticated and undecodable is not a gap in the
                            // network, it is a frame this decoder cannot use.
                            // Concealing it keeps the voice continuous rather than
                            // punching a hole for a fault on this side.
                            Err(_) => {
                                self.frames_concealed += 1;
                                decoder.conceal()
                            }
                        },
                        Err(_) => {
                            self.frames_concealed += 1;
                            decoder.conceal()
                        }
                    }
                }
                // The frame did not arrive in time for its slot. This is the
                // case the concealment exists for, and the buffer reporting it
                // as a slot rather than as an error is what makes it usable.
                Playout::Missing => {
                    self.frames_concealed += 1;
                    decoder.conceal()
                }
                // Nothing buffered at all, or a slot being held for a frame
                // still expected. Neither is a gap in speech: one is silence at
                // the far end and the other is the buffer doing its job.
                Playout::Starved | Playout::Waiting => continue,
            };

            add_into(&mut self.mix, 0, &audio);
        }
    }
}

/// Add samples into a mix at an offset, growing it as needed.
///
/// Sound adds. Two people speaking at once are the sum of two pressures, not
/// one queued behind the other, and a mixer that appends plays them in turn at
/// twice the speed.
fn add_into(mix: &mut Vec<f32>, at: usize, samples: &[f32]) {
    if mix.len() < at + samples.len() {
        mix.resize(at + samples.len(), 0.0);
    }
    for (slot, s) in mix[at..].iter_mut().zip(samples) {
        *slot += s;
    }
}

/// Keep a sum of voices inside what a loudspeaker can carry.
///
/// # Why not simply divide by the number of speakers
///
/// Because most of them are silent most of the time. Dividing by four in a call
/// of four makes one person talking a quarter as loud as the same person in a
/// call of two, so the volume drops every time somebody joins. Clipping only
/// when it would actually clip leaves an ordinary conversation untouched and
/// catches the moment everybody shouts at once.
fn without_clipping(mix: &mut [f32]) {
    let peak = mix.iter().fold(0.0f32, |m, s| m.max(s.abs()));
    if peak > 1.0 {
        let k = 1.0 / peak;
        for s in mix.iter_mut() {
            *s *= k;
        }
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

    /// What this call has decided the link will bear, in kbit/s. Falls when the
    /// path starts queueing or losing and climbs back when it stops.
    pub fn target_kbit_per_second(&self) -> usize {
        self.pace.kbit_per_second()
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

#[cfg(test)]
mod mixing_tests {
    use super::{add_into, without_clipping};

    /// Two people talking at once must be heard at once.
    ///
    /// # The failure this catches
    ///
    /// The playback device takes a queue and plays it in order, so handing it
    /// one person's frame and then another's plays them one after the other.
    /// Two people talking over each other came out taking turns at twice the
    /// speed, and the call fell a frame further behind every time it happened.
    /// Sound adds; it does not queue.
    #[test]
    fn two_speakers_are_summed_not_queued() {
        let mut mix = Vec::new();
        let alice = vec![0.3f32; 960];
        let bob = vec![-0.1f32; 960];

        add_into(&mut mix, 0, &alice);
        add_into(&mut mix, 0, &bob);

        assert_eq!(
            mix.len(),
            960,
            "two speakers took twice as long instead of sharing the time"
        );
        for s in &mix {
            assert!((s - 0.2).abs() < 1e-6, "the two voices were not added: {s}");
        }
    }

    /// A speaker who starts later is placed later, not at the front.
    #[test]
    fn a_later_frame_lands_where_it_belongs() {
        let mut mix = vec![0.0f32; 480];
        add_into(&mut mix, 480, &vec![0.5f32; 480]);
        assert_eq!(mix.len(), 960);
        assert_eq!(mix[0], 0.0);
        assert_eq!(mix[959], 0.5);
    }

    /// Everybody shouting at once must not come out as distortion.
    #[test]
    fn a_loud_sum_is_brought_back_rather_than_clipped() {
        let mut mix = vec![0.4f32; 100];
        add_into(&mut mix, 0, &vec![0.4f32; 100]);
        add_into(&mut mix, 0, &vec![0.4f32; 100]);
        assert!(mix[0] > 1.0, "the test needs a sum that would clip");

        without_clipping(&mut mix);
        assert!(
            mix.iter().all(|s| s.abs() <= 1.0 + 1e-6),
            "the mix was left above what a loudspeaker can carry"
        );
        assert!((mix[0] - 1.0).abs() < 1e-6, "it was brought back too far");
    }

    /// An ordinary conversation must not be turned down.
    ///
    /// Dividing by the number of participants is the obvious way to avoid
    /// clipping and it makes one person talking quieter every time somebody
    /// else joins, whether or not they say anything.
    #[test]
    fn a_conversation_that_does_not_clip_is_left_alone() {
        let mut mix = vec![0.3f32, -0.45, 0.1, 0.0];
        let before = mix.clone();
        without_clipping(&mut mix);
        assert_eq!(mix, before, "a quiet mix was turned down for no reason");
    }
}
