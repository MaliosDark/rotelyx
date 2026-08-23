# Telyx, the voice codec

Rotelyx carries voice with its own codec rather than Opus. This is why, what it
costs, and what it is measured at.

## Why not Opus

Two things make Rotelyx's voice channel different from every other messenger's,
and both follow from one decision: **delay is spendable**.

### Fidelity mode

Every real-time media stack optimises latency and accepts loss, because a
telephone call needs it. Rotelyx offers that, and offers the opposite.

In fidelity mode the buffer runs seconds deep, missing frames are asked for
again rather than concealed, and a playback slot waits rather than producing a
gap. Measured with the retransmissions dropping at the same rate as the
originals:

| packets lost | frames lost | worst delay |
|---|---|---|
| 10% | none | 1980 ms |
| 30% | none | 1980 ms |
| 50% | none | 1980 ms |
| 70% | none | 1980 ms |
| 80% | none | 2040 ms |
| 90% | none | 2200 ms |
| 95% | none | 2380 ms |
| 98% | none | 3989 ms |

**Loss costs delay and never costs words.** With one packet in fifty getting
through, every frame still arrives, four seconds late.

Getting there needed one fix that only appeared above one packet in two. A
receiver knows a frame is missing because it can see the gap, and it cannot see
a gap *before the first frame it ever received*: nothing tells it those frames
existed. So the start of a call, everything lost before anything got through,
was never requested by anybody. It cost the first 260 ms on every run at 80%
loss, no amount of recovery time helped because the request was never made, and
it was invisible at every rate up to a half. The sender now reports the earliest
counter it can still supply, and the receiver reaches back to it.

A deep buffer is time, and time is enough round trips to get back what the
network threw away. Nobody else builds this because nobody else starts from
"delay does not matter".

### Calls are never on a direct path

Messages prefer any direct path over any relayed one, because a relay learns who
talks to whom and the alternative exposure is to an operator.

**Calls invert that.** On a direct path the other party learns your address, and
in a group call every participant does. So `PathPolicy::RelayOnly` never selects
a direct path whatever is on offer, and a media session refuses to be built on
any policy that permits one. There is no switch.

### Telyx

Opus is excellent and is not going to be beaten at its own objective, which is
quality per bit under a hard twenty millisecond latency budget. That budget is
the constraint its whole design bends around: short windows, no lookahead, and
loss concealment inside the codec because the transport cannot recover anything
in time.

Our channel has none of the three. Telyx is the codec that constraint produces:
a 40 ms MDCT window, Bark-spaced bands, energy and shape coded separately, and
PVQ for the shape.

| kbit/s | SNR |
|---|---|
| 6 | refused: the band energies alone need 18 bytes |
| 8 | 2.7 dB |
| 12 | 12.8 dB |
| 16 | 20.2 dB |
| 24 | 28.2 dB |
| 32 and above | 29.2 dB |

All of it on **one synthetic signal**: twelve harmonics with vibrato, a formant
and an amplitude envelope. On actual speech the same codec at the same rates
scores roughly half as many decibels:

| clip | 12 kbit/s | 16 kbit/s | 24 kbit/s |
|---|---|---|---|
| digits | 7.3 dB | 9.9 dB | 12.4 dB |
| fricatives | 8.4 dB | 10.4 dB | 11.7 dB |
| nasals | 14.5 dB | 17.6 dB | 21.1 dB |
| plosives | 10.5 dB | 13.8 dB | 17.8 dB |
| sibilants | 10.6 dB | 13.3 dB | 16.1 dB |
| transients | 7.7 dB | 10.8 dB | 14.1 dB |
| *synthetic vowel* | *12.8 dB* | *20.2 dB* | *28.2 dB* |

Six clips of neural text-to-speech at 22.05 kHz, resampled to 48 kHz: synthetic,
but with the structure of speech rather than an imitation of its spectrum.

The cause is not the resampling. **No bits at all are spent above 11 kHz**, so
the empty top half costs nothing. It is that the synthetic signal keeps 13 of
the 24 bands awake and speech keeps 21: the same sixty bytes spread over 21
bands instead of 13. The codec had been tuned, measured and reported against a
signal materially easier than the one it exists for.

**But the single figure is the wrong way to read it**, and breaking it down by
band says why. At 24 kbit/s:

| region | bits/coefficient | SNR | share of all error |
|---|---|---|---|
| 0-800 Hz | 2.5 to 4.3 | 25 to 29 dB | 3.4% |
| 800 Hz - 3 kHz | 1.2 to 2.4 | 8.6 to 21.6 dB | 10.8% |
| 3 - 12 kHz | 0.01 to 0.78 | -2.5 to 5.3 dB | **85.7%** |

Speech keeps about 79 percent of its energy below 800 Hz, and there the codec
reaches 25 to 29 dB. The 3 to 12 kHz region holds under one percent of the
energy, is deliberately given almost no bits, and produces 86 percent of the
error the single number reports. So that number is largely a measurement of the
bands the codec has chosen to starve, weighted as though they mattered as much
as the ones carrying the voice.

That does not make the codec good. It makes signal to noise the wrong
instrument, which is the same conclusion the fricative reached from the other
direction. Whether starving 3 to 12 kHz is the right decision is a question
about hearing, and no measurement here can answer it. Retuning the allocator
against SNR would be worse than useless: the energy is all at the bottom, so the
optimiser would strip the top of the spectrum, raise the number, and sound more
muffled.

Encoding and decoding together cost 1.2% of real time on one core. That number
is new, and until it existed none of the others meant much: the transform was
written from its definition, which is O(n²), and cost **270% of real time by
itself**. Every quality figure recorded before that was fixed was measured
offline on a codec that could not have carried a conversation. Factored through
an FFT the transform is 540 times faster and, because an FFT accumulates in a
tree rather than a line of 1920 additions, 775 times more accurate.

**Nobody has listened to it.** Every number above is objective, codec quality is
not, and no comparison with any other codec may be made until a listening test
has happened. Opus's decade of advantage is precisely that tuning.

### Running the listening test

```sh
cargo run --release -p rotelyx-codec --example bake_listening_test
scripts/listen                 # one clip, eight versions, random order
scripts/listen --reveal        # scores, with the mapping
```

Eight versions of each clip: the untouched original, Telyx at 12/16/24 kbit/s,
Opus at the same three rates, and the original low-passed at 3.5 kHz. All
trimmed to the same length and named with a meaningless six letter tag, so a
listener has nothing to go on but the sound. The mapping is in `key.txt` and the
whole exercise is worthless if it is read first.

Two of the eight test the listener rather than the codec. The hidden original
should score near 100; if it does not, that session's data is not usable. The
3.5 kHz version is roughly what a telephone sounds like, which gives the bottom
of the scale a meaning everybody shares. The rating scale is MUSHRA's, so the
numbers can be compared with published tests of other codecs.

### What happened when it was given sounds it had never been given

Every figure in this project had been measured on one sustained vowel. Speech is
not made of sustained vowels, so the codec was given the things it had never
seen: a plosive, a fricative, and an onset after silence.

| signal | 12 kbit/s | 24 kbit/s |
|---|---|---|
| sustained vowel | 11.9 dB | 24.0 dB |
| voiced onset | 12.7 dB | 23.9 dB |
| fricative /s/ | -2.7 dB | -1.9 dB |
| plosive /t/ | -2.8 dB | -1.8 dB |

The negative numbers are **not** straightforwardly a failure, and that is the
first useful thing the exercise produced. A fricative is noise: the codec
reproduces its spectrum and not its waveform, and two different noises with
identical spectra sound the same and score about 0 dB against each other. Which
is a demonstration, from our own codec, of why no SNR comparison against Opus
would mean anything.

Three real defects did fall out, none of which any existing test could see:

**The noise fill was not noise.** A band with no bits gets an invented texture,
and that texture was a hash of the coefficient index and nothing else, so it was
the *same pattern in every frame, for ever*. A decoded fricative correlated with
itself one frame later at **+0.991**, against +0.008 for the noise going in.
That is not a hiss, it is a tone at the frame rate, and 48000/960 is 50 Hz. An
/s/ came out as a buzz. Signal to noise cannot see this, the level is right
throughout, and every round trip test passed either way. Now seeded from the
decoder's frame counter: +0.010.

**A rate too low to carry the envelope was delivered rather than refused.** The
encoder finished a frame with `resize(bytes_per_frame, 0)`, which pads and also
truncates, and the truncating case had never been considered. At 15 bytes a
frame the band energies alone need 18, so the last bands were cut off, read back
out of the zero padding, and the whole frame decoded 6 dB quiet. Silently. It
had been published as the 6 kbit/s row of the table above.

**Pre-echo was real, and is shaped rather than switched away.** A plosive used to
put noise 14.8 dB below itself into the silence *before* it, because a 40 ms
window spreads quantisation error over its whole length. That is the known cost
of a long window.

The usual fix is block switching: notice the transient, transform it as several
short windows. It works and it costs the whole framing, two more window shapes
for the transitions, a second band layout, and a decoder that has to agree with
the encoder about every frame's shape or the overlap-add stops reconstructing.
This codec has one hop, 20 ms, and the band tables and the pyramid quantiser are
built on it.

Temporal noise shaping reaches the same problem from the other end. A transient
in time is a smooth ridge across frequency, so linear prediction *along the
coefficients* has something to predict; code the prediction error instead, and
the decoder's synthesis filter shapes the quantisation noise by the temporal
envelope it is reconstructing. The noise lands under the burst, where the burst
masks it, rather than in front of it. One flag bit, three of order, four per tap.

| measurement | before | after |
|---|---:|---:|
| plosive, base codec | -14.8 dB | **-40.7 dB** |
| plosive, layered codec at 30 bytes a frame | -13.6 dB | **-29.3 dB** |
| plosive, layered codec at 60 bytes a frame | -13.9 dB | **-30.9 dB** |
| gaps between words, `transients_amy` | -28.4 dB | **-33.4 dB** |
| gaps between words, `fricatives_jenny` | -35.0 dB | **-38.9 dB** |

**What it costs, stated rather than buried:** 0.4 dB of signal to noise on nasals
and 0.2 dB or less on everything else. That is not free, and the trade is a
judgement about masking that the number cannot make: noise in a gap between
words is audible and noise under a plosive is not, while signal to noise counts
them the same.

The filter fires only on frames whose energy is concentrated in time, judged in
the time domain on purpose. Prediction gain across frequency was the obvious
gate and it is the wrong one: a nasal has harmonics evenly spaced in frequency,
predicts beautifully, and has no transient at all. Gating on prediction gain
cost 2.1 dB on nasals for a problem they do not have. Gating on the temporal
envelope cost 0.4.

### What the band energies cost, and what they were costing us

A band's energy was written at six bits, eighteen bytes of a sixty byte frame,
and getting that number down took four attempts. Three of them are worth having
written down because each one was wrong in a different way.

**The floor was measured wrong.** A helper in a test multiplied each symbol's
surprise by its own count instead of by the total, and reported the entropy of
the energies as under two bytes a frame. The real figure is about fifteen. Every
design decision aimed at that gap was aimed at a saving that did not exist.

**The prediction was pointed at the wrong axis.** Each band was predicted from
the same band in the previous frame, which is the obvious design. What moves
fastest in a voice is the overall level, and 20 ms is long enough for it to move
a great deal; what barely moves is the shape of the spectrum. Predicting each
band from the band below it, inside the same frame, went from 15.4 to 12.9 bytes
a frame, and made every frame independent of every other into the bargain.

**The coder was flushed fifty times a second.** An arithmetic coder must be
closed before its output can be read, and closing costs four to six bytes
whatever it carries. Batching ten frames into one stream pays it once. That is
`rotelyx-codec::grouped`, and it costs 200 ms of latency, which is exactly the
kind of thing this channel has to spend.

**The energy step was the ceiling all along.** The codec saturated at 26.3 dB
however many bits it was given, and nobody had asked why. A 1.5 dB quantiser has
an rms error of 0.43 dB, and 0.43 dB of gain error predicts 25.9 dB of SNR. Every
bit above 24 kbit/s was refining a shape that was then multiplied by the wrong
number. The step is now chosen from the frame size, which both sides already
know, so it costs nothing to signal: coarse where the envelope would crowd out
the shapes, fine where the envelope is what limits us.

### The band was always slightly too loud, and fixing it cost nothing

The encoder measured a band's energy and rounded it to the nearest level on the
grid. That is the right answer to "how loud was this band". The decoder does not
ask that question: it rebuilds the band as *level times shape*, where the shape
is whatever the pyramid quantiser managed. So the question that decides what is
heard is "which level, times **this** shape, lands closest to the coefficients",
and the two have different answers, because the pyramid's shape is not the
direction the energy was measured along.

The error is a parabola in the gain with its minimum at the projection
`<x, s> / <s, s>`, and the measured energy sits above that whenever the shape is
imperfect. Which is always. So every band came out a little too loud, always in
the same direction.

**The fix is free, and the reason is worth knowing.** The pyramid codes
direction, and every search normalises before it starts, so a band's shape bits
do not depend on its level at all. Only the bit allocation does. So a level can
move at no cost whenever the allocation does not follow it: propose the best
level, keep it only if the split of bits across bands comes out identical. No
extra bits, no second search, and it cannot make a frame worse, because a change
that does not reduce the error is not taken.

| bytes a frame | nearest the energy | what ships | the unreachable ideal |
|---|---:|---:|---:|
| 20 | 8.45 dB | 8.85 dB | 9.01 dB |
| 30 | 14.07 dB | 14.39 dB | 14.74 dB |
| 60 | 26.26 dB | 26.32 dB | 26.77 dB |
| 120 | 28.23 dB | 28.23 dB | 28.95 dB |

Those are per funded band. End to end on the recorded speech it is 0.1 to 0.3 dB
and never negative, which is a small number and is stated as one: full-band error
is dominated by the bands that got no bits at all, and this cannot help those.

The gain grows as the rate falls, for the reason the table's shape suggests: a
starved band gets a cruder shape, and a cruder shape projects further from the
energy that was measured.

**The layered codec gets it too, and the trim moved inside to make that
possible.** It rests on the encoder knowing the shape the decoder will hold, and
it did not: `encode` produced every layer and the caller trimmed afterwards with
`frame.within(budget)`, against a budget taken from live congestion. The best
level given four layers is not the best level given one, so the choice was being
made against a frame nobody would receive. `encode_within` takes the budget,
trims the layers itself, and then chooses the levels against the stages that
survived.

One difference from the base codec is worth writing down, because it decided
whether any of this was worth having. There the level section is a fixed number
of bits, so a level moves or it does not. Here the energies are arithmetic
coded, and their coded *length* sets the budget the plan is computed against, so
a single band moving usually changes the length of the whole stream. Proposing
every band at once was refused four times in five, 2938 frames of 3552. Tried
one band at a time, what one band spoils no longer costs the other twenty three,
and the result is better in fourteen of eighteen clip-and-rate combinations,
unchanged in four, and worse in none.

It costs 2.4% of real time against the base codec's 1.9%, where the bar is 25%.

### What the military vocoders had to teach us

MELP, MELPe (STANAG 4591) and Codec 2 run at 600 to 2400 bit/s, an order of
magnitude below Telyx, and most of their machinery does not cross: they are
parametric vocoders that resynthesise speech from pitch, voicing and an LPC
envelope, where Telyx codes a transform of the waveform. Mixed excitation,
bandpass voicing, pulse dispersion and aperiodic jitter all act on an excitation
signal Telyx does not have.

Two things did cross, and both arrived as confirmation rather than as news:

- **MELPe at 600 bit/s groups four frames into a superframe and quantises them
  jointly**, for the same reason `grouped` batches ten. Independently reaching a
  design that a NATO standard reached is not proof it is right, but it is a good
  deal better than reaching it alone.
- **Codec 2 700C delta-codes its mel-spaced spectral envelope along frequency**,
  and deliberately avoids differential coding in time so that a bit error cannot
  propagate. That is the predictor above and the second reason for it, which we
  had not thought of.

One thing did not cross and should have been tried anyway: Codec 2 found 6 dB
envelope steps cost it very little. They cost Telyx 13.7 dB of SNR, because a
vocoder resynthesises from the envelope while Telyx multiplies its coefficients
by it, so an envelope error is a gain error on the output. Worth measuring,
worth not assuming.

Still unexplored from that quarter: MELPe's noise pre-processor, built for
battlefield noise and relevant to anyone on a phone in a loud room, and the
analysis-by-synthesis idea from CELP, which picks the quantiser index that
minimises perceptual error rather than the one nearest in the parameter domain.
Telyx's residual quantiser currently does the latter.

### Layers

A frame is a base plus three refinements, each optional and each improving on
the last. One encode serves every rate: a listener on a poor link is sent the
base and stops, the same recording sent elsewhere carries every layer, and
nothing is re-encoded or stored twice.

This is worthless on a telephone call, where a refinement arriving after its
frame has played is discarded. On a channel that already spends delay and
recovers loss, a refinement that arrives late is a refinement that arrives.

The layers now cross the transport. A frame serialises with a byte of layer
count and a length for each layer but the last, so the sender trims to whatever
the link will carry before it protects the frame, and a second listener on a
worse connection costs no second encode. The whole path is tested end to end:
encode, trim, protect, cross a wire, authenticate, parse, decode.

They do **not** get a datagram each, and that was costed rather than assumed.
Every datagram carries its own sixteen byte tag, and on frames this small the
tag is most of the packet:

| stream | one datagram | one datagram per layer |
|---|---|---|
| 12 kbit/s | 19.6 kbit/s on the wire | 42.4 |
| 16 kbit/s | 23.6 | 46.4 |
| 24 kbit/s | 31.6 | 54.4 |

Splitting a 24 kbit/s stream four ways costs more bandwidth than the stream
carries.

**Trimming currently saves about a tenth**, and the reason is worth stating
plainly rather than leaving as a disappointment: the base layer is 86 percent of
a frame, so dropping every refinement can save at most fourteen percent, and 44
percent of the base is the energy envelope. The mechanism is built and correct
and the payoff waits on a smaller base. Coding the energies across a group of
frames gets them from 20.3 bytes to 12.4, but it costs 200 ms of batching, which
the mailbox can spend and a call cannot.

What is not built: block switching, which temporal noise shaping made a smaller
question rather than an answered one; device capture; and a trained vector
quantiser for the envelope, which is the largest remaining saving and needs a
speech corpus. Echo cancellation and noise suppression were on this list and are
in `rotelyx-audio` now, at 38.3 dB of echo removed and 8 dB off a steady room.

**Long term prediction was built and taken out again**, and it is the most
useful thing on this list to have written down.

The measurement that justified it predicted each window from the genuinely
delayed signal: a median gain of 1.8 to 5.4 dB across the recorded speech, 60 to
87 percent of frames over a decibel. It was unreachable. With a 20 ms hop,
everything reconstructed ends where the current window begins, so predicting
1920 samples at a pitch lag of 120 to 600 reads samples from after that point,
and no decoder has them.

What is available is the last `lag` samples repeated, which is what a periodic
signal's continuation is, and on the same speech it is worth **0.3 to 1.0 dB**
against fourteen bits of lag and gain.

It was built before that was understood, closed loop, with a decoder inside the
encoder so both ends predicted from the same reconstruction. The plumbing was
right: disabling the predictor returned every number exactly to baseline. It
still made every clip worse at every rate by 0.6 to 3.0 dB, and raising the gate
to fire only on frames with 6 dB of gain walked the loss back towards zero and
never past it.

The second reason is the one worth keeping. Subtracting the periodic part
flattens the spectrum, and band energies plus normalised shapes are efficient
*because* a speech spectrum is peaky. This codec pays twice for the same idea:
once in bits for the prediction, and again in a residual its quantiser is worse
at coding. It is the same mechanism that made temporal noise shaping cost 2.1 dB
on nasals until it was gated on the time domain rather than on prediction gain.

---

## Two people listened, and the test was the thing that failed

Every number above is signal to noise, and signal to noise does not say whether
a codec sounds good. On 20 and 21 August 2026 two listeners rated the same three
clips blind and in random order against the untouched original.

**The rating scale was never shown to either of them.** It lived in a comment at
the top of `scripts/listen`, which a listener has no reason to open. What the
script printed was "Rate 0-100", with no statement of what the number meant, so
each listener privately decided what they were judging.

The second listener says they rated on intelligibility and absence of noise, and
gave 95 to versions that sounded robotic but remained fully understandable. On
the MUSHRA scale the script claims to use, audibly robotic is 60 to 40. Speech
stays intelligible long after it stops sounding like the speaker, so rating that
way puts everything near the top and separates nothing: their lowest score of
twelve was 87.

| rate | listener A | listener B |
|---|---:|---:|
| reference | 100.0 | 100.0 |
| 24 kbit/s | 93.3 | 96.7 |
| 16 kbit/s | 88.3 | 98.3 |
| 12 kbit/s | 83.3 | 90.7 |

**These are not pooled and must not be.** Two sessions rated against two
unstated scales answer different questions, and averaging them produces a number
describing neither. The measured error is unaffected and still separates the
rates cleanly: 12 kbit/s is 1855 RMS from the original, 16 is 1374, 24 is 1023.

**What survives, being scale independent.** The untouched reference was scored
100 six times out of six across two people, so neither session was an
inattentive one. And by the second listener's own criterion every rate was fully
intelligible on every clip, 12 kbit/s included. That says the words survive. It
does not say the voice does.

**What does not survive.** Any claim that one rate sounds better than another.
That was weak with one listener and is unsupported now, because the two sessions
are not measuring the same thing. Listener B also wrote the codec, which was
recorded as a caution before the session and is now the smaller of the two
problems.

The script prints the scale before every session now. A first usable measurement
needs the three clips nobody has heard, rated with it on screen, ideally by
somebody who did not write the codec.

The raw ratings are in [`listening-2026-08-20.txt`](listening-2026-08-20.txt)
and [`listening-2026-08-21.txt`](listening-2026-08-21.txt). Rebuild the files
with `cargo run --release -p rotelyx-codec --example bake_listening_test` and run
`scripts/listen --as <name>`.

## A call, end to end

The codec had no consumer for a long time. It has one now: `/call` in the
terminal client, and a Call button in the desktop window, both through
`rotelyx-audio`.

Measured between two processes through a running relay, twenty seconds each way:

| | |
|---|---:|
| frames sent | 991 |
| frames received | 944 |
| audio queued at the end | 79 ms |
| microphone dropped | 0 ms |

The first version managed 322 frames in the same twenty seconds and accumulated
360 ms of delay that never came back, because it encoded one frame per timer
tick and a late tick never fires twice to make up for it. It drains what is
ready instead.

A call refuses to start on a session that permits a direct path. That is
enforced in `rotelyx-media`, not in the caller, because a direct path is your
address handed to whoever is on the other end.
