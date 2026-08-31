# The audio numbers, measured against a room

Every figure this project publishes about echo and noise was measured against a
path this project generated. That is a fair test of the arithmetic and it cannot
be a test of the assumption, because the same person chose both.

There is a microphone and a speaker on the machine this was written on, so both
were measured again with the speaker playing into the microphone. Neither number
survived, and they failed for different reasons.

## The echo canceller

`crates/rotelyx-audio/src/echo.rs` reported **38.3 dB** of echo removed. That
number was real, reproduced on every test run, and measured under two conditions
a telephone call does not have.

This is what happens when those conditions are removed one at a time, and what
was built after seeing it.

## The ladder

Every row is the same canceller. Rows two to four are the same harness,
`crates/rotelyx-audio/examples/acoustic-echo.rs`, so they can be compared with
each other; row one uses its own and is here for where the published figure
comes from.

All of these are 24.6 seconds of the recorded speech, every clip joined so the
signal never repeats. Joining rather than repeating matters: a repeating signal
makes the correlation that finds the alignment ambiguous, and when it was tried
it reported the speaker as eighteen seconds away.

| echo path | how it is measured | linear only | with the residual stage |
|---|---|---:|---:|
| a model in this harness | continuous, white noise | 23.0 | **43.0** |
| a model in this harness | continuous, speech | 19.8 | 19.9 |
| a real room | continuous | **-0.0** | **1.3** |
| a real room | realigned and restarted every 0.5 s | 1.4 | **6.1** |

The third row is the one a call is in.

The right-hand column is what this repository does now, and the difference is
`suppress_residual`, which was written because of the left-hand one. It is worth
about **1.3 dB continuously and 4.7 dB when something keeps the canceller
aligned**, and nothing at all on the synthetic path with speech, where the linear
filter has already converged and there is little left to suppress.

`the_echo_is_removed`, the unit test, reports 58.3 dB with the residual stage
against 38.3 without. That is white noise against a room this project modelled,
which is the easiest thing an adaptive filter can be given, and it is in the
repository as a regression guard rather than as a claim about a room.

## Why speech costs seven decibels

An adaptive filter converges on the assumption that its input keeps exciting
every frequency. White noise does exactly that at every instant, which is why it
is the standard test signal and why a convergence proof assumes something like
it.

Speech does not. It is a handful of formants that move, with silences between
words where there is nothing to adapt on and the filter drifts. The same
canceller, the same room, the same code: 15.0 dB on noise and 7.9 dB on a
recorded sentence.

## Why a real room costs the rest

Measured on this machine, playing through the analogue output and recording
through the webcam microphone a short distance away:

- **The echo arrives 21.8 dB above the room's own noise**, so the ceiling on any
  canceller here is about 21.8 dB. It reached 1.1.
- **The two devices do not share a clock.** The output is an ALC889 and the input
  is a USB webcam, and their crystals differ by **341 ppm**: the recording slides
  48 samples away from the playback every 2.9 seconds. That was the first
  suspect, and it is not the answer. Measuring again on half-second windows, each
  realigned so the slide is nothing, gives 2.1, 0.4, -1.4, 2.5, 1.8 dB. Mean 1.1.
  The same as before.
- What is left is the room and the transducers: an impulse response far longer
  than the 128 ms the filter models, and a small speaker driven at half volume,
  which is not linear. A linear filter cannot cancel what a speaker added
  non-linearly, however long it runs.

## What this does not say

It does not say the canceller is wrong. The arithmetic is right and two real
bugs were found and fixed getting it to 38.3: per-partition normalisation that
diverged to **-26 dB**, and a missing gradient constraint that capped it at 19.

It says the figure was measured where the answer was easy, and that a number
without its conditions is not a measurement. The same applies to every other
figure in this repository that has not met a room: the noise suppressor's 8 dB is
next.

## The residual suppressor, and what it changed

Built after the table above was measured. The linear filter removes what a linear
model of the room can remove; a room is not linear at the ends, because the
reverberant tail runs past the 128 ms the filter covers and a small speaker
driven hard adds harmonics that were never in the signal. No filter of any length
predicts those from the input.

So a second stage estimates how much of the far end is still coming through, and
attenuates by that much. It is one gain per block rather than a spectrum: a
per-bin gain suppresses more for the same damage and needs its own transform, its
own overlap and a smoothing rule per bin to stop it warbling, and the measurement
said what was missing was *a* suppressor rather than a good one.

**The leak estimate tracks a minimum rather than an average, and that is not a
detail.** The leak is learned from what the filter leaves over, and anything the
near end says is also left over, so an average is dragged up by their voice and a
leak that is too high suppresses them. Averaging cost **92 percent of the near
end's voice** in `a_voice_on_this_end_survives_double_talk`, which is the exact
failure that test exists to catch, and it caught it.

Tracking the minimum works on the same fact the noise suppressor uses: the
quietest the residual has been recently is echo, because a voice adds and never
subtracts.

### The double-talk detector does not fire in that test

Worth knowing, because the test's own comment says freezing adaptation is what
protects the voice. The flag asks whether the residual is more than **twice** the
far end's energy, which a near-end voice clears only if it is louder than the
loudspeaker. In that test it never fires at all, so the voice was surviving for a
different reason than the comment claims.

That bar is right for deciding whether to freeze the filter, where a missed
detection costs a stale tap. It is wrong for deciding whether to suppress, where
one costs a syllable. The minimum tracking is what makes the flag unnecessary
here rather than a fix to the flag.

## The gap that is left, and three attempts to close it that failed

Running continuously the room gives 1.3 dB. Realigning and restarting the
canceller every half second gives 6.1. **Five decibels sit between those two and
nothing here closed them.**

The obvious suspect is the clocks. The loudspeaker and the microphone are
different devices with different crystals, measured 341 parts per million apart,
which is the recording sliding 16 samples away from the playback every second. An
adaptive filter converging on an impulse response that walks away from it is
chasing a target.

Three ways of following it were built and all three were removed.

**The filter's own impulse response.** If the room appears to move, and rooms do
not, what moved is the agreement between the two devices. It does not work, and
the reason is the useful part: while the filter converges its centroid **walks
steadily** towards the true delay as energy concentrates, and that walk is
monotone, so looking at it for longer does not separate it from drift. On a path
with **no drift at all** it invented -194 parts per million and followed its own
invention, taking the cancellation from 38 dB to 0.3.

**The same, requiring four observations in a row to agree.** 1.7 seconds of
agreement, on the reasoning that a settling filter wanders and two crystals do
not. It invented -76 ppm and gave 0.4 dB. A tracker whose signal is the thing it
is changing cannot be fixed by being more careful with the signal.

**Correlating the two ends directly**, decimated, independent of the filter. This
one does not invent anything: 0 ppm on the synthetic path, and about 200 ppm in
the room, which is the right order. Applying it did not help. Continuous
measurements with it on, off, and with the correction reversed came out at -1.8,
1.3 and 0.7 dB, which is inside the run-to-run spread of that measurement.

So the five decibels are real and the cause is **not established**. An earlier
version of this document said four of them were drift. That was concluded from a
four-second recording and does not survive twenty-four seconds and 46 windows.

What is left to try, in the order it looks worth trying:

1. **A delay estimate.** 128 ms of taps spent partly on buffering is 128 ms not
   spent on the room, and the bulk delay here is hundreds of milliseconds.
   Restarting the canceller is part of what the windowed measurement does, so
   some of the five decibels may be convergence rather than alignment.
2. **A spectral residual gain**, instead of one number per block. More
   suppression for the same damage.
3. **Drift again, but measured rather than tracked**: told to the canceller by
   something that already knows, rather than inferred from the audio.

## The noise suppressor

`crates/rotelyx-audio/src/denoise.rs` reports **8 dB** off a steady room,
measured against hiss this project generated, added to speech this project
synthesised.

Measured with the same harness, `examples/acoustic-denoise.rs`, which reads the
gaps between words off the **clean reference** rather than off the recording, so
a suppressor that removed the speech cannot move the boundary and flatter itself:

| noise | removed from the gaps | speech energy kept |
|---|---:|---:|
| synthetic hiss added to the clip | **12.9 dB** | 56% |
| a real room | **4.8 dB** | 58% |

Stable across runs to a tenth of a decibel.

Two things worth reading off that table.

**It removes about a third of what it removes from hiss.** Real room noise is not
white: there is a hum at the mains frequency and its harmonics, and the spectrum
is anything but flat. Exactly which part of that a minimum-statistics estimator
handles worse is not established here, and guessing would be the same mistake
this document exists to correct.

**The speech cost is the same in both, and it is not small.** 56 and 58 percent
of the speech energy left is a loss of about 2.4 dB, paid whether the noise was
worth removing or not. The test that guards this asks only that more than 30
percent survives, which allows 5.2 dB. That bound is loose enough that the
suppressor could get considerably worse without anything failing.

### A wrong guess, kept because it was wrong

The first explanation offered for the shortfall was reverberation: in a room the
gaps between words are not silent, they carry the tail of the speech that just
stopped, which is neither stationary nor noise, and a suppressor that removed it
would be removing the room's answer to the voice.

It is a good story and it is not what is happening. The gaps measure **2.6 dB
above the same room with nothing playing at all**, so they are the noise floor
with a little tail on top, not the other way round. The measurement now records
the quiet room and prints that number, because the explanation was plausible
enough to have been believed.

## Running them

### A fourth attempt, and what it found instead

The direct test of drift is whether the per-window realignment **moves**: clocks
a few hundred parts per million apart move it steadily, convergence does not
move it at all. `acoustic-echo` reports that slope now.

It came back **-2024 ppm on one run and -4210 on the next**, both from a spread
of 471 ms with a fit of 0.10. None of that is drift: two crystals 341 ppm apart
move eight milliseconds over twenty four seconds, not half a second, and a
number that doubles between runs is measuring nothing. The alignments are not on
a line. The per-window estimate is picking different correlation peaks, which is
what speech offers a half-second correlation: no sharp one to find.

**So the tool refuses to read a drift out of it.** Below a fit of 0.5 it says
the estimate is noisy and says nothing about clocks. The first version printed
"-2024 ppm, which is drift", and that sentence was wrong in the way this
document exists to catch: confident, plausible, and about the right quantity.

The order of work is settled even though the cause is not. **Sharpen the delay
estimate first.** Until a half-second window aligns to the same place twice,
nothing measured through it separates drift from convergence.

### A fifth attempt: the estimate is sharpened, and it was not the phase transform

`rotelyx_audio::align` replaces the correlation that lived beside these
examples. It moved into the crate because it is an instrument and it had no
tests, which is how it produced two confident wrong answers without anything
noticing.

**The obvious fix was tried first and it is wrong.** Speech has almost no
autocorrelation to find, so the textbook answer is GCC-PHAT: divide the cross
spectrum by its own magnitude and correlate two whitened signals instead. Full
whitening makes this **much worse**. Measured on 24.6 s of the synthesised clips
through a simulated room, against a delay of 3,120 samples:

| whitening | global estimate | error, samples |
|---|---:|---:|
| 0.00, plain correlation | 3,716 | 596 |
| 0.50 | 3,323 | 203 |
| **0.75** | **3,142** | **22** |
| 1.00, full phase transform | 95,999 | 92,879 |

Speech leaves most of a 24 kHz band empty, and dividing an empty bin by its own
magnitude promotes the noise floor in it to a full vote. Three quarters removes
enough of the room's colouring to find the direct arrival and leaves enough
magnitude weighting that the empty bins stay quiet. The constant is set from
that sweep and a test fails if it stops being the value the sweep prefers.

**No confidence measure works, and that is the more useful finding.** Two were
built and both were removed. Peak over the noise floor: under full whitening the
worst window of a run, ninety three thousand samples from the truth, scored the
**second highest of eight**. Peak over its nearest rival: at 0.75 the correct
windows span 1.07 to 2.37 and the two wrong ones both score 1.04, which is three
hundredths of separation from a wrong population of two. Two entirely unrelated
recordings also produce a delay, a respectable margin, and no sign at all that
they have nothing to do with each other.

So `Alignment` carries no `is_confident`. It reports its numbers and says in its
own documentation that none of them licenses believing the answer.

**What closes the gap is structural.** One coarse delay from the whole
recording, where there is far more evidence to take it from, and each window
allowed only to refine it inside a narrow band. Per-window spread on that speech
goes from **471 ms to 13 ms**, and the one window that still fails pins itself
to the edge of its search, which is the single thing that is detectable: a
maximum at a boundary means the correlation was still climbing when the search
ran out of room.

**And a bug found on the way.** The per-window realignment searched only forward
from the coarse delay, so a path drifting the other way clamped at zero and
reported no movement. That has the shape of an answer without being one, which
is the failure mode this whole section is about. The search is now centred on
the coarse delay rather than starting at it.

**What the clips are, said before the numbers get quoted elsewhere.** They come
from `scripts/make-speech`, which is a neural text to speech model, and that
script says plainly that nothing in them has been near a microphone or a room.
They are a model's idea of a voice. That is the right signal for this
measurement, because what defeats a correlation is the spectral shape of speech
and its stretches of near silence and a synthesiser produces both, and it is not
grounds for claiming the numbers hold for people.

**They are also not in the repository**, being 2.3 MB of regenerable binary, so
every measurement that wants them skips itself on a clean clone. The whitening
constant is therefore pinned by a test that does not run in CI. A corpus that
could ship would turn it into a real gate, which is the same open question as
the trained codebook.

**The five decibels are still open.** Nothing above re-measures them: that needs
the loudspeaker and the microphone, not a simulation. What it provides is an
alignment that repeats, which is what the previous section said had to come
first.

### Measured against the room, with the new estimator

The first run of the rebuilt estimator against the actual loudspeaker and
microphone, which is also the run that found it was broken.

**It refused, and said the microphone had heard nothing.** The recording was not
silent: an RMS of 2894 out of 32768. The estimator took the whole reference it
was handed instead of a window of it, so a 24.6 second reference against a 24.6
second recording left no lags to search at all. Ten unit tests passed through
that, because every one of them passes a short window, which is what a
per-window measurement does. The call at the top of the harness passes the whole
recording and happens only on hardware.

The window is taken inside the estimator now. With that fixed, on the same
machine and the same room:

| | Before | Now |
|---|---:|---:|
| Delay found | 3,295 ms unbounded, then 650 bounded | **650 ms**, margin 1.32 |
| Continuous cancellation | 1.3 dB | 0.7 dB |
| Realigned windows | 6.1 dB | 7.9 dB over 39 windows |
| Per-window spread | 471 ms | 100 ms, **and that number is worthless** |
| Line fit | 0.10 | 0.02 |

**The coarse delay is right, and the per-window estimate is no better than it
was.** Those are two different claims and the first version of this section made
only the first while implying the second.

The coarse delay is a real result: 650, 612 and 642 ms across three runs against
a recording whose offset is about 650, where the unbounded search used to return
3,295 and the whole-reference version refused outright.

**The 100 ms spread was the bound, not a measurement**, and one run said so:

| Search bound | Spread that came back |
|---|---:|
| plus or minus 100 ms | 100 ms |
| plus or minus 400 ms | **800 ms** |

800 ms is the entire width of a search bounded at 400 either side. The per-window
alignment fills whatever room it is given. So the improvement from 471 ms to 100
was the range shrinking from two seconds to two hundred milliseconds, and
nothing about the estimate got sharper. At 400 ms the slope reads +5,421 ppm
against a true 341, with a fit of 0.09, which is the same nothing said louder.

**That closes a line of attack rather than leaving it open.** The per-window
path cannot answer what the seven decibels are, in this form, at any bound: too
narrow and it reports the bound, too wide and it reports noise. Something other
than realigning half-second windows of speech has to produce the alignment, and
until it does, the gap between 0.7 dB continuous and 7.9 dB realigned stays
unattributed.

### Measured through the devices a call opens, the canceller makes echo worse

`scripts/measure-echo` plays with `paplay` and records with `parecord`, two
streams with clocks of their own. A call is not that: `Call::start` opens one
`Capture` and one `Playback` through `cpal` and runs them together. The bottom of
that script has carried the suspicion since it was written, that the difference
between continuous and realigned might be the two clocks and not the canceller.

`cargo run -p rotelyx-audio --example acoustic-duplex` measures the same room
through those same devices. Six runs:

| | Continuous | Realigned windows |
|---|---|---|
| Runs | -8.8, -2.6, -7.1, -3.7, -1.8, -7.0 | 7.5, 7.4, 7.9, 8.6, 8.2, 8.5 |
| Mean | **-5.2 dB** | **+8.0 dB** |

**Every continuous run is negative, and the suspicion was backwards.** Taking
both sides from the audio path a call uses does not recover the lost decibels; it
loses more of them. The two-clock harness averages -2.0 dB and the single-path
one averages -5.2.

**That looked like a finding and it was a property of the clips.** It is
written out here rather than deleted, because the correction is the useful part.

Every acoustic number in this document, and this one, was measured against six
clips from one text to speech model. Eight recorded people, truncated to the same
24.6 seconds so that only the voice differs:

| Voice | Continuous | Realigned |
|---|---:|---:|
| f1462 | +1.1 | 8.7 |
| f1673 | +0.1 | 6.4 |
| f1988 | -4.6 | 2.4 |
| f84 | -6.0 | 7.0 |
| m1272 | +2.8 | 7.0 |
| m174 | +2.2 | 7.7 |
| m251 | -3.2 | 7.9 |
| m652 | +0.2 | 4.8 |
| **Mean** | **-0.9** | **6.5** |

Against the synthesised set at the same length: **-5.2 dB, six runs, all
negative**. Against people: -0.9, four positive and four negative.

**Three things follow, and the third is the one that matters.**

The canceller does not add five decibels of echo. It is roughly break-even
continuous on real speech and the synthesised clips sit at the pessimistic end of
the distribution by about four decibels.

The duration was a confound and was tested: these clips are 49 to 102 seconds
long and were cut to 24.6 before this table, so the difference is the speaker and
not the time the filter had to converge.

And **the spread between speakers is 8.8 dB**, which is larger than any effect
this document has ever argued about. A single figure for what the canceller
removes was never a meaningful quantity. Three attempts went into explaining a
five decibel gap between two numbers, and the honest reading is that both numbers
were samples from a distribution nobody had looked at.

**What this does not say.** One machine, one room, one loudspeaker, one
microphone, and that pair is 341 ppm apart. It does not say the canceller is
right either: `f84` loses six decibels and `f1988` loses nearly five, and
whatever is happening to those two voices is real and unexplained.

**What it makes the next question.** Not "where did five decibels go". It is
what separates `m1272` at +2.8 from `f84` at -6.0, measured on the same hardware
in the same minute.

### Seven runs, and the number this document was built on does not repeat

Nobody had asked whether the two numbers being compared are reproducible. Three
attempts went into explaining the difference between them first.

Seven runs, one machine, one room, one afternoon:

| | Continuous | Realigned windows |
|---|---|---|
| Runs | +0.7, -4.6, -1.8, -1.0, -2.8, -2.3, -1.9 | 7.9, 7.7, 7.3, 6.5, 6.7, 5.9, 7.2 |
| Mean | **-2.0 dB** | **+7.0 dB** |
| Range | 5.3 dB | 2.0 dB |

**The realigned figure repeats and the continuous one does not.** Worse than
that: six of seven continuous runs are **negative**, meaning the canceller adds
echo. This document records +1.3 dB for that case and today it was not
reproduced once.

**Continuous is the production configuration.** A call runs the canceller
straight through; nothing in a call realigns half-second windows, which is a
thing this harness does and a client cannot. So the number that describes what a
user gets is the unstable, mostly negative one, and the comfortable number is
the artificial one.

**What this does not establish.** This harness plays through `paplay` and
records through `parecord`, which are two streams with independent clocks, and
production takes both sides from one audio path. That has been written at the
bottom of `scripts/measure-echo` since it was first written, as a suspicion.
It is now the next measurement rather than a note, because there is a reason to
make it: if a shared clock turns -2.0 dB into something positive, the canceller
is fine and this harness was the problem. If it does not, a call on this hardware
is worse with the canceller than without it.

**And the framing this replaces.** "Five decibels between continuous and
realigned" compared a stable measurement against an unstable one and took a
single favourable run as the baseline. The distance is about nine on today's
means, and arguing about its size was never the useful question.

### The search had no bound, and that was worth more than the gap

The estimate searched the whole recording for its peak. On a twenty-four second
clip it found one **3295 ms out, with a correlation of 0.29**, on a recording
whose real offset is about 650 ms: the harness records, waits four tenths of a
second, then plays.

Everything downstream aligned to a delay that does not exist. The canceller,
handed a reference with no relation to what the microphone heard, adapted to
noise and **added 7 dB of echo**. Bounded to two seconds it finds 650 ms at
0.58, and the same canceller removes about 7 dB instead. **Nothing in `echo.rs`
changed.**

A weak correlation is now said out loud rather than used in silence, which is
what let this sit unnoticed. Numbers in this document taken before that bound
was added are not comparable to numbers taken after it.

    scripts/measure-echo [clip]
    scripts/measure-denoise [clip]

Each plays a clip through the speaker, records the room, prints the tables above
and puts the output volume back where it found it. With no speaker attached the
correlation comes out near zero and they say so rather than reporting a number.
