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

    scripts/measure-echo [clip]
    scripts/measure-denoise [clip]

Each plays a clip through the speaker, records the room, prints the tables above
and puts the output volume back where it found it. With no speaker attached the
correlation comes out near zero and they say so rather than reporting a number.
