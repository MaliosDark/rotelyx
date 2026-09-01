# What is left

Only what is not done. Everything finished moved to `docs/DONE.md`, which is
where the measurements and the reasoning behind them live: this file had grown
to 2,399 lines carrying 206 finished entries around 14 open ones, and a list
nobody can read is a list nobody uses.

| Mark | Meaning |
|---|---|
| `[ ]` | Not started, or in progress |
| `[!]` | Blocked on something outside this repository |
| `[?]` | Needs a decision before work can start |


### 1. Field test across two real NATs `[!]`

- [ ] Measure hole punch success rate across NAT types. **Simulated: done**, 46
      tests in `crates/net/rotelyx-transport/tests/patchbay.rs`, NATs of every
      hardness including hard against hard, in CI. **Real networks: not done**,
      and a simulation only says the code punches through the NATs somebody
      wrote a model of.

      **The instrument is finished; what is missing is a second network.**
      `rotelyx-cli probe` prints one record per run and `scripts/measure-punching`
      turns those into a rate: it appends every run to a file so a session cut
      short is still data, counts a failed connection as a data point rather than
      stopping, and pauses between runs so a NAT's mapping table is not measured
      in the state the previous run left it.

      The two machines here are on one LAN, and **a punch between them proves
      nothing because there is no NAT between them**. A phone hotspot is the
      cheapest second network and also the best one, carrier-grade NAT being the
      hard case a simulation models worst. Deliberately not a CI job: it needs two
      networks and a person, and a gate that cannot run is not a gate

      **A second network now exists in the house**, and a call was held across
      it on 1 September 2026: two phones, four minutes, audio both ways. It
      does not close this. Calls are relay only on purpose, so no punch was
      attempted and none of it is data about NAT traversal. What it does mean
      is that the missing half is now a room away rather than a purchase, and
      `rotelyx-cli probe` is what has to be run across it
- [ ] Measure how often `PreferDirect` costs a connection that `Fastest` would
      have kept. **Not started, and deliberately behind the one above.** It
      needs the latency of both paths at the moment the choice is made, and the
      transport does not expose it: `TransportAddrInfo` carries an address and
      how it is used, and no timing. Surfacing it is transport work, and doing
      that to feed a second instrument before the first one has produced a
      single number would be building two things to measure nothing


### 2. Published test vectors for the post quantum composition

- [ ] Cross check against an independent implementation written by somebody else
      from the specification alone


### 3. Encrypted at rest storage

- [ ] Derive the sealing key from the device keystore rather than a passphrase,
      where the platform offers one. **The engine half is done and was the part
      blocking it:** `SessionKey::from_platform_key` and
      `unlock_with_platform_key` take the 32 bytes a keystore or a secure
      enclave returns, so the platform no longer has to make one up and hand it
      over as a passphrase.

      A blob sealed that way has the same shape as any other, salt included, so
      the two are not told apart on disk. Nothing is derived from that salt in
      this path; it is carried because the format has a slot and a blob with an
      empty one would announce which kind of key opened it. Nothing is
      stretched either, so **what goes in has to be a key**: anything typed is
      worth less here than it was on the passphrase path, and 32 bytes is
      enforced rather than padded.

      **And it is reachable.** The ABI had only `key.create` and `key.unlock`,
      both taking a passphrase, so the engine's new path would have been
      unusable from the one place a keystore lives. `key.fromPlatformKey` and
      `key.unlockWithPlatformKey` are in the ABI and in `docs/MOBILE.md`, which
      the parity guard checks.

      What is left is per platform and lives in the app: the Android keystore
      and the iOS enclave are interfaces neither this crate nor the engine can
      call, and the browser has no equivalent, which is why the passphrase path
      stays.

      **And the app has already decided against it, on purpose.** Read
      `lib/platform/biometrics.dart` before building this: the phone treats a
      fingerprint as a shortcut to typing the PIN and not as a replacement, and
      stores nothing to make it work. Its reasoning is written there and it is
      good: *if it were a replacement, the secret would have to live in the
      Keystore rather than in somebody's head, and then an unlocked phone would
      be a phone that opens everything.*

      So this entry and that file disagree, and the disagreement is the useful
      part. The engine half exists and should stay, because a device that is
      **only** unlocked by hardware is a real option for somebody who wants it.
      What is not settled, and is a product decision rather than an engineering
      one, is whether Rotelyx offers it at all: a conversation openable by a
      thumb on a taken phone is a different threat model from one openable only
      by something remembered.

      Nothing should be built here until that is answered, and the answer is not
      this repository's to give

### 4. Relay hardening

- [!] **`rotelyx-discovery` was marked for deletion and is staying.** The crate
      does two unrelated things: 1,011 lines of plain DNS resolution, which
      every relay client needs to resolve a hostname, and 763 lines of
      pkarr/TXT-record discovery, which is the third-party mechanism this
      project must never use. Deleting the crate breaks the transport; 14 of the
      21 references to it are the resolver. The discovery half is unreachable by
      construction: `AddressLookup` has one variant, `Disabled`, and the
      endpoint clears lookup again when it binds. Reasoning recorded in
      `crates/net/README.md` so it is not rediscovered
- [!] **A bought token links its holder's deposits to each other.** The id names
      nobody, which is not the same as linking nothing: the meter counts against
      it, so the mailbox sees a stable pseudonym with a usage history across
      every deposit made under that token. Blind issuance solves the issuer
      recognising what it signed, which is a different problem. Sealed sender
      hides the sender inside the envelope; the token is outside it. Recorded in
      ADV-4 rather than fixed, because fixing it means one token per deposit and
      that is a design decision, not a patch
- [ ] Watch the refusal counters in production. Limits chosen from reasoning
      rather than from traffic, and the first real load will say whether they
      are in the right place
- [?] Whether an open relay should require a proof of work for admission. The
      construction already exists in `rotelyx-core::access`; the question is
      whether an open relay is a configuration we want to support at all


### 5. Multi device

- [?] Which device authorises the next one, and what the user sees when it
      happens

### 6. Audio calls

- [ ] **Retuning the allocator needs ears, not SNR.** The energy is all at the
      bottom of the spectrum, so optimising signal to noise would strip the top,
      raise the number and sound more muffled. Blocked on a listening test
      rather than on effort
- [!] **What it does not support.** The spread within one rate is 13.1 and the
      largest gap between rates is 10.0, so with one listener the three rates
      are not distinguishable from each other. It says the codec is usable at
      12 kbit/s; it does not say how much better 24 is, and must not be quoted
      as though it did
- [!] **The rating scale was never shown to a listener.** It lived in a comment
      at the top of `scripts/listen`, which nobody opens to run it. What the
      script printed was "Rate 0-100" and nothing else, so each listener decided
      privately what the number meant. The second one rated intelligibility and
      gave 95 to versions they described as robotic, where the scale the script
      *claims* to use puts audibly robotic at 60 to 40. Speech stays intelligible
      long after it stops sounding like the speaker, so that criterion puts
      everything near the top: their lowest of twelve was 87. Both sessions were
      therefore rated against unstated and different scales and cannot be pooled.
      The header asserted the numbers "mean the same thing to everyone who has
      run one of these" while the script showed nobody the scale, which is the
      same failure this project keeps finding: a guarantee written down and
      nothing enforcing it. The script prints the scale now
- [!] **The second listener wrote the codec.** Recorded beside the numbers
      rather than in a footnote, because the bias is visible in them: every coded
      rate scored higher than listener A gave it, by 3.3, 10.0 and 7.3 points.
      Blind randomised order stops a listener knowing which file is which, and
      stops nothing else
- [ ] **A listener with no stake in the answer.** Two people, one of whom wrote
      the codec, is not two independent measurements. This is what the rate
      comparison is actually blocked on, and more clips will not substitute
- [ ] **Shrink the base, which is what layering is waiting on.** Trimming saves
      about a tenth today because the base is 86% of a frame and 44% of the base
      is the envelope. Grouped energy coding takes 20.3 bytes to 12.4 but needs
      200 ms of batching: wire it into the mailbox path, where the latency is
      affordable, and leave calls on the per-frame path.

      **There is no mailbox path for audio to wire it into.** `rotelyx-codec`
      is used by calls, per frame; the mailbox carries sealed text. Nothing
      stops a voice note, since an envelope holds whatever ciphertext it is
      given, and nothing builds one either. `grouped` is written, measured and
      called by nobody, and it stays that way until somebody decides voice notes
      are a feature. That is a product decision and not a piece of plumbing
- [ ] **A trained vector quantiser for the envelope**, which is the largest
      saving left. Codec 2 700C spends 18 bits on a K=20 mel-spaced envelope
      where Telyx spends about 100 on 24 bands. It needs a speech corpus and it
      ships a codebook, which is why it is not done.

      **The licence question is settled and it was the cheap half.** A codebook
      is derived from what it was trained on and it ships inside an AGPL
      repository and inside store binaries, so the corpus has to permit both.
      **Mozilla Common Voice is CC0**, which is public domain: no attribution to
      carry into a mobile release, commercial use unrestricted, and multilingual,
      which matters because an envelope codebook trained only on English is tuned
      against every other language this carries. LibriSpeech, LibriTTS and VCTK
      are CC BY 4.0 and are a real fallback at the cost of an attribution notice
      somebody has to remember at every release. TIMIT is paid and is out. Written
      up in `docs/PROVENANCE.md`.

      **Measured, and the answer is no.** `examples/train-envelope` trains an
      LBG codebook on four speakers and measures it on four others, against what
      this codec spends today rather than against a paper:

      | | bits | rms error, levels |
      |---|---:|---:|
      | today, fixed width | 120 | **0.74** |
      | trained, 4096 entries | 12 | 11.22 |
      | shape plus mean, 4096 | 18 | 10.76 |

      At 18 bits, which is Codec 2 700C's figure, the envelope error is 10.76
      levels: **5.4 dB rms against today's 0.37**. This codec's own note says
      0.43 dB of gain error predicts 25.9 dB of SNR, so this is twelve times the
      error it was designed around.

      **Two things that were expected to matter did not.** Balancing the split by
      sex moved 11.24 to 11.22, and removing the overall level before training,
      which is what Codec 2 does and what the first attempt here missed, bought
      half a level and cost six bits.

      **What says it is not a data problem is the slope.** Sixty four entries to
      four thousand, six bits to twelve, moves the error from 14.2 to 11.2. That
      curve is nearly flat, and nothing at the end of it reaches 0.74.

      **What would overturn this**, and what a fair attempt looks like: a
      multi-stage quantiser rather than one stage, and roughly a hundred times
      the training data, since 12,502 frames for 4,096 entries is three frames
      an entry. `dev-clean` is 5.4 hours and `train-clean-360` is 360. If
      somebody runs that and it lands near 0.74, this entry is wrong and should
      be reopened
- [ ] **Five decibels sit between a canceller run continuously and one restarted
      every half second, and three attempts to close them failed.** Continuous
      gives 1.3 dB in a real room; realigned and restarted every 0.5 s gives 6.1.
      Written up in `docs/ACOUSTIC.md`.

      The obvious suspect is the clocks: the speaker is an ALC889 and the
      microphone a USB webcam, 341 ppm apart, which is the recording sliding 16
      samples a second away from the playback.

      **Following the filter's own impulse response does not work**, and the
      reason is the useful part. While the filter converges its centroid walks
      steadily towards the true delay as energy concentrates, and that walk is
      monotone, so looking at it for longer does not separate it from drift. On a
      path with no drift at all it invented **-194 ppm** and followed its own
      invention, taking cancellation from 38 dB to 0.3. Requiring four
      observations in a row to agree brought that to -76 ppm and 0.4 dB. A
      tracker whose signal is the thing it is changing cannot be fixed by being
      more careful with the signal.

      **Correlating the two ends directly** is honest about there being no drift
      when there is none, 0 ppm on the synthetic path and about 200 in the room,
      and applying it still did not help: on, off and reversed came out at -1.8,
      1.3 and 0.7 dB, inside the spread of that measurement.

      So the five decibels are real and the cause is **not established**. An
      earlier version of this said four of them were drift, concluded from a
      four-second recording, and it does not survive twenty-four seconds and 46
      windows. Restarting the canceller is part of what the windowed measurement
      does, so some of the gap may be convergence rather than alignment, and a
      delay estimate is the next thing to try.

      **The delay estimate was tried, and it is not good enough to answer the
      question with.** `acoustic-echo` now reports the slope of the per-window
      realignment, which is the direct test: clocks a few hundred parts per
      million apart move the alignment steadily, and convergence does not move
      it at all. What came back was **-2024 ppm on one run and -4210 on the
      next, both from a spread of 471 ms with a fit of 0.10.**

      None of that is drift. Two crystals 341 ppm apart move eight milliseconds
      over twenty four seconds, not half a second, and a figure that changes by
      a factor of two between runs is measuring nothing. The alignments are not
      on a line: the per-window estimate is picking different correlation peaks
      in speech, which has no sharp autocorrelation to find.

      **The tool says so rather than printing the number.** It refuses to read a
      drift out of a fit below 0.5, because the first version of it printed
      "-2024 ppm, which is drift" and that sentence was wrong in the way that is
      hardest to catch: confident, plausible, and about the right quantity.

      So the order of work is settled even though the cause is not. **Sharpen
      the delay estimate first.** Until a half-second window aligns to the same
      place twice, nothing measured through it separates drift from convergence

      **And a separate finding, worth more than the above.** The estimate had no
      upper bound and searched the whole recording, so it found a peak 3295 ms
      out, on a recording whose real offset is 650. Everything downstream
      aligned to a delay that does not exist and the canceller, handed a
      reference unrelated to what the microphone heard, **added 7 dB of echo**.
      Bounded to two seconds, the same canceller removes 7. Nothing in
      `echo.rs` changed. The numbers at the top of this entry were taken with
      the unbounded search and are not comparable to anything measured now

      **The estimate is now sharpened, and the fix was not the obvious one.**
      `rotelyx_audio::align` replaces it, in the crate with ten tests rather
      than beside the examples with none. The textbook answer for speech is the
      phase transform, and applied at full strength it is **much worse**: on
      24.6 s of the synthesised clips through a simulated room, against a delay of
      3,120 samples, full whitening lands 92,879 samples out where plain
      correlation lands 596 out. Three quarters of it lands 22 out, and that is
      where the constant sits, pinned by a test against the sweep that chose it.

      **No confidence measure survived.** Peak over the noise floor, and peak
      over its nearest rival, were both built and both removed: under full
      whitening the worst window of a run scored second highest of eight, and at
      0.75 the correct windows and the wrong ones are separated by three
      hundredths. Two unrelated recordings produce a delay and a good margin as
      readily as two related ones. What works is structural: one coarse delay
      from the whole recording, each window refining it inside a narrow band.
      **Per-window spread goes from 471 ms to 13.**

      A bug turned up on the way: the per-window realignment searched only
      forward from the coarse delay, so a path drifting the other way clamped at
      zero and reported no movement, which has the shape of an answer without
      being one.

      **The hardware run happened, and it found the estimator broken.** Played
      through the real loudspeaker, the new estimator **refused**, reporting that
      the microphone had heard nothing on a recording with an RMS of 2894 out of
      32768. It took the whole reference it was handed rather than a window of
      it, so 24.6 seconds of reference against 24.6 seconds of room left no lags
      to search. **Ten unit tests passed through that**, because every one of
      them passes a short window; the whole-recording call happens once, at the
      top, on hardware. The window is taken inside the estimator now and that
      shape has a test.

      With it fixed, the coarse delay is right on hardware: 650, 612 and 642 ms
      across three runs against a recording whose offset is about 650, where the
      unbounded search used to answer 3,295.

      **The per-window estimate is not better, and the first write-up of this
      said it was.** The spread came back at 100 ms against a bound of 100, so
      the bound was measured rather than the room. Run again at 400: the spread
      is **800 ms**, the entire width of the search. It fills whatever room it is
      given. The apparent improvement from 471 ms to 100 was the range shrinking
      from two seconds to two hundred milliseconds.

      **That is a result, not a dead end:** the per-window path cannot answer
      this at any bound. Too narrow and it reports the bound, too wide and it
      reports noise. The alignment has to come from something other than
      realigning half-second windows of speech.

      **And the question was wrong.** Seven runs on one machine in one
      afternoon: the realigned figure repeats, 5.9 to 7.9 dB, and the continuous
      one does not, +0.7 to -4.6, with **six of the seven negative**. This entry
      was built on a documented +1.3 dB that was not reproduced once. Continuous
      is the production configuration, so the number describing what a user gets
      is the unstable one, and on today's mean the canceller **adds about 2 dB**.

      Nobody had checked whether the two numbers repeat before three attempts
      went into explaining the distance between them.

      **That measurement was made, and the suspicion was backwards.**
      `examples/acoustic-duplex` runs the same room through the `Capture` and
      `Playback` a call opens. Six runs: continuous is **-8.8, -2.6, -7.1, -3.7,
      -1.8, -7.0**, mean **-5.2 dB**, every one negative. Realigned is +8.0 and
      steady. Taking both sides from one audio path does not recover the
      decibels, it loses more of them than the two-stream harness did.

      **That was a property of the clips, not of the canceller**, and it took
      eight recorded people to see it. Every acoustic number here was measured
      against six clips from one text to speech model. Cut to the same 24.6
      seconds so only the voice differs, eight real speakers give a continuous
      mean of **-0.9 dB, four positive and four negative**, against the
      synthesised set's -5.2 with six of six negative. The synthesiser sits four
      decibels at the pessimistic end.

      **And the spread between speakers is 8.8 dB**, from +2.8 to -6.0. That is
      larger than any effect this entry has ever argued about, which means a
      single figure for what the canceller removes was never a meaningful
      quantity, and three attempts went into explaining the distance between two
      samples of a distribution nobody had looked at.

      `scripts/make-speech-corpus` builds those clips from LibriSpeech, and
      `examples/acoustic-duplex` takes one by name.

      **The next question is what separates `m1272` at +2.8 from `f84` at -6.0**,
      on the same hardware in the same minute

      Continuous is 0.7 dB and realigned is 7.9 over 39 windows on this run. **The
      gap is still not attributed.** What changed is that the instrument now
      finds the right delay on hardware, which none of the earlier attempts could
      rely on

### 7. Mobile clients

- [!] **iOS needs a Mac**, and no amount of wanting changes that. The targets and
      the `xcframework` step are in `scripts/build-mobile ios` and have never
      been run
- [ ] Background lifecycle. iOS will not hold a socket, and every design
      decision downstream of "the phone hosts it" collides with this
- [?] Whether to ship the browser harness as a Tauri shell or write native
      clients


### 8. Selling capacity without learning who bought it

- [ ] Payment gateway, talking only to the issuer and never to the mailbox
- [ ] A store the browser can actually buy from
- [ ] Legal review. Selling encrypted communications carries obligations that
      vary by jurisdiction and some collide with being unable to read anything


## Blocking any public security claim

- [!] **Review by somebody outside the project.** Protocol design plus
      implementation. A commissioned audit runs roughly 50,000 to 150,000 USD
      for work of this scope, there is no budget for one, and pretending
      otherwise would leave this item open forever with a plan nobody intends
      to fund. So the realistic path is an unpaid reviewer, and the work that
      makes that possible is done: the models, the harness and the reachability
      arguments are all in the repository, and `SECURITY.md` promises ninety
      days and tells a reporter to publish anyway if we go quiet.


### 9. Before a store build

- [ ] The APK that proved the calls carries the diagnostics: it is built with
      `--dart-define=ROTELYX_CALL_DIAG=true`, and the Kotlin level measurement
      is off unless `log.tag.RotelyxAudio` is made loggable. A shipped build
      must be made without the define. One line, and the kind of line that gets
      shipped because it was true for every build during the work

- [ ] `android/key.properties` does not exist, so every release APK is signed
      with the debug key and cannot be uploaded anywhere. Stated in the build
      output every time and easy to stop reading
