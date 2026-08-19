# Rotelyx TODO

Status as of 16 August 2026. 158 tests passing.

This file is the honest ledger. Items move to **Done** only when a test proves
them, not when the code exists. Three separate defects in this project were
types that documented a guarantee and were never wired to anything, so "the code
is written" is not a completion criterion here.

---

## Legend

| Mark | Meaning |
|---|---|
| `[x]` | Done and covered by a test that fails if it regresses |
| `[ ]` | Not started or in progress |
| `[!]` | Blocked on something outside this repository |
| `[?]` | Needs a decision before work can start |

---

## Done

### Foundations

- [x] Threat model written before code, ten adversaries modelled
- [x] Cargo workspace, seven first party crates
- [x] Ed25519 identity with a `Debug` that redacts and key generation that
      panics rather than degrading if the OS entropy source is unavailable
- [x] Safety numbers, twelve groups of five digits, order independent
- [x] Framed wire format with the length cap validated before allocation

### Transport (L0 / L1)

- [x] Transport stack vendored into the repository, 121,197 lines across
      fourteen crates, renamed throughout. No upstream networking package is
      downloaded
- [x] Identity publishing code deleted from the tree: the pkarr and DNS lookup
      providers and the third party presets are gone, not merely unreachable
- [x] Default and staging relay modes deleted. `RelayMode` has only `Disabled`
      and `Custom`, so there is no variant that could resolve to somebody
      else's servers
- [x] Guard hardened after it was defeated by our own rebranding: it now scans
      manifests and comments as well as code, treats a hostname inside a string
      literal as an unexceptable failure, and requires every other occurrence to
      appear in a reviewed ledger
- [x] Zero foreign infrastructure guard: live endpoints, source scan,
      environment override neutralisation. Build fails if it regresses
- [x] Metadata resistant path selector. Any direct path beats any relayed path
      at any latency
- [x] Two endpoints connecting over real QUIC with mutual public key
      authentication
- [x] `NetSession::finish`, because dropping a QUIC send stream resets it and
      silently discards data the sender believes was delivered

### Message crypto (L2)

- [x] MLS conversations via OpenMLS. A one to one chat is a group of two
- [x] Ciphersuite pinned explicitly. The default would have selected AES-GCM
      while every key package advertised ChaCha20-Poly1305
- [x] Plaintext padded to a multiple of 256 bytes before encryption. OpenMLS
      does none by default
- [x] X-Wing hybrid key agreement, ML-KEM-768 plus X25519
- [x] Post quantum secret reaching the MLS key schedule as an external pre
      shared key, bound to group id and epoch
- [x] A PSK commit fails for a member missing the secret, which is what proves
      the post quantum layer is load bearing rather than decorative
- [x] Mailbox tag keys derived from the MLS exporter, so addressing is never
      transmitted

### Blind mailbox (L3)

- [x] Sealed envelopes with no sender field and no length prefix
- [x] Five padding buckets, sized against measured MLS overhead
- [x] Rotating unlinkable tags with a lookback window for clock skew
- [x] TTL expiry enforced on collection, not only on sweep
- [x] Per tag capacity cap so a known tag cannot be used to fill a disk

### Reachability

- [x] `InvitationOnly` as the default reachability policy
- [x] Non transferable proof of work, bound to sender, recipient and hour
- [x] Blocklist checked before any verification work
- [x] Surgical invitation revocation, distinct from expiry
- [x] Admission control enforced on the accept path and verified over real
      sockets, not only in unit tests

### Operable software

- [x] `rotelyx-cli`, a two terminal chat that runs the real protocol
- [x] `rotelyx-relay` with an allowlist, refusing to fall open on an empty file
- [x] `rotelyx-web`, a local browser harness with no Node and no CDN
- [x] `rotelyx-mailbox-server`, the blind mailbox as a WebSocket service
- [x] `rotelyx-wasm`, the message layer compiled for the browser
- [x] A browser client that runs the real protocol against the real mailbox,
      with its handshake pinned by a test over a real socket
- [x] Groups of up to 1000, with per member mailbox tags, epoch-tracked tag
      keys, and a post-quantum secret sealed to each member rather than derived
      pairwise
- [x] Server side fan-out, so a sender uploads once regardless of group size,
      with the padding still applied by the client
- [x] Tiers, capability tokens and metering. A token carries its own quota, so
      sharing it shares the allowance and one purchase cannot serve a thousand
      people without anybody being identified
- [x] Mailbox keepalive, so a proxy that cuts idle sockets does not end
      conversations, and `unsubscribe`, so a client stops consuming envelopes
      meant for others
- [x] Cross layer tests: a message surviving the whole offline path, and the
      operator's view containing no plaintext, sender or recipient

---

## Next

Ordered by value, which is not the same as ordered by effort.

### 1. Field test across two real NATs `[!]`

**Blocked on infrastructure, not code.** Every test so far runs on loopback,
which needs no hole punching. Real traversal cannot be asserted from one host.

Requires a relay on a public address and two devices behind different NATs.
Everything needed for this is built.

- [x] DNS, nginx and TLS configured for `relay-rotelyx.ideoa.co`
- [x] Relay running and verified end to end: `101 Switching Protocols` through
      Cloudflare and nginx
- [ ] Measure hole punch success rate across NAT types
- [ ] Measure how often `PreferDirect` costs a connection that `Fastest` would
      have kept

### 2. Published test vectors for the post quantum composition

- [x] Seven deterministic vectors in `crates/rotelyx-crypto/tests/pq-vectors.txt`,
      verified against the implementation on every test run so the file cannot
      drift from the code
- [x] Written specification in `docs/PQ-COMPOSITION.md`, complete enough to
      reimplement from without reading our source
- [x] The construction extracted into pure functions taking their inputs, so it
      can be exercised without running MLS
- [x] Unambiguity of the binding pinned by a test rather than argued in prose
- [ ] Cross check against an independent implementation written by somebody else
      from the specification alone

### 3. Encrypted at rest storage

- [x] Identity keys sealed with Argon2id and XChaCha20-Poly1305, with in place
      migration of plaintext keys from earlier builds
- [x] Persistent blocklist, so a block survives a restart
- [ ] Derive the sealing key from the device keystore rather than a passphrase,
      where the platform offers one
- [ ] Encrypted MLS group state at rest
- [ ] A backup format that does not create a state rollback vector

### 4. Relay hardening

- [!] **nginx connection and request rate limits: documented, not deployed.**
      `docs/nginx-relay.conf` carries `limit_conn` and `limit_req`, and CWP
      rejected both, so they were removed from the live configuration and the
      documents were not. Measured on 18 August: **35 unique requests in a few
      seconds, 35 answers, not one refusal.** There is no rate limit at any
      layer, which is the fourth time in this project a document has claimed a
      guarantee nothing enforces
- [x] **Admission control, in `rotelyx-relay::limits`.** Not in the vendored
      tree, so re-vendoring cannot silently remove it, and composed around the
      access control so the allowlist and the open relay both get it:
      8 concurrent connections and 30 a minute with a burst of 10 per identity,
      4096 in total
- [x] **Keyed on identity rather than address.** The endpoint id is proven by
      the relay handshake before access control is asked, so it cannot be
      claimed without the key; an address can be changed for free. Generating a
      keypair is cheap too, which is exactly why the global cap exists and is
      not decoration
- [x] Turned on `client_rx`, the per-connection byte rate the vendored server
      *does* implement, at 512 KiB/s: far above a voice stream, far below a link
      somebody is using as free transit
- [x] **A status monitor on the relay's landing page.** Green served, amber in
      progress, **red not serving**, grey no record. Server rendered rather than
      polled by a script, so the content security policy stays at
      `default-src 'none'`: loosening a relay's CSP for a live status widget is
      a poor trade and it is the usual reason people do
- [x] **The same monitor on the mailbox**, from one shared crate rather than a
      second copy: `rotelyx-status`. Two strips whose colours mean subtly
      different things are worse than one, and a copy drifts. The relay and the
      mailbox now render the same four states from the same code, and the
      mailbox carries the Rotelyx mark and favicon like the relay does, with
      `img-src data:` so both stay unable to fetch anything from anywhere
- [x] **It keeps a record, so red means something.** `--status <path>` writes
      the half-hour buckets it served, once a minute. Without it the strip can
      only say "up since this process started" and an outage is invisible: a
      relay that is down serves no page, so the only way it can report having
      been down is to have written it beforehand. Verified by injecting a gap:
      eight red bars appeared exactly where the record was missing
- [x] **Published no traffic and no limits.** No connection count, no
      identifiers, no addresses, no logs: a relay's whole exposure is which
      endpoints talk to which, and a page saying how many are connected
      publishes the size and rhythm of a community to anybody who polls it. The
      per-identity limits were dropped too, though those are discoverable by
      probing in seconds; the total cap is the one that matters, because it is
      the number an attacker must exceed and cannot find without mounting the
      attack. Asserted on the rendered bytes so a counter added later fails a
      test rather than a review
- [!] **`rotelyx-discovery` was marked for deletion and is staying.** The crate
      does two unrelated things: 1,011 lines of plain DNS resolution, which
      every relay client needs to resolve a hostname, and 763 lines of
      pkarr/TXT-record discovery, which is the third-party mechanism this
      project must never use. Deleting the crate breaks the transport; 14 of the
      21 references to it are the resolver. The discovery half is unreachable by
      construction: `AddressLookup` has one variant, `Disabled`, and the
      endpoint clears lookup again when it binds. Reasoning recorded in
      `crates/net/README.md` so it is not rediscovered
- [x] **The vault re-derived its key on every write, and the wake registry
      writes on every device registration.** Argon2id at 64 MiB is 265 ms and
      allocates 64 MiB, which is the point when a passphrase is being checked
      and pure waste when the same passphrase writes the same file again.
      Measured against a real server: **eight unauthenticated `revokeWake`
      messages took 2.26 seconds, so three and a half a second saturated a
      core.** Cached, it is 0.4 ms and 2,649 a second. Latent rather than live,
      because production runs without `--wake-state`
- [x] **The first version of that cache was an authentication bypass.** Keyed on
      the salt alone, opening a file with the wrong passphrase found the entry
      cached from the right one and decrypted. Caught before it ran. The cache
      is bound to a hash of the passphrase, compared in constant time, and there
      is a test that opens with a wrong passphrase against a warm cache
- [ ] `registerWake` and `revokeWake` are unauthenticated, and `revokeWake`
      accepts any token without proof of possession: anybody who learns a
      device's push token can silence its notifications
- [ ] Watch the refusal counters in production. Limits chosen from reasoning
      rather than from traffic, and the first real load will say whether they
      are in the right place
- [x] **The refusal counters were unreadable.** `Limited` incremented them on
      every refusal and nothing could read them back: the limiter becomes a
      trait object the moment it is installed, and a trait object has no
      `refusals()` on it. A `Counters` handle is now taken before installation
      and reported to the operator's journal on change, and at shutdown. Not on
      the public page: a live count of open connections is a load signal, and on
      a small relay a load signal correlates with who is talking
- [x] **The mailbox had the same defect.** `delivered` and `refused` were
      declared, never incremented, and never shown. Both are wired now and both
      tiles are on the page
- [?] Whether an open relay should require a proof of work for admission. The
      construction already exists in `rotelyx-core::access`; the question is
      whether an open relay is a configuration we want to support at all

### 5. Multi device

- [?] Which device authorises the next one, and what the user sees when it
      happens
- [ ] MLS multi device as separate leaves rather than shared keys
- [ ] Device revocation that is visible to every conversation partner

### 6. Audio calls

Transport is settled: RTP over QUIC. The media stack is the long part, and by a
wide margin the largest single task remaining in the project.

- [x] **Telyx**, a transform codec of our own, in `rotelyx-codec`. MDCT with a
      40 ms window, Bark-spaced bands, energy and shape coded separately. Built
      because our constraint is not Opus's: latency is spendable, the whole
      utterance is available, and `rotelyx-media` recovers loss rather than
      concealing it, so none of the three things Opus bends around apply
- [x] **Give it sounds it had never been given.** Every figure was measured on
      one sustained vowel. A plosive, a fricative and an onset after silence, in
      `rotelyx-codec/tests/stress.rs`, found three defects no existing test
      could see
- [x] **The noise fill was not noise.** A band with no bits got a texture hashed
      from the coefficient index alone, so it was the same pattern in every
      frame for ever: a decoded fricative correlated with itself one frame later
      at +0.991 against +0.008 for the input. A buzz at the frame rate, 50 Hz,
      not a hiss. Seeded from the decoder's frame counter now, +0.010
- [x] **A rate that cannot carry the envelope is refused.** `resize` pads and
      also truncates, and the truncating case was never considered: at 15 bytes
      a frame the energies alone need 18, the last bands were cut off and read
      back out of zero padding, and the frame decoded 6 dB quiet with no error.
      It had been published as the 6 kbit/s row of the rate table
- [ ] **Pre-echo, measured at 14.8 dB below the burst that causes it.** A 40 ms
      window spreads quantisation error over its whole length, so a plosive puts
      noise into the silence before it. The fix is block switching
- [x] **Measure it on speech.** Six neural TTS clips at 48 kHz, in
      `rotelyx-codec/tests/speech/`. Real speech scores 11.7 to 21.1 dB at
      24 kbit/s against 28.2 for the synthetic vowel every published figure
      used. Not the resampling: no bits go above 11 kHz. The synthetic signal
      keeps 13 of 24 bands awake and speech keeps 21
- [x] **Broke the speech figure down by band**, which is the only honest way to
      report it: 0-800 Hz reaches 25-29 dB and holds 79% of the energy, while
      3-12 kHz holds under 1% of the energy, is deliberately starved, and
      produces 86% of the error the single number reports
- [ ] **Retuning the allocator needs ears, not SNR.** The energy is all at the
      bottom of the spectrum, so optimising signal to noise would strip the top,
      raise the number and sound more muffled. Blocked on a listening test
      rather than on effort
- [x] **Built the listening test.** `bake_listening_test` writes eight versions
      of each clip: the original, Telyx at 12/16/24, Opus at the same rates from
      libopus, and a 3.5 kHz anchor. Same length, meaningless names, mapping
      withheld. `scripts/listen` plays them in random order and takes MUSHRA
      ratings; `--reveal` joins them to what they were
- [ ] **Run it, with more than one pair of ears.** One listener is an anecdote.
      The hidden reference is the check: if it does not score near 100 the
      session is not usable Every number recorded is objective. Codec quality is
      settled by listening panels and nobody has heard a second of this. No
      comparison with anything may be published before that happens
- [x] A rate-distortion allocator: reverse water-filling. The curve no longer
      goes backwards. A band's next increment is worth `E² · 4^-r`, which does
      not scale with width while its cost does, so a wide high band can no
      longer displace the narrow ones where speech is understood
- [x] **PVQ shape coding.** The scalar quantiser had a floor of one bit per
      coefficient against a budget of a third of that, so every band fell to
      noise while the whole budget went unspent. PVQ describes a band as a
      direction chosen from every placement of `k` signed pulses, at any
      fraction of a bit. Measured: 24 kbit/s went from 8.4 dB to 26.2
- [x] **Residual vector quantisation.** The idea neural codecs win with, used
      without a network. Measured, staging is *not* a better rate: it is a
      ceiling one stage does not have. `V(64,16)` outruns a 64 bit index, so a
      single stage on a wide band stops at 0.751 while three stages reach 0.867,
      and the gain grows with band width
- [x] RVQ wired into the codec, in `layered`. Each band is coded in residual
      stages and the stages become the transmission layers
- [x] **Layered transmission.** A frame is a base plus three refinements, each
      optional and each improving on the last. One encode serves every rate: a
      listener on a poor link gets the base and stops, the same recording sent
      elsewhere carries every layer, with no re-encoding
- [x] **Carry the layers over the transport.** A frame serialises with a byte
      of layer count and a length for each layer but the last, the sender trims
      to whatever `MediaOut::payload_budget` reports before protecting, and the
      whole path is tested end to end in
      `rotelyx-media/tests/layers_over_the_wire.rs`
- [x] **Costed giving each layer its own datagram, and refused it.** Every
      datagram pays a sixteen byte tag: splitting a 24 kbit/s stream four ways
      puts 54.4 kbit/s on the wire against 31.6, and a 12 kbit/s stream goes
      from 19.6 to 42.4. The layers share a datagram
- [ ] **Shrink the base, which is what layering is waiting on.** Trimming saves
      about a tenth today because the base is 86% of a frame and 44% of the base
      is the envelope. Grouped energy coding takes 20.3 bytes to 12.4 but needs
      200 ms of batching: wire it into the mailbox path, where the latency is
      affordable, and leave calls on the per-frame path
- [x] **An arithmetic coder**, in `rotelyx-codec::entropy`, with an adaptive
      model that is never transmitted. A constant source costs 0.013 bits per
      symbol; an incompressible one costs 1.008, which is the theoretical floor
- [x] Use it for the band energies. **The first attempt made them worse**: 19.2
      bytes against 18 for fixed width, over four hundred frames
- [x] **The floor had been measured wrong.** A helper computing the entropy
      multiplied each symbol's surprise by its own count rather than by the
      total, reporting under two bytes a frame against a true fifteen. The
      redesign it motivated was aimed at a saving that did not exist
- [x] **Predict along the spectrum, not along time.** Each band was predicted
      from the same band in the previous frame, which is the obvious design and
      the losing one: the fastest-moving thing in a voice is its overall level,
      and 20 ms is long enough for it to move a lot, while the shape of the
      spectrum barely moves. Predicting from the band below, in the same frame,
      went 15.4 to 12.9 bytes a frame and made frames independent of each other
- [x] Context models on the residual, by band position and by what the band
      below did. Thirty models, carried across groups so they learn once
- [x] **Batch the energies of several frames into one arithmetic stream**, in
      `rotelyx-codec::grouped`. Ten frames, one flush, 12.4 bytes a frame. Costs
      200 ms of latency and ties a group's levels together, both of which this
      channel can afford and a telephone call cannot. MELPe at 600 bit/s groups
      four frames into a superframe for the same reason
- [x] **The energy step was the ceiling all along.** The codec saturated at
      26.3 dB however many bits it was given. A 1.5 dB quantiser has 0.43 dB rms
      error, and 0.43 dB of gain error predicts 25.9 dB of SNR: every bit above
      24 kbit/s was refining a shape that was then multiplied by the wrong
      number. The step now comes from the frame size, which both sides already
      know, so it costs nothing to signal. 26.2 to 28.2 dB at 24 kbit/s, ceiling
      26.3 to 29.2
- [ ] **A trained vector quantiser for the envelope**, which is the largest
      saving left. Codec 2 700C spends 18 bits on a K=20 mel-spaced envelope
      where Telyx spends about 100 on 24 bands. It needs a speech corpus and it
      ships a codebook, which is why it is not done
- [ ] **Analysis by synthesis in the residual quantiser.** CELP picks the index
      minimising perceptual error; Telyx picks the one nearest in the parameter
      domain. Unmeasured
- [ ] **A noise pre-processor**, the one part of MELPe built for a loud room.
      Needs device capture first
- [x] **A fast transform.** The MDCT was written from its definition and cost
      270% of real time on one core for one call, which meant the codec could
      not have run at all: 1.8 million multiplies and as many calls to `cos` per
      frame. Factored as a fold, a DCT-IV and a 480 point complex FFT, it is
      0.5%, and the whole codec is 1.2%. It is also 775 times more accurate,
      because an FFT accumulates in a tree of depth nine and the definition
      accumulates in a line of length 1920
- [ ] Block switching, long term prediction
- [x] **A call, end to end, in one binary**: `cargo run -p rotelyx-media
      --example call -- in.wav out.wav [loss%] [fidelity]`. The codec had no
      consumer and the media layer had no application; nothing in this
      repository made a call until this. Audio from a file through the encoder,
      frame encryption, a network that drops and reorders, the jitter buffer,
      the decoder, and out to a file you can play. At 20% loss: 53 gaps
      concealed in conversational mode against **4 in fidelity**, which is the
      whole argument for the second mode in one line
- [ ] Device capture, which needs a microphone and therefore is not something
      that can be finished here
- [x] **Jitter buffer**, adaptive. Depth follows the observed jitter with
      RFC 3550's estimator, grows fast and shrinks slowly so the delay does not
      oscillate audibly, and is bounded at 200 ms because a caller can talk
      through gaps and cannot talk through delay. Verified against synthetic
      networks with loss, reordering, duplication and jitter
- [x] **Fidelity mode: loss recovery rather than concealment.** A deep buffer
      is time, and time is round trips. The receiver reports its gaps, the
      sender resends from a 256 frame history, and a slot waits rather than
      being concealed. Measured to lose nothing at one packet in two, with the
      retransmissions dropping at the same rate
- [x] **The start of a call was never recovered.** A receiver cannot see a gap
      before the first frame it ever got, so everything lost before anything
      arrived was never asked for: 260 ms gone on every run at 80% loss,
      invisible at any rate up to one in two. The sender now reports its oldest
      recoverable counter. Measured, **nothing is lost at any loss rate up to
      98%**; only the delay grows, to 4 s
- [x] **Removed the Spanish that had got into test literals.** 55 string
      literals across seven crates, all passphrases and test messages
- [ ] Packet loss concealment, for conversational mode where recovery is too
      late to help. The buffer already reports a gap as `Missing` rather than
      an error, which is what a decoder needs to extrapolate. The extrapolation
      itself belongs to the codec
- [ ] Acoustic echo cancellation
- [ ] Congestion control and bandwidth estimation
- [x] **Media keys derived from MLS exporters**, so a call is as end to end as
      a message. `rotelyx-media`: per sender frame encryption in the shape of
      SFrame (RFC 9605), with a replay window and a counter that refuses to
      wrap. A membership change rekeys the call, verified against real groups
- [x] Variable length frame counter. Overhead on an 80 byte Opus frame went
      from 25 bytes to 18, or 31% to 22%. Three counter bytes carry 93 hours of
      continuous speech at fifty frames a second
- [~] Truncated authentication tags. **Tried and rejected.** An eight byte tag
      would take frame overhead from 22% to 14%, and SFrame permits it, but
      `aes-gcm` gates it behind a feature named `hazmat` for a specific reason:
      truncating a polynomial MAC is not truncating an HMAC. Ferguson showed in
      2005 that short GCM tags leak the authentication subkey across repeated
      forgery attempts, so security degrades faster than 2^-64. The safe route
      is AES-CTR with a truncated HMAC, which means composing encrypt-then-MAC
      by hand, and this project does not write its own constructions
- [x] **Path policy for calls: always relayed, no switch.** A direct path hands
      your address to whoever is on the call. Messages keep preferring direct,
      where the alternative exposure is to an operator instead of to a stranger
- [x] Enforced in the transport. `PathPolicy::RelayOnly` never selects a direct
      path whatever is on offer, and `MediaOut`/`MediaIn` refuse to be built on
      any policy that permits one. A call cannot silently become an address
      disclosure the moment hole punching succeeds
- [x] Media rides QUIC datagrams rather than a stream. A stream stalls behind a
      lost packet to preserve an order audio does not need, and a retransmitted
      frame is worthless by the time it lands
- [ ] Use a proven media engine rather than writing one. None of SimpleX,
      Session, Briar or Cwtch built their own: SimpleX uses WebRTC, and the
      other three have no calls at all. Opus, a jitter buffer, packet loss
      concealment and echo cancellation are decades of work each. Taking them
      as libraries while keeping our own transport and frame encryption is the
      only version of this that ships
- [ ] A forwarding unit for group calls. The frame format already suits one:
      the header is authenticated but not encrypted, so it can route by sender
      without reading anything. What it will see is who speaks and when, which
      with silence suppression is the rhythm of the conversation

### 7. Mobile clients

- [x] **`rotelyx-mobile`: the engine as a native library.** The same crate the
      browser gets, behind a C ABI of three symbols instead of `wasm_bindgen`.
      Depends on `rotelyx-wasm` as an rlib and reimplements nothing: two
      implementations of one handshake diverge, and the divergence is a security
      bug that presents as an interoperability bug. Contract in `docs/MOBILE.md`,
      built by `scripts/build-mobile`, and the whole pairing flow is tested
      through the C boundary rather than through the Rust API underneath it
- [x] **The audio path, in raw buffers rather than JSON.** Six entry points that
      fill caller-owned memory and return counts, so a wrapper can call them
      from an audio callback without allocating. Tested through the C boundary
      with two real sessions
- [x] **A receiver is keyed for the sender it listens to, not for itself.** The
      first version built one `MediaIn` with its own index, which made a
      loopback test pass and a real two-party call completely silent. Found by
      writing the two-session test; a test that had looped back to itself would
      have shipped it. One receiver per participant now, routed by the sender id
      the datagram claims
- [ ] Packet loss concealment. A gap plays as silence today
- [ ] Mixing, for a group call with more than one person speaking
- [ ] Build for Android on a machine with the NDK, and for iOS on a Mac. The
      Rust targets are installed; `cargo-ndk` is not
- [ ] UniFFI bindings for Swift and Kotlin, if the C ABI turns out not to be
      enough
- [ ] Background lifecycle. iOS will not hold a socket, and every design
      decision downstream of "the phone hosts it" collides with this
- [ ] Silent push with jittered delivery and decoy pushes
- [?] Whether to ship the browser harness as a Tauri shell or write native
      clients

### 8. Selling capacity without learning who bought it

- [x] Free and plus tiers, enforced per request on fan-out width, envelope
      size, retention and volume
- [x] Ed25519 capability tokens with `keygen` and `mint`
- [x] A meter holding a random id and a byte count, swept every period
- [x] **Blind signature issuance.** RFC 9474 blind RSA, one key per tier so a
      blind issuer cannot be handed a tier it cannot read. Verified end to end:
      what the issuer sees during a sale does not appear in the token
- [ ] Payment gateway, talking only to the issuer and never to the mailbox
- [x] Blind redemption in the browser: `TokenRequest` blinds, pays, unblinds.
      The page still takes a pasted token, since there is no store to buy from
- [ ] A store the browser can actually buy from
- [x] Persist the meter, so a restart does not hand everyone a fresh allowance.
      Verified over a real socket: spend, restart, and the allowance is still
      spent
- [ ] Legal review. Selling encrypted communications carries obligations that
      vary by jurisdiction and some collide with being unable to read anything

### 9. The browser client, beyond a demo

- [x] Deploy `rotelyx-mailbox-server` to `mail-rotelyx.ideoa.co:3341`, verified
      end to end: `101 Switching Protocols` through Cloudflare, pfSense and nginx
- [ ] Upload `site/` to `rotelyx.ideoa.co`, and add the same `location /mailbox`
      block there so the page finds the mailbox at its own origin
- [x] Persist mailbox state, encrypted under an operator passphrase, so a
      restart does not drop every uncollected envelope
- [x] Message history survives a reload, sealed under the same key as the
      session, with local arrival timestamps
- [ ] **Superseded:** message history does not survive a reload. The conversation resumes
      and the group is intact, but the visible log starts empty: nothing has
      ever stored plaintext messages. Needs a decision first, since storing them
      is the one place this design would keep readable content at rest
- [x] Persist conversation state in the tab, sealed under a passphrase, with the
      key derived once so saving after every message stays cheap
- [x] **The build machine's username was in every shipped artifact**: 173 paths
      in the wasm every visitor downloads, 387 in the relay, 269 in the mailbox
      server. `--remap-path-prefix` in the build scripts, which now refuse to
      finish if any remain
- [x] **The builds are reproducible.** They were not: two clean builds of
      identical source gave different binaries, so nobody could check a served
      artifact against the source it claims to come from. Byte-identical now
- [x] **Rejected subresource integrity as theatre.** SRI protects a trusted page
      against an untrusted subresource; ours share an origin, so an attacker who
      can swap the module can swap the hash in the page that checks it. Recorded
      in the threat model, with what does work instead: a published hash that
      somebody outside the page can compare against
- [x] **Published the artifact hashes in the repository**, `docs/ARTIFACTS.md`,
      written and checked by `scripts/artifact-hashes`. In git rather than
      served: a hash from the same origin as the file proves nothing, because
      whoever can replace one can replace the other. Verified that the check
      actually fails on a changed hash rather than passing by construction
- [ ] A signed manifest, so that a page load can be
      checked against something. It does not close the gap, it narrows it
- [x] **Shrank the wasm from 2.35 MB to 1.51**, 749 KB to 531 gzipped: -35.8%
      and -29.1%. A size profile (`opt-level = "z"`, fat LTO) plus
      `--remove-name-section`, which alone was 397 KB of debugging symbol names.
      Both were written down as optional steps in a document and therefore never
      run; `scripts/build-wasm` now does the whole pipeline including the cache
      stamp. Exported API verified identical, all 31 wasm imports still resolved
      by the glue. **Not verified in a browser**
- [x] **The mailbox runs as a systemd user service** and comes back on its own.
      No root: `Linger=yes` was already set on this machine, so a user unit
      survives the session ending, which is what kept killing it. Four hardening
      options had to come out because an unprivileged service may not drop
      capabilities, and the failure names the step rather than the option
      (`status=218/CAPABILITIES`). Verified by `kill -9`: back in five seconds
- [x] **The relay runs as a service too**, and comes back on its own: verified
      by `kill -9`. It refused to start for one reason and one only, which is
      deliberate: no `--allow <file>` and no `--open`, because an open relay
      should be a decision somebody made rather than the result of forgetting a
      flag. No allowlist exists on this machine, so it runs `--open`
- [ ] **Decide whether the relay stays open.** Open costs capacity and logs, not
      confidentiality: it forwards ciphertext it cannot read either way. But its
      connection log covers people with no relationship to the operator. Closing
      it is one file and one flag, and the unit says how
- [ ] Verify the smaller wasm in a browser before deploying it
- [ ] `wasm-opt` is not installed here and was not run

---

## Ongoing

- [ ] **Upstream security patch watch.** Vendoring means fixes no longer arrive
      on their own. Somebody has to watch the upstream repository and port
      security patches by hand. This is the price of owning the code and it is
      not optional in a cryptographic project
- [x] **Hostile input tests on every parser reachable from the network**, in
      `hostile_input.rs` in five crates, the fifth being `rotelyx-net`: the
      relay URL and the endpoint id, which are the two things it parses from
      outside and both reachable before anything is authenticated. Also: the wire frame reader, the mailbox
      envelope and tag, the three post-quantum parsers, the media frame header,
      and both codec frame formats. Systematic mutation rather than a fuzzer, so
      it runs in the ordinary suite on every change instead of in a tool nobody
      starts: every truncation, every byte value at every position, extension,
      and arbitrary input
- [x] **It found one, and it was the worst kind.** A single corrupted byte in a
      Telyx frame decoded to a peak of **3530**, three thousand times full
      scale, because a band's energy level is exponential and one byte moves it.
      In headphones that is not an artefact. The overlap-add now clamps, which
      costs one comparison per sample
- [x] **The synthetic test signal was never valid audio.** It peaked at 1.113,
      so 203 samples of every clip were past full scale and no device could have
      played it. Found only because the clamp above started cutting them. Scaled
      to 0.25, and every published figure is unchanged, so the overshoot was
      never what the numbers rested on
- [ ] Fuzzing every parser reachable from the network with a real fuzzer: the frame reader, the
      envelope parser, the admission decoder and MLS message handling
- [x] **Constant time review**, recorded in `docs/THREAT-MODEL.md` section 6.
      Every comparison in the first-party crates touching a key, tag, token,
      proof or passphrase was located and classified. Three were already
      constant time and correct; the rest compare public values. One was not:
      `Tag` derived `PartialEq`, so it short-circuited on secret-derived bytes.
      **It was not exploitable** (reaching the comparison requires already
      knowing the tag) and it is constant time now regardless
- [ ] Measure whether the primitive libraries are constant time, which this
      review explicitly did not do and did not claim

---

## Blocking any public security claim

- [!] **Independent cryptographic audit.** Protocol design plus implementation
      review by a firm that does this as its primary business. Industry range
      is roughly 50,000 to 150,000 USD for work of this scope

Until that is done, the README, the site and every public statement must keep
saying **unaudited**. See `docs/THREAT-MODEL.md` section 5 for the full list of
review gates.

---

## Known gaps, stated rather than hidden

These are real and currently unsolved. They are listed here so that nobody
discovers them by surprise.

| Gap | Why it matters |
|---|---|
| Full workspace builds are memory hungry | 121,000 vendored lines plus Tauri. `.cargo/config.toml` caps jobs at four; a machine with 2 GiB of swap can still stall |
| Message history is not persisted | Conversations live only for the session. Encrypted history at rest is not implemented |
| Mailbox timing correlation | An operator that logs everything can correlate a deposit with a collection. Padding and tag rotation raise the cost, they do not eliminate it |
| Push notification metadata | Apple and Google see that a device was woken and when. Inherent to mobile platforms, and unsolved |
| Browser harness trust boundary | Plaintext crosses loopback. The desktop app does not have this problem, its IPC is in process |
| The browser client has no direct path, ever | A browser cannot open a UDP socket, so QUIC and hole punching cannot run there. Every browser message goes through the mailbox, which means the operator always learns that two parties are talking. On a direct path nobody does |
| Web code is re delivered on every load | An installed binary is verified once. A page is served again on each visit, so the operator could serve different code to one visitor. This is not in the threat model, which assumes an installed binary |
| Persisting the mailbox trades seizure resistance for delivery | A stopped server with no state file hands over nothing. With one, a seized disk plus the passphrase yields tags and ciphertext. Content stays unreadable either way |
| The recipient set is explicit on send | A fan-out names every recipient's tag in one request. The operator could already infer this from a burst of deposits plus who subscribes to what, so it makes an existing inference cheap rather than creating a new one. It is still a reduction, taken to make groups beyond a few dozen possible |
| Commits grow with the group | 21.8 KB at 256 members, downloaded by everyone on every membership change. Fine at 256, heavy past it |
| Group size is capped at 1000 | Beyond it a commit exceeds 83 KB and the per member cost of a join keeps climbing. TreeKEM, not padding: the ladder no longer cliffs |
| Padding above 1 KiB is coarser than it was | The ladder doubles instead of jumping 64 KiB to 1 MiB. Lengths above the floor are known to within a factor of two rather than eight. Conversation is unaffected, since the 1 KiB floor did not move |
| Mailbox delivery is exactly once | Collection removes, so two devices polling one tag race and one loses the message. The alternative is a mailbox that keeps copies of what it delivered, which is worse |
| Relay chaining not implemented | A single relay sees both endpoints of a session. Chaining two would split that knowledge, at a latency cost |

---

## Non goals

Recorded so that scope creep has something to be refused against.

- **Anonymity against a global passive adversary.** Rotelyx is not a mixnet
- **Protection from a compromised device.** A device that renders plaintext can
  have that plaintext taken
- **Deniability.** Not claimed. A recipient can prove what they received to
  anyone willing to trust their device
- **Guaranteed message deletion.** Any recipient can retain anything
- **Account recovery without a trust anchor.** Any mechanism that does not
  require a key the user holds is a backdoor, and Rotelyx will not ship one
