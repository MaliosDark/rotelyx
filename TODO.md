# Rotelyx TODO

Status as of 26 August 2026. 599 tests passing.

**Calls work, between two implementations.** A phone and a desktop have called
each other over the production relay with this project's own codec, and audio
crosses in both directions. Between two processes through a relay: 991 frames
sent and 944 received in twenty seconds, 79 ms queued, nothing dropped. `/call`
in the terminal client, a Call button in the desktop window and in the app.

Four faults stood in the way and none of them was visible from either end, and
the reason is worth keeping: a frame that cannot be decoded is concealed rather
than counted, so a call ran with eleven usable frames out of three thousand and
every layer said it was healthy. `CallEnded` reports concealment now.

**A conversation crosses the mailbox too.** A code shown on a phone and read by
the desktop window is one conversation, both directions, with read receipts.

**What a call still lacks:** echo cancellation that works in a room, congestion
control, more than two participants, and any measurement under deliberate loss
or on a mobile network.

**Echo cancellation was measured against a real room and removed -0.0 dB**, or
1.3 with the residual suppressor written after seeing that. `docs/ACOUSTIC.md`
has the ladder. Android uses the platform's canceller instead.

Two people have listened to the codec, and what that found was a broken test:
the rating scale was never shown to either of them. There is no perceptual
measurement of this codec yet, only the objective one.
`docs/listening-2026-08-21.txt` records how it was found.

**Open, found by running the phone's suite against this engine.** A conversation
read back from storage refuses to send: `Session::rekey_after_restore` has to run
first, and `session.rekeyAfterRestore` is not one of the operations
`rotelyx-mobile` exposes over the C ABI, so the phone cannot call it. The browser
build can, because it binds the method directly. Two tests in the phone client
fail on it. Ghost mode is unaffected, since nothing is read back.

**An external audit found two defects that every test here passed through.**
Both are fixed, both have regression tests, and both are worth stating plainly
because neither was a mistake in an algorithm.

**Media keys repeated their nonces between calls.** They were derived from the
group's exported secret and the speaker's position in the roster, which are
fixed for an MLS epoch, and the frame counter restarts at zero every call.
Ordinary messages do not advance an epoch. So hanging up and calling again
encrypted the second call's first frame under the first call's key and nonce.
Under ChaCha20-Poly1305 that loses confidentiality *and* integrity: two
ciphertexts under one nonce give the exclusive-or of the plaintexts, and two
authenticated messages under one nonce recover the Poly1305 key, after which
frames can be forged. The keys are now bound to a per-call value both ends
already agreed on in the call signalling. `rotelyx_call_open` takes it and
refuses without it; a call over a direct invitation, which has no signalling to
carry one, is refused rather than started on repeating keys.

**The safety number attested to nothing.** It was `BLAKE3(group_id)`, and a
group id is fixed at creation, so the number never moved when a member joined,
when a device was added, or when a key changed. The one primitive a person can
check by hand could not detect the thing it exists to detect. It is now the
sorted, length-prefixed set of member signature keys.

**A second audit round confirmed both by reproduction and the rating dropped
from Critical to High.** The rest of that report is now closed too, and the
short version of each is below. What none of it changes is the gate: the
composition still has not had an independent cryptographic review.

- **The mailbox held the group id in the clear.** An envelope carried the MLS
  message verbatim, and RFC 9420 puts `group_id` and `epoch` in cleartext ahead
  of the encrypted content, so an operator read a stable name for the
  conversation out of every envelope with no key. Rotating tags hid who; they
  did not hide that these belong together. The payload is now sealed under a key
  derived from the same exporter as the tag key, with the tag bound in.
- **The post-quantum wrap committed to nothing.** Anyone holding a member's
  published hybrid key could mint one and knock that member out of the group,
  and a wrap captured at one epoch replayed into the next. It is bound to the
  group, the epoch and the recipient now, and staging refuses to overwrite.
- **Reading a tag destroyed what was under it.** Collection removed on delivery,
  and a tag is derivable by every member and by one recently removed, so any of
  them could drain another member's mailbox silently and permanently. Delivery
  and removal are separate now: nothing goes until the recipient says it arrived.
- **The panic guard at the C boundary did nothing.** `catch_unwind` under
  `panic = "abort"` catches nothing, so a malformed input took the host
  application rather than the call. There is a `mobile` profile that unwinds.
- **Smaller ones, all closed**: decrypted secrets landed in unzeroized buffers;
  `receive` threw away the sender MLS had authenticated; the tag-key
  documentation told a third-party client to pin a key forever, which would let
  a removed member address the group for life; `Unsubscribe` counted itself as a
  deposit; there was no `deny.toml`; and the media parser had no fuzz target.

**Two the app shipped rather than wrote.** The bundled WebAssembly and the three
Android libraries predated the fixes they were supposed to carry, so the source
was right and the binaries were not. Rebuilt, and `test/shipped_engine_test.dart`
now fails if that happens again.

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
- [x] Cargo workspace, sixteen first party crates
- [x] Ed25519 identity with a `Debug` that redacts and key generation that
      panics rather than degrading if the OS entropy source is unavailable
- [x] Safety numbers, twelve groups of five digits, order independent
- [x] Framed wire format with the length cap validated before allocation

### Transport (L0 / L1)

- [x] Transport stack vendored into the repository, 123,893 lines across
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

- [x] DNS, nginx and TLS configured for `amber.telyx.me`
- [x] Relay running and verified end to end: `101 Switching Protocols` through
      Cloudflare and nginx
- [x] **The browser client could not have worked as served.** The site's
      Content-Security-Policy was written for static pages and says so in a
      comment beside it. `chat.html` is not static: it loads a WebAssembly
      module, instantiates it, and opens a WebSocket. Under `default-src 'none'`
      with no `connect-src`, all four are refused and the page renders and does
      nothing. Its own policy now, in `docs/DEPLOYMENT.md` section 6a, which is
      version controlled where the site is not
- [x] **The module itself is sound, and that was checked.** Valid module, the 61
      symbols the glue calls all exported, the 31 imports it needs all defined,
      cache stamp matching the binary beside it
- [x] **Opened the page in a browser and completed a conversation.** Two tabs
      against the deployed site: both loaded their WebAssembly and reached ready,
      met on a random rendezvous phrase, established a conversation, showed the
      *same* safety number on both sides, and delivered a message each way
      through the real mailbox. Nothing was wrong, which is worth as much as a
      failure would have been: before this, nobody had ever opened it.
      `scripts/browser-test/run` does the whole thing again in one command, with
      a DevTools client small enough to need no packages. Not in CI: it needs a
      browser and a deployed site, and a test that fails when the network is slow
      is one people learn to re-run
- [x] **The page will not let you send until the safety number is confirmed.**
      Found by driving it: the input and the button stay disabled through
      "conversation established" and only enable on "Numbers match". Worth
      recording because it is the kind of thing a later change could drop
      without anybody noticing, and `scripts/browser-test/run` now fails if it
      does

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
- [x] ~~Persistent blocklist, so a block survives a restart~~. Built, then
      removed: it refused nobody unwilling to be refused. See section 3, where
      blocking became withdrawing an invitation
- [ ] Derive the sealing key from the device keystore rather than a passphrase,
      where the platform offers one
- [x] **Encrypted MLS group state at rest, in the browser**, which is the only
      client that keeps any. `sealSession` puts the signing key, the hybrid key
      and the whole group state behind Argon2id at 64 MiB, because the obvious
      place to keep it there is local storage, which any script on the origin can
      read and which outlives the tab
- [x] **The lock exists, in the same format as the identity's.**
      `sealed::seal_bytes` and `store::save_conversation` put arbitrary state
      behind the same Argon2id and XChaCha20-Poly1305 the identity uses, owner
      only on disk, with a test that the file does not contain the plaintext and
      that a wrong passphrase gets nothing. The bytes are the participant rather
      than a message: whoever holds them reads everything the current epochs can
      read, so a sealed identity beside an unsealed conversation would make the
      seal on the identity a decoration
- [x] **Conversations survive a restart, in all three native clients.** The
      decision the item was waiting on is taken and it is the first of the three
      it listed: `listen` reopening on the same invitation, and **no new
      command**.

      An invitation already is the identity of a conversation. Each is answered
      on its own transport key and therefore at its own address; the
      per-conversation name both sides show each other is derived from that
      address; and the file is now named after it. A host that starts listening
      is already answering where it answered before, and a guest holding the same
      code already dials there. Neither of them was looking to see whether they
      had been here before.

      A `resume` command would have been a second way to do what `listen` does,
      and the mailbox would have made a conversation depend on a server the
      direct path exists to avoid.

      **The exchange cannot deadlock.** The dialer speaks first, as it always
      has: with state it sends `FrameKind::Resume` carrying the group it holds,
      without it a key package and nothing changes. A listener that gets a resume
      request and has nothing answers with an empty payload and the dialer starts
      again. Whoever has less decides, and the fallback is the path that already
      worked. Verified by deleting one side's file and watching both start fresh.

      **Saved before a word is typed, not on exit.** A conversation only written
      on a clean exit is one people lose to a closed terminal or a flat battery,
      and this side has just committed an epoch the other has already processed.
      Found by measurement: across four runs of the client the epoch went 1, 2,
      2, because the host was being killed before it saved. It goes 1, 2, 3, 4
      now, with the host killed every time.

      `a_saved_conversation_remembers_the_epoch_it_reached` pins the property in
      `rotelyx-crypto`, because reopening the same epoch for ever is the rollback
      `restored_needs_rekey` exists to prevent, reached through the door marked
      save.

      The web client keeps its identity unsealed, so there is no passphrase to
      reuse; its conversations are sealed under a key derived from that identity,
      which is **exactly as strong as the key file beside them and no stronger**,
      and the comment says so rather than implying a lock
- [x] **A backup format that does not create a state rollback vector**,
      `crates/rotelyx-core/src/backup.rs`. The first thing it says is what is
      actually on the table: **a backup is a rollback vector, that is what a
      backup is**. A file that restores a group to the state it held an hour ago
      restores the message keys that were used and deleted in that hour, and
      forward secrecy *is* the deletion of those keys. No format changes that.

      Three narrower things it does instead, each worth having on its own.
      The file is **sealed**, under the same Argon2id and XChaCha20-Poly1305 as
      the identity, so a backup on a laptop is not the whole conversation in the
      clear. The device **notices**: it keeps a high-water mark of the furthest
      epoch it has ever held, the mark does not live inside the backup, and a
      restore that moves backwards is refused by name. And the restored copy
      **cannot send until it has rekeyed**, which `Group::reopen` already
      enforced with `restored_needs_rekey`.

      The header travels sealed rather than beside the ciphertext, because the
      header is the input to the rollback check: an attacker who could edit the
      epoch in the clear would walk any backup past it.

      What the mark does not defend against is written down rather than implied.
      It is a file on the same device, so an attacker who restores the whole
      device restores the mark with it. Closing that needs somewhere the device
      cannot rewrite, or the other member noticing, and the other member noticing
      already exists: a rolled-back copy must rekey before it speaks, and the
      rekey is a commit the other side sees. The mark stops the ordinary case,
      somebody restoring an old file by accident, which is the far likelier one.

      **Writing the tests found a real defect one layer down.** `open_bytes`
      rejected its own output: its minimum length counted a 32 byte identity
      secret that arbitrary state does not have, so sealing anything shorter came
      back as `Truncated { len: 77, min: 97 }`. Fixed, with a round-trip test at
      0, 1, 12, 31, 32 and 33 bytes.

      Deliberately not wired to a command. The item above it is blocked on a
      product decision about how two sides find each other again, and a restore
      that nothing can reopen would be the file that only grows a risk

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
- [x] **`revokeWake` now needs a secret, and `registerWake` now needs the
      current one to replace a row.** The first half alone achieved nothing:
      registration replaced any row with a matching token without asking for
      anything, so learning a device token still let an attacker claim it and
      then revoke it, locking the owner out on the way. A push token is an
      address, not a credential. Replacement now requires proving the secret the
      row was registered with, and the reinstall case is unaffected because a
      reinstalled app is issued a new token and the old row dies on Apple's 410.
      Six tests, two of them end to end over the WebSocket
- [x] **A refused registration told whoever holds a token that this server had
      a row for it**, and the parties holding every push token are Apple and
      Google. The way out was not to lie about registering: a row is now
      identified by the token **and** the secret, so a caller with a secret of
      its own gets a row of its own instead of an answer about somebody else's.
      The owner's row is untouched and still only theirs to revoke, which is
      what the refusal was protecting. Wakes are sent one per distinct token so
      extra rows are not extra pushes, and a token holds at most four rows,
      reached silently because a reply that changed at the bound would be the
      same oracle a few registrations later
- [x] **A wake secret had no floor.** `revokeWake` needs no capability and no
      rate limit, and it removes every row whose secret hashes to what it was
      given, so a guessable secret was a device anybody could silence. The same
      measurement that forced the vault cache put that path at thousands of
      attempts a second. A secret is now absent or at least 32 characters. No
      client implements `registerWake` yet, which is why this cost nothing to
      add and why it had to be added before one did
- [x] **The sweep never removed anything.** It handed each token Apple reported
      dead to `revoke`, which hashes what it is given and compares it against
      hashes of secrets. A token is not a secret, so nothing matched: dead rows
      stayed forever and were pushed to forever, while the log said they had
      been forgotten. It also meant the reinstall case that justified requiring
      a secret rested on a mechanism that did nothing. `forget_token` removes by
      token, with a test
- [x] **The published systemd units carried the operator's account name and
      home directory**, in files meant to be read by other people. The same
      class of leak the build scripts already refuse in binaries, which slipped
      through because these are documentation rather than an artifact.
      Placeholders now.

      Writing this entry reintroduced it: the first version quoted the real
      account name and path as evidence. A note about a leak is published too
- [x] **One free caller could take the free tier away from everybody.** The
      free capability used a constant meter id, so every unauthenticated caller
      on a mailbox drew from one 64 MiB bucket that resets once a day. Filling it
      needed no token, no payment and no identity, and at the free fanout of 25
      with 64 KiB envelopes that is 41 deposits. The metering built to stop abuse
      was the cheapest way to commit it. Each free caller now gets a fresh random
      id. The tests that existed covered two *bought* tokens, which have
      different ids by construction, so none of them ever reached the free path;
      the new one fails without the fix
- [x] **A mailbox holds at most four thousand sockets open.** Nothing bounded
      it: a connection costs a descriptor, a task and a buffer, and opening them
      in a loop costs the other end no token, no payment and no identity. The
      metering counts bytes deposited and never counts a connection that
      deposits nothing, so a caller that only opens sockets was free. Refusing
      at a ceiling is the honest failure; running out of descriptors is the same
      denial arriving later and taking the accepted connections with it
- [x] **Per-address limits on a mailbox, in the mailbox.** The ceiling above
      bounded the resource whatever was in front and could not tell one caller
      from a thousand. This item used to say the limits belong in the reverse
      proxy. They do belong there and they were never going to arrive there: the
      control panel rejected `limit_conn` and `limit_req` twice, and re-measured
      on 23 August 2026 there is still no refusal at any layer, 25 requests to
      `/mailbox` and 20 to the site root and not one 429.

      The deeper reason to move them is that **a proxy is not always there**.
      Somebody running this on their own machine has no nginx and no control
      panel, and a limit that only exists in a configuration file most operators
      will never write is a limit most deployments do not have.

      `crates/rotelyx-mailbox-server/src/limits.rs`: 16 concurrent connections
      per address, 60 a minute with a burst of 20, 4096 in total, idle buckets
      forgotten after ten minutes. Keyed on the **address**, not the address and
      port, because a fresh connection gets a fresh source port and keying on
      the pair would give every connection its own bucket and limit nothing.

      The slot is released on `Drop` rather than by the handler, because a
      handler that returns early, panics, or is cancelled mid-await still has to
      give it back, and all three happen on a websocket.

      **Behind a proxy every connection arrives from the proxy**, so keying on
      the address would put the world in one bucket and the first abuser would
      lock out everybody, which is worse than no limit. A forwarded address is
      believed only from an address named with `--trusted-proxy`, and only the
      right-most hop of `X-Forwarded-For`, which is the one that proxy wrote.
      Ignored by default: a header is written by whoever is talking to us.

      Eight unit tests and one over a real socket, and the wire one was checked
      by removing the limit and watching it fail. What it is worth is stated
      rather than implied: an address is worth less than an identity, it is
      shared by everyone behind one NAT and cheap for an attacker with a subnet.
      This stops one host holding sockets until the server runs out. The total
      cap is what bounds the patient attacker
- [!] **A bought token links its holder's deposits to each other.** The id names
      nobody, which is not the same as linking nothing: the meter counts against
      it, so the mailbox sees a stable pseudonym with a usage history across
      every deposit made under that token. Blind issuance solves the issuer
      recognising what it signed, which is a different problem. Sealed sender
      hides the sender inside the envelope; the token is outside it. Recorded in
      ADV-4 rather than fixed, because fixing it means one token per deposit and
      that is a design decision, not a patch
- [x] **Section 6 claimed a complete review of a set that had grown.** "Every
      comparison ... was located and classified" was true when written and
      nothing kept it true: the vault's passphrase check and the wake registry's
      revocation secret were added afterwards and neither reached the table. Both
      are listed now, and
      `crates/rotelyx-crypto/tests/secret_comparisons.rs` fails the build on a
      comparison the table does not mention, or a row describing code that is
      gone. The same shape as the guard on foreign infrastructure, which already
      says in its own header that a promise in a document does not enforce itself
- [x] **A membership change was reported as "something happened".**
      `Conversation::receive` returned the same value for a commit that added a
      member, a routine rekey, and a message it did not recognise, so the clients
      announced "the group changed" for all three and could show only a count.
      One commit can remove a member and add another, which leaves the count
      where it was: a client reading only the number says "2 members" while the
      person on the other side has been replaced. It now reports who joined and
      who left, and the terminal, desktop and browser clients name them. The
      browser page already read the whole roster aloud, which is why it was the
      only one this did not affect
- [x] **The wasm binding says which of three things arrived.** It returned the
      plaintext or `undefined`, and `undefined` meant a member joining, a
      routine rekey, and a message the group did not recognise, so `chat.html`
      announced that the group had changed for all three. A notice a person is
      meant to read, firing on ordinary traffic, is a notice people learn to
      dismiss. It returns JSON naming the case now, and the page says who joined
      or left by name and stays quiet on a rekey. Verified by building the wasm,
      serving `site/` locally against a mailbox of its own, and running
      `scripts/browser-test/run` at it: conversation established, safety numbers
      matching, a message delivered each way
- [x] **A timing test measured the machine's spare capacity.** The MDCT speed
      bound averaged one run and failed at 10.6% against a 10% limit while a
      build was running, then passed three times in a row a minute later on the
      same machine. A test that fails for reasons the code did not cause is one
      people learn to re-run, and a test people re-run guards nothing. It takes
      the fastest of five batches now: stolen time only ever makes a batch
      slower, so the minimum reads the transform rather than the load, and a
      real regression slows every batch including that one
- [x] **One identity was shown to every contact, so contacts could link you.**
      This was the SimpleX property that per-invitation addresses only half
      delivered: each contact reached a different address, and then the group
      handshake showed all of them the same long-lived identity. All three
      clients derive a name per conversation now, from the invitation secret
      both sides hold. Measured with a real relay: the identity is `ef53e87e`,
      one contact sees `a82d5b96`, another sees `e875cc93`. It cost no
      authentication, because an MLS credential is a label the member chooses
      and never proved anything; what it costs is recognising the same person in
      two places, which is the point
- [x] **Swept every "Defended" line in the threat model against what enforces
      it.** Ten adversaries and the side-channel section. Corrected: ADV-3 (the
      relay still links correspondents through the alias table), ADV-4 (a bought
      token links its holder's deposits), ADV-5 ("no key material on any server"
      was too broad: a mailbox that wakes devices holds the APNs private key and
      its registry passphrase), ADV-9 (named jitter as a mitigation, which the
      design deliberately rejects in favour of one fixed schedule for every
      device), ADV-7 (the count-only reporting above). ADV-1, ADV-2 and ADV-10
      hold up; ADV-6 and ADV-8 claim nothing
- [x] **ADV-2 had no test at L2.** It claims injection and modification fail
      authentication at both layers and that replay is rejected. What existed was
      `no_single_byte_corruption_panics`, which discards the result: it asserts
      nothing crashes, not that anything is refused. An implementation that
      quietly accepted a tampered ciphertext passed the whole suite. Two tests
      now refuse a modified message across eight positions and refuse a replayed
      one
- [x] **Only one side of a conversation padded its messages.** MLS applies
      padding per member and only the group's creator had it set; a joiner took
      the library default of none, so its ciphertext grew a byte for every byte
      of plaintext. Measured: 318 bytes for every plaintext from 1 to 100 on the
      creator's side, and 146, 155, 195, 246 on the joiner's. With two people
      that is one direction whose lengths a relay reads off the wire, and ADV-1
      says padding buckets hide them. Both sides pad now, with a test that fails
      if the two ever differ
- [x] **Review gate 4, the state-corruption class, measured rather than
      reasoned about.** One backup on two devices and a rollback to an older one
      both end the same way: the receiver refuses, because it deletes each
      generation's secret as it uses it. A sender jumping ahead is bounded at a
      thousand skipped generations. A message replayed into a reinstalled device
      is refused as too old. Written up in section 5b of the threat model, with a
      test for each: three of the four hold because of library behaviour this
      crate never chose, so an upgrade could move them without anybody noticing
- [x] **A restored copy refuses to send until it has rekeyed.** It used to send
      into a hole: a copy reopened from storage believes it is at a generation
      the group has spent, the receiver refuses everything it sends because it
      deletes each generation's secret as it uses it, and `send` succeeded
      anyway. Nothing told the person holding the device, so to them messages
      simply stopped arriving. Confidentiality held and availability did not,
      silently, which is the worst way for anything to fail. `send` now returns
      `RestoredAndNotRekeyed`, and `rekey_after_restore` moves the epoch and
      returns the commit the caller has to deliver. It cannot be done inside
      `reopen`, which has no way to send anything: a rekey nobody receives is
      the same failure from the other side
- [x] **Swept the other four documents the same way.** The README, the
      architecture note, the codec note and the paper. Corrected: "addressing is
      never transmitted", which said no addressing information crosses the
      network and described a mailbox that could not route at all, contradicting
      ADV-4 of this project's own threat model where the rotating tag is exactly
      what the operator sees. It appeared in the architecture note, in the paper,
      and inside a paper figure as the label "tag never transmitted", which is
      the worst place for it because a figure is read at a glance. The key is
      what never travels; the tag derived from it must. Also corrected: the
      paper still named jittered delivery as a mitigation, and the README said
      the mailbox is not told who sent a message without saying that a bought
      token links one buyer's deposits to each other
- [x] **`AddressLookup` said it had two variants and has one.** The comment
      described "nothing" and "our own rendezvous"; only the first exists. What
      it enforces is stronger than the comment implied, since a single-variant
      enum cannot be set to anything else
- [x] **Ran the MLS fuzzer for forty minutes: 8.5M cases, 2,563 coverage
      points, nothing.** The one artifact was a "slow unit" of 44 seconds for
      1,761 bytes, which looked like a denial of service worth panicking about
      and was 78 ms when run on its own. libFuzzer times a case by the clock on
      the wall, and I had started the full test suite beside it. Same mistake as
      the MDCT bound. The manifest now says not to
- [x] **No identifiers, the SimpleX property, in the terminal client.** A client
      that puts its long-lived identity in every MLS credential shows every
      contact the same value, which is the linkage per-invitation addresses take
      away from the network and then hand straight to the contacts. A name is now
      derived per conversation from the invitation secret, which both sides know
      and nobody else does. Measured live with a real relay: Alice's identity is
      `ef53e87e`, Bob sees `a82d5b96`, Carol sees `e875cc93`, and the safety
      number matches inside each conversation. Two of her contacts cannot compare
      notes. It costs no authentication, because the credential was a label the
      member chose and never proved anything; what it costs is recognising the
      same person in two places, which is the point
- [x] **Blocking has never worked against anybody unwilling to be blocked, so
      it became revocation.** Measured first: a peer that puts its real identity
      in the credential was refused, and the same peer putting any other bytes
      there was admitted, because the credential is chosen by the member and
      nothing proves it. `Gate::admit` also checked the blocklist against the
      transport peer, which is an ephemeral per-invitation key, so that never
      matched at all. Somebody was told a block worked and was reachable anyway.

      **Decision taken: "block" means "withdraw the invitation they came in
      on".** There is no identity to ban and there was never going to be one,
      because a caller arrives on a key belonging to one invitation and the name
      anybody sees is derived per conversation. What can be withdrawn is the
      invitation, and that is checked against a secret this side holds rather
      than against something the caller chose to say about itself, which is
      exactly why it works where the blocklist did not.

      Gone entirely: `Blocklist`, `Paths::blocks`, `Gate::block`,
      `Gate::unblock`, `Gate::is_blocked`, `Gate::blocked_member`,
      `AccessError::Blocked`, `refuse_if_blocked`, and the `unblock` and
      `blocks` commands in both clients. Dead machinery that looks alive is the
      thing the old item called the worst of the three outcomes.

      Added: `store::revoke_invitation`, `rotelyx invitations` to list what can
      be withdrawn, and `rotelyx block <n|code>`. The desktop panel says the
      same thing in the same words. `a_revoked_invitation_is_refused_over_the_wire`
      replaces the blocking test it used to be, and now proves something true.

      What the interface says out loud, because it would otherwise be assumed:
      withdrawing stops the next connection and not one already open, and there
      is no undo. To let somebody back in, issue a new invitation.

      **Withdrawing now takes the conversation with it.** An invitation retired
      while the conversation it carried stays on the disk is a person told they
      are blocked and a file that still decrypts everything they said. All three
      clients forget it, which also gave the web client the withdraw it never
      had: `POST /api/withdraw`, verified against the running server, two
      invitations down to one and a 404 for a code it never issued
- [x] **Decided: the relay stays open.** Open costs capacity and a connection
      log covering people with no relationship to the operator; it costs no
      confidentiality, because it forwards ciphertext it cannot read either way.
      Closing it is one file and one flag and the unit says how, so this is
      reversible on any day it stops being the right answer
- [x] **The desktop and web clients bind per invitation now, so they have
      per-conversation names too.** Both listened under the identity, which put
      every caller at one address and left the host unable to tell which
      invitation was used. They bind the newest invitation and answer at the
      rest, derive the name from whichever address answered, and dial with an
      ephemeral transport key instead of the identity. Verified by driving two
      web clients through two conversations in a real browser: each pair's
      safety number matches on both sides and the two pairs differ
- [x] **The desktop could not accept the invitation code it issues.** It wrote
      sixty four bytes, secret and address, and its connect parsed thirty two
      and refused anything else. Both clients read the whole code now
- [x] **The web client had an invitation format of its own**, `<secret>
      <expiry>`, with no transport key in it, so it could only ever listen under
      its identity and its codes were not the codes anything else issues. It
      shares `rotelyx-core::store` now. Its gate also rebuilt every invitation
      through `Invitation::from_secret`, which generates a *fresh* transport
      key, so every address in the gate was unrelated to the address its holder
      had been told to call
- [x] **A client must dial the address inside its code.** Found by driving it:
      pasting the host's endpoint address and a code belonging to a different
      invitation is refused, which is the address binding working. The id now
      comes from the code and the network addresses from what was pasted: one
      says which key to ask for, the other says where the machine is
- [x] **Nine hundred million fuzzing cases, nothing found.** Twenty five minutes
      on each target, one at a time and with no build running beside them:
      279,856,821 on the frame reader at 78 coverage points, 604,526,799 on the
      envelope parser at 39, and 15,156,212 on MLS handling at 2,565 with a
      corpus of 1,635. No crash, no hang, no artifact. The first two are small
      parsers and their coverage did not move with a seeded corpus, which is the
      honest reading: that is probably all of them
- [x] **Both sides derive the conversation name from the address, not from the
      invitation secret.** The secret is only shared when the caller arrived with
      a code: an open host that holds live invitations answers at an invitation's
      address, and a caller without one has no secret to derive from, so the two
      would compute different names and read out safety numbers that cannot
      match. That is a break that looks exactly like somebody in the middle. The
      address is the thing both sides always know, and it does not need to be
      secret, because what is hashed with it is the identity's own key. Verified
      live on both paths: with invitations, and with an open host
- [x] **The desktop dialled the address pasted beside a code rather than the one
      inside it.** The same defect the web had, left behind when its code parsing
      was fixed and its dialling was not
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
- [x] **MLS multi device as separate leaves rather than shared keys.**
      `Member::for_device(person, device)` gives each device its own signing key
      and its own leaf. The alternative is devices sharing one key, which is
      simpler and wrong where it counts: a shared key cannot be taken from one
      device without taking it from all of them, and nothing in the group can
      tell which device sent a message, so a stolen phone is indistinguishable
      from its owner until somebody notices.

      The credential carries `person_len ‖ person ‖ device`, one byte of length
      rather than a delimiter because a person's bytes are a hash and can contain
      anything a delimiter could be. `Participant` keeps `identity` meaning the
      person, so every caller comparing it against a name still works, and gains
      `device` and `well_formed`. A credential from another implementation is
      reported as unparseable rather than split at a plausible place, and two
      unparseable credentials are never "the same person" however identical their
      bytes.

      **What this does not prove** is written into the doc comment rather than
      left to be assumed: a credential says what its holder chose to say. What
      makes it mean anything is who committed the Add, so an interface should say
      "a device was added by Ana" rather than "Ana added a device"
- [x] **Device revocation that is visible to every conversation partner**,
      `Conversation::remove`. A lost device is a leaf that can still decrypt, and
      forgetting it locally changes nothing, so revocation has to be a commit.
      Being a commit is what makes it visible: everybody who applies it moves to
      an epoch derived without that leaf and sees the device in
      `MembershipChange::removed`. A revocation nobody else notices is one the
      removed device does not have to respect.

      Keyed on the signature key rather than a leaf index, because an index is a
      position in a tree that shifts as members come and go and a caller holding
      one across an epoch would remove somebody else. Removing yourself is
      refused by name: the commit would be encrypted under a key schedule you
      have just left.

      **Building this found a live bug.** `receive` computed who joined and left
      by comparing credential identities. That was wrong twice: the identity is
      self-asserted, so two members claiming the same one hid a real change, and
      once devices became separate leaves sharing a person, **adding a second
      device looked like nothing happening at all**. It compares signature keys
      now, which is what MLS authenticates

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
- [x] **Pre-echo, was 14.8 dB below the burst that causes it, now 40.7.** A 40 ms
      window spreads quantisation error over its whole length, so a plosive put
      noise into the silence before it. The item said the fix is block switching.
      It is not the only one, and it is the wrong one here.

      Block switching means noticing the transient and transforming it as
      several short windows: two more window shapes for the transitions, a
      second band layout, and a decoder that has to agree with the encoder about
      every frame's shape or the overlap-add stops reconstructing. This codec
      has one hop, 20 ms, chosen for a conversation, and the band tables and the
      pyramid quantiser are built on it.

      `crates/rotelyx-codec/src/tns.rs` reaches the same problem from the other
      end. A transient in time is a smooth ridge across frequency, so linear
      prediction *along the coefficients* has something to predict; code the
      prediction error and the decoder's synthesis filter shapes the noise by
      the temporal envelope it is rebuilding. The noise lands under the burst
      that masks it. One flag bit, three of order, four bits per tap, no change
      to the framing or the latency.

      | measurement | before | after |
      |---|---:|---:|
      | plosive, base codec | -14.8 dB | -40.7 dB |
      | plosive, layered at 30 bytes | -13.6 dB | -29.3 dB |
      | plosive, layered at 60 bytes | -13.9 dB | -30.9 dB |
      | gaps between words, `transients_amy` | -28.4 dB | -33.4 dB |
      | gaps between words, `fricatives_jenny` | -35.0 dB | -38.9 dB |

      Both are bounded now rather than reported, and both codecs are measured,
      because they were not: the shaping went into the layered codec, the
      pre-echo test drove the base one, and the first measurement read as no
      improvement whatsoever. Two encoders sharing one transform drift apart
      exactly there.

      **The gate is in the time domain, and that is the whole tuning.** The
      obvious trigger is prediction gain across frequency, and it is wrong: a
      nasal has harmonics evenly spaced in frequency, predicts beautifully, and
      has no transient at all. Shaping it flattens the comb the band energies
      were exploiting. Gating on prediction gain cost 2.1 dB of signal to noise
      on nasals for a problem they do not have; gating on whether one eighth of
      the window stands three times above the frame's average costs 0.4 dB and
      keeps every decibel of the gain. Swept, not guessed: at a ratio of 8 the
      filter never fires on real speech, at 2 it fires on held sounds

      Still not built, and now a smaller question: block switching, for the case
      shaping cannot reach
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
- [x] **Somebody listened.** 20 August 2026, one listener, three clips, blind
      and in random order. The reference scored 100 all three times, so the
      sessions are valid, and no rate scored below 80 against it, including
      12 kbit/s. Recorded in `docs/listening-2026-08-20.txt`
- [!] **What it does not support.** The spread within one rate is 13.1 and the
      largest gap between rates is 10.0, so with one listener the three rates
      are not distinguishable from each other. It says the codec is usable at
      12 kbit/s; it does not say how much better 24 is, and must not be quoted
      as though it did
- [x] **Figure 5 drew one statistic and its caption quoted another.** The bar is
      the full range, 70 to 100 for 16 kbit/s, and the caption cited the spread,
      13.1, without saying they were different measures. A reader who measured
      the bar got 30 and read 13.1. In a figure whose whole purpose is being
      honest about weak data that is the wrong defect to leave in. Both now name
      what they are, checked by rendering it rather than by reading the source
- [x] **Every rating went into one file with no name on it.** A second listener
      would have been pooled into an average describing neither person, and the
      pooling could not be undone afterwards, because the ratings are the only
      record of who said what. Since the entire value of a second listener is
      seeing whether two people agree, that would have wasted the session the way
      the orphan-file bug already wasted one. `scripts/listen --as <name>` now
      writes per listener, and `--reveal` prints each listener separately plus
      where they disagree. The first session was moved to `ratings-2026-08-20.txt`
      unchanged, and reproduces its published means exactly
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
- [x] **A second pair of ears, 21 August 2026.** Same three clips, blind and
      random. It did not settle the rate comparison, it closed it: pooled,
      24 kbit/s and 16 kbit/s differ by 1.7 points while the spread within one
      rate is 11.7, so adding a listener made the gap *smaller*. The second
      listener scored 16 kbit/s above 24, inverted against the measurement, and
      the first had produced an inverted point of its own. Both disagree with the
      measurement about 16 kbit/s, in opposite directions, which is where the
      instability lives. What is now supported by two people: the reference was
      identified as untouched six times out of six, and nothing scored below 70
- [!] **The second listener wrote the codec.** Recorded beside the numbers
      rather than in a footnote, because the bias is visible in them: every coded
      rate scored higher than listener A gave it, by 3.3, 10.0 and 7.3 points.
      Blind randomised order stops a listener knowing which file is which, and
      stops nothing else
- [ ] **A listener with no stake in the answer.** Two people, one of whom wrote
      the codec, is not two independent measurements. This is what the rate
      comparison is actually blocked on, and more clips will not substitute
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
- [x] **Analysis by synthesis in the residual quantiser.** Measured, and the
      answer moved most of the item somewhere else. The residual quantiser was
      already doing it: `rvq::encode` projects the residual onto each stage's
      shape and subtracts the *quantised* gain, so the next stage corrects the
      error the decoder will really make, and the pyramid search maximises the
      match with the target rather than rounding in a parameter. For a
      one-dimensional gain the error is a parabola with its minimum at the
      projection, so the nearest level is the best level and there is nothing to
      win.

      The gap was one level up, in the **band energy**. The encoder measured a
      band's energy and rounded it to the grid, which is the best answer to "how
      loud was this band" and not to "which level, times the shape the decoder
      will hold, lands closest to the coefficients". The pyramid's shape is not
      the direction the energy was measured along, so the band always came out
      slightly too loud, always in the same direction.

      **It turns out to be free.** The pyramid codes direction and every search
      normalises before it starts, so a band's shape bits do not depend on its
      level at all. Only the bit allocation does. `refine_levels` proposes the
      best level and keeps it only when the split of bits across bands comes out
      identical, which costs no bits, no second search, and cannot make a frame
      worse because a change that does not reduce the error is not taken.

      | bytes a frame | nearest the energy | what ships now | the unreachable ideal |
      |---|---:|---:|---:|
      | 20 | 8.45 dB | 8.85 dB | 9.01 dB |
      | 30 | 14.07 dB | 14.39 dB | 14.74 dB |
      | 60 | 26.26 dB | 26.32 dB | 26.77 dB |
      | 120 | 28.23 dB | 28.23 dB | 28.95 dB |

      End to end on the recorded speech it is 0.1 to 0.3 dB, never negative. A
      small number, stated as small: the per-band figure is larger because it
      counts only funded bands, and full-band error is dominated by the bands
      that got no bits at all
- [x] **The same for the layered codec, and the trim moved inside it.** The
      trick above rests on the encoder knowing the shape the decoder will hold,
      and here it did not: `encode` produced every layer and `rotelyx-audio`
      called `frame.within(budget)` afterwards, against a budget taken from live
      congestion. The best level given four layers is not the best level given
      one, so the choice was being made against a frame nobody would receive.

      **Decision taken: the budget goes into the encoder.** `encode_within`
      trims the layers itself, then chooses each band's level against the stages
      that actually survived. `encode` is that call with no ceiling, so nothing
      else had to change. The pacer's number is now read before the encode
      rather than after it, which it always could have been.

      **Accepting band by band is what made it worth anything.** A level may
      only move if the frame comes out the same shape, because the energies
      decide the plan and the coded size of those energies decides the budget
      the plan is computed against. Proposing every band at once was refused
      four times in five, 2938 of 3552 frames, since one band moving is usually
      enough to change the arithmetic-coded length of the whole stream. Tried
      one band at a time, what one band spoils no longer costs the other twenty
      three.

      | clip | 12 kbit/s | 16 | 24 |
      |---|---|---|---|
      | digits_alan | 4.3 to 4.4 | 7.7 to 7.8 | 10.9 to 11.1 |
      | fricatives_jenny | 5.8 to 5.9 | 9.0 to 9.2 | 11.8 to 11.9 |
      | nasals_libritts | 8.5 to 8.7 | 13.2 to 13.3 | 17.9 to 17.9 |
      | plosives_ryan | 6.2 to 6.2 | 10.0 to 10.1 | 13.8 to 14.0 |
      | sibilants_lessac | 7.7 to 7.8 | 11.1 to 11.2 | 14.7 to 14.9 |
      | transients_amy | 3.8 to 3.8 | 7.7 to 7.7 | 11.3 to 11.4 |

      Better in fourteen of eighteen, unchanged in four, worse in none. Costs
      2.4% of real time against 1.9% for the base codec, where the bar is 25%.

      Two measurements exist now that did not: `layered_speech_across_the_budgets`
      and `the_layered_codec_runs_faster_than_real_time`. **Nothing measured the
      shipping codec on speech or on the clock at all**, which is how temporal
      noise shaping came to be wired into one codec and measured on the other
- [x] **A noise pre-processor**, `crates/rotelyx-audio/src/denoise.rs`, spectral
      subtraction over minimum-statistics noise estimation, taking 8 dB off a
      steady room. It sits between the echo canceller and the encoder, which is
      the only order that works: the canceller is predicting what the speaker
      played, and denoising before it would change the thing it is predicting.

      The stated prerequisite was wrong. This needs a capture stream, not a
      capture device, and the loopback the call already runs on is one. Writing
      "needs device capture first" is how an item nobody can start stays open.

      What it cannot do is written into a test rather than left implied:
      `a_sound_that_never_stops_is_treated_as_noise` pins the limitation that a
      minimum-statistics estimator learns any continuous sound as the floor. That
      is correct for a fan and wrong for a held note, and speech survives it only
      because speech stops
- [x] **A fast transform.** The MDCT was written from its definition and cost
      270% of real time on one core for one call, which meant the codec could
      not have run at all: 1.8 million multiplies and as many calls to `cos` per
      frame. Factored as a fold, a DCT-IV and a 480 point complex FFT, it is
      0.5%, and the whole codec is 1.2%. It is also 775 times more accurate,
      because an FFT accumulates in a tree of depth nine and the definition
      accumulates in a line of length 1920
- [x] **Block switching, long term prediction.** Both answered, neither built,
      and the reasons are different.

      **Block switching** was wanted for pre-echo, and pre-echo is fixed: `tns`
      took it from -14.8 dB to -40.7. Block switching would cost two more window
      shapes, a second band layout and a decoder that has to agree with the
      encoder about every frame's shape, for a problem that is now bounded and
      tested. It stays unbuilt on purpose rather than by omission.

      **Long term prediction was built, measured, and removed.** It is worth
      writing down in full because the measurement that justified it was wrong in
      a way that looked right.

      The first measurement predicted each window from the genuinely delayed
      signal and reported a median gain of 1.8 to 5.4 dB, with 60 to 87 percent
      of frames over a decibel. Convincing, and **unreachable**: with a 20 ms hop
      everything reconstructed ends where the current window begins, so
      predicting 1920 samples at a lag of 120 to 600 reads samples from after
      that point, which no decoder has.

      What is available is the last `lag` samples repeated, which is what a
      periodic signal's continuation is and is what CELP's adaptive codebook does
      for the same reason. That is worth **0.3 to 1.0 dB** on the recorded
      speech, against fourteen bits, which at 30 bytes a frame is 6% of it.

      Built before that was understood: `ltp.rs`, closed loop, with a decoder
      inside the encoder so both sides predicted from the same reconstruction.
      The plumbing was correct, confirmed by disabling the predictor and watching
      every number return exactly to baseline. It still made **every clip worse
      at every rate, by 0.6 to 3.0 dB**, and raising the gate to fire only on
      frames with 6 dB of gain walked the loss back towards zero and never past
      it.

      Two reasons. The reconstruction is not the main one: open loop on the clean
      signal is worth no more than closed loop, 0.7 dB against 0.6. The hop is.
      And the second generalises past this feature: subtracting the periodic part
      flattens the spectrum, and band energies plus normalised shapes are
      efficient *because* a speech spectrum is peaky. This codec pays twice for
      the same idea, which is the same mechanism that made temporal noise shaping
      cost 2.1 dB on nasals until it was gated on the time domain instead.

      Removed rather than left switched off. What survives is
      `measure_what_long_term_prediction_would_buy`, which now reports open loop
      and closed loop side by side, because the two being equal is the finding
- [x] **A call, end to end, in one binary**: `cargo run -p rotelyx-media
      --example call -- in.wav out.wav [loss%] [fidelity]`. The codec had no
      consumer and the media layer had no application; nothing in this
      repository made a call until this. Audio from a file through the encoder,
      frame encryption, a network that drops and reorders, the jitter buffer,
      the decoder, and out to a file you can play. At 20% loss: 53 gaps
      concealed in conversational mode against **4 in fidelity**, which is the
      whole argument for the second mode in one line
- [x] **Device capture, run against a real microphone at last.** `device.rs`
      had been written, compiled, and never executed: everything else in this
      repository can be tested on a machine with no sound card, and this cannot.
      Code written against a library's documentation and never run is the kind
      that opens a stream and delivers zeros for ever.

      There is a microphone on this machine now, so it was run.
      `the_microphone_reaches_the_codec_and_comes_back`, ignored by default
      because it needs hardware: one channel at 48 kHz with no resampling
      anywhere, three seconds captured at rms 0.0107, through the echo canceller
      and the noise suppressor and the layered codec, 148 frames at 19.0 kbit/s,
      and out the other side finite and audible rather than silent or clipped.

      It checks the failures that look like working code: a stream that opens and
      delivers zeros, a channel count read wrong so every other sample is
      dropped, a gain applied twice. It writes the result to a wav, because the
      one check that matters is somebody listening and no test can make it
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
- [x] **Packet loss concealment.** A gap played as silence, and a hole in the
      middle of a vowel is heard as a click at each edge rather than as a loss:
      the overlap-add window is fed a full frame and then nothing, so the signal
      falls off a cliff and climbs back out. `LayeredDecoder::conceal` carries
      the last frame's band energies forward as noise at those levels, quieter
      each time, so a short gap sounds like the same timbre continuing and a
      long one is inaudible within about a tenth of a second. Concealment that
      keeps inventing sound for a dead connection is a machine talking to
      itself, so it fades and the call path stops after eight in a row
- [x] **Acoustic echo cancellation.** A microphone in the same room as a
      loudspeaker hears the loudspeaker, so the far end hears itself: the single
      most unpleasant thing a telephone can do, and the reason the README told
      people to use headphones. What reaches the microphone is not what was
      played but what was played convolved with the room, so the room is
      measured rather than subtracted: a partitioned frequency-domain adaptive
      filter covering 128 ms, which is the buffering of two devices plus a small
      room. **38.3 dB removed** on a synthetic path with an unknown delay and
      four reflections, driven by white noise. Both of those conditions turned
      out to be doing the work: see the item below, which measured it against a
      real speaker and a real microphone and got 1 dB.
      Two things it took to get there, both written down where they happened.
      Normalising each partition against its own power diverges: twenty four
      partitions each take a full step, so it overshot every block and came out
      *louder* than the microphone, measured at -26 dB, which is to say it was
      adding echo. And without zeroing the half of each partition's impulse
      response that the transform invents, it reached 19 dB rather than 38: the
      filter spends its step size chasing circular wrap-around that is not part
      of any room.
      Adaptation freezes while both ends talk, with a test: a filter that keeps
      learning through double talk learns to predict the near end and starts
      subtracting *them*, which is how a canceller chews words
- [x] **Congestion control.** A call cannot slow down and arrive later: audio
      that is late is dropped rather than queued, so congestion is invisible in
      the ordinary way. Nothing backs up, the sender keeps producing, and what a
      listener hears is not a slower call but holes. The rate comes down on
      purpose instead, and the layered codec is what makes that possible without
      renegotiating anything: a frame cut shorter still decodes, rougher.
      It watches loss *and* delay, which say different things. Loss is a queue
      that already overflowed, so somebody has already heard the hole. The round
      trip climbing above the lowest this connection has managed is the same
      event a second earlier, and that is the one worth reacting to. The round
      trip on its own says nothing: a satellite link is slow and empty, and
      there is a test that distance is not mistaken for congestion.
      Down fast and up slowly, because a rougher frame for a second is cheap and
      refilling a queue is not. The floor is 30 bytes, which is 12 kbit/s: the
      lowest rate anybody has actually listened to this codec at. Going below a
      rate nobody has heard would be choosing a number because the arithmetic
      allowed it
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
- [x] **Decided: the media engine stays ours.** The argument for taking one is
      still true and worth leaving on the record. None of SimpleX, Session, Briar
      or Cwtch built their own: SimpleX uses WebRTC and the other three have no
      calls at all. Opus, a jitter buffer, packet loss concealment and echo
      cancellation are decades of work each.

      The decision goes the other way, and it is the owner's to make. It is also
      largely already executed, which changes what is being decided: the codec,
      the adaptive jitter buffer, the concealment, the echo canceller, the noise
      suppressor, the pacer and the forwarding unit are written, measured and
      tested here.

      **What that costs, stated rather than glossed.** Against a mature stack we
      do not have: a trained vector quantiser for the envelope, block switching,
      automatic gain control, or any of the tuning by ear that a decade of
      shipping buys. What we do have is measured rather than assumed, which is
      the trade in the other direction: 58.3 dB of echo removed against a
      synthetic path and about 7 dB against a real room, both measured in
      `docs/ACOUSTIC.md`; 12.9 dB off synthetic hiss and 4.8 dB off a real room,
      with the limitation of a
      minimum-statistics estimator written into a test, pre-echo at -40.7 dB,
      concealment that fades rather than repeats, and a codec that costs 2.4% of
      one core.

      Two things follow. Every one of those numbers is now ours to defend, and
      the items below that need ears or a corpus stop being optional: nobody
      else's tuning is going to arrive and fix them
- [x] **A forwarding unit for group calls**, `rotelyx-media::forward`. The frame
      format already suited one: the header is authenticated but not encrypted,
      so it routes by sender without reading anything. Below a handful of people
      nothing is needed, but a six-way mesh asks a phone on a home connection to
      upload five streams at once, and that is where calls happen.

      **The leak this item named turned out to be two leaks, and one of them
      closes.** Sizes were the first: speech is not a constant bit rate, a coded
      frame of silence is smaller than a vowel, so datagram lengths alone are a
      voice activity detector anybody on the path can run. `Sender::pad_to` makes
      every frame come out the same size, padded **inside** the encryption,
      because padding after the tag tells anybody counting bytes exactly how much
      of it is padding.

      ISO/IEC 7816-4, and the marker is written on every frame whether or not
      anything is padded. That costs one byte always, overhead 18 to 19, and it
      buys there being no flag in the clear saying which frames were padded,
      which would have been most of what the padding was hiding.

      The second leak does not close: the forwarder knows which connection a
      datagram arrived on, so it knows who sent it. Hiding that needs onion
      routing or a group small enough not to need a forwarder, and it is written
      down rather than implied.

      **The routing does check one thing.** The sender id in the header is
      associated data: the recipients can tell it was not altered, the forwarder
      holds no key and cannot check anything. So a participant could put somebody
      else's id in its header, and the recipients would refuse it *after* the
      impersonated stream had consumed their replay window at those counters,
      which silences a person without ever holding their key. `route` refuses a
      claimed id that does not match the connection it arrived on, which is the
      thing the forwarder actually knows.

      Ten tests, including that a speaker is not sent their own voice back, that
      what comes out still opens, and that a replay is still forwarded, because
      refusing one is the recipient's job and a forwarder dropping it would be
      deciding something it cannot check.

      Not a server: no sockets, no admission, no spawning. That shell belongs to
      whatever runs it, the way `rotelyx-relay` wraps its admission around
      `rotelyx-relay-proto`

- [x] **The echo canceller removed 1 dB in a real room, against 38.3 on the
      synthetic path. It removes about 7 now.** Measured on this machine with a real speaker and a real
      microphone, written up in `docs/ACOUSTIC.md`, repeatable with
      `scripts/measure-echo`.

      Two assumptions were doing the work and both come out one at a time. The
      far end in the published test is **white noise**, which excites every
      frequency at every instant, which is what a convergence proof wants and
      what a call never has: the same canceller and the same synthetic room give
      15.0 dB on noise and 7.9 dB on a recorded sentence. Then the room takes the
      rest, down to 1.1 dB.

      Clock drift was the first suspect and is not the answer. The speaker and
      the microphone are different devices whose crystals differ by 341 ppm, so
      the recording slides 48 samples every 2.9 seconds; measuring again on
      half-second windows each realigned to remove it gives the same 1.1 dB.

      The ceiling in that room is 21.8 dB, because that is how far the echo sits
      above the room's own noise. So the gap is real and not a limit of the
      setup.

      **The residual suppressor was built and it is most of the answer.** A
      linear filter removes what a linear model of the room can remove, and a
      room is not linear at the ends: the tail runs past the 128 ms of taps, and
      a small speaker driven hard adds harmonics that were never in the signal.
      A second stage estimates how much of the far end still comes through and
      attenuates by that much.

      Measured over 24.6 seconds of recorded speech, every clip joined so the
      signal never repeats:

      | echo path | how measured | linear only | with the residual stage |
      |---|---|---:|---:|
      | a model | continuous, white noise | 23.0 dB | **43.0 dB** |
      | a model | continuous, speech | 19.8 dB | 19.9 dB |
      | a real room | continuous | -0.0 dB | **1.3 dB** |
      | a real room | realigned every 0.5 s | 1.4 dB | **6.1 dB** |

      **The leak estimate has to track a minimum, not an average**, and that is
      not a detail. It is learned from what the filter leaves over, and anything
      the near end says is also left over, so an average is dragged up by their
      voice and a leak that is too high suppresses them. Averaging cost 92% of
      the near end's voice, and `a_voice_on_this_end_survives_double_talk` caught
      it, which is the whole reason that test exists.

      **And that test's own comment turned out to be wrong.** It says freezing
      adaptation during double talk is what protects the voice. The flag asks
      whether the residual is more than twice the far end's energy, which a near
      voice clears only if it is louder than the loudspeaker: in that test it
      never fires at all, so the voice had been surviving for a different reason
      than the comment claimed
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
      delay estimate is the next thing to try
- [x] **Measured the noise suppressor against a real room.** It removes
      **12.9 dB** from synthetic hiss added to the clip and **4.8 dB** from a real
      one, stable across runs to a tenth of a decibel. `docs/ACOUSTIC.md`,
      repeatable with `scripts/measure-denoise`.

      It fares better than the canceller, which lost almost everything, and it
      still loses two thirds. Why exactly is not established, and guessing would
      be the mistake that document exists to correct: real room noise is not
      white, there is mains hum and its harmonics, and which part of that a
      minimum-statistics estimator handles worse would need measuring rather than
      asserting.

      **A wrong guess is kept in the document because it was wrong.** The first
      explanation offered was reverberation, that a room's gaps carry the tail of
      the speech rather than noise, and that removing it would be removing the
      room's answer to the voice. Plausible, and false: the gaps measure 2.6 dB
      above the same room with nothing playing, so they are the noise floor with
      a little tail on top. The tool records the quiet room now and prints that
      number, because the story was good enough to have been believed
- [ ] **The suppressor costs 2.4 dB of speech, and the test allows 5.2.** Both
      the synthetic and the acoustic runs keep 56 to 58 percent of the speech
      energy, which is a real cost paid whether the noise was worth removing or
      not. `a_voice_survives` asks only that more than 30 percent survives. That
      bound is loose enough for the suppressor to get considerably worse without
      anything failing, which is the shape of a guard that stops guarding

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
- [x] **Packet loss concealment in a call.** The receiver counts the frames
      that never arrived rather than inferring a gap from silence, because a
      caller that waits to notice has already played the hole, and the call
      fills them from the codec before playing what did arrive. Reported as
      `frames_concealed`, which is the loss somebody actually heard
- [x] **Mixing, for more than one person speaking.** The playback device takes a
      queue and plays it in order, so handing it one person's frame and then
      another's played them one after the other: two people talking over each
      other came out taking turns at twice the speed, and the call fell a frame
      further behind every time. Sound adds rather than queues. Everything that
      arrives in a tick is summed at the same position and handed over together,
      and brought back only if the sum would actually clip, because dividing by
      the number of participants makes one person talking quieter every time
      somebody else joins whether or not they say anything.
      **The decoder was shared between senders too**, which is a worse version
      of the same mistake: half of every window is the tail of the previous one
      waiting to be added to the next, so two voices through one decoder each
      got half of the other folded into their own output, and a gap in one was
      concealed with the timbre of the other. With two participants only one
      ever sends, so nothing showed. One decoder per sender now
- [x] **A jitter buffer per speaker, on one playout clock.** It existed and the
      call was not using it. `MediaIn` has carried one the whole time and says
      so: `frame` is documented as being for tests and for a caller doing its
      own buffering, with a real call using `accept` and `play`. The call used
      `frame`, so it decoded on arrival and played on the *network's* clock,
      which makes every wobble in arrival time a wobble somebody hears and
      leaves two speakers interleaved on the way in and interleaved on the way
      out. It buffers per speaker now and takes one slot from each on the tick,
      which is one clock for everybody.
      That also puts the concealment where the design always said it went: a
      frame that misses its slot is `Missing`, a slot rather than an error, and
      that is what the decoder extrapolates over
- [x] **Built for Android**, on this machine, with NDK r27c and `cargo-ndk`
      4.1.2. `scripts/build-mobile android` produces all three ABIs Play
      requires:

      | ABI | bytes |
      |---|---:|
      | arm64-v8a | 14,357,088 |
      | armeabi-v7a | 10,366,932 |
      | x86_64 | 15,008,248 |

      x86_64 is not optional: without it nobody can run the app in an emulator on
      a laptop. Checked for the leak this project has had before, the build
      machine's paths in the shipped binary: zero home paths and zero occurrences
      of the username in all three, so `--remap-path-prefix` is doing its job on
      this target too.

      One trap for whoever runs it next: `cargo-ndk` 4 reads `-p` as `--package`,
      not as the platform level. `-p 21` fails with "unknown package: 21"
- [!] **iOS needs a Mac**, and no amount of wanting changes that. The targets and
      the `xcframework` step are in `scripts/build-mobile ios` and have never
      been run
- [x] **The C ABI is enough, demonstrated rather than argued.** The question was
      whether a foreign runtime can reach the engine through twelve C symbols and
      a JSON string, or whether it needs generated glue for records, enums and
      error types.

      `scripts/abi-check/run` answers it by being a foreign runtime: Python
      through `ctypes`, no compiler, no header, no binding generator, nothing
      this repository produced. It opens two sessions, exchanges a key package,
      invites, joins, sends an encrypted message and reads it back, then opens
      two calls and runs a second of audio from one to the other. 49 datagrams,
      50 slots played, peak 8864 out of a tone that went in at 8000, and the
      stats say `bufferMs 40, concealed 0, droppedTooLate 0`.

      If `ctypes` can do that, Kotlin through JNA and Swift through its C interop
      can, because both are better at this than `ctypes` is.

      **One thing found while doing it, and it argues the other way.**
      `rotelyx_call_deliver` takes four arguments, the fourth being the arrival
      time the jitter buffer places the frame by. Declaring three compiles, runs,
      returns success, and produces a second of silence, because the missing
      argument is whatever was in the register. A generated binding cannot make
      that mistake. The ABI is sufficient; it is not safe, and the difference is
      worth knowing before somebody writes the app.

      Also found: delivering a call's own datagrams back to itself drops every
      one, because a call builds a receiver for every participant except itself.
      That is correct, and it is what nobody hearing their own voice means
- [ ] Background lifecycle. iOS will not hold a socket, and every design
      decision downstream of "the phone hosts it" collides with this
- [x] **Silent pushes marked as decoys, on one fixed schedule.** Not jittered
      delivery, which this line used to plan and which would be a weakening: a
      device woken on a rhythm of its own is identifiable by that rhythm, so one
      schedule shared by every registered device is the stronger arrangement
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

- [x] **The wire says which wire it is, so a build that cannot be talked to is
      named rather than misunderstood.** `WIRE_VERSION` crosses in a
      `FrameKind::Hello` before anything that depends on it, and both ends refuse
      a mismatch by name.

      This exists because of what was measured earlier in this section. Two
      builds that disagree about a format do not fail cleanly: on the credential
      change a peer running the older build was understood **seven times in eight
      and misunderstood the eighth**, depending on the first byte of a key, and
      the eighth is not an error. It is a safety number that does not match, with
      no reason given, for that pair, for ever.

      A version reported only to the local caller cannot catch that, and
      `protocol_version()` was exactly that: a string handed to whoever asked,
      never crossing. It has to cross, and it has to cross first.

      A peer too old to say anything is named as such, which is a different
      answer from one that names a different version, and both beat a parse
      failure three frames later. One round trip per conversation, and the
      comment says so after an earlier draft claimed it was free.

- [ ] **The Flutter app ships a wasm three builds behind and cannot talk to
      anything current.** It reaches the engine through `rotelyx-wasm` and a JS
      bridge rather than the native library, and its copy hashes `b04f4425`
      against `9a71d887` from this source. That is older than the deployed site
      was before it was rebuilt, so it predates the credential change and is in
      the seven-in-eight case above.

      Not touched: it is somebody else's directory and it is in production. What
      it needs is `scripts/build-wasm` and the two files from `site/rotelyx/`
      copied into its `web/rotelyx/`, after which `WIRE_VERSION` will say plainly
      whether it worked

- [ ] **Redeploy `site/`. The live one is behind, and mixing it with a current
      client fails one time in eight.** This session changed the MLS credential
      from the person's bytes to `person_len ‖ person ‖ device`, so devices could
      be separate leaves. Both ends of this repository were changed together and
      every test passed, which is exactly why nothing caught it: a suite where
      both sides are built from the same commit cannot see a wire break.

      A 32 byte identity written the old way is read by a current client as a
      length byte and 31 bytes of person, and **whether that parses depends on
      the first byte of the key**. Above 31 the length runs off the end, the
      credential is kept whole, it happens to be 32 bytes and it happens to work.
      At or below 31 it splits, the identity comes out short, and
      `peer_identity` wants exactly 32, so the safety number cannot be computed.
      224 of 256 first bytes survive and 32 do not. Pinned by
      `the_credential_wire_format_is_pinned`.

      The fix is not a version byte. Nothing is released, so everything gets
      rebuilt and redeployed together: `site/`, and any CLI or desktop binary
      anybody is carrying.

      The new build is verified: `scripts/build-wasm` reproduces
      `9a71d8877f3db90df24de2018c83ad9e2fb3518ccc9b9723d5b9344d606a34c0`,
      `docs/ARTIFACTS.md` carries it, and `scripts/browser-test/run` drove two
      real tabs through a whole conversation against it with the safety numbers
      matching. `scripts/verify-deployment` reports DIFFERS until it is uploaded,
      which is the check working rather than failing

- [x] Deploy `rotelyx-mailbox-server` to `m1.telyx.me:3341`, verified
      end to end: `101 Switching Protocols` through Cloudflare, pfSense and nginx
- [x] Upload `site/` to `rotelyx.com`, and add the same `location /mailbox`
      block there so the page finds the mailbox at its own origin. Verified from
      outside on 2026-08-22: `scripts/verify-deployment` reports both served wasm
      artifacts matching the source, and `scripts/browser-test/run` against
      `https://rotelyx.com/chat.html` drives two real browsers through a
      whole conversation, safety numbers agreeing and messages delivered both
      ways. Delivery is what proves the proxy block: the page derives its mailbox
      from its own origin, so a message arriving at all means `wss://.../mailbox`
      is being routed
- [x] Persist mailbox state, encrypted under an operator passphrase, so a
      restart does not drop every uncollected envelope
- [x] Message history survives a reload, sealed under the same key as the
      session, with local arrival timestamps
- [x] **Message history survives a reload, sealed.** The line above was written
      when nothing stored messages at all and said the decision was still open.
      It was taken: `persist()` writes the log under the same vault key as the
      session, capped at five hundred entries, and `resumeWith` replays it. The
      decision it was waiting on is therefore made and worth stating plainly
      rather than leaving implied: this design keeps readable content at rest in
      exactly one place, a browser's local storage, behind Argon2id at 64 MiB,
      and `localStorage.removeItem` on the way out
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
- [x] **A way to actually run the check, which is what was missing.**
      `scripts/verify-deployment <url>` fetches what a server is handing out
      right now and compares it against `docs/ARTIFACTS.md`. The hashes were
      published and nobody ever compared them against a live deployment, and a
      published hash nobody checks is a claim rather than a check. Run against
      the live site the first time, it found the deployment two builds behind.
      **A signature was the wrong shape for this.** It would matter if the
      manifest travelled apart from the source; it does not, because git is the
      channel and git is already the thing being trusted. Signing would add a
      key to guard without narrowing the gap that is left.
      The gap that is left, said plainly in the script: this tells a browser
      nothing. Somebody loading the page runs whatever the server sent, and no
      code inside that page can prove otherwise, because it is code the server
      chose. A check from outside is the only place the check can honestly live
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
- [x] **Decided: the relay stays open**, recorded in section 3 with what it
      costs. Reversible: one file and one flag, and the unit says how
- [x] **Verified the module in a browser before deploying it.** Built it, served
      `site/` locally against a mailbox of its own, and ran
      `scripts/browser-test/run` at it: two tabs, conversation established,
      safety numbers matching, a message delivered each way
- [x] **`wasm-opt` is installed, was run, and is deliberately not used.** It
      makes the file smaller and the download larger, which is the opposite of
      the point. Measured, raw against `gzip -9`: none 1,514,620 / 533,914;
      `-Oz` 1,351,201 / 571,267; `-Os` 1,379,416 / 570,320; `-O2` 1,407,376 /
      574,203; `-O3` 1,396,050 / 572,908. Every level shrinks the file by about
      a tenth and costs about 36 KB compressed, and a server serves this
      compressed. The table is in `scripts/build-wasm` so the next person does
      not have to rediscover it, with a note that it is a property of this
      module and this version of the tool rather than a law

---

## Ongoing

- [x] **Upstream security patch watch**, `scripts/watch-upstream` and a weekly
      job in `.github/workflows/upstream.yml`, with the verdict on every
      advisory written down in `docs/UPSTREAM.md`. Vendoring means fixes no
      longer arrive on their own, and the first run found one that had been
      missing for two months: **RUSTSEC-2026-0185**, remote memory exhaustion in
      the QUIC stream assembler, reachable before a handshake completes. A peer
      that leaves a gap between every fragment leaves defragmentation nothing to
      join, so each one-byte frame keeps a whole packet buffer alive. Ported
      from quinn PR 2694 and pinned by
      `fragments_that_never_touch_are_refused_before_memory_runs_out`.

      What makes this worth having is why version numbers could not have found
      it. Every vendored crate was level with the newest release its upstream
      had published. The QUIC crates come from N0's fork of quinn, renamed and
      renumbered to 1.x: `noq-proto 1.1.1` was the newest `noq-proto` in
      existence and was still behind quinn. The advisory is filed under
      `quinn-proto`, and searching for `noq` finds nothing. So the watch looks
      advisories up under the original name, and clears each one by reading this
      tree rather than by comparing versions
- [x] **Dependency advisory check**, `scripts/audit-dependencies`, in the same
      weekly job. The watch above covers the 124,000 vendored lines where fixes
      never arrive on their own; this covers the other 719 packages, where fixes
      do arrive and still only when somebody is given a reason to run
      `cargo update`. Nothing had ever looked at that side. It matches every
      locked version against the RustSec database, separates vulnerabilities
      from unmaintained notices, and exits non-zero until every advisory id has
      a written verdict in `docs/UPSTREAM.md`.

      The first run found eight. One was real and fixed by updating: **h2**
      queueing empty DATA frames without limit, reached through the DNS
      resolver, 0.4.15 to 0.4.18. Six were unreachable and the reading is what
      established that: the libcrux AEAD crates are in `Cargo.lock` through a
      dev-dependency of a dependency and are never compiled, and the two
      `libcrux-sha3` bugs are in the incremental and AVX2 APIs while `hpke-rs`
      calls only the one-shot one. A checker that reads the lock file cannot
      tell a package apart from a package that is actually built, which is why
      the verdicts are written down rather than computed.

      The eighth has no fix and is a constraint on future work rather than a
      finding: **RUSTSEC-2023-0071**, the Marvin timing attack on `rsa`, with no
      patched version in existence. It reaches nothing today because no shipped
      binary performs an RSA private-key operation: `blind_sign` appears only
      under `#[cfg(test)]`, and both the mailbox server and the clients hold
      only the issuer's public key. **An issuer built on this crate and exposed
      to the network would leak the key that mints capability tokens.** That is
      a decision to take when the issuer is built, not after
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
- [x] **Fuzzing, with a real fuzzer.** `fuzz/` has a libFuzzer target for each
      of the three parsers the threat model names, run on nightly with
      `cargo +nightly fuzz run <target>`. First pass: 15.5M cases on the frame
      reader, 30.7M on the envelope parser once its corpus was seeded, and 1.5M
      on MLS handling, which got to 2,155 coverage points and a 1,187 case
      corpus. Nothing crashed, hung, or left an artifact. The envelope target
      found nothing at 29 coverage points until it was seeded with real
      envelopes and reached 39: a fuzzer that never gets past the length check
      proves nothing, and the number to watch is coverage rather than executions
- [x] **Ran them for twenty five minutes each instead of ninety seconds.** About
      nine hundred million cases across the three targets, one at a time with
      nothing building beside them. Nothing found
- [x] **Somewhere the fuzzers run without anybody remembering.**
      `.github/workflows/fuzz.yml`, nightly, fifteen minutes on each target, one
      target per job. Not on every push: twenty seconds of fuzzing on a push is a
      ritual that passes and proves nothing, and the passing gets mistaken for
      coverage. One job per target rather than three in a row, because libFuzzer
      times a case by the clock on the wall and a machine doing something else
      produces "slow unit" artifacts that are reports about the machine. A crash
      is kept as an artifact so somebody can replay it, and belongs in the
      ordinary suite as a regression rather than in a corpus nobody re-runs
- [x] **Constant time review**, recorded in `docs/THREAT-MODEL.md` section 6.
      Every comparison in the first-party crates touching a key, tag, token,
      proof or passphrase was located and classified. Three were already
      constant time and correct; the rest compare public values. One was not:
      `Tag` derived `PartialEq`, so it short-circuited on secret-derived bytes.
      **It was not exploitable** (reaching the comparison requires already
      knowing the tag) and it is constant time now regardless
- [x] **Measure whether the primitive libraries are constant time**, which that
      review explicitly did not do and did not claim.
      `crates/rotelyx-crypto/tests/constant_time.rs` is a dudect measurement:
      time an operation over two classes of input chosen so a leak separates
      them, Welch's t-test, |t| over 10 is not noise. In release, the control
      leaks at -650, `subtle::ConstantTimeEq` reads 1.3 and XChaCha20-Poly1305
      rejecting a forged tag reads 0.2. Those two carry every first-party secret
      comparison and every sealed file.

      **The null control is what makes it worth anything.** An earlier version
      gave each class its own array and reported `subtle::ConstantTimeEq`
      leaking at t = 65, reproducibly across runs. It was measuring the distance
      between two addresses: two buffers holding data that differed in the *same*
      byte produced t = -26 on their own. Both classes now read one buffer,
      flipped and restored outside the timed region. Without a control that
      nothing real could separate, that would have been written up as a finding
      in `subtle`.

      The harness also refuses to report an all-clear it did not earn: it
      measures a comparison written to leak first, and if the machine is too
      noisy to see that, it says so and stops rather than passing. Still
      unmeasured: `ed25519-dalek`, `ml-kem`, and the RSA blind signature path

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
