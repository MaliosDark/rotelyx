# What was done, and what it cost

Moved out of `TODO.md` so that file lists work rather than history. Kept
rather than deleted because several of these entries are the only record of a
measurement, and a number nobody wrote down has to be measured again.


### Foundations

- [x] Threat model written before code, ten adversaries modelled
- [x] Cargo workspace, nineteen first party crates
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
- [x] Tiers, capability tokens and metering. A token carries its own quota, so
      sharing it shares the allowance and one purchase cannot serve a thousand
      people without anybody being identified
- [x] Mailbox keepalive, so a proxy that cuts idle sockets does not end
      conversations, and `unsubscribe`, so a client stops consuming envelopes
      meant for others
- [x] Cross layer tests: a message surviving the whole offline path, and the
      operator's view containing no plaintext, sender or recipient


### 1. Field test across two real NATs `[!]`

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


### 2. Published test vectors for the post quantum composition

- [x] Seven deterministic vectors in `crates/rotelyx-crypto/tests/pq-vectors.txt`,
      verified against the implementation on every test run so the file cannot
      drift from the code
- [x] Written specification in `docs/PQ-COMPOSITION.md`, complete enough to
      reimplement from without reading our source
- [x] The construction extracted into pure functions taking their inputs, so it
      can be exercised without running MLS
- [x] Unambiguity of the binding pinned by a test rather than argued in prose

### 3. Encrypted at rest storage

- [x] Identity keys sealed with Argon2id and XChaCha20-Poly1305, with in place
      migration of plaintext keys from earlier builds
- [x] ~~Persistent blocklist, so a block survives a restart~~. Built, then
      removed: it refused nobody unwilling to be refused. See section 3, where
      blocking became withdrawing an invitation
- [x] **Encrypted MLS group state at rest, in the browser.** It was the only
      client that kept any when this was written; the native clients and the
      phone keep theirs now, sealed the same way, in the two items below.
      `sealSession` puts the signing key, the hybrid key
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

- [x] **nginx rate limits were rejected by the panel, so the limit moved into
      the servers.** `docs/nginx-relay.conf` carried `limit_conn` and
      `limit_req`, CWP refused both, they came out of the live configuration and
      the document went on describing them: the fourth time here that a document
      claimed a guarantee nothing enforced. Measured on 18 August and again on
      23 August, dozens of requests and not one refusal.

      A configuration file an operator has to write, on a panel that can veto
      it, is not where a limit belongs. Both servers now carry their own, so
      every deployment has one whether or not anybody reads that file, and
      `docs/nginx-relay.conf` says plainly that it is an optional extra rather
      than the limit. What nginx would still add, if a panel ever accepts it, is
      refusing before the TLS handshake completes
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
      client implemented `registerWake` when this was written, which is why it
      cost nothing to add and why it had to be added before one did. The phone
      client implements it now, and sends 64 hex characters, which clears the
      floor
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

### 5. Multi device

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

      **The phone could not do it until 29 August 2026.** `removeMember` was on
      the wasm surface and not on the C ABI, so the browser and the desktop
      could revoke and the Android client could not, which is the wrong way
      round: a phone is the device that gets lost. It is on the ABI now, with
      `rosterDetail` beside it, because either without the other is useless:
      `roster` gives labels, a label is a claim two members can both make, and
      removal takes a signature key.

      Long-press a member in the safety panel, which is the panel somebody
      opens when they are worried. The dialog says the three things that are
      assumed wrongly: everyone sees it, there is no undo, and it does not reach
      backwards.

      Two tests, and one of them found a real defect in the first version of
      this: the Dart sent `session.removeMember` without the session handle, so
      it failed at the boundary rather than removing anybody. Nothing above the
      ABI would have noticed.

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
- [x] **Built the listening test.** `bake_listening_test` writes eight versions
      of each clip: the original, Telyx at 12/16/24, Opus at the same rates from
      libopus, and a 3.5 kHz anchor. Same length, meaningless names, mapping
      withheld. `scripts/listen` plays them in random order and takes MUSHRA
      ratings; `--reveal` joins them to what they were
- [x] **Somebody listened.** 20 August 2026, one listener, three clips, blind
      and in random order. The reference scored 100 all three times, so the
      sessions are valid, and no rate scored below 80 against it, including
      12 kbit/s. Recorded in `docs/listening-2026-08-20.txt`
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
- [x] **A second pair of ears, 21 August 2026.** Same three clips, blind and
      random. It did not settle the rate comparison, it closed it: pooled,
      24 kbit/s and 16 kbit/s differ by 1.7 points while the spread within one
      rate is 11.7, so adding a listener made the gap *smaller*. The second
      listener scored 16 kbit/s above 24, inverted against the measurement, and
      the first had produced an inverted point of its own. Both disagree with the
      measurement about 16 kbit/s, in opposite directions, which is where the
      instability lives. What is now supported by two people: the reference was
      identified as untouched six times out of six, and nothing scored below 70
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
      synthetic path and 1.3 dB against a real room running continuously, both
      measured in `docs/ACOUSTIC.md`; 12.9 dB off synthetic hiss and 4.8 dB off a real room,
      with the limitation of a
      minimum-statistics estimator written into a test, pre-echo at -40.7 dB,
      concealment that fades rather than repeats, and a codec that costs 2.4% of
      one core.

      Two things follow. Every one of those numbers is now ours to defend, and
      the items below that need ears or a corpus stop being optional: nobody
      else's tuning is going to arrive and fix them
- [x] **A forwarding unit for group calls**, `rotelyx-media::forward`. The frame
      format already suited one: the header is authenticated but not encrypted,
      so it routes by sender without reading anything.

      Below a handful of people
      nothing is needed, but a six-way mesh asks a phone on a home connection to
      upload five streams at once, and that is where calls happen.

      **No client calls it.** The unit is written and tested; nothing wires it
      to a call, so a group call is not a thing anybody can place today. Said
      here because a ticked box beside the words "group calls" reads as a
      feature, and the gap between a component existing and a feature working is
      how three guarantees in this project ended up documented and unenforced.

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
      synthetic path. It removes 1.3 dB run continuously, which is how a call
      runs, and 6.1 when something keeps it aligned.** Measured on this machine
      with a real speaker and a real microphone, written up in `docs/ACOUSTIC.md`, repeatable with
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
- [x] **Two timing gates took one wall clock reading each, and one of them
      failed on a busy machine.** `the_codec_runs_faster_than_real_time` came
      out at 1.7 times its bound during a run with eight other tests saturating
      the cores, and at 14.6% of the bound on its own a minute later. A single
      reading on a shared machine measures the machine.

      **Two attempts at resampling failed, and both are written down so they
      are not tried again.** Cheapest of three long samples: the layered gate
      then failed at 32% against a bound of 25. Cheapest of many short samples:
      worse, 41% and 38%. A long sample overlaps contention that lasts the whole
      run, and a short sample that is preempted mid-way charges the entire time
      slice to the codec.

      Neither is a sampling problem. The assertion is about **CPU cost**, and
      wall clock is a different quantity that only agrees on an idle machine.
      Measuring the right one needs a platform call, and `rotelyx-codec` has one
      dependency and no dev-dependencies, which is worth more than this gate is.

      So the two gates are `#[ignore]` and a CI job runs them alone, in
      `release-test` because release is `panic = "abort"`. **In an optimised
      build they cost 1.4% and 2.0% of real time against a bound of 25**, which
      is the number that matters, because an optimised build is what ships. The
      12 to 14% figures everything above argued over were debug builds.

      Sabotage confirms the gate is still a gate: tighten the bound past what
      the codec can do and both fail
- [x] **The lint job checked five crates of nineteen, and the format check was
      failing.** `cargo clippy` named five crates by hand and `cargo fmt` seven,
      lists written when the workspace was smaller and never revisited. The
      codec, the audio, the mailbox server, the capability tokens, the wasm
      build and the mobile ABI were in neither.

      Widening clippy found **71 warnings**, of which two were real. One was a
      `MutexGuard` reported across an await and was a false positive. The other
      is below.

      **`--all` is the wrong way to widen `cargo fmt`.** It follows the path
      dependency into `crates/net` and would reformat 71 files of vendored
      upstream, which is what the original comment was guarding against and what
      the first attempt at this did. The job now derives its package list from
      `cargo metadata --no-deps`, which lists workspace members only, so it
      covers everything of ours, nothing of theirs, and picks up a new crate
      without anybody remembering this file. Clippy's `--workspace` was already
      safe: cargo's workspace excludes `crates/net`, `cargo fmt`'s `--all` does
      not.

      **And the format check was red before any of this.** With no `rustfmt.toml`
      anywhere, `cargo fmt --check` on the seven crates the job already named
      reported 201 differences in files nobody had touched. Either the job has
      been failing or the runner's rustfmt formats differently from a local one;
      this repository is private and that cannot be checked from here. 588
      differences across the nineteen crates are now closed and the check is
      clean
- [x] **A test called `the_registry_is_bounded` tested nothing.** Its whole body
      was `assert!(MAX_DEVICES > 0)`. It carried the right comment, that without
      a bound anything able to open a socket can make the server spend its life
      calling Apple, and it asserted that a constant is positive: **the registry
      could have grown without limit and it would still have passed.** It now
      fills the registry to `MAX_DEVICES` and checks the next one does not land.
      Found by clippy, which had never been pointed at that crate
- [x] **An `#[allow]` was attached to the wrong item.**
      `clippy::too_many_arguments` for `router_stateful` sat on the `Waking`
      struct one line above, which takes no arguments at all. It silenced
      nothing and clippy went on reporting the function, while the annotation
      looked to a reader like the matter had been dealt with
- [x] **`ci.yml` listed ten jobs and nine ran.** Two were keyed `transport`,
      YAML keeps the last of two identical keys, and the one silently dropped
      was `cargo test --all-features` on `rotelyx-relay-proto`: 117 tests on the
      crate that carries the relay wire format, in a repository whose
      `crates/net/README.md` said every crate there had a CI job.

      Nothing could have reported it. A duplicate key produces no warning from
      YAML, from GitHub, or from anything reading the file as a map, and the
      file reads correctly to a person.

      `crates/rotelyx-net/tests/every_ci_job_exists.rs` now refuses it, reading
      the file as text rather than through a parser, because the failure being
      caught is exactly that a parser accepts it and returns fewer jobs than are
      written. A second test checks that the reader finds jobs at all, since a
      scanner that finds none reports no duplicates just as confidently
- [x] **The guard is bounded on both sides now, and the second side mattered
      more.** `a_voice_survives` asked only that more than 30 percent of the
      speech energy survived, while the suppressor keeps 56, which left room for
      it to get half again as destructive without anything failing.

      That much the entry already said. What it did not say is that **a
      suppressor doing nothing at all passed.** The input is voice plus hiss, so
      leaving it untouched keeps *more* energy than the voice had: sabotaged to
      return its input unchanged, the test reported 136 percent and passed every
      assertion. The other test in the module watches a held tone, a different
      signal, and would not have caught it either.

      Bounded above and below now, and the measured figure is printed so a
      change of a few points is visible without reading the source to find out
      what the bound was. Both bounds were checked by breaking the code they
      guard.

      The 2.4 dB of speech the suppressor costs is unchanged and still real. It
      is a cost paid whether the noise was worth removing or not


### 7. Mobile clients

- [x] **`rotelyx-mobile`: the engine as a native library.** The same crate the
      browser gets, behind a C ABI of nine symbols instead of `wasm_bindgen`.
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
- [x] **The C ABI is enough, demonstrated rather than argued.** The question was
      whether a foreign runtime can reach the engine through nine C symbols and
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
- [x] **Silent pushes marked as decoys, on one fixed schedule.** Not jittered
      delivery, which this line used to plan and which would be a weakening: a
      device woken on a rhythm of its own is identifiable by that rhythm, so one
      schedule shared by every registered device is the stronger arrangement

### 8. Selling capacity without learning who bought it

- [x] Free and plus tiers, enforced per request on fan-out width, envelope
      size, retention and volume
- [x] Ed25519 capability tokens with `keygen` and `mint`
- [x] A meter holding a random id and a byte count, swept every period
- [x] **Blind signature issuance.** RFC 9474 blind RSA, one key per tier so a
      blind issuer cannot be handed a tier it cannot read. Verified end to end:
      what the issuer sees during a sale does not appear in the token
- [x] **The issuer's contract, written and executable.** `docs/ISSUER.md` has
      the two routes a client needs, `GET /tiers` and `POST /issue`, what the
      issuer must not keep beside a payment, and the rule that is not
      cryptographic: **one payment reference signs exactly one blinded
      message.** Without it a buyer who repeats the request gets a second token
      for one payment and nothing downstream can tell, because the two tokens
      are unlinkable by construction.

      Two tests walk it against a fake issuer over real HTTP: read the key off
      the wire, blind against it, take the signature back, unblind, and present
      the result to a mailbox that never spoke to the issuer. Every piece had
      unit tests already; the sequence had none, and a sequence is where formats
      stop fitting.

      **It also turned up a residual nobody had written down.** Blind signing
      does not defeat timing: the issuer knows when a payment completed and the
      mailbox knows when a token was first used, and where purchases are rare
      those two records narrow to one. Recorded in `docs/THREAT-MODEL.md` under
      ADV-4
- [x] **A bought token could not be spent by anything.** Blind issuance was
      finished on the server and had no client. Nothing in this repository sent
      `authblind`: not the browser, which sent every token as `auth` and had the
      blind kind refused, and not `rotelyx-mailbox-client`, which had **no auth
      frame at all** and left the desktop permanently on the free tier. A tier
      could be sold and not used, and nothing failed: every client worked, on
      the free tier, exactly as if nobody had paid.

      Both present one now. The frame is chosen by length, because the holder is
      the side that knows what it holds and the mailbox refuses to guess on
      purpose; `rotelyx_capability` has a test that fails if the two formats grow
      close enough for that to become a guess.

      **The token is held rather than presented.** ADV-4 says a token is a
      stable pseudonym with a usage history, and an unauthenticated caller gets
      a fresh capability per connection, so presenting one at connect ties every
      conversation together permanently and does it for nothing on traffic the
      free tier would have taken. `Mailbox::hold_token` keeps it and
      `Mailbox::deposit` presents it only when a tier actually refuses
      something, which the mailbox allows because `auth` upgrades a capability
      mid-connection. The safe behaviour is the default rather than something a
      caller has to remember.

      Stored once per identity, sealed with the key the conversations already
      use. The desktop exposes saving, forgetting and asking whether one is
      held, and never reads one back into the window
- [x] **The client and the server disagreed about the wire, and the test agreed
      with the client.** `rotelyx-mailbox-client` declared its enums
      `rename_all = "camelCase"` where the server declares `lowercase`. Those
      agree for every variant of one word and differ for every other, and the
      only one that mattered was `OverQuota`: the server sends `overquota`, the
      client read `overQuota`, so a spent allowance arrived as an unknown tag,
      was skipped, and `deposit` waited for a `stored` the server had already
      decided not to send. **A deposit at the quota hung.**

      That hang already had a fix, written with the wrong spelling, and a test
      that fed the client a string in the client's own spelling and confirmed
      the client could read it.

      The convention is aligned now rather than patched variant by variant, and
      the wire has one authority: `every_reply_is_spelled_the_way_a_client_reads_it`
      in the mailbox server pins the exact bytes of every reply, and the clients
      copy those literals
- [x] Blind redemption in the browser: `TokenRequest` blinds, pays, unblinds.
      The page still takes a pasted token, since there is no store to buy from
- [x] Persist the meter, so a restart does not hand everyone a fresh allowance.
      Verified over a real socket: spend, restart, and the allowance is still
      spent

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

- [x] **The Flutter app shipped a wasm three builds behind.** Its copy hashed
      `b04f4425` against the source, which predated the credential change and put
      it in the seven-in-eight case above. Rebuilt and copied: its
      `web/rotelyx/rotelyx_wasm_bg.wasm` and this repository's `site/rotelyx/`
      copy are the same bytes, `d95035a6`, and `test/shipped_engine_test.dart`
      fails if they drift again

- [x] **Redeploy `site/`. The live one was behind, and mixing it with a current
      client failed one time in eight.** Done, and verified from outside with
      `scripts/verify-deployment https://rotelyx.com`: the page and the engine it
      loads are the same build as this source. This session changed the MLS credential
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

      Deployed and verified in a browser on 29 August 2026:
      `scripts/browser-test/run https://rotelyx.com/chat.html` drove two Chrome
      tabs through a whole conversation against the live site, safety numbers
      matching on both sides and a message delivered each way.

      **Six days of uploads went nowhere, and the cause was one word.** The
      `location /rotelyx/` block that `docs/BROWSER.md` recommends, to serve the
      module as `application/wasm` with `no-cache`, was deployed with `root`
      where it needed `alias`. `root` appends the whole request URI to the path
      it is given, so a request for `/rotelyx/x.js` was looked for in
      `public_html/rotelyx/rotelyx/`, which does not exist. Every upload to that
      directory was ignored: the site served a module from six days earlier and
      then 404ed, and the page stopped loading at all, because an ES module
      import of a name the module does not export is a SyntaxError before a line
      of it runs.

      Found by putting one file in three places and asking for all three: the
      root and `/assets/` answered, `/rotelyx/` did not. Fixed on the server,
      and `docs/BROWSER.md` now carries the working block rather than a
      description of one.

      `verify-deployment` gained the check that would have named this: whether
      the page and the module it loads are the same build. Both files differing
      from source is also true of a merely old deployment and does not say the
      site is down.

      It only started reporting it after `docs/ARTIFACTS.md` was regenerated.
      The manifest had not been rewritten since the wasm was rebuilt on 27
      August, so all four hashes in it were stale and the check was comparing
      the live site against an out-of-date record and passing. A verification
      whose reference is not kept current is a verification that agrees with
      whatever it finds

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


### A spent allowance is silent on two of the three clients

- [x] **`overQuota` is handled everywhere now.** It was the browser only: the
      phone's reply switch had no case for it and `rotelyx-mailbox-client` folded
      it into `Reply::Other`, so on both a refused deposit returned as though it
      had worked. The message was not stored and the sender was not told, which
      is the same shape as the fan-out defect and the reason that one survived:
      a refusal that produces no error looks exactly like success.

      The Rust client has `Reply::OverQuota` and fails on it. The phone handles
      it in `mailbox_client.dart`, whose doc now carries the rule that stops this
      recurring: **every reply saying a request failed has a case here.**

- [x] **`Collected` is sent by every client now.** It was the Rust one only.
      Delivery peeks and removal waits for an acknowledgement, which is the P-4
      fix, so an envelope nobody acknowledged sat in the mailbox for its whole
      seven-day TTL: a seized disk yielded seven days of ciphertext rather than
      only what was never delivered, a tag filled its 256 slots and the server
      refused further deposits, and every reconnect re-downloaded the backlog.

      `site/chat.html` sends it. The phone sends it from `rotelyx_service.dart`,
      using the receipt the engine hands it through `mailbox.receiptFor`.

      **Read out of the code rather than believed from here**, because this
      entry said otherwise long after it had stopped being true, and was
      repeated as a live defect on the strength of that.

### Calls on a phone, 1 September 2026

Seven faults between two phones and a conversation. Not one of them raised an
error, and every one was covered by a test that could not fail. That pattern is
the entry worth keeping; the fixes are ordinary.

- [x] **The answer carried no address.** The caller dials and the answerer
      accepts, and the ring carried the caller's address outward, so the only
      side that needed one never got it. `endpoint.connect('')` returns -3,
      which reached the screen as "Connection lost" through a value the caller
      discarded. Both phones opened a microphone zero times, which is what
      finally located it. Untested since 20 August because the controller is a
      singleton wired to the global service and has no unit test at all;
      guarded now by reading the source, which is weaker and was writable
      today.

- [x] **The phone accepted a call the way it accepts a message.**
      `rotelyx_net_accept` used `NetEndpoint::accept`, which waits for a
      bidirectional stream after the handshake. A call never opens one: its
      audio is datagrams. `accept_media` exists for exactly this, was written
      when the desktop hit it, and the mobile ABI was never moved across.
      Nothing failed, because every test of that ABI opens a stream. Measured
      before the fix: the dialling side reported a connection 3.2 s in, the
      accepting side gave up 10 s later having seen nothing, on both sides of
      two calls in each direction.

- [x] **Decoded frames reached the speaker out of order.**
      `unawaited(playFrame(pcm))` every twenty milliseconds with no wait for
      the last, and a platform channel promises nothing about the order two
      outstanding calls arrive in. The same fault was found and fixed on the
      capture side in August and nothing was changed here at the time. Now the
      desktop's policy, from `rotelyx-audio/src/device.rs`: one in flight, the
      rest in order, bounded at 400 ms, oldest dropped.

- [x] **The call mode was set by the speaker button.**
      `MODE_IN_COMMUNICATION` was set in `route`, which runs when somebody
      presses it. A call where nobody did ran with the platform's voice path
      unselected: `VOICE_COMMUNICATION` was accepted, a microphone was
      selected, the echo canceller was enabled against a reference the mode had
      not arranged, and capture measured 10 to 15 rms out of 32767 with
      somebody speaking into it. The log said `enabling echo-reference` and
      `out_snd_device(0: )` on the same line for hours before that was read.
      Set before either device opens now, and the loudspeaker starts first so
      the reference exists.

- [x] **Three effects over a source that already applies them.**
      `VOICE_COMMUNICATION` runs echo cancellation, suppression and gain in the
      platform, and all three were attached again in software. Two cancellers
      in series cannot tell a near voice from what they are there to remove.
      `MIC` was tried instead and measured worse, 1 to 28 rms, which is the
      other half of the same mistake: those effects are defined against the
      voice source. One chain now, and a gain stage of our own under it.

- [x] **Capture gain, and then the gain's own two faults.** With the route
      fixed the level was still about -44 dBFS, some 20 dB under speech, and
      the touch tones mixed in after capture arrived 26 dB louder than the
      person talking, so a call carried its keypad and not its voices. A gain
      stage was added and had to be fixed twice: it moved five percent a frame
      in both directions, so a syllable after a silence was multiplied by a
      factor meant for the silence and clipped for most of a second; and it
      applied one factor per frame, stepping the waveform at the boundary fifty
      times a second. Down at once, up slowly, and ramped across the frame.

- [x] **The screen never learned the loop existed.** `CallLoop` is created in
      `_open`, after the phase reaches `talking` and the screen has already
      been built with `loop` as null, and nothing published a change
      afterwards. Everything visible kept working, because it comes from
      `CallState`; the keypad was the only control that needed the loop, so the
      only symptom was a key that made no sound at the far end, on one side of
      a call and not the other, depending on whether an unrelated rebuild had
      refreshed the screen in between.

- [x] **The round trip test could not fail.** `audio_path.rs` sends audio
      through this ABI and reads it out, and it passed the entire time a call
      carried its keypad and not its voices. Its signal is `0.4 * sin(2 pi 440
      t)`: every frame of a held tone equals the frame before it, so a tone is
      the one signal that survives having its frames mishandled, and it is
      exactly what a touch tone is. Its assertion is `heard_energy > 0.0`,
      which noise satisfies, and a hum, and the previous frame played twice.
      `a_voice_survives_the_round_trip` speaks instead and measures how much of
      what went in is in what came out: 0.984 whole, 0.984 with one frame in
      ten dropped, which also disproved the dropped-frame theory before it cost
      a build.

- [x] **Neighbouring sample correlation is not a measure of a voice.** It was
      read as one for most of a day, including out loud: a hum at a hundred
      hertz scores 0.99 and so does speech, and a phone playing the first while
      somebody said it was not the second was believed because the number
      agreed with the wrong one of them. Where a voice must be told from a
      smooth signal that is not one, the measure is where the energy sits.

Result: two phones on different networks, nine years apart in hardware, four
minutes of audio in both directions, nothing dropped, sent and received
matching exactly.

Also done alongside: touch tones generated in `tool/sound/build.py` beside the
message tone, for connecting and for failing; a DTMF keypad, in band, with the
frequencies checked by Goertzel the way a receiver would read them; a voice
ring around the avatar drawn from both directions' levels; a name that is kept
and suggested rather than demanded, which had been read from a setting nothing
ever wrote; and the shipped strings gone over for store review.
