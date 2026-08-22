# Rotelyx TODO

Status as of 20 August 2026. 459 tests passing.

**Calls work.** Two processes, real devices, real datagrams, through a relay:
991 frames sent and 944 received in twenty seconds, 79 ms queued, nothing
dropped. `/call` in the terminal client, a Call button in the desktop window.
Two people have listened to the codec, and what that found was a broken test:
the rating scale was never shown to either of them. There is no perceptual
measurement of this codec yet, only the objective one.
`docs/listening-2026-08-21.txt` records how it was found.

**What a call still lacks:** echo cancellation, congestion control, more than
two participants, and any measurement across a real network rather than a
loopback relay.

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

- [x] DNS, nginx and TLS configured for `relay-rotelyx.ideoa.co`
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
- [x] Persistent blocklist, so a block survives a restart
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
- [!] **Resuming a conversation in a native client needs a decision, not code.**
      The storage is built and nothing calls it, because saving is the easy half:
      to carry on, the two sides have to find each other again, and whether that
      is `listen` reopening on the same invitation, a `resume` command, or the
      mailbox is a product question. Saving state that nothing can reopen would
      be a file that only ever grows a risk
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
- [ ] **Per-address limits on a mailbox, which belong in the reverse proxy.**
      The ceiling above bounds the resource whatever is in front, and it does
      not tell one caller from a thousand. `docs/nginx-relay.conf` has the zones
      written and they are still not deployed
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
- [!] **Blocking has never worked against anybody unwilling to be blocked.**
      Measured: a peer that puts its real identity in the credential is refused,
      and the same peer putting any other bytes there is admitted. The credential
      is chosen by the member and nothing proves it. The comment above the
      safety number called it "the identity the group authenticated"; the group
      binds it to a signature key and authenticates nothing about who it belongs
      to. `Gate::admit` also checks the blocklist against the transport peer,
      which is an ephemeral per-invitation key now, so that never matches either.
      Revocation does work and is verified against a secret the issuer holds.
      **This needs a decision, not a patch:** either "block" becomes "revoke the
      invitation", or the command goes. Leaving a command that silently does
      nothing is the worst of the three
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
      four reflections.
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
- [x] **Packet loss concealment in a call.** The receiver counts the frames
      that never arrived rather than inferring a gap from silence, because a
      caller that waits to notice has already played the hole, and the call
      fills them from the codec before playing what did arrive. Reported as
      `frames_concealed`, which is the loss somebody actually heard
- [ ] Mixing, for a group call with more than one person speaking
- [ ] Build for Android on a machine with the NDK, and for iOS on a Mac. The
      Rust targets are installed; `cargo-ndk` is not
- [ ] UniFFI bindings for Swift and Kotlin, if the C ABI turns out not to be
      enough
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

- [x] Deploy `rotelyx-mailbox-server` to `mail-rotelyx.ideoa.co:3341`, verified
      end to end: `101 Switching Protocols` through Cloudflare, pfSense and nginx
- [ ] Upload `site/` to `rotelyx.ideoa.co`, and add the same `location /mailbox`
      block there so the page finds the mailbox at its own origin
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
- [ ] **Somewhere the fuzzers run without anybody remembering.** The corpus is
      gitignored because it is machine-specific; a case that finds something
      belongs in the ordinary suite as a regression
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
