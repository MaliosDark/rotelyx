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

- [x] nginx connection and request rate limits, applied before the backend is
      reached
- [ ] Implement `accept_conn_limit` and `accept_conn_burst`, which the vendored
      relay declares and marks as having no effect
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

- [ ] Opus encode and decode with device capture
- [ ] Jitter buffer and packet loss concealment
- [ ] Acoustic echo cancellation
- [ ] Congestion control and bandwidth estimation
- [ ] Media keys derived from MLS exporters so a call is as end to end as a
      message
- [ ] Group calls above six participants, which needs SFrame and a forwarding
      unit that cannot decrypt

### 7. Mobile clients

- [ ] UniFFI bindings for Swift and Kotlin
- [ ] Background lifecycle. iOS will not hold a socket, and every design
      decision downstream of "the phone hosts it" collides with this
- [ ] Silent push with jittered delivery and decoy pushes
- [?] Whether to ship the browser harness as a Tauri shell or write native
      clients

---

## Ongoing

- [ ] **Upstream security patch watch.** Vendoring means fixes no longer arrive
      on their own. Somebody has to watch the upstream repository and port
      security patches by hand. This is the price of owning the code and it is
      not optional in a cryptographic project
- [ ] Fuzzing every parser reachable from the network: the frame reader, the
      envelope parser, the admission decoder and MLS message handling
- [ ] Constant time review of every comparison touching secret material

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
