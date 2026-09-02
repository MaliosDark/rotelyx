# Working on Rotelyx

> **A security problem does not go in an issue.** Email
> <contact@ideoa.co.uk>. A public issue is a working exploit handed to
> everybody reading the repository, including whoever is running a relay or a
> mailbox at the time. [`SECURITY.md`](../SECURITY.md) says what to include and
> what happens next.

## Sending code

Comment on your pull request with **"I have read CLA.md and I accept it."**,
once, for all of your contributions. [`CLA.md`](../CLA.md) is short and the
reason it exists is in its first paragraph: Rotelyx is AGPL-3.0-only and is
also published in stores whose terms that licence cannot satisfy alone, so the
project has to be able to grant itself an exception, and it can only do that
over code it holds the rights to. One contribution without it and that stops
being possible for the whole of it.

You keep your copyright and your name in the history, and your contribution
stays published under the AGPL like everything else.

If you would rather not, say so and open an issue describing the change
instead. An idea is not a contribution in the copyright sense and there is
nothing to sign for one.

## Repository layout

```
crates/
  rotelyx-net       L0/L1  transport, relay policy, path policy
                           NOTICE, VENDORING.md, LICENSE-{MIT,APACHE,BSD3}
  rotelyx-core      L1     identity, admission control, safety numbers, framing
  rotelyx-crypto    L2     MLS integration and the hybrid PQ composition
  rotelyx-mailbox   L3     blind store and forward, self hostable
  rotelyx-codec           Telyx, a transform speech codec for a channel where
                           latency is spendable and loss is recovered. MDCT,
                           Bark bands, PVQ shape coding, residual stages
  rotelyx-media     L2     calls: per sender frame encryption keyed from MLS, an
                           adaptive jitter buffer with a loss recovery mode that
                           survives 50% packet loss, QUIC datagrams, never direct
  rotelyx-wasm      L2/L3  the message layer compiled for the browser
  rotelyx-capability       capability tokens: the format, and verifying them.
                           Issuing them is a separate crate, not published here,
                           so a mailbox runs free without any of it. See
  rotelyx-status           the availability record behind both landing pages
  rotelyx-mobile           the C ABI the phone bindings call
  rotelyx-cli              two terminal chat, for running the protocol
  rotelyx-relay            the relay server binary
  rotelyx-mailbox-server   the blind mailbox as a WebSocket service
  rotelyx-desktop          native desktop window, Tauri v2, no Node
  rotelyx-web              local browser harness
  net/                     the vendored transport stack, 124,632 lines
site/                          the public site and the browser client, self contained
docs/
  brand/                       logo, light and dark variants, and the square mark
  DEPLOYMENT.md                what is deployed, where, and why each choice was made
  THREAT-MODEL.md              what Rotelyx defends against, and what it does not
  PQ-COMPOSITION.md            the novel construction, specified for review
  rotelyx-architecture.html    the architecture assessment
TODO.md                        what is left: open, blocked, undecided
docs/DONE.md                   what was done, and what each thing cost
```

---

## Building and memory

The vendored transport is 124,632 lines and includes a 50,000 line QUIC state
machine. Cargo defaults to one compile job per core, and on a machine with a
small swap file that peak is enough to make the kernel start killing processes.
An editor is a large, easy target.

`.cargo/config.toml` in this repository caps the build at four jobs for that
reason. Raise it if you have RAM headroom:

```sh
cargo build --workspace -j 8
```

If builds still stall the machine, more swap helps more than fewer jobs:

```sh
sudo fallocate -l 8G /swapfile2 && sudo chmod 600 /swapfile2
sudo mkswap /swapfile2 && sudo swapon /swapfile2
```

## Before you push

```sh
cargo test --workspace          # 597
cargo clippy --workspace        # no errors
cargo deny check                # bans, licences, sources, advisories
cargo audit                     # the same advisories, the other tool
scripts/audit-dependencies      # and that those three agree with UPSTREAM.md
scripts/benchmarks              # what it costs, on your machine
```

And if you rebuilt anything that ships, the wasm module or either server:

```sh
scripts/artifact-hashes         # rewrite docs/ARTIFACTS.md
scripts/verify-deployment https://rotelyx.com   # does the live one match
```

`ARTIFACTS.md` is the reference the deployment check compares against, so a
manifest nobody regenerates turns that check into one that agrees with whatever
it finds. It went stale for two days in August 2026 and `verify-deployment`
passed the whole time against a live site that was two builds behind.

**Upload `site/` whole, or not at all.** The page names the module it wants by
hash, and imports functions from it by name. A page newer than the module in
the engine next to it does not degrade: an ES module import of a name the
module does not export is a SyntaxError, so nothing on the page runs. That
happened on 29 August 2026, `chat.html` went up and `rotelyx/` did not, and the
browser client stopped loading for everybody. `verify-deployment` says so
directly now, in its own paragraph, because "both files differ from source" is
true of a merely old deployment too and does not tell you the site is down.

The dependency script is the unusual one. An advisory may only be passed over
where `deny.toml`, `.cargo/audit.toml` and `docs/UPSTREAM.md` all agree, and the
argument has to be written down before a tool is told to skip it. Deleting a
section from the ledger breaks the build, which is checked by deleting one.

## Testing

```sh
cargo test --workspace
```

**597 tests**, and 11 more in the issuer crate that is not published here. The
distribution matters more than the count:

| Suite | Tests | What it proves |
|---|---:|---|
| `rotelyx-codec` | 84 + 17 | The transform, the quantiser, real speech, and every corrupted frame |
| `rotelyx-core` | 74 + 16 | Identity, sealed storage, framing, admission control **over real sockets** |
| `rotelyx-mailbox-server` | 58 | Deposits, acknowledged collection, tiers, quota, the vault, waking a phone |
| `rotelyx-media` | 51 + 9 | Per sender keys, the jitter buffer, layers crossing a real wire |
| `rotelyx-crypto` | 37 + 17 | MLS conversations, X-Wing, the PQ secret reaching the key schedule |
| `rotelyx-wasm` | 40 | The message layer as the browser and the phone both see it |
| `rotelyx-mailbox` | 29 + 7 | Envelopes, buckets, tag rotation, TTL expiry |
| `rotelyx-capability` | 25 | Token format and verification, against tokens frozen from the real issuer |
| `rotelyx-net` | 15 + 10 | Path policy, the zero foreign infrastructure guard, **live QUIC connections** |
| `rotelyx-audio` | 20 | The echo canceller, the noise suppressor and the dereverberator, against recorded speech |
| `rotelyx-desktop` | 19 | The window's handshake and key file, and **two clients meeting through a code** at a real mailbox |
| `rotelyx-cli` | 10 + 6 | Key file sealing and migration, plus a message surviving the whole offline path |
| `rotelyx-relay` | 12 + 3 | Admission limits, the allowlist refusing to fall open, the status page |
| `rotelyx-mobile` | 9 | The C ABI boundary, and audio across it |
| `rotelyx-mailbox-client` | 3 + 3 | The queue that used to discard what it read past, against the real server |
| `rotelyx-web` | 5 | The local browser harness |
| `rotelyx-status` | 4 | The availability record both landing pages read |
| `rotelyx-path` | 2 | The selector that prefers any direct path to any relayed one |

The phone client is a separate tree and runs its own suite, which this count does
not include.

Hostile input tests run in six crates and account for 36 of the total: every
truncation, every byte value at every position, extension, and arbitrary input,
against every parser reachable before anything has been authenticated.

### Two defects found by an audit, not by testing

Both passed every test in this repository, and both are the same shape: a
property that holds whenever the thing is done **once**.

1. **Media keys repeated their nonces between calls.** Derived from the group's
   exported secret and the speaker's roster index, both fixed for an MLS epoch,
   with the frame counter restarting at zero. One call never repeats a nonce, so
   every test passed. The second call in an epoch reused the first one's keystream
   from its first frame, which under ChaCha20-Poly1305 loses confidentiality and
   integrity together. Keys are now bound to a per-call value.
2. **The safety number was a hash of the group id**, which never changes, so it
   never moved when a member or a device was added. One roster never changes, so
   every test passed. It is now the sorted set of member signature keys.

### Four defects found by testing, not by review

Every unit test passed while these were live. Only cross layer tests and tests
over real sockets found them:

1. **MLS was not padding at all.** Overhead is a constant 145 bytes and the rest
   is one to one, so plaintext length leaked exactly. Worst on the direct path,
   where there is no envelope to hide behind.
2. **Padding buckets were too small.** A 256 byte bucket held barely a hundred
   characters after MLS overhead, so ordinary messages straddled the boundary
   and told the operator "short" or "long" every time.
3. **Dropped QUIC streams discarded data.** A send stream dropped without
   finishing resets and silently discards data the sender believes was
   delivered. Write then drop is the obvious pattern, and it lost the last
   message with no error anywhere.
4. **A failure that looked like a normal condition.** A media frame that cannot
   be decoded is concealed rather than counted, which is correct for packet loss
   and hides a format mismatch completely. A call ran with eleven usable frames
   out of three thousand and every layer reported it healthy. Concealment is
   counted and reported now.

---

## Roadmap

Full status in [`TODO.md`](../TODO.md). The short version:

**Done.** Transport vendored and renamed, zero foreign infrastructure with a
build breaking guard, MLS conversations, hybrid post quantum key agreement
reaching the MLS key schedule, blind mailbox, admission control enforced on the
accept path, metadata resistant path selection, relay server, CLI and browser
harnesses.

**Also done since that list was written.** Calls between two desktop clients and
between a phone and a desktop, over the relay and this project's own codec; the
meeting code path, so a phone and a desktop can start a conversation without
either holding an address for the other; an Android client with its own suite.

**Next.** Field test across two real NATs, published test vectors for the PQ
composition, echo cancellation that works in a room, iOS.

**Blocking any public security claim.** An independent cryptographic audit.

---
