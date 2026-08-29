<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/rotelyx-logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/brand/rotelyx-logo-light.png">
  <img src="docs/brand/rotelyx-logo-light.png" alt="Rotelyx" width="380">
</picture>

**Encrypted messages, straight between two devices.**

No accounts, no phone numbers, and no servers belonging to anybody else.

[![tests](https://img.shields.io/badge/tests-597%20passing-6a31ee?style=flat-square)](docs/CONTRIBUTING.md)
[![rust](https://img.shields.io/badge/rust-1.85%2B-6a31ee?style=flat-square)](#try-it)
[![licence](https://img.shields.io/badge/licence-AGPL--3.0-8b8b8b?style=flat-square)](#licence)
[![status](https://img.shields.io/badge/internally%20audited-5%20rounds-C8A76B?style=flat-square)](#security-status)


</div>

---

> [!CAUTION]
> **Rotelyx is internally audited and pre release.** Five rounds closed every
> finding raised against code written here. No outside review yet, so the gates
> in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) section 5 are not all met.

---

## What it is

A messenger where **your identity is a key, not an account.** No phone number,
no email, no sign up, nothing published anywhere.

And that key is never the name anybody sees. Each person you invite reaches a
different address and is shown a different name, so two of your contacts cannot
compare what they were given and find each other.

When both people are online, messages go **straight between the two devices**
and touch no server. When one is offline, the message waits in a mailbox that
cannot read it and is never told who sent it: an envelope carries no sender, and
a deposit made without a paid token carries nothing that ties it to any other
deposit. A paid token does carry a random identifier, because the allowance has
to be counted against something, and that identifier links one buyer's deposits
to each other without naming them. It is written up in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) rather than glossed here.

Everything it runs on is in this repository. It contacts no infrastructure
belonging to anyone else, and there is a test that fails if that ever changes.

Two encryption layers, independent of each other, and post quantum key exchange
from the first version rather than as a later migration.

A phone, a desktop window and a terminal all speak it, and there is a browser
build besides. A code shown on one screen and read on another is one
conversation between them, and a call between a phone and a desktop carries
audio in both directions over this project's own relay and its own codec. No
WebRTC anywhere.

## The clients

| | | |
|---|---|---|
| **Phone** | Android. Flutter over these same crates through a C ABI | `crates/rotelyx-mobile` |
| **Desktop** | A native window. Its IPC is in process, so plaintext never crosses a socket | `crates/rotelyx-desktop` |
| **Terminal** | Everything the protocol does, with nothing drawn. The quick start below | `crates/rotelyx-cli` |
| **Browser** | A WebAssembly build, labelled a harness in its own interface because it speaks to a local process over loopback | `crates/rotelyx-wasm` |

They are not interchangeable and the difference is written down rather than
smoothed over: see [`docs/BROWSER.md`](docs/BROWSER.md) for what the harness
gives up.

The desktop window is one script, and it points at the same relay and mailbox
the phone ships with:

```sh
scripts/rotelyx-desktop            # production
scripts/rotelyx-desktop --local    # a relay on this machine, for trying things
scripts/rotelyx-desktop my.key     # an identity you keep
```

### What works today

Pairing by a QR code, by a phrase two people say out loud, or by an invitation
sent through whatever messenger they already have. One to one and group
conversations, replies, reactions and attachments. Messages that burn on both
devices from the moment the other person reads them. A read tick that is never
inferred from anything. Encrypted history on the device, or a mode that writes
nothing down at all and asks again next time. A conversation list that survives
a restart, on the phone and in the desktop window. Removing somebody from a
group, in the desktop window and the browser but **not yet on the phone**: the
engine does it and the C ABI does not expose it, so the client most likely to be
lost or stolen is the one that cannot revoke a device. Calls, between two
desktops and between a phone and a desktop.

What is not here is in [`TODO.md`](TODO.md), which is the ledger rather than the
plan: an item moves to done when a test proves it, not when the code exists.

### Meeting somebody who is not on your network

An invitation carries keys, and something has to deliver it to an address. A
phone has no listening socket, moves between networks and is asleep most of the
time, so there is a second way in that needs no address at all.

A **meeting code** is 120 random bits written as 29 characters:

```
RTLX1 DZR7 6K4H FIBG 7GI4 XJET 6FHC
```

It carries no key. It names a place at a mailbox, in the same sense as a table
number in a cafe. Both sides run it through the same derivation, arrive at the
same opaque tag, and hand each other the real keys there, where their size costs
nothing. Putting the invitation in the QR instead cannot be done: an X-Wing
public key is 1216 bytes because that is what resisting a quantum computer
costs, and with the key package and base64 around it an invitation runs to about
three thousand characters, past what a QR holds at a correction level that
leaves room for a logo.

One side shows it as a QR and the other points a camera at it, or one side reads
it aloud. What a code buys an attacker is exactly one attempt at being first:
whoever arrives before the intended person completes the handshake in their
place, and nothing here prevents that, because a code is not proof of who is
holding it. Comparing the safety number is what detects it, which is why it is
on screen from the moment the conversation exists.

The tags rotate every hour and each side listens on the previous windows too, so
an envelope deposited at 10:59 is still collected at 11:00.

## Try it

You need [Rust](https://rustup.rs) 1.85 or newer.

```sh
cargo build -p rotelyx-cli
R=./target/debug/rotelyx-cli
```

**Alice, in one terminal.** She creates an invitation and waits:

```sh
$R --identity alice.key invite --hours 24
#   7otIsVn_jAFHYFb1Yp62rDxm5spaU75eM5MoDSHosgo

$R --identity alice.key listen
#   rotelyx connect 'eyJpZCI6...'
```

**Bob, in another.** He needs both her address and her invitation:

```sh
$R --identity bob.key connect 'eyJpZCI6...' \
   --invite 7otIsVn_jAFHYFb1Yp62rDxm5spaU75eM5MoDSHosgo
```

Both of them see a safety number:

```
safety number 41908 75433 94850 77313 01440 94499 53654 59718
```

> [!TIP]
> **Read those digits out loud to each other before you trust the chat.** The
> computer checked a key, not a person. If your numbers differ, somebody is
> sitting in the middle.

Nobody can reach you unless you hand them an invitation first. That is the
default and it is not a setting you have to find.

### Talking

Type `/call` in the chat, or press the call button in the desktop window or the
app. `/hang` stops it.

Both sides need `--relay <url>` for a call, and it will tell you so if you
forget. That is not a network preference: over a direct path the other side
sees your address, so a call refuses to start on one.

**A phone and a desktop have called each other**, and audio crosses in both
directions. Four faults stood between an open call and a voice and not one of
them was visible from either end: a QUIC stream opened and never written to, so
the far side sat in `accept_bi` while this side sent audio into a connection
nobody was reading; an address published before the relay had finished
registering the endpoint behind it; two clients speaking different frame
formats, which authenticated perfectly and decoded into chirps; and a sixteen
bit buffer read from offset zero of the platform channel's whole reply rather
than from the start of the window onto it, so what got encoded was the reply's
header.

Why that took so long to see is the part worth keeping. **A frame that arrives
and cannot be turned into sound is concealed, not counted.** That is the right
behaviour for packet loss and it hides a corrupted payload completely: a real
call ran with eleven usable frames out of three thousand and every layer
reported a healthy call. `CallEnded` carries the concealed count now, and the
tools that found it stay in the tree: `ROTELYX_CALL_DUMP` records what the
speaker played, `ROTELYX_FRAME_DUMP` records each payload as it arrived, and
`decode_a_recording` replays them away from the call. The measure is the
correlation between neighbouring samples, which is above 0.9 for a voice and
near zero for broadband noise. Before the last fix, 0.156. After it, 0.992.

Measured between two processes through a relay: 991 frames sent and 944
received in twenty seconds, 79 ms of audio queued, nothing dropped. Two desktop
windows calling each other over the production relay is a test rather than a
story, `two_desktops_calling`, and it asserts on what arrives rather than on
what was sent, because sending proves nothing. It is not one of the 597: it
needs the live relay and mailbox, so it is marked `#[ignore]` and run
deliberately, and a test that needs the network is one people learn to re-run
when it is slow rather than believe when it fails.

Two people have also listened to the codec, and what that found is written down
in [`docs/listening-2026-08-20.txt`](docs/listening-2026-08-20.txt) and
[`docs/listening-2026-08-21.txt`](docs/listening-2026-08-21.txt). What it found
was a broken test: the rating scale was never shown to either listener, so there
is no perceptual measurement of this codec yet, only the objective one.

**Echo cancellation has now met a real room and the room won.** The canceller
measures the path from your speaker to your microphone and subtracts what it
predicts, which took 38.3 dB off a room this project generated. Played through
this machine's own speaker into its own microphone it removed **-0.0 dB**. A
residual suppressor written after seeing that brings it to 1.3 dB run
continuously, or 6.1 dB when something keeps the filter aligned.

The echo arrives 21.8 dB above that room's own noise, so the ceiling on any
canceller there is about 21.8 dB and what is missing is not tuning. The two
devices are 341 ppm apart on their clocks, which was the first suspect and is
not the answer: measured again on half second windows, each realigned so the
slide is nothing, the mean is still 1.1 dB. What is left is an impulse response
far longer than the 128 ms the filter models, and a small speaker driven at half
volume, which is not linear. A linear filter cannot cancel what a speaker added
non-linearly, however long it runs. Every figure and how it was measured is in
[`docs/ACOUSTIC.md`](docs/ACOUSTIC.md).

On Android none of that runs. The platform's own canceller does, through
`VOICE_COMMUNICATION` and `AcousticEchoCanceler`, which is the right answer on a
device where one process owns both the speaker and the microphone. On a desktop,
headphones are still the answer if the other person hears themselves.

## What the people running a server can see

Nothing you write, ever. Here is the rest of it, in full:

| | Can they see it |
|---|---|
| What you wrote | **No.** Not the operator, not a court order, not a stolen disk |
| How long your message was | **No.** Everything is padded |
| Who you are | **No.** There is no account to look up |
| That two keys are talking | **Yes**, if your messages go through their relay |
| Roughly when you were online | **Yes** |

The last two are what relaying costs anywhere it is used. The way around them
is to run your own, which is the point of the next section.

Two limits no messenger removes, and this one does not pretend otherwise: an
adversary who can watch the entire internet at once still sees that traffic is
moving, and nothing on any server protects a phone that has already been taken
over. Both are written up in [the threat model](docs/THREAT-MODEL.md) instead
of being left for you to find out.

## Run your own

Both servers are one command and neither needs an account, a key, or a payment
of any kind.

```sh
cargo build -p rotelyx-relay -p rotelyx-mailbox-server

./target/debug/rotelyx-relay          --bind 0.0.0.0:3340 --open
./target/debug/rotelyx-mailbox-server --bind 0.0.0.0:3341
```

Point your client at it and the table above describes a machine you own,
instead of somebody else's.

Details in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## What it costs

Measured on the machine that ran it, in a release build, medians rather than
best cases. Reproduce with `scripts/benchmarks`; the full table and the hardware
it came from are in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| | |
|---|---|
| X-Wing encapsulate / decapsulate | 212 us / 266 us |
| Encrypt a short message | 74 us |
| Decrypt a short message | 101 us |
| Derive a mailbox tag for an hour | 249 ns |
| Seal and open a payload | 3.3 us / 2.6 us |
| Protect and open one audio frame | 579 ns / 561 ns |
| Export a group key at 8 members / at 1000 | 4.5 us / 4.3 us |
| Encode and decode 20 ms of speech | **1.14 % of one core** |
| Unlock the vault, Argon2id at 64 MiB | 224 ms |

Two of those are worth reading twice. **The whole voice codec, both directions,
costs a hundredth of a core**, which is what makes a call on a phone possible at
all. And **the vault takes a fifth of a second on purpose**: everything else here
is measured in microseconds because it runs per message, and that one runs when
somebody types a passphrase, where slow is the feature.

The group row is the third. Exporting a key costs the same at a thousand members
as at eight, because it reads one secret out of the epoch rather than walking the
tree, so a large group is expensive to change and free to use.

Sizes are measured the same way and land where the paper says they do. A commit
at a thousand members is 83,008 bytes, which is the figure the padding ladder was
redesigned around.

## Verified rather than asserted

Some things about this code were checked by machine rather than by argument.

**The post-quantum composition is verified three ways.** The novel part of
Rotelyx is feeding an X-Wing secret into the pre-shared-key input MLS already
defines, and until August 2026 nobody had shown that the result holds. All three
models are in [`formal/`](formal/) and [`security/ct/`](security/ct/), so the
results below can be re-run and attacked rather than taken on trust.

*Symbolically*, in ProVerif: a model of the whole construction gives an attacker
the entire X25519 private key, which is what a quantum break of the classical
half would look like, and the group secret and the MLS epoch secret both
survive. A second model with both halves broken shows the secret leaking, which
is what says the first result is about the construction rather than about a
model that proves anything.

*Computationally*, in CryptoVerif: the X-Wing combiner's output is
indistinguishable from random with an explicit bound when the post-quantum
secret is unknown, with the classical secret in the adversary's hands.

*Empirically*, with DudeCT: comparing a mailbox tag shows no timing difference
between a match and a miss over 349 million samples, `|t|` around 1.0 against a
conventional threshold of 10. That comparison is how a mailbox is addressed, so
a leak there would give away tags to anybody who can time the server.

What none of them establish is the hardness of ML-KEM, the interior of the MLS
key schedule, or the constant-time behaviour of the third-party primitives
underneath. Those are assumptions the models rest on, not results they produce,
and they need somebody else's eyes.

**The parsers survive being fuzzed, and the hand-written ones are free of
undefined behaviour.** `cargo fuzz` on the media frame reader found no crashes,
and Miri on the two crates that do the parsing and the padding reported none of
what it looks for. Both are `#![forbid(unsafe_code)]` to begin with.

## Read more

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | How a message actually travels, layer by layer |
| [Threat model](docs/THREAT-MODEL.md) | Ten adversaries, and what is not defended |
| [The voice codec](docs/CODEC.md) | Why calls do not use Opus, and what a listener made of it |
| [Post quantum](docs/PQ-COMPOSITION.md) | The construction, written for review |
| [Deployment](docs/DEPLOYMENT.md) | Running one properly |
| [Working on it](docs/CONTRIBUTING.md) | Layout, tests, roadmap |
| [Provenance](docs/PROVENANCE.md) | Where the vendored code came from |
| [What it costs](docs/BENCHMARKS.md) | Every timing, and the machine that produced it |

## Security status

Rotelyx makes **no claim** of being unbreakable, un interceptable or impossible
to access. Those claims are false for every system that has ever made them.

What it claims is bounded, written down and testable. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

The code has been through five rounds of internal review at Ideoa Labs. Every
finding raised against code written here is fixed, and each fix has a test that
fails without it: the arc ran from a critical nonce reuse across calls, through
a mailbox that leaked which group an envelope belonged to and a post-quantum
wrap anybody could forge, down to nothing open. The dependency advisories that
remain are argued unreachable one by one, and `scripts/audit-dependencies`
fails the build if any of them is ever ignored without that argument written
down.

Nobody outside the project has reviewed it, and there is no budget to commission
that. So it is an open invitation: the models are in [`formal/`](formal/), the
harness in [`security/ct/`](security/ct/), the advisory arguments in
[`docs/UPSTREAM.md`](docs/UPSTREAM.md). Whatever you find is yours to publish.

**Found something? Email <contact@ideoa.co.uk>, and please do not open a public
issue.** A public issue is a working exploit handed to everybody reading this
repository, including the people running the relays and mailboxes this project
asks you to trust. What to include, what we do with it and how long we take is
in [`SECURITY.md`](SECURITY.md).

---

## Licence

**GNU Affero General Public License v3** ([`LICENSE`](LICENSE)). Run your own
relay, your own mailbox, your own client; publish what you change if you offer
it over a network.

The transport stack under `crates/net/` is derived from other projects and
stays under the licences they granted: MIT, Apache-2.0 and BSD-3-Clause. See
[`LICENSING.md`](LICENSING.md) for what is under which, and
[`crates/rotelyx-net/NOTICE`](crates/rotelyx-net/NOTICE) for provenance.

Rotelyx is a trademark. The licence covers the code, not the name.

<div align="center">


</div>
