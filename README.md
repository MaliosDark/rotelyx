<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/rotelyx-logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/brand/rotelyx-logo-light.png">
  <img src="docs/brand/rotelyx-logo-light.png" alt="Rotelyx" width="380">
</picture>

**Encrypted messages, straight between two devices.**

No accounts, no phone numbers, and no servers belonging to anybody else.

[![tests](https://img.shields.io/badge/tests-450%20passing-6a31ee?style=flat-square)](docs/CONTRIBUTING.md)
[![rust](https://img.shields.io/badge/rust-1.85%2B-6a31ee?style=flat-square)](#try-it)
[![licence](https://img.shields.io/badge/licence-AGPL--3.0-8b8b8b?style=flat-square)](#licence)
[![status](https://img.shields.io/badge/status-unaudited-E0808C?style=flat-square)](#security-status)


</div>

---

> [!CAUTION]
> **Rotelyx is unaudited and pre release. Do not use it to protect anything.**
> It makes no security claims until the review gates in
> [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) section 5 are met.

---

## What it is

A messenger where **your identity is a key, not an account.** No phone number,
no email, no sign up, nothing published anywhere.

When both people are online, messages go **straight between the two devices**
and touch no server. When one is offline, the message waits in a mailbox that
cannot read it and does not know who sent it.

Everything it runs on is in this repository. It contacts no infrastructure
belonging to anyone else, and there is a test that fails if that ever changes.

Two encryption layers, independent of each other, and post quantum key exchange
from the first version rather than as a later migration.

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

## Read more

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | How a message actually travels, layer by layer |
| [Threat model](docs/THREAT-MODEL.md) | Ten adversaries, and what is not defended |
| [The voice codec](docs/CODEC.md) | Voice is built and tested, but there is no call command yet |
| [Post quantum](docs/PQ-COMPOSITION.md) | The construction, written for review |
| [Access and tiers](docs/ACCESS.md) | What a mailbox limits, and how |
| [Deployment](docs/DEPLOYMENT.md) | Running one properly |
| [Working on it](docs/CONTRIBUTING.md) | Layout, tests, roadmap |
| [Provenance](docs/PROVENANCE.md) | Where the vendored code came from |

## Security status

Rotelyx makes **no claim** of being unbreakable, un interceptable or impossible
to access. Those claims are false for every system that has ever made them.

What it claims is bounded, written down and testable. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

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
