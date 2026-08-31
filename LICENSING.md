# Licensing

Rotelyx is free software under the **GNU Affero General Public License,
version 3**. The full text is in [LICENSE](LICENSE).

This document exists because the repository is not under a single license, and
saying so plainly is better than leaving somebody to work it out from fourteen
`Cargo.toml` files.

## What is under what

| Path | License | Holder |
|---|---|---|
| `crates/rotelyx-*` | AGPL-3.0-only | Andryu Schittone |
| `crates/net/*` | MIT OR Apache-2.0 | N0, INC. |
| `crates/net/rotelyx-relay-proto`, `crates/net/rotelyx-transport` | the above, **and** BSD-3-Clause | N0, INC. and Tailscale Inc |
| `site/`, `docs/` | AGPL-3.0-only | Andryu Schittone |

Everything under `crates/rotelyx-*` is original work, roughly 29,000 lines,
written by one author. Everything under `crates/net/` is a derived work of
existing projects and keeps the license those projects granted.

### About the transport stack

`crates/net/` holds 121,000 lines derived from `iroh`, `quinn` and related
crates, with the package names changed to Rotelyx's and parts replaced. See
[crates/net/README.md](crates/net/README.md) for what came from where.

**Renaming a package does not change who holds its copyright.** A derived work
carries the original license no matter how much of it has been rewritten, and
the license files in each crate are there for that reason. They are an
obligation this project meets, not a formality.

The relay and transport crates additionally contain code derived from
Tailscale's DERP, which is BSD-3-Clause. Their SPDX expression reflects both:
`(MIT OR Apache-2.0) AND BSD-3-Clause`.

### Combining them

MIT, Apache-2.0 and BSD-3-Clause are permissive and one-way compatible with the
AGPL: a larger work may be distributed under the AGPL while its permissively
licensed parts keep their own terms and notices. That is what this repository
is. The direction does not reverse, so the AGPL parts cannot be taken back out
under MIT.

## Why the AGPL

Rotelyx is a messenger whose entire claim is that the operator cannot read
messages, cannot link a payment to a user, and cannot see who talks to whom.
That claim is worth exactly as much as a reader's ability to check it.

An operator running a modified Rotelyx that quietly weakens any of those
properties would be indistinguishable from one running this code, and a
permissive license would let them do it and say nothing. Section 13 of the AGPL
is the clause that closes that: **anyone who offers a modified Rotelyx over a
network must offer its source to the people using it.**

So the license is not chosen to restrict use. It is chosen because a private
fork of a privacy tool, running as a service, is the failure mode this project
exists to prevent.

Running your own relay, your own mailbox, or your own client is expressly what
this is for. Publish your changes and you are done.

## Trademark

**Rotelyx is a trademark of Andryu Schittone.** The AGPL grants rights to the
code. It grants nothing over the name, the logo, or the marks.

A fork may use the code. A fork may not call itself Rotelyx, imply it is
Rotelyx, or present itself as the official service. Name it something else and
say what it is derived from.

This is the ordinary arrangement for a project whose users need to know which
service they are actually trusting.

## Commercial licensing

The AGPL suits anyone willing to publish their changes. For those who are not,
a separate commercial license can be granted.

That option only exists while the copyright is held in one place, which is why
contributions require the agreement in [docs/CLA.md](docs/CLA.md).

Enquiries: see the repository owner.

### Store builds

Apple's terms restrict what a person may do with an app they download: install
it on devices they own, and not pass it on. The AGPL says the opposite, that
nobody may add restrictions on top of the rights it grants. Both cannot hold at
once, which is why Apple removed VLC in 2011 after one of its authors objected.

Only a copyright holder of code inside the app can raise that objection. Every
AGPL line here is held by one person, and nothing the apps depend on is
copyleft: `deny.toml` admits no GPL and no LGPL beyond one exception, on a
target this project does not build for.

So the binaries submitted to Apple and Google are distributed under the owner's
own terms, while this repository stays AGPL and carries the same source. That is
the dual licensing described above, applied to the project's own apps.

It stops working the moment either half stops being true: a contribution taken
without [docs/CLA.md](docs/CLA.md), or a copyleft dependency added. Both are
refused for this reason and not only on taste.

**This grants no exclusivity and is not meant to.** Anyone may build the code
and publish an app of their own; the AGPL is what makes that permitted and
Section 13 is what makes them publish their changes. What they may not do is
call it Rotelyx, which is a question of the trademark above and not of any
license.

## What is not in this repository

No issuer secret, no operator keys, no customer records, no payment
integration, and no deployment credentials. The mechanisms are here and can be
audited. The keys are supplied at runtime and never committed.

That split is deliberate. **The mechanism has to be public for the privacy
claims to mean anything; the keys have to be private for them to hold.**
