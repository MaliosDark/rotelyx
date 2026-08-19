# rotelyx-net: provenance and replacement plan

`rotelyx-net` is Rotelyx's transport layer. The entire stack is **vendored into this
repository** under `crates/net/`: Rotelyx downloads no upstream transport
package, and `cargo tree` shows no `iroh`, no `noq`, no `n0-*`. From here it is
being built by **owning the policy layer outright and replacing the machinery
underneath it subsystem by subsystem**, rather than by rewriting a QUIC stack
and a NAT traversal implementation from scratch before anything works.

Vendoring is done. Rewriting is not. Those are different claims and this
document keeps them apart on purpose.

This document records where the code came from, what the licences oblige us to
do, and what has actually been replaced so far. It is kept honest on purpose:
the claim "Rotelyx ships its own transport" has to survive somebody reading this
file.

---

## 1. What is actually underneath

Measured against the vendored sources at the versions we build.

| Crate | LOC | Author | Role |
|---|---:|---|---|
| `iroh` | 27,768 | Number 0 | endpoint, socket, hole punching |
| `noq-proto` | 50,162 | Number 0 (fork of quinn) | QUIC protocol state machine |
| `noq` | 7,872 | Number 0 | QUIC async layer |
| `iroh-relay` | 12,361 | Number 0 | relay client + server |
| `netwatch` | 5,679 | Number 0 | link/route change detection |
| `iroh-metrics` | 4,636 | Number 0 | metrics |
| `portmapper` | 3,054 | Number 0 | UPnP / PCP / NAT-PMP |
| `noq-udp` | 2,790 | Number 0 | UDP socket abstraction |
| `iroh-dns` | 2,524 | Number 0 | pkarr / DNS discovery |
| `n0-error`, `n0-future`, `n0-watcher` | 4,801 | Number 0 | utilities |
| `iroh-base` | 1,139 | Number 0 | key and address types |
| **Total** | **122,786** | | |

Two things worth knowing before anyone claims this is a small dependency:

- **The QUIC implementation is itself a fork.** `noq-proto` is Number 0's fork
  of `quinn`. Half the line count above is a QUIC state machine that neither
  they nor we wrote.
- **The hole punching is derived from Tailscale.** `iroh/src/socket/**` is
  BSD-3-Clause, "Copyright (c) 2020 Tailscale Inc & AUTHORS", per
  `LICENSE-BSD3` in the iroh distribution.

Nobody in this lineage wrote NAT traversal from zero. Tailscale did the original
work, Number 0 derived from it, and Rotelyx derives from that. Building on it is
the normal case, not the exception.

## 2. Licence obligations

`rotelyx-net` is a derivative work and carries three obligations we do not get to
opt out of.

- **iroh and its sibling crates:** `MIT OR Apache-2.0`. Both require the
  copyright notice and licence text to be retained in redistributed source.
  Apache-2.0 §4(b) additionally requires that modified files **carry prominent
  notices stating that we changed them**.
- **`iroh/src/socket/**`:** `BSD-3-Clause`, Tailscale Inc & AUTHORS. Requires
  retention of the copyright notice and disclaimer, and forbids using the
  authors' names to endorse our product.

What this permits: renaming every type, changing every default, deleting
whatever we do not need, shipping it under our own crate name, and never
mentioning the upstream name in the product UI.

What this forbids: deleting the notices. `LICENSE-*` and `NOTICE` in this
directory are not optional and must not be removed to make the authorship story
cleaner. A licence violation is a worse look than a derived dependency.

## 3. What Rotelyx owns today

These are Rotelyx's design decisions, not upstream's, and they are the reason
this crate exists rather than a direct dependency:

- **`RelayPolicy`**: no variant meaning "the library's defaults". Upstream's
  `RelayMode::Default` and `RelayMode::Staging` point at Number 0's servers and
  are unreachable through this API.
- **`AddressLookup::Disabled` as the only variant**: upstream's default preset
  registers a pkarr publisher, a pkarr resolver and a DNS lookup against
  `dns.iroh.link`, announcing the endpoint's public key to a third party on
  every startup. Rotelyx does rendezvous at L3, sealed. This is deleted, not
  configured off.
- **`PathPolicy`**: the genuine divergence. Upstream selects paths by latency.
  Rotelyx selects by metadata resistance, and the two conflict: given a fast
  relayed path and a slow direct one, latency-first hands the social graph to a
  relay operator to save milliseconds.
- **`tests/no_foreign_infrastructure.rs`**: the guarantee, enforced. Binds live
  endpoints, reads back their relay maps, scans workspace source for
  third-party hostnames, and asserts upstream environment overrides have no
  effect. Fails the build otherwise.

## 4. Replacement roadmap

Ordered by value, which is not the same as ordered by size.

| Subsystem | Status | Plan |
|---|---|---|
| Vendoring | **done** | All 14 crates in `crates/net/`, renamed, path-linked. No upstream package is downloaded. |
| Address lookup / discovery | **unreachable** | Removed from the public API and never constructed. The vendored `rotelyx-discovery` crate is still present and is slated for outright deletion once nothing links it. |
| Relay + path policy | **ours** | `RelayPolicy` / `PathPolicy` in `config.rs`. |
| Path *selection algorithm* | next | Implement upstream's `PathSelector` hook with a metadata-resistance objective instead of an RTT one. ~800 LOC, and the most novel work in the crate. |
| Relay server | planned | We operate relays regardless, so writing one is justified and tractable: a stateless QUIC forwarder is the simplest of the four components. Replaces ~12,000 LOC. |
| Metrics | planned | Delete. Telemetry in a privacy tool is a liability, and it is 4,636 LOC of dependency surface bought for nothing. |
| Port mapping (UPnP/PCP) | under review | Announces our presence to the local gateway. May be a metadata leak worth refusing. ~3,000 LOC. |
| Socket / hole punching | keep | Derived from Tailscale, battle-tested across every NAT type in the wild. Rewriting buys nothing and risks a lot. |
| QUIC state machine | keep | 50,000 LOC of protocol conformance. Rewriting this is not a project, it is a career. |

## 5. The honest summary

After the roadmap above completes, Rotelyx will have written its own discovery,
its own relay, and its own path selection: the parts where privacy is actually
decided, and will still be running a QUIC implementation and a NAT traversal
implementation derived from other people's work.

That is the same position Signal is in with respect to TCP and TLS, and the same
position Number 0 is in with respect to Tailscale and quinn.

The defensible claim is: **"Rotelyx ships its own transport, derived from iroh and
substantially rewritten for metadata resistance."**

The indefensible claim is: **"we wrote a transport library from scratch."**
Do not make it.
