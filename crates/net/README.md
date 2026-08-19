# crates/net: the vendored transport stack

This directory holds Rotelyx's transport machinery as source, in this repository.
Rotelyx downloads no upstream transport package: `cargo tree` shows no `iroh`, no
`noq`, no `n0-*`.

It is excluded from the Rotelyx workspace (`exclude = ["crates/net"]` in the root
manifest) so that upstream's own test suites and lint configuration do not run
as part of Rotelyx's. Each crate here is its own workspace root.

## What is here

| Crate | Derived from | LOC | Role |
|---|---|---:|---|
| `rotelyx-quic-proto` | `noq-proto` (a fork of `quinn`) | 50,162 | QUIC protocol state machine |
| `rotelyx-transport` | `iroh` | 27,768 | endpoint, socket, hole punching |
| `rotelyx-relay-proto` | `iroh-relay` | 12,361 | relay client and server |
| `rotelyx-quic` | `noq` | 7,872 | QUIC async layer |
| `rotelyx-netwatch` | `netwatch` | 5,679 | link and route change detection |
| `rotelyx-metrics` | `iroh-metrics` | 4,636 | metrics |
| `rotelyx-quic-udp` | `noq-udp` | 2,790 | UDP socket abstraction |
| `rotelyx-discovery` | `iroh-dns` | 2,524 | DNS resolution, **kept**; the discovery half is unreachable. See below |
| `rotelyx-error` | `n0-error` | 1,820 | error plumbing |
| `rotelyx-future` | `n0-future` | 1,506 | async utilities |
| `rotelyx-watcher` | `n0-watcher` | 1,475 | change notification |
| `rotelyx-transport-base` | `iroh-base` | 1,139 | key and address types |
| `rotelyx-error-macros` | `n0-error-macros` | 978 | derive macros |
| `rotelyx-metrics-derive` | `iroh-metrics-derive` | 487 | derive macros |
| | **Total** | **121,197** | |

## How the rename works

Package names are ours. Dependency *keys* still carry the upstream name, with
Cargo's `package = "..."` rename pointing them at our crates:

```toml
[dependencies.iroh-base]
package = "rotelyx-transport-base"
path = "../rotelyx-transport-base"
```

That means 121k lines of vendored source keep compiling with their existing
`use iroh_base::` imports while the packages themselves are Rotelyx's. The import
rename is mechanical and happens per crate as each one is worked on, it is not
a prerequisite for owning the code.

Rotelyx's own crates never do this. `rotelyx-net` imports `rotelyx_transport`
directly; nothing in `crates/rotelyx-*` names an upstream crate.

## Licences

`crates/rotelyx-net/NOTICE` carries the required attributions for everything in
this directory: iroh and siblings (MIT OR Apache-2.0, N0 INC.), the socket layer
(BSD-3-Clause, Tailscale Inc & AUTHORS), and the QUIC layer (MIT OR Apache-2.0,
the quinn developers). Apache-2.0 §4(b) also requires stating the modifications
we made, and that list is in the same file.

**Do not delete those notices.** Renaming a package does not end the obligation,
and a licence violation is a far worse look than a derived dependency.

## What has actually changed from upstream so far

Policy, which is the part that decides privacy: see `crates/rotelyx-net/src/`.
The machinery in this directory is still substantively upstream's. The
per-subsystem replacement plan, in priority order, is in
`crates/rotelyx-net/VENDORING.md`.

## Why `rotelyx-discovery` is still here

It was marked for deletion, on the reasoning that pkarr and DNS-based endpoint
discovery are exactly the third-party infrastructure this project must never
contact. That reasoning is right and the conclusion was wrong: the crate does
two unrelated things.

| | lines | what it is |
|---|---|---|
| `dns.rs` | 1,011 | plain DNS resolution. **Needed**: resolving `relay.example.com` is how a client finds a relay at all |
| `endpoint_info.rs` + `attrs.rs` | 763 | the discovery: endpoint records in DNS TXT, pkarr signed packets |
| `android.rs` | 93 | JNI context, needed for the Android build |

Deleting the crate removes DNS resolution and breaks every relay client. Of the
21 references to it across the transport, 14 are the resolver.

**The discovery half is unreachable, and by construction rather than by
configuration.** `rotelyx_net::AddressLookup` has exactly one variant,
`Disabled`; there is no value a caller could pass to turn discovery on. The
endpoint additionally calls `clear_address_lookup()` when it binds, which the
code there calls belt-and-braces so that adding a preset later cannot silently
reintroduce a publisher.

So the 763 lines compile and nothing can reach them. Removing them is tidiness,
not a fix, and it means editing a vendored tree that upstream patches still have
to apply to. The cost of keeping them is that they are 763 lines nobody has
reviewed. That is the trade, written down so the next person can take it again
rather than rediscover it.
