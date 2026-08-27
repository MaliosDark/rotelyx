# Upstream watch

`crates/net` holds 124,000 lines derived from other people's projects. Vendoring
means fixes no longer arrive on their own: `cargo update` will never change a
line in this repository, so somebody has to read what upstream did and port it
by hand. This file is where that reading gets written down.

`scripts/watch-upstream` does the mechanical half. It compares each vendored
crate against the project it was taken from, lists the security advisories filed
against that code, and exits non-zero if any advisory is not named in this file.

## Why the version numbers cannot be trusted on their own

Every vendored crate is level with the newest version its upstream has
published. That is not the same as being safe.

The QUIC crates come from N0's fork of quinn, renamed to `noq` and renumbered to
1.x. `noq-proto 1.1.1` is the newest `noq-proto` that exists, and it was still
missing a fix quinn had already shipped, under a version number that cannot be
compared with it. The advisory is filed under `quinn-proto`; searching for `noq`
finds nothing at all.

So the watch looks up advisories under the *original* name, and every advisory
is cleared by reading the source in this tree, never by comparing versions.

## Advisories reviewed

Each entry says what the advisory is and what was found here.

### RUSTSEC-2026-0185, quinn-proto: ported

Remote memory exhaustion. Out-of-order stream fragments are buffered until they
can be joined into contiguous chunks. A peer that leaves a gap between every
fragment leaves nothing to join, so each one-byte frame keeps its own entry and
its own reference-counted packet buffer alive, and the receiver runs out of
memory while the sender spends almost nothing. Reachable before a handshake
completes, over the CRYPTO stream.

Our fork did not have the fix. Ported from quinn PR 2694: `Assembler::insert`
now returns an error once defragmentation leaves more than 1024 chunks standing,
and both call sites close the connection instead. Covered by
`fragments_that_never_touch_are_refused_before_memory_runs_out` in
`crates/net/rotelyx-quic-proto/src/connection/assembler.rs`.

### RUSTSEC-2026-0037, quinn-proto: already fixed here

Panic on malformed transport parameters: `unwrap()` on a truncated
`max_datagram_frame_size` or `min_ack_delay`. Both sites in
`crates/net/rotelyx-quic-proto/src/transport_parameters.rs` already use `?`, so
the fork was taken after quinn PR 2559.

### RUSTSEC-2024-0373, quinn-proto: not applicable

Fixed in quinn-proto 0.11.7. The transport-parameters check above places this
fork after 0.11.14, so it carries this fix.

### RUSTSEC-2023-0063, quinn-proto: not applicable

Fixed in quinn-proto 0.10.5, long before the fork point established above.

### RUSTSEC-2021-0035, quinn: not applicable

Fixed in quinn 0.7.0, in 2021. The async layer here derives from a fork made
years after that.

## Crates with no advisories on file

`iroh`, `iroh-base`, `iroh-relay`, `iroh-dns`, `iroh-metrics`,
`iroh-metrics-derive`, `netwatch`, `n0-error`, `n0-error-macros`, `n0-future`,
`n0-watcher`, `quinn-udp`. Nothing filed means nothing found by anybody, which
is weaker than nothing being there. The watch will say so the day that changes.

# Dependency advisories

`scripts/audit-dependencies` checks the 719 packages in `Cargo.lock` against the
same database. It matches version ranges and nothing more: whether a vulnerable
function is reachable from Rotelyx is a question about this code, and answering
it means reading. The answers are below, one per advisory id, because an id not
named here makes the check exit non-zero.

## Vulnerabilities

### RUSTSEC-2026-0258, h2: fixed by updating

Empty DATA frames queued without limit, so a peer that never drains a stream can
grow memory without bound. Reached through `hickory-resolver`, which the
transport uses for DNS. Updated 0.4.15 to 0.4.18.

### Three records, and none of them may drift

`deny.toml` is what `cargo deny` reads. `.cargo/audit.toml` is what `cargo audit`
reads. This document is where the reasoning lives. All three carry the same list,
and `scripts/audit-dependencies` fails if they stop agreeing.

That check exists because they did not always agree, and it cost something. For
four consecutive review rounds a continuous audit harness reported the same
dependency finding as open, recommending a `cargo update` that cannot work,
while the analysis answering it sat in this file. `cargo deny` had been told;
`cargo audit` had not. **Two dependency tools disagreeing is how a real finding
gets lost between them**, and a report that carries a permanent false red trains
its readers to skim exactly the section where a true one will eventually appear.

The two tools also disagree honestly, which is worth knowing when reading their
output: `cargo deny` resolves the build graph and `cargo audit` reads
`Cargo.lock`, so a crate that is locked but never compiled shows up in one and
not the other. The libcrux AEAD entries are exactly that case. The lists are
kept identical anyway.

### Why these are in `deny.toml` and not merely written about

Every advisory below appears in the `ignore` list of `deny.toml`, and that is
deliberate rather than a way of quieting a tool.

An audit listed the same three dependency findings in three consecutive rounds,
each time recommending `cargo update`, and each time the recommendation did not
apply: `hpke-rs 0.6.1` pins `libcrux-sha3` at `^0.0.8`, which no `0.0.10` can
satisfy, and there is no fixed `rsa` at all. An open finding that cannot be
closed and is not real is worse than either: it trains everybody reading the
report to skim that section, which is where a real one will eventually sit.

So the tools now carry the conclusion. `cargo deny check advisories` passes,
with a one-line reason beside each id. And `scripts/audit-dependencies` refuses
to pass if an advisory id is missing from **this file**, so an entry cannot be
added to `deny.toml` without the argument that justifies it being written down
first. Deleting a section here breaks the build, which was checked by deleting
one.

The bar for an entry is that the code cannot run, not that the fix is
inconvenient. Where that bar is not met, the entry says so: the `rsa` one is
accepted because no patched version exists, and it carries a constraint on
future work rather than a clean bill of health.

### Two majors of x25519-dalek: neither is ours to choose

An audit noted two implementations of the same primitive in one binary, which is
a fair thing to notice: it doubles the code that has to be right and means a
fix landing in one does not reach the other.

Neither version is a direct dependency. 2.0.1 arrives through
`hpke-rs-rust-crypto` under `openmls_rust_crypto`, and 3.0.0 through `x-wing`.
Unifying them means moving one of those upstreams, and the only route for the
MLS side is the same release-candidate jump that RUSTSEC-2026-0207 would need.
That is a large change to the most security-critical dependency in the tree, to
remove a duplicate rather than a defect.

What makes it tolerable is that the two are not used for the same thing. The MLS
copy performs the classical half of the ordinary handshake; the X-Wing copy
performs the classical half of the post-quantum composition. The composition's
whole claim is that both halves must break, so it does not rest on either copy
alone.

Revisit with OpenMLS 0.9, alongside the libcrux entries below.

### RUSTSEC-2023-0071, rsa: no patch exists, and nothing here performs the operation

The Marvin attack: a non-constant-time private-key operation leaks the key
through timing an attacker can measure over the network. There is no fixed
version. Stable `rsa` is affected and so is the 0.10 release candidate that
`blind-rsa-signatures` pulls in, so this cannot be updated away.

It does not reach anything Rotelyx builds. The private half of a blind-RSA key
is only ever touched by `blind_sign`, and the only calls to it in this tree are
inside `#[cfg(test)]`. `crates/rotelyx-capability/src/blind.rs` exposes exactly
two things to the rest of the program: `Redeemer`, which blinds and unblinds
with the issuer's public key, and `BlindVerifier`, which verifies with it. The
mailbox server is given a public key and has no other half.

This is worth writing down carefully because it is a constraint on future work
rather than a clean bill of health. **An issuer built on the `rsa` crate and
exposed to the network would be vulnerable, and the consequence is recovery of
the key that mints capability tokens.** It does not touch message content: MLS
keys are unrelated. When an issuer is built, either the timing has to be
unobservable or the signing has to move off this crate.

### RUSTSEC-2026-0207, RUSTSEC-2026-0208, libcrux-sha3: the affected functions are not called

Both are fixed in 0.0.10 and both are unreachable at 0.0.8, which is where
`hpke-rs 0.6.1` pins us with `^0.0.8`. Getting 0.0.10 means `hpke-rs 0.7`, which
means `openmls_rust_crypto 0.6.0-rc.3` and `openmls 0.9.0-rc.3`: moving the MLS
stack onto release candidates. That is the wrong trade for two bugs that cannot
fire here.

0207 is in the incremental XOF API, when output is squeezed across several calls
with a length not divisible by the rate. `hpke-rs` calls `libcrux_sha3::shake256`
with a const length, which is the one-shot API: it calls `portable::shake256`
once and never touches `Shake256Xof::squeeze`.

There is a second reason, and it is the stronger one. In `hpke-rs`, both calls to
`shake256` sit in `derive_key_pair`, in the arms for `XWingDraft06` and
`MlKem768 | MlKem1024`. `CIPHERSUITE` in `crates/rotelyx-crypto/src/group.rs` is
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, whose KEM is
`DhKem25519`, and that arm goes to `dh_kem::derive_key_pair` and never reaches
SHAKE at all. Rotelyx's post-quantum material is X-Wing composed separately and
injected at the pre-shared-key input, not an MLS ciphersuite, so nothing moves
this to the ML-KEM arm. An external audit raised these two in August 2026 and
explicitly left reachability open; this is the answer.

0208 is in `libcrux_sha3::avx2::x4::shake256`, used by ML-KEM and ML-DSA. Neither
is in this graph and nothing calls that path.

Revisit when OpenMLS 0.9 is stable.

### RUSTSEC-2026-0212, libcrux-secrets: not called on any platform

Constant-time `select` and `swap` could return the wrong answer on aarch64,
because the inline assembly compared a 32-bit register against an 8-bit
selector. Fixed in 0.0.6; we hold 0.0.5, pinned the same way as above.

This one deserved a careful look because aarch64 is every phone Rotelyx runs on.
It does not reach us: `libcrux-secrets` arrives only as a dependency of
`libcrux-traits`, which arrives as a dependency of `libcrux-sha3`, and
`libcrux-sha3` contains no reference to `Select` or `Swap` at all.

### RUSTSEC-2026-0209, RUSTSEC-2026-0211, RUSTSEC-2026-0124, libcrux AEAD: never compiled

An unbounded AAD length, a non-constant-time GCM tag comparison, and a panic on
an overlong ciphertext buffer. All three would matter if this code ran.

It does not. `libcrux-aesgcm` and `libcrux-chacha20poly1305` reach the lock file
through `libcrux-aead`, which reaches it through `hpke-rs-libcrux`, which is the
optional libcrux backend of `hpke-rs` and one of its dev-dependencies.
`openmls_rust_crypto` asks for `hpke-rs-rust-crypto`, the RustCrypto backend, so
the libcrux backend is never selected. `cargo tree -i hpke-rs-libcrux --target
all` finds no path from this workspace.

A package in `Cargo.lock` is not the same as a package in the binary, and a
checker that only reads the lock cannot tell the difference. This is one of the
places where the reading has to happen.

## Informational

These are not vulnerabilities. They are mostly notices that nobody is
maintaining a package any more, which is a reason to watch it rather than a
reason to act today.

**GTK 3 bindings, no longer maintained**: RUSTSEC-2024-0411, RUSTSEC-2024-0412,
RUSTSEC-2024-0413, RUSTSEC-2024-0414, RUSTSEC-2024-0415, RUSTSEC-2024-0416,
RUSTSEC-2024-0417, RUSTSEC-2024-0418, RUSTSEC-2024-0419, RUSTSEC-2024-0420, and
the `Iterator` unsoundness in RUSTSEC-2024-0429. Eleven notices with one cause:
Tauri 2 draws the Linux desktop window with GTK 3, and gtk-rs has stopped
maintaining those bindings. Nothing here can be fixed by updating; it changes
when Tauri moves off GTK 3. It affects the desktop build on Linux only, and no
part of it handles key material or parses anything from the network.

**`ring` is unmaintained**: RUSTSEC-2025-0007. This one is worth naming on its
own, because `ring` is a cryptographic library and it arrives under `rustls`,
which is what the transport uses for TLS. It is a maintenance notice, not a
flaw. `rustls` is aware of it and is moving toward `aws-lc-rs`, which is already
in this graph. Watch it; it is the informational notice here most likely to turn
into something.

**Unmaintained utility crates**: RUSTSEC-2020-0053 (`dirs`), RUSTSEC-2023-0089
(`atomic-polyfill`), RUSTSEC-2024-0370 (`proc-macro-error`), RUSTSEC-2024-0384
(`instant`), RUSTSEC-2024-0436 (`paste`), RUSTSEC-2026-0173
(`proc-macro-error2`), and the Unicode tables in RUSTSEC-2025-0075,
RUSTSEC-2025-0080, RUSTSEC-2025-0081, RUSTSEC-2025-0098, RUSTSEC-2025-0100. All
transitive, none cryptographic, several of them compile-time only.

**RUSTSEC-2026-0210**: `libcrux-aesgcm` was renamed to `libcrux-aes`. It refers
to the crate established above as never compiled.
