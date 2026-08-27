# What it costs

Written by `scripts/benchmarks --write`. Do not edit by hand: the next
run overwrites it.

The paper quotes sizes throughout and timings almost nowhere, and the two
are not equally checkable. A size can be recomputed by reading the code.
A timing cannot be recomputed by anybody who does not run it, which is
why this file exists and why it names the machine that produced it.

| | |
|---|---|
| Machine | Intel(R) Core(TM) i7-2600K CPU @ 3.40GHz |
| Compiler | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| Profile | release |

Each figure is the median of the sample count the harness states, after a
warm-up, not a best case. A best case is what a machine produces when
nothing else is happening, which is not the condition any of this runs in.

```
Rotelyx benchmarks
median of 64 runs, release build


Post-quantum key agreement
--------------------------
  encapsulate                                   212.5 us
  decapsulate                                   266.5 us
  encapsulation key                              1216 bytes
  ciphertext                                     1120 bytes

Message layer
-------------
  encrypt, 2 bytes                               73.5 us
  encrypt, 4 KiB                                118.0 us
  decrypt, 2 bytes                              100.9 us
  ciphertext for 2 bytes                          318 bytes
  ciphertext for 4 KiB                           4414 bytes

Groups
------
  commit at 8 members                            1342 bytes
  export the tag key at 8                        4464 ns
  commit at 100 members                          9022 bytes
  export the tag key at 100                      4348 ns
  commit at 1000 members                        83008 bytes
  export the tag key at 1000                     4344 ns

Blind mailbox
-------------
  derive a tag for one hour                       249 ns
  seal a payload                                 3268 ns
  open a payload                                 2609 ns
  envelope, seal into a bucket                    126 ns
  sealed payload for 900 bytes                    942 bytes
  envelope on the wire                           1056 bytes

Media
-----
  protect one frame                               579 ns
  unprotect one frame                             561 ns
  frame on the wire, 60 byte payload               79 bytes

Voice codec
-----------
  encode one frame, 12 kbit/s                   107.0 us
  decode one frame, 12 kbit/s                   100.1 us
  frame at 12 kbit/s                               32 bytes
  encode one frame, 16 kbit/s                   167.0 us
  decode one frame, 16 kbit/s                   102.1 us
  frame at 16 kbit/s                               41 bytes
  encode one frame, 24 kbit/s                   122.4 us
  decode one frame, 24 kbit/s                   103.5 us
  frame at 24 kbit/s                               55 bytes
  encode and decode together                     1.14 % of real time, one core

At the door
-----------
  safety number, two identities                  50.9 us
  mint a meeting code                             692 ns
  derive a rendezvous tag                        2104 ns
  unlock the vault (Argon2id, 64 MiB)           223.9 ms  (5 runs)

Nothing here touches a network. See the module comment.
```

## What is deliberately absent

Anything that needs a network: establishing a direct path, reaching a
relay, depositing to a mailbox over a socket. Those are dominated by the
network, and a number for them would say more about one room's wifi than
about Rotelyx. They belong in a field test across real NATs, which is
listed as open in `TODO.md` and has not been done.

## Reproducing it

```sh
git clone <this repository> && cd rotelyx
cargo test --workspace              # 597 tests
cargo test -p rotelyx-crypto --test pq_vectors   # the published vectors
scripts/benchmarks                  # this file
scripts/audit-dependencies          # every advisory, reviewed
cargo deny check                    # bans, licences, sources, advisories
```
