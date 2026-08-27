# The constant-time harness

One question, asked empirically rather than by reading the code: does comparing
a mailbox tag take a different amount of time when the tag matches?

It matters because a tag is how a mailbox is addressed. A comparison that
returned faster on a mismatch would let somebody who can time the server learn a
tag one byte at a time, and a tag is the only thing standing between an observer
and knowing which mailbox is which.

The comparison is `subtle`'s constant-time equality, so the answer should be no.
This measures whether it actually is.

## Running it

```sh
cd security/ct
cargo run --release --bin ct_tag -- --continuous tag_eq
```

It runs until interrupted, printing a running t-statistic. `--continuous` takes
the name of the benchmark, not a sample count.

DudeCT feeds two classes of input, one always equal to the reference and one
random, and applies Welch's t-test to the two timing distributions. A leak shows
up as `|t|` climbing without bound as samples accumulate. The conventional
threshold for "no leak detected" is `|t| < 10`.

## What it reported

```
bench tag_eq ... : n == +349.014M, max t = -1.00933, max tau = -0.00005
```

349 million samples, `|t|` around 1.0 and not trending upward. The audit's own
run reached 1.98 over 39 million on different hardware, which is the same
answer.

## What it does not cover

One comparison, on one machine, under one compiler. It says nothing about the
constant-time behaviour of the third-party primitives underneath, which is named
as out of scope in the audit and remains open to somebody else's measurement.

It is excluded from the workspace because it pulls a benchmarking dependency
that nothing shipped depends on, and because it is run deliberately rather than
as part of `cargo test`.
