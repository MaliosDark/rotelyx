# Rotelyx blind mailbox

A store and forward server for peers that are not both online. It holds sealed
envelopes under opaque rotating tags, hands them to whoever asks for a tag, and
holds no key: it cannot read a byte of what it stores, and it cannot read a tag
back to a person. See `docs/MAILBOX-WIRE.md` for the protocol and
`docs/DEPLOYMENT.md` for running one.

```sh
rotelyx-mailbox-server --bind 0.0.0.0:3341 --max-connections 500000
```

| Route | Purpose |
|---|---|
| `/mailbox` | WebSocket. Deposit and subscribe |
| `/front` | WebSocket. A front's multiplexed sessions, with `--front-key` |
| `/front-key` | The public front key, with `--front-key` |
| `/directory` | The constellation this mailbox belongs to, with `--directory` |
| `/ping` | Health probe |
| `/` | Landing page, self contained |

## What it holds, measured

The connection ceiling used to be a fixed 4096, a conservative floor set before
the cost of a connection was measured. It was measured, and the floor was the
only thing keeping a mailbox small.

A load generator (`cargo run --release --example loadtest -- <url> direct <n>`)
opened connections in waves and held them, while the server's memory, processor
and descriptors were sampled. On a commodity eight core host with 23 GB of
memory, holding tens of thousands of idle connections at once:

| What | Cost |
|---|---|
| Memory per connection | about 16.5 KB |
| Descriptors per connection | one |
| Processor, tens of thousands of idle connections | single digit percent, all keepalive pings |
| Memory per subscribed tag | about 64 bytes |
| Disk per connection | none; disk grows only with undelivered envelopes, TTL seven days |

The generator itself topped out near 28,000 connections, not because the server
refused them but because one source address has only about 28,000 ephemeral
ports to one destination port. The server carried those 28,000 in 465 MB at
under 10 percent of the processor. Real clients arrive from many addresses and
do not share that limit.

What the numbers say about a single mailbox on such a host:

| Bound | Connections |
|---:|---:|
| Memory, 23 GB at 16.5 KB each | about 1,400,000 |
| Descriptors, limit raised to 1,048,576 | about 1,000,000 |
| **Practical ceiling** | **about 1,000,000 connections, about 15 GB** |

At nine connections per device without a front, that is roughly **110,000
devices on one mailbox**, up from the few hundred the old floor allowed. The
descriptor limit has to be raised to match the memory, or the operating
system's default of 1024 caps it long before memory does; the deployment guide
covers this.

## The front changes the shape

With a **front** in front of the mailbox, a device is one sealed session rather
than nine connections, and a session is a task and a few tags rather than a
held socket. The connection ceiling stops binding, and the same host holds an
order of magnitude more. See `docs/FRONT.md`.

## Constellation, and failover

A mailbox can belong to a constellation: run it with `--directory <file>` and it
serves that constellation's directory at `/directory`. A client fetches the
directory, computes on its own which mailboxes hold a conversation's tag, and
writes to and reads from all of them, so the conversation survives one being
down and its load spreads. No mailbox talks to another, and none learns the
whole of a conversation. `docs/CONSTELLATION.md` has the design; the directory
format and placement live in the `rotelyx-directory` crate.

Without the flag the endpoint is closed and a client that finds nothing there
uses its one configured mailbox, which is the one-replica case of the same
placement. Nothing changes for a single mailbox.

The `constellation` example is a client that exercises the whole path against real
mailboxes:

```sh
cargo run --release --example constellation -- directory.json "a phrase" roundtrip "hi"
```

It computes placement, deposits to every replica, collects from every replica,
and deduplicates by digest. Deposit with all replicas up, stop one, then
collect: the message still arrives from the survivor.

The phone application uses a constellation when its build carries one. It does
not fetch the directory: the list is compiled in, for the same reason the
mailbox list is, which is that a device asking a server where its mailboxes are
would be handing that server the address of every user and the hour they opened
the application. `/directory` is served for clients that would rather ask, and
for an operator checking what a mailbox believes it is part of.

What the application does with it: one connection per mailbox, each address
subscribed only on the mailboxes that hold it, deposits to those same ones, and
the second copy of an envelope dropped on arrival. A mailbox going down is not
reported as a disconnection while another still answers.

Two honest limits. The browser build cannot compute placement yet, because that
lives in the native core, so it uses every mailbox in the directory instead:
more traffic, same delivery. And a device pointed at a mailbox outside the
constellation stays on that one alone, which is deliberate, since spreading
somebody's mail onto servers they did not choose is the opposite of why they
would run their own.

## The name on the page

`--name <NAME>` puts that name in the corner of the landing page, on a small
seal. It exists so a person opening the page can compare the name they were told
to expect against the one the server states, beside the URL in the address bar.

It is worth being exact about what that is and is not. It is a convenience for a
human. It is **not** a security control: a page that copies the markup can state
any name it likes, and nothing about the seal is checked by anything. What
actually establishes that a mailbox is the right one is the TLS certificate, the
domain it is under, and the safety numbers two people compare in the
application. Presenting a badge as proof would teach people to trust a picture,
which is worse than having no badge at all.

Without the flag the page shows no name, exactly as every build before it.

## Set the ceiling to the machine

`--max-connections N` names the real capacity. A strong host serving many
devices sets it high with the descriptor limit raised; a small host that also
runs a relay sets it low. The default is a figure a modest server carries
comfortably, not a hardware wall.
