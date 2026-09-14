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

## What it cannot do yet

There is no failover between mailboxes. A conversation's tag lives on one
mailbox, so if it is down the conversation's delivery pauses until it returns;
nothing is lost, because envelopes wait up to seven days. Redundancy across
mailboxes, whether by client side mirroring or server side replication, is not
built.

## Set the ceiling to the machine

`--max-connections N` names the real capacity. A strong host serving many
devices sets it high with the descriptor limit raised; a small host that also
runs a relay sets it low. The default is a figure a modest server carries
comfortably, not a hardware wall.
