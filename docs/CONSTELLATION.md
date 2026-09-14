# Mailbox constellation: sharded, replicated, and still blind

## The problem

A conversation's envelopes live on one mailbox. Both parties deposit to and
collect from that one server, chosen when the conversation was created. Two
things follow, and both are limits worth removing.

The first is failure. If that mailbox is down, the conversation cannot deliver
until it returns. Nothing is lost, because an envelope waits up to seven days,
but the pause is visible and it lasts as long as the outage.

The second is capacity. A single mailbox holds a single mailbox's worth of
traffic. A deployment grows by running more mailboxes, but with each
conversation pinned to one of them, a busy community still lands on one server,
and moving it means telling everyone in it a new address.

Constellation removes both, and the constraint that makes it interesting is that
it must remove them without giving any server the one thing the blind mailbox
is built to withhold: which conversations a device is in. A constellation that
learned the social graph to spread the load would have traded the whole point
for throughput.

## How Tor does it, and what carries over

Tor solves two problems that look like ours and are worth borrowing from.

Discovery is a **signed consensus**. A small set of directory authorities vote,
hourly, on a document that lists every relay and its keys. A client downloads
the consensus and then knows the network without asking any single server to be
the network. The authorities sign it, so a client can tell a real consensus
from a forged one, and no relay can add itself by claiming to exist.

Location is a **distributed hash**. An onion service publishes its descriptor to
the relays whose identifiers are closest, under a hash function, to
`hash(service id, time period)`. A client that knows the service id computes the
same set and fetches the descriptor from them. No central server holds the map;
the hash is the map, and it moves the descriptor to a fresh set each day so that
watching one relay reveals nothing durable.

Two ideas carry over cleanly. A **signed directory** answers "which mailboxes
exist", and it is the only authoritative thing in the system. And a **hash over
a rotating label** decides where a thing lives, so that both ends compute the
same placement from a value they already share, and nobody has to be told.

What does not carry over is Tor's purpose. Tor hashes to hide where a service
is. We hash to place a store, spread load, and survive a failure, over a label
that is already opaque. The mechanism is the same family; the goal is different,
and the result is a construction that, as far as we can find, no messenger has
built.

## The design

### The label we already have

A conversation is addressed by a tag derived from the group's exporter secret
and the hour, and it rotates every hour (`tagBucketSeconds`). Both members
derive the same tag from state they share, and a mailbox sees only the tag, not
the group, not the members, not the hour's meaning. Every property below is
built on the tag and adds nothing a mailbox can read.

### The directory

A **directory** is a signed list of the mailboxes in a constellation: for each,
its address and its public front key, and a version and an expiry. It is signed
by a directory key whose public half is shipped in the client, exactly as the
notifier key and the relay's room are shipped today, so a client verifies the
directory the way it verifies everything else and a forged one does not load.

The directory is small, changes rarely, and is fetched from any mailbox in it
(each serves the current directory at a fixed path, and they all serve the same
signed bytes, so which one answers does not matter). A mailbox that leaves is
dropped in the next signed version; one that joins is added. This is the one
authoritative document, and it is deliberately the only one: everything else is
computed.

Who holds the directory key is a deployment decision, not a protocol one. For a
single operator it is one key they hold. For a constellation of independent
operators it becomes a small set that co-sign, the way Tor's authorities do, and
that is a later step the format leaves room for rather than requires.

### Placement by rendezvous hashing

Given the directory and a tag, both ends compute the same **placement**: the set
of mailboxes that hold this tag's envelopes this hour. The function is rendezvous
hashing (also called highest random weight): for each mailbox `m` in the
directory, compute `score(m) = hash(m.id, tag)`, sort by score, and take the top
`K`. Those `K` are where this tag lives.

The properties that make this the right function:

- **Both ends agree with no coordination.** They share the tag and both have the
  directory, so they compute the same `K` mailboxes independently. A depositor
  writes to all `K`; a collector reads from any that answer.
- **It fails over for free.** The envelope is on `K` mailboxes. If one is down,
  the other `K - 1` still have it, and the collector reaches them without knowing
  anything changed. There is no promotion, no replication step, no second code
  path: the redundancy is the placement.
- **It spreads load.** Each mailbox holds only the tags whose top-`K` it is in,
  which is `K / N` of all tags for `N` mailboxes. Traffic shards across the
  constellation by construction, and it shards evenly because the hash is uniform.
- **It moves gently when the set changes.** Rendezvous hashing has the property
  that adding or removing one mailbox re-places only the tags that involved it,
  not the whole space. A constellation that grows from ten mailboxes to eleven moves
  about one eleventh of the tags, not all of them, so growth is not a
  reshuffle everyone feels at once.

The hour is already inside the tag, so placement rotates with the tag: a mailbox
holds a conversation's traffic for an hour and a different set holds the next
hour's, which is the same unlinkability the rotating tag already buys, now
spread across the constellation as well.

### Collecting from K without duplicates

An envelope is deposited to `K` mailboxes, so a collector subscribed to all `K`
receives up to `K` copies. This costs nothing to resolve, because an envelope is
already identified by its digest and collection is already acknowledged by
digest: the client keeps the first copy and drops the rest, exactly as it drops
a redelivery today. The deduplication that constellation needs is the
deduplication the mailbox protocol already has.

Acknowledgement spans the set the same way. When a device has a copy and is
done with it, it acknowledges the digest to all `K`, so the envelope is released
everywhere it was placed and no mailbox holds it past its use. A mailbox that
was down during the acknowledgement releases its copy on its own seven day
timer, which is the backstop that already exists.

### What each mailbox sees, after constellation

Less than before, not more. A mailbox in a constellation of `N` sees only the
`K / N` of tags that hash to it, each still an opaque rotating label, with no
address behind it when a front is in front. It does not see the other tags at
all, it does not talk to the other mailboxes, and it cannot tell that two tags
it does hold belong to one conversation any more than it could before. The
constellation narrows what one operator observes rather than widening it, which is
the property that made this worth doing the blind way rather than the easy way.

## What it costs

A deposit is written `K` times instead of once, so deposit bandwidth from a
sender rises by a factor of `K`. `K` is small (two or three to start), the
envelopes are already a fixed small size, and a sender deposits far less than it
collects, so the cost is modest and it is the price of surviving a failure
without a server side replication protocol. A collector holds `K` subscriptions
where it held one, which is cheap on the front (a session is a task and a few
tags) and is the reason constellation and the front belong in the same design: the
front is what makes `K` subscriptions per conversation affordable.

## Prior art, and why this gap exists

It is worth stating plainly why a technique this old, applied to a problem this
common, appears not to have been built. The honest answer is not that nobody
thought a server should not see the social graph, nor that nobody knows
rendezvous hashing, which is from 1996 and is a standard tool in databases and
caches. It is that the field forked years ago into three lines of work, and
each line made an early architectural commitment that put this particular
combination off its path.

**The centralized line, Signal, does not federate on principle.** Its founder
argued publicly that metadata protection needs to evolve quickly and that
centralized systems evolve faster than constellation ones, so Signal protects
metadata in the center, with sealed sender and private groups, and never
pursued constellation metadata privacy. There was no reason for it to build a
constellation blind store, because constellation was the thing it had decided against.

**The constellation line, Matrix and XMPP, federates in a way that is hostile to
metadata by construction.** A homeserver sees who talks to whom, when, and in
which rooms, because routing is by account and room and the server must know the
graph to route. Blindness cannot be bolted onto that. The constellation line has
constellation and not metadata privacy.

**The metadata-private line, SimpleX, is the closest, and its address model is
what stops it here.** It removes user identifiers and uses a separate unlinkable
queue per contact, which is a real metadata-privacy result. But a queue's
address is pinned to one server when the queue is created, and redundancy is
handled by the client using more than one queue, duplicating the whole channel,
rather than derived from the address. Because the address is a queue on a
server rather than a label that can be placed, it cannot be hash placed or
replicated across servers without changing the queue model.

**The academic line, systems such as Vuvuzela, XRD, and the 2025 PingPong
design, solves metadata privacy with heavy machinery:** mix networks,
differential privacy noise, coordination rounds, or secure enclaves running
oblivious algorithms. These aim higher than we do, at unobservability against a
global passive adversary, and they pay for it in cost or in trusted hardware
that no phone messenger ships. A system in that line would not reach for plain
rendezvous hashing, because its threat model demands obliviousness rather than
an opaque label.

The ingredient that makes the combination a small step here, and a rewrite
everywhere else, is our address. A conversation is addressed by an opaque tag
derived from the group secret that rotates every hour, not by an account and
not by a queue pinned to a server. Rendezvous hashing can place that tag across
K servers precisely because the tag already hides the conversation, so the
placement leaks nothing new. The people who had rotating opaque labels had
committed to a queue-pinned model; the people who had constellation had committed
to a graph-aware model; and the people who cared most about metadata had
committed against constellation entirely. Standing on a blind mailbox addressed by
a rotating tag, with a front that makes K subscriptions cheap, is the one
vantage point from which this is the obvious next step rather than a departure.

The honest framing is therefore not that this is unprecedented cleverness. The
mathematics is old and the goal is old. What is new is the vantage point, and
the claim is narrow and defensible: among the systems that actually ship, none
does blind, sharded, K-replicated store and forward with placement computed by
the client from a shared rotating label. That is the gap, and it is the gap
this design fills.

Sources consulted: Signal on sealed sender and its centralization argument,
Matrix homeserver metadata discussions, the SimpleX messaging protocol and its
client-managed redundancy, the rendezvous hashing literature, and the 2025
PingPong metadata-private messaging paper.

## What it does not defend against

It does not hide the constellation from a network observer, who sees a device reach
`K` mailboxes. It does not defend against an operator who runs a majority of the
mailboxes in a small constellation and correlates the tags that land on their
share; the defence there is a constellation large enough, and diverse enough in who
runs it, that no operator holds a majority, which is the same defence Tor's
directory rests on and the same honest limit. And it is not anonymity: a tag
that lands on a mailbox still tells that mailbox a tag was fetched, from the
front's address, which is exactly what the blind mailbox and the front already
bound and no more.

## Open decisions, before code

Three choices are the design, and they are named here so they are made
deliberately rather than defaulted into.

- **K, the replication factor.** Two survives one failure and doubles deposit
  cost; three survives two and triples it. Two is the place to start, with `K` in
  the directory so it can be raised without a client change.
- **Who signs the directory.** One operator holds one key now. The format
  carries a version and leaves room for a co-signed directory later, so a
  single-operator constellation can become a multi-operator one without a new wire.
- **How a client learns the first directory.** The same way it learns the first
  mailbox today: shipped in the build. From there it refreshes from any mailbox
  in the directory, and a signed newer version replaces an older one.

## Implementation shape

The pieces, in the order they can be built and tested, each inert until the one
before it is in place, so nothing changes for a single-mailbox deployment until
the whole path is ready and turned on.

1. `rotelyx-directory`: the signed directory format, its signing and
   verification, and the rendezvous placement function, with vectors. No
   network. This is the reviewable core, the way the front's sealed session was.
2. `rotelyx-mailbox-server`: serve the current directory at a fixed path, and
   accept `--directory` and `--directory-key` so a mailbox knows the constellation
   it is part of.
3. The client's mailbox layer: given a tag, compute the `K` placement from the
   directory, deposit to all `K`, subscribe to all `K`, and deduplicate by digest,
   which the client already does. One mailbox is the `K = 1` case of the same
   code, so a constellation of one behaves exactly as today.
4. The directory refresh: fetch and verify a newer signed directory, and re-place
   live conversations when the set changes, which rendezvous hashing keeps to the
   fraction of conversations that actually moved.

Steps 1 and 2 deploy without touching a client. A client that does not know
about a directory keeps using its one configured mailbox, which is the `K = 1`
constellation of that one server, so the change is additive from the first commit
to the last.
