# The front: one socket per device, and nobody who sees both halves

## The problem it closes

The mailbox is blind to content and not to shape. A connection that asked for
the tags of every conversation a device is in would hand the mailbox that
device's whole social graph, so the application opens one connection per
conversation and the mailbox sees N connections that share nothing. That is
the strictest position of any messenger in this space, and it costs nine
sockets per phone, a per-address ceiling of sixteen, and a mailbox that is
full at about four hundred and fifty people connected at once.

The competitors did not solve this; they chose. SimpleX offers the same
isolation as a setting and ships it off. Session lets the server correlate
everything and hides the address instead. Briar and Cwtch have no server and
need both ends awake.

## What it is

A **front** is a relay that stands between phones and the mailbox and can read
neither side's secret:

    phone  ==(one socket, TLS)==>  front  ==(few sockets)==>  mailbox

- The phone opens **one** connection, to the front, and inside it runs any
  number of sessions, one per conversation, each sealed to the mailbox's own
  key. The front sees the phone's address and opaque blobs.
- The mailbox sees sessions arriving from the front's address, with no way to
  tell which sessions belong to one phone. It sees tags, never an address.
- Neither can put a device and a conversation together. Two operators who
  collude can, and the design says so rather than pretending otherwise; the
  front is a thing anybody can run, and running your own is the answer to
  that.

The per-address ceiling then counts fronts, not phones. A front holds no state
worth the name and is added like any relay.

## The wire

Everything the mailbox already speaks is unchanged: `subscribe`, `deposit`,
`collected`, `registerWake` and the rest, as JSON text frames. What the front
adds is an envelope around each frame.

### Keys

The mailbox holds a hybrid key pair (X-Wing: X25519 and ML-KEM-768, the same
key the group wrap and the wake tickets use) at `--front-key <path>`,
generated on first start. It publishes the public half at `GET /front-key`
as base64. The front proxies that path so a phone that knows only the front
can read it.

### A session

    hello  = kem_ct (1328 bytes) || 8 byte session id chosen by the phone
    keys   = HKDF(shared, "rotelyx front session v1" || session id) ->
             k_up (phone to mailbox), k_down (mailbox to phone)
    frame  = XChaCha20-Poly1305(k_dir, nonce = 16 zero bytes || counter, aad = session id, frame text)

Counters start at zero in each direction and never repeat inside a session; a
frame whose counter is not the next one is refused and the session ends. The
nonce is derived from the counter rather than random so a reused nonce is a
bug that tests can catch rather than a probability.

### On the front's wire

Between phone and front, and between front and mailbox, the same multiplexed
text frames:

    {"s": "<session id, base64>", "hello": "<base64 hello>"}   opens a session
    {"s": "<session id>", "b": "<base64 sealed frame>"}        carries one
    {"s": "<session id>", "close": true}                        ends one

The front rewrites nothing. It maps (phone connection, session id) to
(upstream connection, session id), forwards in both directions, and closes
the sessions of a phone whose connection drops. Session ids are chosen by the
phone and namespaced by the front per upstream connection, so two phones
choosing the same id never collide at the mailbox.

### What each party may see

| | address | tags | content |
|---|---|---|---|
| front | yes | no | no |
| mailbox | front's | yes | no |
| both together | yes | yes | no |

## Limits

The mailbox keeps its per-session limits (tags per session, frame size) and
applies its per-address connection limits to the front's address with the
front's allowance raised by `--front <address>`; a front is a known thing, not
a household. The front applies the per-address connection and rate limits the
relay already has to the phones, and a ceiling on sessions per connection so
one phone cannot hold a thousand.

## What changes where

1. **Done.** `rotelyx-crypto::front`: the session (hello, keys, seal, open in
   order), with nine tests. No network.
2. **Done.** `rotelyx-mailbox-server`: the connection handler runs over a
   `Wire` transport rather than a websocket, so a front session is the same
   code over a channel; `/front` accepts a front's multiplexed connection,
   `/front-key` publishes the key, `--front-key <path>` turns it on. Every
   existing test passes unchanged, and a phone reaching the mailbox through a
   front, sealed the whole way, is tested end to end. Deploys on its own and
   changes nothing for a phone that does not use it.
3. **Done.** The front itself, `rotelyx-mailbox-server front --mailbox <url>`:
   a websocket multiplexer that serves the `{s, hello|b|close}` framing and
   `/front-key` to phones and forwards onto a pool of upstream `/front`
   connections, giving every session a fresh upstream id from a counter that
   never repeats and rewriting it both ways. The property that the id a phone
   chose means nothing past its own connection is held by a test: two phones
   choosing the same session id on one shared upstream connection, and one's
   envelope never reaching the other while each still gets its own.
4. **Done.** `rotelyx-mobile`: `front.open`, `front.seal`, `front.unseal`,
   `front.free` on the JSON ABI, and `RotelyxEngine.openFront` in the Dart
   engine. A test seals through the mobile ABI what a mailbox holding the
   matching key opens, and opens what it seals. (The web build throws until a
   wasm front session is exposed; it connects directly for now.)
5. **Done.** A `FrontConnection` in the app owns one websocket to the front
   and carries every conversation as a sealed session on it, routing each
   reply by session id to the one conversation that can open it; `MailboxClient`
   in front mode seals through a channel instead of its own socket, and
   `RotelyxService` passes the config's `frontUrl`/`frontKey` to every client.
   Both null is one socket per conversation straight to the mailbox, so it is
   inert until a mailbox serves a front key. Verified on the phone: pointed at
   a mailbox with a front and a `front` process in front of it, the device held
   **one** connection carrying all its sessions and joined a live group through
   it. The full suite passes.

Everything above steps 1-4 is on the server and the engine, is fully tested,
and deploys without touching any phone: a mailbox with `--front-key`, a
`rotelyx-mailbox-server front` in front of it, and the engine ready to seal.
The phone keeps connecting straight to `/mailbox` until step 5 ships and a
front is deployed.

Steps 1 to 3 deploy on their own and change nothing for a phone that does not
know about them: the mailbox's `/mailbox` keeps working as it does today.

## What it does not do

It does not hide that a device is talking to a front at all, nor how much.
It does not protect against a front and a mailbox run by one operator who
joins their logs; today that operator is us, and the honest statement is that
the property holds against each of them alone and against anybody who runs
their own front. It is not the wake-driven idle (zero sockets while nothing
happens), which needs a push path on Android that this project does not have,
and it is not the single envelope per group message, which becomes possible
once the mailbox no longer sees which connections read a tag.

## One front per mailbox, which is how it meets the constellation

A front sits in front of **one** mailbox, because a session is sealed to that
mailbox's key. A constellation has several mailboxes, so it has several fronts:
one each, and a device holds one connection to each.

That is the saving, and it is worth being exact about where it comes from. A
device keeps a handful of conversations live, and without a front it opens a
connection per conversation **per mailbox**: seven conversations across three
mailboxes is twenty one connections. With a front per mailbox it is three,
whatever the number of conversations, because every conversation is a session
inside the one connection to that mailbox's front.

Measured on a handset after this landed: three established connections, one to
each front, and nothing else.

The mailbox side does not grow either. A front holds a small fixed pool of
connections to its mailbox and spreads every session across it, so the mailbox
counts that pool and not the people behind it. Ten devices or ten thousand, the
mailbox sees the same handful from the front. The sockets did not disappear:
they moved to the piece that can be multiplied, since a front holds nothing and
anybody can run another.

## Running one

```sh
rotelyx-mailbox-server front --mailbox ws://127.0.0.1:3341 --bind 0.0.0.0:3343
```

The `--mailbox` value is the mailbox's **base** URL, with no path: the front
appends what it needs. Giving it the `/mailbox` path produces a front that asks
for `/mailbox/front-key` and exits saying the mailbox serves no front key,
which reads like the wrong flag on the mailbox and is not.

The mailbox it points at must be started with `--front-key`, which is what
opens `/front` and publishes the key a device seals to.

Behind a reverse proxy, `/front` needs its own location with the WebSocket
upgrade headers, pointing at the front's port rather than the mailbox's. The
proxy's catch-all will pass `/front` through without those headers, and the
symptom is a `400` on what looks like a correctly configured route. The
deployment guide carries the block.

## A front that is not there

A device that cannot reach its front connects to the mailbox directly instead.

The front is an optimisation: it saves connections and stops the mailbox
grouping a device's conversations. Neither is worth failing to deliver a
message over, so a front that refuses or disappears costs the saving and
nothing else. This is what makes a front safe to deploy, and safe to move.

## Where the fronts are, and why that matters

The point of a front is that **the front and the mailbox are different
parties**: the front sees an address and opaque frames, the mailbox sees tags
and no address, and neither holds both halves.

Run on the same machine as its mailbox, one operator holds both halves and the
property is not there at all. The connection saving is real either way, which
is what makes that arrangement tempting: it looks finished and is half of it.

So the fronts are **crossed**. Each member's front runs on a different
member's machine, and points back at the mailbox it fronts for:

| A device asking for | is served by the front on | which talks to the mailbox on |
|---|---|---|
| the first member | the third member's machine | the first member |
| the second member | the first member's machine | the second member |
| the third member | the second member's machine | the third member |

Now no machine sees both halves of the same traffic. The machine that took the
connection cannot read the tags inside it, and the machine holding those tags
never saw where they came from. Taking one machine yields one half.

The reverse proxy is what makes this a routing question rather than a protocol
one: the member's `/front` location points at another machine's front port, and
nothing in the client changes. A device still asks for
`wss://<member>/front` and neither knows nor cares which machine answers.

**What this is not.** Crossing protects against one machine being taken or
compromised. It does not protect against the operator, who runs all of them and
could put the halves together. That is not a gap in the arrangement, it is the
reason the front is an ordinary program anybody can run: the property is only
complete when the fronts belong to somebody else.
