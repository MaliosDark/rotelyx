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
3. **Next.** The front itself: a small websocket multiplexer that serves the
   `{s, hello|b|close}` framing to phones and forwards it onto a few upstream
   `/front` connections, remapping session ids so two phones never collide at
   the mailbox. This is where the socket saving at the mailbox comes from --
   many phones over few upstream connections -- and it is the one piece whose
   bug would be a privacy bug (two phones' sessions crossing), so it is built
   and tested with somebody watching rather than overnight.
4. **Next.** `rotelyx-wasm` and `rotelyx-mobile`: `front.open`, `front.seal`,
   `front.unseal`, so the phone seals with the same engine it does everything
   else with.
5. **Next.** The application's `MailboxClient` gains one mode: when the mailbox
   URL answers `/front-key`, it seals every frame and runs its sessions inside
   one connection. `RotelyxService` then holds one socket. No screen changes,
   and verified on the phone before it ships, because the send path is exactly
   what broke this week.

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
