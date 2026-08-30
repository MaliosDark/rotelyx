# Relay chaining

A design, not an implementation. Written first because this changes what the
project is allowed to claim, and a change of that kind should be argued on paper
where it is cheap to be wrong.

---

## 1. The problem, stated exactly

A relay carrying a session learns **which endpoint is talking to which**. That is
ADV-3 in the threat model, it is written into the relay's own module docs, and
no configuration removes it, because the client tells the relay where to forward:

```rust
ClientToRelayMsg::Datagrams { dst_endpoint_id, datagrams }
RelayToClientMsg::Datagrams { remote_endpoint_id, datagrams }
```

The destination travels in the clear. It has to: something must route.

Roughly one NAT pair in five cannot be punched through, so this is not a rare
path. The current mitigations are real and neither removes the observation: path
selection prefers any direct path at any latency, and self-hosting moves the
observation to somebody the participants chose.

---

## 2. What chaining buys, and what it does not

Two relays instead of one. The first learns who is sending and not who is
receiving; the second learns who is receiving and not who is sending.

**It does not** protect against:

- **The two operators colluding.** Together they hold what one held before.
  Chaining through two relays run by the same person buys nothing at all, and
  the software cannot check that they are different people.
- **A global passive adversary.** Already a stated non-goal. Somebody watching
  both relays correlates by timing regardless of what either knows.
- **Traffic analysis at one relay.** Volume and timing at the first hop still
  describe the conversation's rhythm.

So the honest claim is narrow: **no single relay operator learns the pair.** It
is worth having because the realistic adversary here is one operator, or one
seizure, rather than a global observer.

---

## 3. Why this needs no directory, which is the part that decides it

The obvious blocker is key distribution. To seal something to the second relay,
the sender needs its public key and a reason to believe it. A directory of
relays is exactly the mechanism this project has deleted twice, and adding one
back to gain a privacy property would be a poor trade.

**It is not needed.** An invitation already carries reachability: a secret and
the address it is answered at, handed over out of band by the person being
invited. The recipient chooses their own relay, so the invitation is the natural
place to say which one:

```
invitation  =  secret ‖ address ‖ exit_relay_id ‖ hash(exit_relay_key)
```

**A hash, not the key.** The key itself is 1216 bytes and an invitation is
scanned, and the QR ceiling was measured rather than guessed: at the error
correction level the logo needs, a code holds 1292 raw bytes or 1029 encoded,
and an invitation carrying the key outright would be 1312. It misses by twenty.
`crates/rotelyx-desktop/tests/qr_ceiling.rs` holds the measurement and fails if
the ceiling ever moves.

So the key is fetched, and **through the first relay, never from the exit relay
itself**. Asking the exit relay directly would put the caller's address in front
of the one party this whole design exists to keep it from, at the first step and
before any circuit exists. The first relay learns which relay is being chained
through, which it learns anyway the moment it forwards, and it cannot substitute
a key of its own because the hash in the invitation pins it.

```
A                         R1                        R2
|-- AskRelayKey{url} ----->|                         |
|                          |-- GET /circuit-key ---->|
|                          |<---------- the key -----|
|<-- RelayKey{url, key} ---|                         |
```

`ExitRelay::accepts` is the step that makes this safe, and it is not optional:
R1 could answer with a key of its own and read every circuit sealed to it. It
cannot, because the fingerprint came from the person who issued the invitation,
and that is the person whose relay it names.

Every failure is one answer, an empty key: a relay that terminates no circuits,
one that cannot be reached, one R1 will not talk to, and something that is not
an address. Telling them apart would say which relays R1 is willing to reach.

The sender picks its own first relay, freely and independently. Nobody consults
a list, and the trust in the exit relay is exactly the trust already placed in
the person who issued the invitation. That is the same shape as the rest of the
design: reachability is something a person hands you, not something you look up.

---

## 4. The circuit

Onion routing of one hop. A circuit is established once and then carries
datagrams cheaply, which is what makes the cost bearable: the sealed layer is
1328 bytes and no per-packet budget could pay that fifty times a second.

### 4.1 Setup

```
A                    R1                      R2                    B
|-- Open{ sealed } -->|                       |                     |
|                     |-- Open{ inner } ----->|                     |
|                     |                       |-- (B is a client) --|
|<---- CircuitId -----|<----- CircuitId ------|                     |
```

`sealed` is opaque to R1 and names R2. R1 learns only that A wants a circuit
through R2. `inner` is what R2 opens: it names B, and it names the key A wants
presented to B, which is a key A generated for this call and which belongs to no
identity. R2 learns nothing about A that outlives the call.

### 4.2 What is sealed, and how

The same construction as the group secret wrap, for the same reason: it exists,
it is specified, and inventing a second one would be a second thing to review.

```
aad   = be64(len(LABEL)) ‖ LABEL
      ‖ be64(len(exit_id)) ‖ exit_id
      ‖ be64(expiry_hour)

LABEL = "rotelyx relay circuit v1"

(kem_ct, kem_ss) = XWing.Encapsulate(exit_relay_hybrid_public_key)
key              = BLAKE3_derive_key("rotelyx relay circuit v1", kem_ss)[0..32]
nonce            = 24 random bytes
sealed           = XChaCha20Poly1305.Seal(key, nonce, inner, aad)

inner            = dst_endpoint_id ‖ return_key ‖ be64(expiry_hour)
```

Hybrid rather than classical, and the reason is specific to this payload: a
circuit descriptor recorded today says who talked to whom, and that is worth
exactly as much to an adversary in fifteen years as it is now. It is the same
harvest-now-decrypt-later argument the message layer already makes, applied to
the social graph rather than to content.

**The hour is bound in** so a captured circuit request cannot be replayed the
next day to reopen a path.

### 4.3 Carriage

After setup both hops hold a circuit id. Datagrams carry the id and nothing
else that identifies anybody:

```
ClientToRelayMsg::CircuitDatagrams { circuit: CircuitId, datagrams }
```

The id is per-hop and different on each: A↔R1 and R1↔R2 do not share one, or R1
and R2 could correlate their tables by comparing ids alone.

There are two frame types behind that one line, a plain one and a batch one,
because the segment size is only on the wire when a batch has one and the frame
type is what says which. The addressed datagrams have been split that way since
before this design, and a circuit datagram that was not split decoded a batch
without complaining and put the segment size at the front of the payload.

### 4.4 The return path

B does not know it is on a circuit and does not need to. It sees traffic from
the return key and replies to it as it would to any peer. R2 answers on that key
and maps the reply onto its link to R1; R1 maps it onto its connection to A.
Neither learns anything new, because the mapping was established at setup and no
reply names a destination.

**Why a return key rather than the caller's own.** B's transport matches
arriving packets to a peer by the sender's key, so the exit relay has to present
one. The first relay's own key would make every circuit through it look the same
to B, and a reply addressed to it could not be matched back to one circuit. The
caller's per-call key is the natural choice and costs nothing: this transport
already dials under a key generated for one call, so there is no long-lived name
to give up. Sealing it into `inner` rather than passing it beside the descriptor
keeps the choice with the caller, since the first relay carries it and cannot
read it.

---

## 5. What each party learns

| | Today, one relay | Chained |
|---|---|---|
| First relay | A, B, and that they are talking | A, and that A opened a circuit through R2 |
| Second relay | | B, a key that exists for one call, and that traffic arrives from R1 |
| Either alone | the pair | one end |
| Both, colluding | the pair | the pair |
| A network observer at one relay | volume and timing | volume and timing |

---

## 6. What it costs

**A round trip.** Every datagram crosses two relays instead of one. On a call,
where the media layer already refuses direct paths, that is added to a budget
that is already the worst case.

**The first relay stops being stateless.** Today a relay holds no session state,
which is stated as a property in its module docs and is part of why a seizure
yields little. A circuit is state: a table of ids and where each one goes, living
in memory and lost on restart. It holds no keys and no content, and it is still
state that did not exist before.

**A relay must be a client of another relay.** No relay-to-relay relationship
exists anywhere in the protocol today. R1 has to open and maintain a connection
to R2, which is a new operational burden and a new failure mode: R2 being down
takes out every circuit through it.

**Connections multiply.** One relay connection per participant becomes one per
participant plus one per distinct exit relay.

---

## 7. Where the work is, honestly

`crates/rotelyx-relay` is 788 lines and is the admission and limits wrapper.
The forwarding protocol is in `crates/net/rotelyx-relay-proto`, 13,605 lines
vendored from iroh, and that is where the frames, the circuit table and the
relay-to-relay link have to go.

That matters for planning. This is not a feature added beside the existing
code; it is a protocol extension inside the largest piece of software in this
repository that nobody here wrote.

---

*The order to build it in, and where it can safely be abandoned, is in
[`RELAY-CHAINING-PLAN.md`](RELAY-CHAINING-PLAN.md).*

## 8. What can be built before touching any of that

The sealing is ours, it is small, and it can be specified, implemented and
tested without a single change to the vendored tree:

- `CircuitSeal::seal(exit_key, dst, hour) -> bytes`
- `CircuitSeal::open(exit_secret, bytes, hour) -> dst`

With published vectors, the same way the post-quantum composition has them, so
the construction can be reviewed before anybody commits to the protocol work.
That is section 5b of `docs/PQ-COMPOSITION.md` in shape and in spirit.

---

## 9. Open questions

- **Nothing stops a sender chaining through two relays run by one operator**, and
  the software cannot detect it. Is that a warning in an interface, a hint in
  the invitation, or accepted and documented?
- **Does the exit relay need admission control of its own** against first relays,
  or does the circuit seal being unforgeable suffice? A relay that accepts
  circuits from anybody is a relay anybody can use as free transit.
- **What happens when the exit relay named in an invitation goes away?** The
  invitation is out of band and cannot be updated. A fallback to direct relaying
  is the obvious answer and it is also a downgrade an attacker would like to be
  able to force.
- **Is one hop the right number?** Two would resist one colluding pair, at
  another round trip. Beyond that it is a mixnet, which is a stated non-goal.
- **Should this be the default, or a policy?** `PathPolicy` has three variants
  today. A fourth, chained-only, is the shape that matches the rest.
