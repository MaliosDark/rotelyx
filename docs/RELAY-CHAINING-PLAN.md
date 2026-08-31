# Relay chaining: how to build it

The design is in [`RELAY-CHAINING.md`](RELAY-CHAINING.md). This is the order to
build it in, what each step proves, and where it can be abandoned without
leaving the tree worse than it was.

Written before starting because the work is inside
`crates/net/rotelyx-relay-proto`, which is 13,605 lines nobody here wrote, and a
change of that size begun without a plan becomes a branch nobody can finish or
review.

---

## The rule that shapes every phase

**Each phase must leave the tree shippable.** Not "compiling": shippable, with
the existing behaviour unchanged and the existing tests green. A relay that has
learned half of chaining must still relay exactly as it does today for every
client that does not ask for a circuit.

That is why nothing below changes an existing frame. Chaining is new frames
beside the old ones, and a relay that never receives one behaves as it does now.

---

## Phase 0: the seal, **done**

`rotelyx-crypto::circuit`, with nine tests and published vectors for the two
deterministic halves. Nothing calls it.

It is first because it is the only part that can be reviewed on its own, and if
the review says the construction is wrong, everything after it was going to be
wasted.

---

## Phase 1: the frames

Add to `crates/net/rotelyx-relay-proto/src/protos/relay.rs`:

```rust
ClientToRelayMsg::OpenCircuit { sealed: Bytes }
ClientToRelayMsg::CircuitDatagrams { circuit: CircuitId, datagrams: Datagrams }
RelayToClientMsg::CircuitOpened { circuit: CircuitId }
RelayToClientMsg::CircuitClosed { circuit: CircuitId, reason: u8 }
RelayToClientMsg::CircuitDatagrams { circuit: CircuitId, datagrams: Datagrams }
```

**Proves:** the wire format round-trips and an old relay rejects the new frames
by name rather than misreading them.

**Test:** the encode/decode tests that already exist for every other frame, plus
one that a `CircuitDatagrams` frame is refused by a version that does not know
it. That last one is the point: two builds that disagree about a format must
fail cleanly, and this repository has already been bitten once by a wire change
that failed seven times in eight and silently the eighth.

**Stop here safely:** frames nothing sends are dead weight and nothing more.

**Done.** Frame types 15 through 21 in `common.rs`, the five variants above with
their codecs, and the server refusing every one of them by name with
`CIRCUIT_REFUSED`. Three things came out of building it that the design above
had wrong:

- **A circuit datagram needs two frame types, not one.** Batching is signalled
  by the frame type here, the way `ClientToRelayDatagram` and
  `ClientToRelayDatagramBatch` already do it, so 20 and 21 are the batch forms.
  Written with one type, the decoder had to guess, guessed wrong, and prepended
  two bytes of segment size to the payload. It decoded without error, which is
  why the round-trip test is the one that caught it.
- **The descriptor is 1328 bytes, not 1192.** The number came from the group
  envelope, which seals a 32-byte secret; a hop seals 168, being a destination,
  a return key, room for the next relay's address and an hour. `crates/rotelyx-relay/tests/circuit_frame.rs` fails
  the build if the relay's copy of that constant and the crypto's ever part
  ways, and fails it again if both agree on a number a real descriptor does not
  measure. It caught the drift twice while this was being written, the second
  time before anybody had thought to look.
- **There is already a version negotiation, and phase 5 should use it.**
  `ProtocolVersion` is agreed in the websocket subprotocol at handshake, and
  `Error::FrameNotAllowedInVersion` is how a frame is refused for being from the
  wrong side of a version boundary. A client should learn whether a relay can
  chain by asking at the handshake, not by opening a circuit and reading the
  refusal. That is a `V3`, and it belongs with the policy rather than here.

While running that crate's own suite for the first time, a subprotocol
negotiation test turned out to have been broken by the rename away from
upstream's name: it offered `rotelyx_transport-relay-v2` where the server
answers to `rotelyx-relay-v2`. Nothing ran it, because `cargo test --workspace`
cannot reach an excluded crate. The `vendored transport` job in CI runs it now.

---

## Phase 2: the circuit table, at the exit relay

**Building this found a gap in the design above, and it is the reason a
descriptor now carries a third field.** The exit relay forwards to the
destination as an ordinary relayed datagram, and the destination's transport
associates arriving packets with a peer by the sender's key. So the exit relay
has to present some key. It cannot be the first relay's: every circuit through
that relay would look identical to the destination, and a reply addressed to the
relay could not be matched back to one circuit. It cannot be the caller's
identity either, and does not need to be, because a caller already dials under a
key generated for one call and belonging to no identity.

So the caller seals its own return key into the descriptor. The first relay
carries it and cannot read it, which keeps the choice with the caller rather
than the relay. The exit relay presents that key to the destination and answers
on it for the reply, which makes its table two-directional: circuit id to
destination on the way out, return key to circuit on the way back.

`server/clients.rs` holds the connected-client table. Add a second table beside
it, both directions, with an expiry.

The exit relay opens a `SealedHop`, learns the destination, allocates an id, and
answers `CircuitOpened`. A `CircuitDatagrams` on that id forwards to the
destination exactly as `handle_frame_send_packet` does today.

**Proves:** the exit half works end to end, with one relay, by a client that
seals a hop to that same relay. Silly in production and exactly right as a test:
it exercises the seal, the table, the expiry and the forwarding without any
relay-to-relay link existing yet.

**Tests:**
- a circuit opens, carries a datagram and closes
- an expired descriptor is refused
- a descriptor sealed to another relay is refused
- a circuit id from one connection is not usable from another, which is the
  authorisation question: an id must be a handle on that connection and never a
  capability anybody can name
- the table is bounded, and the bound is enforced per connection as well as in
  total, for the reason `limits.rs` already gives about sockets

**Stop here safely:** a relay that can terminate circuits and no client that
opens them. Dead code, honestly labelled.

**Done.** `server/circuits.rs` holds the trait and the bounds, the forward table
lives in each connection's own actor and the return table in the shared one, and
`rotelyx-relay` implements the opening with a key it makes on first use behind
`--circuit-key`. Without that flag a relay refuses every circuit, which is what
it did before.

What building it settled, beyond the return key above:

- **The opening arrives as a trait, not a dependency.** The exit relay has to
  open a descriptor, and that is the message layer's hybrid construction. Having
  `rotelyx-relay-proto` depend on `rotelyx-crypto` would invert the layering, so
  the transport declares `CircuitOpener` and the binary implements it. The
  binary does now link the crypto, and the earlier claim that it must not was
  too strong: a relay cannot read messages because it holds no message keys, not
  because it lacks the code.
- **An id is a handle, not a capability, and that is structural.** The forward
  table lives in the connection that opened the circuit, so an id from another
  connection is not there to be found. No check to write and none to forget.
- **Circuit traffic is kept out of the peer-gone bookkeeping.** That
  notification names an endpoint. Sending it along a circuit would tell the
  connection at one end which endpoint at the other end has gone, which is the
  fact the chain exists to withhold. A circuit hears `CircuitClosed`, which
  names the circuit and nobody. This was a live leak in the first version of the
  table, found by asking what the existing notification would do rather than by
  a test.
- **Every refusal is the same refusal.** Expired, sealed to another relay, not a
  descriptor at all: all `REFUSED`. Telling them apart would let somebody hold a
  captured descriptor up to each relay in turn to learn which it was for. The
  `EXPIRED` reason is kept reserved and never sent.
- **The published circuit key is 1216 bytes.** That is the X-Wing public key an
  invitation would have had to carry, and it is a much bigger number than the
  rest of an invitation. Measured against the QR ceiling in phase 4 below: it
  does not fit, so the invitation carries a hash of it instead.

---

## Phase 3: the relay-to-relay link

The first relay becomes a client of the exit relay. `rotelyx-relay-proto`
already has a client (`src/client/`), so the machinery exists; what does not
exist is a relay holding one.

**This is the phase with the real design risk**, and it should be the one that
gets a second opinion before it is written:

- The link is authenticated by the relays' own keys, so the exit relay knows
  which relay a circuit came from, which is what stops it being open transit.
- Reconnection, and what happens to circuits when the link drops. The honest
  answer is that they close and the client rebuilds; anything cleverer is state
  that survives a failure it should not survive.
- One link per relay pair, multiplexing every circuit, or one per circuit. One
  link is fewer connections and a correlation surface: the exit relay sees every
  circuit from that relay arrive on one connection. One per circuit is the
  opposite trade.

  **Proposed: one link per pair.** The trade turns out to be one sided once the
  first bullet above is taken seriously. The link is authenticated by the
  relays' own keys, deliberately, so that the exit relay knows which relay a
  circuit came from and is not open transit. That means the exit relay can
  already count the circuits arriving from one relay however they are carried:
  separate connections from the same authenticated peer group exactly as well as
  one connection does. Per-circuit links would multiply connections between two
  machines by the number of live calls and buy nothing that the authentication
  does not already give away. The correlation the second option was meant to
  break is not breakable while the link is authenticated, and unauthenticating
  it is the thing that makes a relay open transit.

  This is a proposal, and it is the piece the plan says should be read by
  somebody else before it is written.

**How the first relay finds the second.** A relay is dialled by URL, not by
endpoint id, so the descriptor sealed to the first relay has to carry where the
second one is. Nothing before this phase noticed that, and it is the third time
work on a later phase has sent a change back into the descriptor format.

The alternative is an operator-configured set of relays each relay will chain
to, which keeps the descriptor as it is and keeps a relay from being told to
dial arbitrary hosts. It was rejected because it would mean the caller's relay
and the recipient's relay have to be paired in advance, and the design's claim
is that the sender picks its own first relay freely.

So the URL travels in the sealed descriptor, and **the hazard that creates is
written down rather than papered over**: a relay that chains can be told by a
stranger to open a connection to a host of the stranger's choosing. That is why
chaining is off unless the operator turns it on, and why an operator may also
give an allowlist of relays theirs will chain to. An operator who wants the
property without the exposure can have both, and one who turns it on knows what
they turned on.

**How the second descriptor reaches the second relay.** The design's own diagram
has A send `Open{sealed}` to R1 and R1 send `Open{inner}` to R2, which means the
frame from A carries two things: the descriptor R1 opens, and `inner`, which R1
carries and cannot read. Phase 1's `OpenCircuit` carries only one, so this is a
frame change: a second field, empty when the circuit terminates at the relay
being asked.

Empty is the case phase 2 already serves, so nothing that works today changes.
The alternative considered was letting `inner` ride as the first datagram on the
circuit, which would need the first relay to work out that its destination is a
relay rather than a person, and to treat one payload differently from every
other. Two fields say it outright instead of asking the relay to infer it.

With that, both relays run the phase 2 table unchanged. R1's circuit ends at R2
and R2's ends at B, and each holds only what its own table holds. The setup
frame costs 2656 bytes, twice the descriptor, once per circuit.

**Proves:** two relays in one test, a circuit through both, and neither holding
the pair.

**Done, with two things the proposal did not have.**

- **The requester chooses the circuit id, not the relay.** `CircuitOpened` says
  which circuit opened but not which request it answers, so with the relay
  choosing, two opens in flight on one link could not be told apart. The
  alternatives were serialising opens, which puts a network round trip between
  every circuit a busy relay pair builds, or adding a request id, which is a
  second number meaning almost what the first one means. Letting the side that
  will use the name choose it removes the problem instead of numbering it, and
  it is what an id being a handle on one connection already implied.
- **A chained open is answered late, not slowly.** It is a dial and a round
  trip, and doing that inside the read loop would stop the connection carrying
  anything else while it waited. The request is recorded as `Opening`, the work
  goes to a task, and the answer is written when the far relay gives one. A
  datagram arriving in between is dropped rather than queued: a datagram held
  for a circuit that may never open is one delivered late to somewhere nobody is
  waiting.

**Also settled while building it.** The link delivers replies into the waiting
connection's own writer queue rather than through the client table. Reaching for
the table looked natural and would have made a cycle: the table holds the links,
so a link holding the table would keep it alive for ever. A queue keeps alive
only the connection it belongs to.

**And `--circuit-id` is gone.** A relay dialling another authenticates with its
own transport key, so it needs one, and its public half is the endpoint id a
descriptor is sealed to. Two flags saying the same name is a way to configure a
relay that answers to a name it cannot prove. One `--identity` now says it once.

**Two relays, both running, and something at the far end.**
`scripts/chain-test` starts one relay that opens circuits and one that carries
them onward, and `crates/rotelyx-relay/tests/chained_circuit.rs` opens a circuit
through both, sends a datagram that arrives at a third client really connected
to the exit relay, and reads the reply back on the circuit. The destination sees
the return key as the sender, which is the property the whole return-key design
exists for, and the test fails on that line if it ever sees anything else.
Plain http on loopback, so no certificate is needed, which leaves TLS and DNS
for a pair of deployed relays to cover.

It found a defect on its first run that nothing else would have. The dialler
asked `rustls` for the process default crypto provider, and nothing in this
binary installs one, so **every dial would have failed in production** while
every test in one process passed. It uses the transport's own
`tls::default_provider` now. That is the second time this phase that the thing
worth testing was the seam between two pieces that each worked.

**Test:** the assertion that is the whole point, written as a test rather than a
sentence: with A talking to B through R1 and R2, R1's tables contain A and never
B, and R2's contain B and never A.

**Stop here safely:** the relays can do it and no client asks.

---

## Phase 4: the invitation carries the exit relay

`rotelyx-core::access::Invitation` gains the exit relay's id and a hash of its
hybrid public key. This is a wire change to the invitation format, which means:

- the code somebody pastes gets longer, and the QR ceiling has now been
  measured. `crates/rotelyx-desktop/tests/qr_ceiling.rs` does it: at
  `EcLevel::H`, which is the level the logo needs, a code holds **1292 raw bytes
  or 1029 bytes base64url encoded**. An invitation carrying the exit relay's id
  and key is 1312 bytes. **It does not fit**, in either encoding, and it misses
  by twenty bytes raw.

  Two guesses in that paragraph were wrong before it was measured. An invitation
  today is 64 bytes, not three thousand characters. And the first measurement
  said 1852 bytes, because the test filled its payload with `A`, which a QR
  encoder reads as alphanumeric: a mode an invitation can never use, since
  base64url has lowercase in it. The number only became true when the filler
  forced byte mode.

  **So the key does not travel in the invitation.** The invitation names the
  exit relay by id and carries a 32 byte hash of its key, and the key itself is
  fetched **through the first relay**, not from the exit relay. Fetching it from
  the exit relay directly would put the caller's address in front of the very
  relay chaining exists to keep it from, which would undo the whole thing at the
  first step. The first relay learns which relay is being chained through, which
  it learns anyway the moment it forwards, and it cannot substitute a key of its
  own because the hash in the invitation pins it. Total cost to the invitation:
  64 bytes today, 128 with the exit relay named. That fits with room left.

  This is not the weaker property the paragraph above expected. Pinning on first
  use would have been weaker; pinning against a hash the issuer handed over is
  the same trust as the rest of the invitation.
- `WIRE_VERSION` moves, and both ends refuse a mismatch by name. That mechanism
  exists for exactly this.

**Proves:** a sender can learn where to send without any directory, which is the
claim the design rests on.

**The protocol half is done.** A relay publishes its circuit key at
`/circuit-key`, or answers 404 when it terminates no circuits, which is also
what a relay built before circuits answers. A caller asks its **own** relay for
another relay's key with `AskRelayKey`, and gets `RelayKey` back naming the
address it asked about, so two asks in flight are told apart without a second
number to keep in step. Both are covered by `scripts/chain-test`, against two
relays that are running.

- **Every failure is one answer, an empty key.** A relay that terminates no
  circuits, one that cannot be reached, one this relay will not talk to and
  something that is not an address at all all look the same. Telling them apart
  would say which relays this one is willing to reach.
- **The fetching relay checks the key decodes before passing it on.** It came
  from a machine nobody has vouched for and what the caller does with it is seal
  a circuit.
- **Redirects are not followed.** The address came from a stranger and passed an
  allowlist; a redirect would let it point somewhere else after the allowlist
  had already said yes.

**The invitation carries it now.** `Invitation::code_with_exit` writes the exit
relay after the sixty four bytes a code has always been, and
`Invitation::read_code_full` reads both forms.

**Length says which form it is, not a version byte.** Sixty four bytes is the
code that has been handed out since before chaining and it keeps working
untouched; longer carries an exit relay after it. Nothing between the two is
accepted, because that would be an exit relay with something missing and
reading what is there would invent a relay nobody named. So `WIRE_VERSION` does
not move: an old code did not become version zero of something, it stayed a
code.

**`ExitRelay::accepts` is where the safety of the whole fetch lives.** The relay
that fetches a key on the caller's behalf could answer with a key of its own and
read every circuit sealed to it. It cannot, because the invitation carried a
fingerprint of the real one, and the person who issued the invitation is the
person whose relay it names. A caller that skips that check has a chain that
protects nothing, which is why the check is a method on the thing that carries
the hash rather than a step somebody has to remember.

---

## Phase 5: the policy, and the default

A fourth `PathPolicy`. The default does not change: chaining costs a round trip
and it should be something somebody chose.

**Negotiate it at the handshake.** Phase 1 found that this protocol already
agrees a `ProtocolVersion` in the websocket subprotocol, and already has
`Error::FrameNotAllowedInVersion` for a frame that is from the wrong side of a
version boundary. Circuits should be a `V3`, so a client knows before it seals a
descriptor whether the relay it is talking to can carry one. The alternative,
opening a circuit and reading the refusal, costs a round trip to learn something
the handshake already had a place for.

**The interface has to say the thing the software cannot check:** that chaining
through two relays run by one operator buys nothing. That is a sentence in a
screen, and it is the last piece of work rather than the first because until
phase 4 there is nothing to say it about.

**Done: the policy and the version.**

`PathPolicy::Chained` never takes a direct path and **requires** a chain rather
than preferring one. If none can be built the connection fails, for the reason
`RelayOnly` fails: somebody who chose this and quietly got a single relay would
believe in a split that is not there, with no way to tell. Its documentation
carries the sentence above, where the person choosing it will read it.

`ProtocolVersion::V3` carries the circuit frames, and building it found a
stronger reason for the version than the plan had. A frame type a relay does
not know is not refused politely: reading it fails, and a failed read **ends the
connection**. So a client that spoke circuits to a relay built before them would
not learn "no", it would lose the connection it was using. Agreeing the version
at the handshake is how it finds out before that costs anything.

Two things the version does and does not mean, both now tested:

- It says a peer **knows** these frames, not that it will serve them. Whether a
  relay terminates or carries circuits is its operator's decision and is still
  answered with `CircuitClosed`.
- **The far end of a circuit needs none of it.** A destination is an ordinary
  client that never learns it was on a circuit, and the tests keep it at version
  two to hold that true.

The version check on frames arriving at a relay stays absent, deliberately: that
direction has no version to check against without changing `RelayedStream::new`,
which is public API, and a relay understanding more than was negotiated is not a
hazard. What is a hazard is a relay *answering* below the version, so a
connection that agreed an older version and sends circuit frames is ended rather
than answered with frames it could not decode.

---

## Phase 6: an ordinary session through a circuit

Not in the original plan, which stopped at the protocol. Without this, every
flag can be on and nothing a user sees changes.

**Done.** The path from an application to the wire:

```
ExitRelay::seal_circuit          two layers, one per relay
  -> NetEndpoint::route_through_circuit(url, peer, sealed, inner)
    -> the relay actor opens it and records peer -> circuit
      -> datagrams for that peer go out as CircuitDatagrams
      -> datagrams arriving on it are delivered as if from that peer
```

- **A peer with no circuit is sent exactly as before.** The send path is a map
  lookup, not a mode, so a connection holding no circuits produces byte for byte
  what it produced before circuits existed. That is what keeps this off the path
  everybody uses.
- **Circuits are re-opened on reconnect**, like aliases and for the same reason:
  a relay forgets its side when the connection goes, and a circuit that was not
  rebuilt would leave traffic going out addressed to the peer. Somebody who
  asked for a circuit silently getting an addressed datagram is the one outcome
  this must not produce.
- **The entry is recorded before the relay answers.** A datagram sent in the gap
  goes on the circuit and is dropped if it never opened. Recording afterwards
  would send that same datagram addressed instead. Losing a datagram is the
  better failure.
- **The descriptors arrive sealed.** The transport reads neither, which is the
  same rule the relay follows, and `rotelyx-core` seals them because that is
  where an invitation's `ExitRelay` lives.

**A circuit that closes does not become addressed traffic.** That was left
undecided and is now decided the only way it can be: a peer stays marked as
reachable only through a circuit from the moment one is asked for, and while
none is open its traffic is **dropped**. Losing datagrams is a failure somebody
notices; losing the property is a failure nobody notices, and it would have been
carried out under the peer's own name with a line in a log as the only sign.

The circuit is re-opened with the descriptor that opened it the first time, at
most three times per connection. Three because a relay that refuses answers
with a close and a close is what asks for a re-open: without a bound those two
are a loop that asks a relay to open circuits as fast as the network allows, for
as long as the connection lasts, which would be this endpoint attacking a relay
somebody else runs.

**And somebody is told when it cannot be fixed from here.** A descriptor has an
hour sealed into it and stops opening once that hour has passed, so this
recovers a link that dropped a moment ago and not one that has been down since
yesterday. When the tries run out, the peer is reported through
`NetEndpoint::circuits_needing_a_new_descriptor`, and the fix is to seal a fresh
descriptor and call `route_through_circuit` again, which clears the report and
the count together.

Told rather than only logged, and the difference matters: a log is read
afterwards by somebody wondering why a contact went quiet, and this is read by
the code that can seal a descriptor and make them not quiet. A caller that
ignores it has a contact who silently stopped working, which is the same failure
the dropping was chosen to avoid, moved one layer up.

---

## Phase 7: somebody can actually use it

Not in the plan either, and without it every piece above is reachable only from
code nobody has written.

**Done, and run between two machines with a person at each end.** Both sides
calculated the same safety number, so the whole MLS handshake crossed the
circuit rather than one test datagram.

```sh
# The one being reached, on the relay that will be the far end
rotelyx-cli invite --through https://exit.example
rotelyx-cli listen --relay https://exit.example

# The caller, on a relay of their own choosing
rotelyx-cli connect <code> --relay https://mine.example
```

The caller does the rest without being told: reads the exit relay out of the
invitation, asks **its own relay** for that relay's key, checks it against the
fingerprint, seals two layers and routes the session through the circuit.

**A relay publishes its name alongside its key.** It published only the key, and
a descriptor is sealed *to* a name and *with* a key, so an invitation could not
be built without asking the operator for a line it prints at startup. One
request answers both now, at a path that lives in the protocol module rather
than the server one, because the side that asks is not built with the server.

**Two things running it found that no test had.**

- The fingerprint check refused a key that was correct. The wire carries base64
  and the invitation hashes bytes, so the two were hashing different things. The
  check caught it, which is what it is for, and it caught its author.
- **A chained hop must not claim a return key.** It claimed one, and the relay
  refused it because the name was already taken: by the caller, who is connected
  to that relay under exactly that key. A hop that continues has no use for one,
  because its replies arrive over the link carrying a number and no name. The
  refusal was right and asking the question was not.

  The chained test used a freshly generated key there and so never asked it. It
  passes the caller's own key now, which is what a client does, and it fails
  against a relay without the fix.

---

## What would make me stop

- **If phase 3's link design does not survive review.** It is the part with no
  precedent in this codebase.
- **If phase 4 measures past the QR ceiling** and the fallback pinning is judged
  worse than the property is worth.
- **If the added round trip makes calls unusable.** Measure it in phase 3, on
  the production relay, before phase 4 makes it reachable.

Each of those is a decision, not a failure, and each of the phases before it
still leaves the tree shippable.

---

## What this does not include

Anything that would make Rotelyx a mixnet. Cover traffic, batching, more than
one hop and randomised delays are all outside this, and the threat model says
resisting a global passive adversary is a non-goal. Chaining narrows what one
operator learns. It does not change what somebody watching the whole network
learns, and no phase here should be described as if it does.
