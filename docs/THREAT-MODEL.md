# Rotelyx Threat Model

**Status:** draft v0.1 · 15 August 2026
**Applies to:** Rotelyx protocol as specified in `docs/rotelyx-architecture.html`

This document exists so that every later engineering decision has something to be
checked against, and so that any security claim Rotelyx makes in public is bounded.
It is a peer of the code, not documentation of it. Where the code and this
document disagree, that is a bug in one of them and must be resolved, not
tolerated.

Rotelyx makes **no** claim of being unbreakable, un-interceptable, or impossible to
access. Those claims are false for every system that has ever made them.

---

## 1. Assets

What Rotelyx is trying to protect, in priority order.

| # | Asset | Why it ranks here |
|---|-------|-------------------|
| A1 | Message and call **content** | The obvious one, and the easiest to protect. |
| A2 | **Social graph**, who talks to whom, when, how often | Harder than A1, more valuable to most real adversaries, and the thing almost every messenger leaks. |
| A3 | **Identity linkability**: connecting an Rotelyx key to a legal person | No phone number is the design's main lever here. |
| A4 | Group **membership** | Who is in a conversation is often more sensitive than what was said. |
| A5 | **Presence**: whether a given identity is online now | Leaks routine, location patterns, and sleep schedule. |
| A6 | **Availability** of the service | Ranked last deliberately: a denial of service is recoverable, a disclosure is not. |

---

## 2. Adversaries

Each adversary is listed with the capabilities we assume, and what Rotelyx claims
against it. Claims are per-asset and use the asset IDs above.

### ADV-1: Passive network observer
*Capability:* reads all traffic on one or more links. Cannot modify.

- **Defended:** A1 (QUIC/TLS 1.3 at L1, MLS at L2), A4.
- **Partially defended:** A2: the observer sees IP-level flow between two
  addresses. Direct P2P paths reveal both peers' IPs to each other and to
  anyone on-path. Padding buckets hide message *length*; they do not hide that
  a flow exists.
  **Both directions pad, and for a while only one did.** MLS applies padding
  per member, and only the member who created the group had it configured: a
  joiner took the library's default of none, so its ciphertext grew a byte for
  every byte of plaintext. With two people that is one direction on the wire in
  the clear as far as length goes. It mattered most on a live session, where the
  ciphertext travels in a frame of its own; a message through the mailbox is
  sealed into an envelope that pads to its own buckets either way.
- **Not defended:** A5 for on-path observers.

### ADV-2: Active network attacker
*Capability:* modifies, injects, drops, replays, reorders. Controls DNS and
routing.

- **Defended:** A1, A4. Injection and modification fail authentication at both
  L1 and L2 independently. Replay is rejected by MLS epoch and generation
  tracking.
- **Not defended:** A6. An active attacker can always drop packets.
- **Residual:** downgrade is prevented structurally: a new wire format takes a
  new ALPN rather than negotiating in band, so there is no version field to
  strip.

### ADV-3: Relay operator (including us)
*Capability:* full control of a relay carrying a session that failed to
hole-punch.

- **Defended:** A1, A4. Relays are stateless forwarders of QUIC ciphertext and
  hold no session state.
- **Not defended:** **A2.** The relay sees which address sends to which. This
  is the single largest metadata exposure in the system and it is inherent to
  relayed transport. Mitigations: prefer direct paths and surface relay use in
  the UI; support self-hosted relays; rotate relay selection.
- **What a name per contact does and does not change here.** The identity key
  never reaches the wire; each invitation carries a transport key of its own, so
  no two people you invited are given the same **address**; and each conversation
  carries a **name** of its own, derived from the invitation secret both sides
  hold, so no two of them are shown the same name inside the conversation
  either. That defeats a **passive observer** and it defeats **correspondents
  comparing notes**, which is the whole of what SimpleX means by having no user
  identifiers.
  A middle draft of this line said the opposite, and was right at the time: the
  addresses differed and the identity did not, because a client put its
  long-lived key in every MLS credential. Measured after the change, with a real
  relay: the identity is `ef53e87e`, one contact is shown `a82d5b96` and another
  `e875cc93`.
  It costs no authentication. An MLS credential is a label the member chooses
  and never proved anything about who it belonged to; what authenticates is the
  safety number, which both sides contribute to and compare out of band. What it
  costs is recognition: somebody who verified you in one conversation cannot
  recognise you in another, and cannot vouch for you to anybody else.
  It does **not** defeat this adversary: all of one
  endpoint's addresses are answered on a single relay connection, and the relay
  holds the table mapping them to it, so it can still see that the parties
  reaching those addresses are reaching the same host. Correspondent
  unlinkability against the relay would need a separate relay connection per
  invitation, which is not built and is not cheap: it multiplies connections,
  handshakes and presence signals by the number of invitations.
- **Not defended:** A5: connecting to a relay reveals presence to it.

### ADV-4: Mailbox operator
*Capability:* full control of the blind mailbox node, including its disk. Can
read all stored envelopes, retain them past TTL, and correlate timing.

- **Defended:** A1: envelopes are L2 ciphertext, sealed, and the mailbox has no
  keys.
- **Defended:** sender identity: sealed sender means the envelope carries no
  sender field, and a caller presenting nothing is given a fresh capability id
  per connection, so the mailbox has no value tying its deposits together.
- **Not defended for a paying sender:** a bought token carries a random 16 byte
  id, and the meter counts against it, so the mailbox can tie together every
  deposit made under one token. The id names nobody, which is not the same as
  linking nothing: it is a stable pseudonym with a usage history. Blind issuance
  keeps the *issuer* from recognising the token it signed, which is a different
  problem from the mailbox recognising a token it has already served. **Design
  consequence:** paying for a tier costs the holder unlinkability at the
  mailbox, and that trade should be visible to whoever makes it.
- **Partially defended:** A2: the recipient is addressed by a rotating
  pseudonymous tag rather than an identity key, and all envelopes are padded to
  fixed size buckets. A mailbox that logs everything can still perform timing
  correlation between a deposit and a collection.
- **Defended:** taking the free tier away from everybody else. The free
  capability used a constant meter id, so every unauthenticated caller in the
  world shared one 64 MiB bucket that resets once a day. Filling it needed no
  token, no payment and no identity, and at the free fanout that is 41 deposits:
  the metering built to stop abuse was the cheapest way to commit it. Each free
  caller now gets its own id. It does not stop somebody opening many connections,
  which is the ordinary flooding question and is **still not defended**, but one
  caller can no longer silence the rest by behaving within its own limits.
- **Not defended:** A6, and deletion. "Deleted on delivery" is a promise the
  operator makes, not one the protocol enforces. **Design consequence:** the
  mailbox must never be the only copy, and clients must not treat mailbox
  acknowledgement as proof of deletion.

### ADV-5: Server seizure / legal compulsion
*Capability:* obtains everything ADV-3 and ADV-4 hold, plus future traffic,
plus the ability to compel silence.

- **Defended:** A1, A4 retroactively. No server holds anything that can read a
  message: envelopes are L2 ciphertext, relays forward QUIC ciphertext, and the
  capability keys a mailbox holds are the **public** halves, so seizing one
  cannot mint tokens either. The private halves live with the issuer, which is a
  separate service.
- **Not defended, and a stronger claim used to be made here.** "No key material
  on any server" was too broad. A mailbox configured to wake devices holds the
  APNs `.p8`, which is a private key, and the passphrase to its wake registry.
  Seizing it therefore yields the ability to push to every device registered
  with that mailbox, and the list of which devices those are. It reads nothing,
  and it is not nothing. **Design consequence:** a mailbox that wakes devices is
  a more valuable thing to seize than one that does not, and an operator should
  know that before configuring one.
- **Not defended:** A2 for the period of retention. TTL and no-log policy limit
  but do not eliminate this.
- **Design consequence:** the mailbox must be trivially self-hostable, so that
  seizing any one operator does not compromise a population.

### ADV-6: Compromised endpoint
*Capability:* code execution on a participant's device. Malicious OS,
jailbroken/rooted device, malware, forensic extraction of an unlocked device.

- **Not defended. At all.** This is the honest boundary of the entire system.
  A device that renders plaintext to a screen can have that plaintext taken.
- **Partially mitigated:** MLS forward secrecy limits how far *back* a
  compromise reads; post-compromise security limits how far *forward* it reads
  once the group rekeys and the attacker loses access. Neither helps while the
  attacker is present.
- **Not mitigated:** screenshots, keyloggers, camera access, backup extraction.

### ADV-7: Malicious group member
*Capability:* a legitimate member of a conversation.

- **Not defended, by definition.** A participant can record and republish
  anything. Rotelyx does not attempt deniability guarantees it cannot keep.
- **Defended:** a member cannot add another member without producing an MLS
  commit that every other member sees. Silent addition is what "ghost user"
  attacks rely on, and MLS makes it visible: **provided the client actually
  surfaces membership changes.** That UI obligation is a security control, not
  a nicety.
- **How that obligation is met.** `Conversation::receive` reports who joined and
  who left, rather than reporting that something happened. It used to return the
  same value for a membership change, a routine rekey and a message it did not
  recognise, so the clients announced "the group changed" for all three and could
  report only a count. A count is not enough on its own: one commit can remove a
  member and add another, leaving the number where it was, so a client reading
  only the count says "2 members" while the person on the other side has been
  replaced. The terminal, desktop and browser clients now name them.

### ADV-8: Global passive adversary
*Capability:* observes traffic at many points simultaneously, correlates by
timing and volume across the whole network.

- **Not defended.** Rotelyx is not a mixnet. Constant-rate cover traffic would be
  required and is incompatible with mobile battery life.
- **Stated plainly** so that no user at risk from this adversary class mistakes
  Rotelyx for a tool that protects them. Such users need Tor, a mixnet, or not to
  use a phone.

### ADV-9: Push notification provider (Apple, Google)
*Capability:* sees that a device received a wake signal, and when.

- **Defended:** A1: pushes carry no content.
- **Defended:** asking a mailbox whether it wakes a given device. This adversary
  holds every push token, so a registration that could be refused was a
  membership oracle pointed straight at it: present a token, and a refusal meant
  the device is registered here. A wake row is now identified by the token *and*
  the secret that registered it, so any well formed registration is accepted and
  gets a row of its own. The owner's row is untouched and still only theirs to
  revoke, wakes go one per distinct token so extra rows are not extra pushes,
  and the per-token bound is reached silently. The only refusal left is a
  malformed token, which depends on what the caller sent and nothing else.
- **Not defended:** A5, and partially A2 by timing correlation with a mailbox.
- **Mitigations, as built:** wakes carry no content and are marked as decoys, so
  a device cannot tell from the push whether anything is waiting, and neither
  can Apple. Every registered device is woken on **one fixed schedule**,
  identical for all of them and regardless of whether anything arrived.
  **Not jitter, and deliberately not.** An earlier version of this line named
  jittered delivery windows as a mitigation, which would be a weakening: a
  device woken on a rhythm of its own is a device identifiable by that rhythm.
  Anybody tempted to add jitter here should read the comment above the wake loop
  first. None of this is a solution and all of it costs battery.
- This is an unsolved problem inherent to mobile platforms. It is listed here
  rather than hidden because a threat model that only lists solved problems is
  marketing.

### ADV-10: Spam / abuse actor
*Capability:* generates unlimited identities at zero cost, because identities
are just keypairs.

- **Not defended by cryptography.** No phone number means no natural scarcity.
  Scarcity has to be manufactured, and there are only two ways to do it.
- **Implemented** in `rotelyx-core::access`:
  - **`InvitationOnly` is the default.** An identity is unreachable without a
    capability it issued out of band. Unsolicited contact is impossible rather
    than merely expensive. The proof commits to the caller's identity: the one
    the QUIC handshake already authenticated, so an observed proof cannot be
    replayed by anyone else.
  - **`ProofOfWork`** for identities that must be publicly reachable. The work
    binds to *both* identities and to the hour, so it is non-transferable: a
    bulk sender pays per recipient, pays again per throwaway identity, and
    cannot stockpile proofs in advance. That forces the choice between reusing
    one blockable identity and paying for every new one.
- **Still not defended:** a determined individual attacker with time. Neither
  mechanism is meant to stop one person; both are meant to destroy the
  economics of bulk contact, which is the actual threat.
  - **Blocklists**, checked *before* any verification runs. A block that still
    costs CPU is one the blocked party can keep spending.
  - **Revocation.** Expiry is a promise about the future; a leaked invitation is
    a problem now, so `Gate::revoke` retires one immediately without affecting
    holders of the others.
    - **A permission is for one address.** Admission reads the address the call
      was *answered at*, never the one the caller asked for, and admits only on
      the invitation answered there. The distinction is the whole check: a
      server name the endpoint does not hold is answered by its own key anyway,
      so a hostile caller reading its own request back would simply name an
      address belonging to no invitation and land in the branch where any of
      them admits. Checking the proof alone would let a holder
      take an address it suspected of belonging to the same identity, call it,
      present its own invitation, and learn from being admitted that the guess
      was right. That would give back by testing what per-invitation addresses
      remove from view.
- **Enforced on the accept path**, not merely defined: the caller's first frame
  must be its admission evidence, and it is checked before the MLS handshake, so
  an unauthorised peer cannot make us do group-crypto work. Live-socket tests in
  `crates/rotelyx-core/tests/admission.rs` assert the refusals actually happen.
- **Outstanding:** rate limiting per source, and a way to distribute blocklists
  across a user's own devices.

---

## 3. Cryptographic assumptions

If any of these fails, the corresponding claims fail with it.

| Assumption | Used for | If broken |
|---|---|---|
| Ed25519 signatures are unforgeable | identity, MLS credentials | Full impersonation. |
| X25519 CDH is hard | L1 transport, L2 key agreement | Retroactive decryption of anything recorded. |
| ML-KEM-768 is IND-CCA2 secure | PQ half of the hybrid combiner | Falls back to X25519-only security, which is why it is a *hybrid*, not a replacement. |
| The hybrid combiner is secure if **either** component is | L2 key agreement | The reason a novel PQ construction is acceptable risk here at all. |
| BLAKE3 / SHA-256 are collision resistant | safety numbers, key schedule | Safety number confusion; identity binding attacks. |
| ChaCha20-Poly1305 is a secure AEAD | message encryption | Content disclosure. |
| The OS CSPRNG is not backdoored | every key generated | Total compromise, undetectable. |

**Explicitly assumed:** that we do **not** invent primitives. The hybrid
combiner is the one novel construction in Rotelyx, it composes standard
primitives, and it is the specific item that must be independently reviewed
before any public release. See §5.

---

## 4. Non-goals

Stated so that scope creep has something to be refused against.

- **Anonymity from a global adversary.** Rotelyx provides confidentiality and
  metadata *minimisation*, not anonymity. Not a mixnet, not Tor.
- **Protection from a compromised device.** See ADV-6.
- **Deniability.** Not claimed. A recipient can prove what they received to
  anyone willing to trust their device.
- **Guaranteed message deletion.** "Delete for everyone" is a UI convenience.
  Any recipient can retain anything.
- **Availability under attack.** A well-resourced attacker can deny service.
- **Account recovery without a trust anchor.** Losing every device means losing
  the identity. Any recovery mechanism that does not require a key the user
  holds is a backdoor, and Rotelyx will not ship one.

---

## 5. Review gates

No public security claim is made before all of these are met.

1. **Hybrid PQ combiner reviewed independently.** The one novel construction.
   Published with test vectors and a written security argument before review.
2. **Full implementation audit** of L2 and L3 by a firm that does cryptographic
   review as its primary business.
3. **Fuzzing** of every parser reachable from the network: the L1 frame reader,
   the L3 envelope parser, and MLS message handling.
   *Harness built, gate not closed.* `fuzz/` holds a libFuzzer target for each
   of the three, run with `cargo +nightly fuzz run <target>`. Nothing found so
   far, over about nine hundred million cases: 279,856,821 against the frame
   reader at 78 coverage points, 604,526,799 against the envelope parser at 39,
   and 15,156,212 against MLS handling at 2,565 with a corpus of 1,635. No
   crash, no hang, no artifact.
   An earlier pass did produce one artifact, a "slow unit" of 44 seconds, which
   ran in 78 ms on its own: libFuzzer times by the clock on the wall and the
   machine was compiling. Do not run these beside a build.
   They run nightly now, fifteen minutes on each target, one target per job:
   `.github/workflows/fuzz.yml`. Not on every push, because a fuzzer is not a
   test: a test says yes or no about a property somebody chose, and a fuzzer
   looks for the case nobody thought of by running for a long time. What still
   keeps this gate open is that nothing has come back from it yet, and a gate
   closes on a review rather than on a schedule.
   The frame and envelope targets also assert that anything accepted re-encodes
   to the bytes it came from, so a second encoding of one value is a finding
   rather than something the fuzzer would pass over.
4. **Documented handling** of the state-corruption class that kills hand-written
   ratchets, and which MLS does not automatically solve for us:
   nonce reuse under concurrency, state rollback after backup restore,
   unbounded skipped-key retention, replay across device re-registration.
   *Measured and written down in §7. All four hold, three of them because of
   library behaviour this crate never chose, which is why each now has a test.*
5. **Constant-time review** of every comparison touching secret material.

---

## 5b. State corruption: what was measured

Review gate 4 names four failures. Each was reproduced rather than reasoned
about, and each has a test in `rotelyx-crypto` so that a change to the library
underneath does not move the answer quietly.

| Failure | What actually happens |
|---|---|
| One backup restored onto two devices | The receiver refuses the second message: it deletes each generation's secret as it uses it, so there is nothing left to decrypt with |
| A device rolled back to an older backup | The same. Every message it sends from the rewound state is refused |
| A sender jumping far ahead of a receiver | Bounded at a thousand skipped generations, about seven milliseconds of derivation, then refused |
| A message replayed into a reinstalled device | Refused. A reinstall is a new member added by a commit that moves the epoch, and the captured message belongs to an epoch that member never had |

**The sender is now stopped rather than left talking to itself.** A copy
reopened from storage refuses to send until it has rekeyed: `send` returns
`RestoredAndNotRekeyed`, and `rekey_after_restore` moves the epoch and hands
back the commit the caller has to deliver. It used to succeed, have the receiver
drop the message, and tell nobody, so to the person holding the device their
messages simply stopped arriving. Confidentiality held and availability did not,
silently.

**Three of the four are inherited.** The forward-secrecy deletion, the forward
distance limit of a thousand and the epoch check are the library's behaviour,
not decisions this project made or configured. That is why they are pinned by
tests: an upgrade that changed any of the three would otherwise change what this
table says without anybody editing it.

---

## 6. Side channels: what was checked

Every comparison in the first-party crates that touches key material, a tag, a
token, a proof or a passphrase is located and classified below.

That sentence was first written after a single review, in the past tense, and
went stale within weeks: the vault's passphrase check and the wake registry's
revocation secret were both added afterwards and neither reached the table,
while the section went on describing itself as complete. The two rows naming
them were added when that was noticed.

It is now enforced rather than asserted.
`crates/rotelyx-crypto/tests/secret_comparisons.rs` scans the first-party crates
and fails the build on a comparison this table does not mention, and on a row
here describing code that no longer exists. Same reasoning as the guard on
foreign infrastructure: a promise in a document does not enforce itself.

**Already constant time, and correct to be:**

| Site | What it compares |
|---|---|
| `PqSecret::ct_eq` | Two post-quantum shared secrets |
| `access.rs` contact proof | An arriving proof against the expected one |
| `access.rs` invitation revocation | An invitation secret against the revoked list |
| `vault.rs` passphrase binding | A passphrase against the one a cached key was derived from |
| `wake.rs` `secrets_match` | A device's revocation secret against the stored hash |

**Variable time and correct to be, because the values are public:**

The sender identity and counter in a media header, an MLS epoch number, a
signature key (a public key by definition), a connection identity in the
mailbox server, and every `.len()` check in every parser.

**Variable time on a secret-derived value, now fixed:** `Tag`.

A tag derives from a conversation secret. It is not secret from the operator,
who routes with it, and it is secret from everybody else, for whom knowing one
buys the ability to deposit into that mailbox and correlate its traffic. Its
`PartialEq` was derived, so it short-circuited on the first differing byte.

**It was not exploitable**, and saying so matters as much as the fix. The
comparison that matters is on the client, checking an arriving envelope against
the tag it expected, and to reach it an attacker must get an envelope delivered.
The mailbox only delivers to subscribers of the tag the envelope names, so
putting bytes in front of that comparison already requires knowing the answer.
The server compares tags where the attacker does choose them, but its reply
already says whether anybody was subscribed, so timing reveals nothing the
protocol does not.

It is constant time now anyway. That argument is four paragraphs long and rests
on details of delivery that one commit could change, by somebody who never read
it. A variable-time comparison on secret-derived material is a standing
obligation to keep re-deriving the argument; `ct_eq` costs one pass over 32
bytes and discharges it permanently.

`Tag`'s `Ord` and `Hash` stay variable time deliberately: they exist so a tag
can key the map the server routes with, and making that constant time would mean
scanning every subscriber on every deposit.

**Not covered by this review**, and worth stating rather than leaving implied:
the timing of the underlying primitives is the libraries' responsibility, not
ours. Whether `chacha20poly1305`, `ed25519-dalek`, `ml-kem` and the RSA blind
signature implementation are constant time is their claim; we have not measured
it, and a review that said otherwise would be claiming work nobody did.

## 7. What the artifacts leaked, and what can now be verified

Two properties of the shipped files, both found by measuring rather than by
reasoning, and both fixed.

**The build machine's username was in every artifact.** Rust embeds `file!()` in
panic messages, and for a dependency that is the full path into the build
machine's cargo registry. Counted:

| Artifact | Paths containing the build user's home |
|---|---|
| `rotelyx_wasm_bg.wasm` | 173 |
| `rotelyx-relay` | 387 |
| `rotelyx-mailbox-server` | 269 |

The wasm is the one that matters most: it is downloaded by every visitor, so
every visitor received the build machine's username. `--remap-path-prefix` in
`scripts/build-wasm` and `scripts/build-release` removes them, and both scripts
**refuse to finish** if any remain, so this cannot come back quietly.

**The builds were not reproducible.** Two clean builds of identical source
produced different binaries. They now produce byte-identical ones.

That is the more valuable half. A user who is told "here is the source" cannot
check that the module their browser just ran corresponds to it unless building
that source gives the same bytes. Without reproducibility, publishing source is
a gesture; with it, it is a claim anybody can test.

### What this does not solve, and cannot

Subresource integrity was considered and rejected as security theatre here. SRI
protects a page served from a trusted origin against a subresource from an
untrusted one. Our page and our module come from the same origin: an attacker
who can serve a modified `rotelyx_wasm.js` can serve a modified `chat.html`
carrying the matching hash. The check would verify the attacker's work.

**A web client cannot defend against its own server.** That is inherent to
shipping code over the same channel that serves the page, not a gap in this
implementation, and no amount of hashing inside the page changes it. What
reproducibility buys is the ability for somebody *outside* the page, a user with
the published hash, a third party watching, to notice that what is being served
is not what was published. That is a real defence and it is a different one.

## 8. Open questions

- How does a client detect that a mailbox is withholding messages rather than
  none having been sent? Suppression is currently invisible.
- Rotating recipient tags must be unlinkable to an observer but derivable by the
  recipient. The rotation schedule leaks something regardless: what, exactly?
- Multi-device without a server-held key bundle: which device authorises the
  next one, and what does the user see when it happens?
- Does surfacing "this call is relayed, not direct" help users or train them to
  ignore a warning they cannot act on?
