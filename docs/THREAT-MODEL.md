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
| A2 | **Social graph** — who talks to whom, when, how often | Harder than A1, more valuable to most real adversaries, and the thing almost every messenger leaks. |
| A3 | **Identity linkability** — connecting an Rotelyx key to a legal person | No phone number is the design's main lever here. |
| A4 | Group **membership** | Who is in a conversation is often more sensitive than what was said. |
| A5 | **Presence** — whether a given identity is online now | Leaks routine, location patterns, and sleep schedule. |
| A6 | **Availability** of the service | Ranked last deliberately: a denial of service is recoverable, a disclosure is not. |

---

## 2. Adversaries

Each adversary is listed with the capabilities we assume, and what Rotelyx claims
against it. Claims are per-asset and use the asset IDs above.

### ADV-1 — Passive network observer
*Capability:* reads all traffic on one or more links. Cannot modify.

- **Defended:** A1 (QUIC/TLS 1.3 at L1, MLS at L2), A4.
- **Partially defended:** A2 — the observer sees IP-level flow between two
  addresses. Direct P2P paths reveal both peers' IPs to each other and to
  anyone on-path. Padding buckets hide message *length*; they do not hide that
  a flow exists.
- **Not defended:** A5 for on-path observers.

### ADV-2 — Active network attacker
*Capability:* modifies, injects, drops, replays, reorders. Controls DNS and
routing.

- **Defended:** A1, A4. Injection and modification fail authentication at both
  L1 and L2 independently. Replay is rejected by MLS epoch and generation
  tracking.
- **Not defended:** A6. An active attacker can always drop packets.
- **Residual:** downgrade is prevented structurally — a new wire format takes a
  new ALPN rather than negotiating in band, so there is no version field to
  strip.

### ADV-3 — Relay operator (including us)
*Capability:* full control of an iroh relay carrying a session that failed to
hole-punch.

- **Defended:** A1, A4. iroh relays are stateless forwarders of QUIC ciphertext
  and hold no session state.
- **Not defended:** **A2.** The relay sees which endpoint id sends to which. This
  is the single largest metadata exposure in the system and it is inherent to
  relayed transport. Mitigations: prefer direct paths and surface relay use in
  the UI; support self-hosted relays; rotate relay selection.
- **Not defended:** A5 — connecting to a relay reveals presence to it.

### ADV-4 — Mailbox operator
*Capability:* full control of the blind mailbox node, including its disk. Can
read all stored envelopes, retain them past TTL, and correlate timing.

- **Defended:** A1 — envelopes are L2 ciphertext, sealed, and the mailbox has no
  keys.
- **Defended:** sender identity — sealed sender means the envelope carries no
  sender field.
- **Partially defended:** A2 — the recipient is addressed by a rotating
  pseudonymous tag rather than an identity key, and all envelopes are padded to
  fixed size buckets. A mailbox that logs everything can still perform timing
  correlation between a deposit and a collection.
- **Not defended:** A6, and deletion. "Deleted on delivery" is a promise the
  operator makes, not one the protocol enforces. **Design consequence:** the
  mailbox must never be the only copy, and clients must not treat mailbox
  acknowledgement as proof of deletion.

### ADV-5 — Server seizure / legal compulsion
*Capability:* obtains everything ADV-3 and ADV-4 hold, plus future traffic,
plus the ability to compel silence.

- **Defended:** A1, A4 retroactively. There is no plaintext, and no key
  material, on any server.
- **Not defended:** A2 for the period of retention. TTL and no-log policy limit
  but do not eliminate this.
- **Design consequence:** the mailbox must be trivially self-hostable, so that
  seizing any one operator does not compromise a population.

### ADV-6 — Compromised endpoint
*Capability:* code execution on a participant's device. Malicious OS,
jailbroken/rooted device, malware, forensic extraction of an unlocked device.

- **Not defended. At all.** This is the honest boundary of the entire system.
  A device that renders plaintext to a screen can have that plaintext taken.
- **Partially mitigated:** MLS forward secrecy limits how far *back* a
  compromise reads; post-compromise security limits how far *forward* it reads
  once the group rekeys and the attacker loses access. Neither helps while the
  attacker is present.
- **Not mitigated:** screenshots, keyloggers, camera access, backup extraction.

### ADV-7 — Malicious group member
*Capability:* a legitimate member of a conversation.

- **Not defended, by definition.** A participant can record and republish
  anything. Rotelyx does not attempt deniability guarantees it cannot keep.
- **Defended:** a member cannot add another member without producing an MLS
  commit that every other member sees. Silent addition is what "ghost user"
  attacks rely on, and MLS makes it visible — **provided the client actually
  surfaces membership changes.** That UI obligation is a security control, not
  a nicety.

### ADV-8 — Global passive adversary
*Capability:* observes traffic at many points simultaneously, correlates by
timing and volume across the whole network.

- **Not defended.** Rotelyx is not a mixnet. Constant-rate cover traffic would be
  required and is incompatible with mobile battery life.
- **Stated plainly** so that no user at risk from this adversary class mistakes
  Rotelyx for a tool that protects them. Such users need Tor, a mixnet, or not to
  use a phone.

### ADV-9 — Push notification provider (Apple, Google)
*Capability:* sees that a device received a wake signal, and when.

- **Defended:** A1 — pushes carry no content.
- **Not defended:** A5, and partially A2 by timing correlation with a mailbox.
- **Mitigations:** content-free silent wakes, jittered delivery windows, decoy
  pushes. None of these is a solution and all cost battery.
- This is an unsolved problem inherent to mobile platforms. It is listed here
  rather than hidden because a threat model that only lists solved problems is
  marketing.

### ADV-10 — Spam / abuse actor
*Capability:* generates unlimited identities at zero cost, because identities
are just keypairs.

- **Not defended by cryptography.** No phone number means no natural scarcity.
  Scarcity has to be manufactured, and there are only two ways to do it.
- **Implemented** in `rotelyx-core::access`:
  - **`InvitationOnly` is the default.** An identity is unreachable without a
    capability it issued out of band. Unsolicited contact is impossible rather
    than merely expensive. The proof commits to the caller's identity — the one
    the QUIC handshake already authenticated — so an observed proof cannot be
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
| ML-KEM-768 is IND-CCA2 secure | PQ half of the hybrid combiner | Falls back to X25519-only security — which is why it is a *hybrid*, not a replacement. |
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
4. **Documented handling** of the state-corruption class that kills hand-written
   ratchets, and which MLS does not automatically solve for us:
   nonce reuse under concurrency, state rollback after backup restore,
   unbounded skipped-key retention, replay across device re-registration.
5. **Constant-time review** of every comparison touching secret material.

---

## 6. Open questions

- How does a client detect that a mailbox is withholding messages rather than
  none having been sent? Suppression is currently invisible.
- Rotating recipient tags must be unlinkable to an observer but derivable by the
  recipient. The rotation schedule leaks something regardless — what, exactly?
- Multi-device without a server-held key bundle: which device authorises the
  next one, and what does the user see when it happens?
- Does surfacing "this call is relayed, not direct" help users or train them to
  ignore a warning they cannot act on?
