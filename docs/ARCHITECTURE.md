# Architecture

How Rotelyx is put together, for somebody who wants to read the code or check
the design. If you only want to run it, the [README](../README.md) is enough.

## How a message travels

The full path of a single message, from typing to reading.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','secondaryColor':'#122A26','tertiaryColor':'#2F1B20',
  'fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart TD
    A["<b>Alice types a message</b>"] --> B

    subgraph L2["L2 Message crypto"]
        direction TB
        B["Pad plaintext to a multiple of 256 bytes"]
        B --> C["Encrypt with MLS<br/>ChaCha20-Poly1305<br/>epoch key includes the PQ secret"]
    end

    C --> D{"Is Bob online?"}

    D -->|"Yes"| E["<b>Direct path</b>"]
    D -->|"No"| F["<b>Blind mailbox</b>"]

    subgraph DIRECT["L1 / L0 Direct transport"]
        direction TB
        E --> E1["Frame it, length capped"]
        E1 --> E2["QUIC + TLS 1.3<br/>peer authenticated by public key"]
        E2 --> E3["Hole punched path<br/>no server involved"]
    end

    subgraph MAILBOX["L3 Store and forward"]
        direction TB
        F --> F1["Pad to a fixed bucket<br/>1 KiB / 8 KiB / 64 KiB / 1 MiB / 8 MiB"]
        F1 --> F2["Address to a rotating tag<br/>derived from a shared MLS secret"]
        F2 --> F3["Deposit<br/>operator sees an opaque tag<br/>and a fixed size blob"]
        F3 --> F4["Bob polls his tag window<br/>collection deletes"]
    end

    E3 --> G["<b>Bob decrypts and reads</b>"]
    F4 --> G

    style A fill:#33280F,stroke:#E8A33D,color:#E8A33D
    style G fill:#122A26,stroke:#4FB39A,color:#4FB39A
    style D fill:#1B222D,stroke:#8B96A8,color:#DFE5EE
    style L2 fill:#141A23,stroke:#E8A33D,color:#DFE5EE
    style DIRECT fill:#141A23,stroke:#4FB39A,color:#DFE5EE
    style MAILBOX fill:#141A23,stroke:#E8A33D,color:#DFE5EE
```

**The direct path involves no server whatsoever.** The mailbox exists only for
the case where the recipient is not there, which on phones is most of the time.

---

## Architecture

Five layers. The two encryption layers are independent by construction.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart TB
    subgraph L4["<b>L4</b> Client surface"]
        direction LR
        A1["Safety numbers"]
        A2["Device management"]
        A3["Membership change alerts"]
    end

    subgraph L3["<b>L3</b> rotelyx-mailbox"]
        direction LR
        B1["Sealed envelopes"]
        B2["Padding buckets"]
        B3["Rotating tags"]
        B4["TTL expiry"]
    end

    subgraph L2["<b>L2</b> rotelyx-crypto"]
        direction LR
        C1["MLS groups<br/>RFC 9420"]
        C2["X-Wing hybrid KEM"]
        C3["PQ secret as external PSK"]
    end

    subgraph L1["<b>L1</b> rotelyx-core + rotelyx-net"]
        direction LR
        D1["Ed25519 identity"]
        D2["Admission control"]
        D3["Framed sessions"]
        D4["QUIC + TLS 1.3"]
    end

    subgraph L0["<b>L0</b> rotelyx-net"]
        direction LR
        E1["Hole punching"]
        E2["Relay policy"]
        E3["Metadata resistant<br/>path selection"]
    end

    L4 --> L3 --> L2 --> L1 --> L0

    style L4 fill:#141A23,stroke:#8B96A8,color:#DFE5EE
    style L3 fill:#141A23,stroke:#E8A33D,color:#DFE5EE
    style L2 fill:#141A23,stroke:#E8A33D,color:#DFE5EE
    style L1 fill:#141A23,stroke:#4FB39A,color:#DFE5EE
    style L0 fill:#141A23,stroke:#4FB39A,color:#DFE5EE
```

### Why two independent layers

If TLS 1.3 inside QUIC were broken tomorrow, L2 would still hold. If a device
leaked an MLS epoch key, L1 and L0 would still deny an eavesdropper the raw
stream. **No key material is derived from one layer into the other.** That
separation is a design rule, not an accident.

---

## What each layer guarantees

| Layer | Crate | Guarantees | Does not guarantee |
|---|---|---|---|
| **L3** | `rotelyx-mailbox` | Operator sees no sender, no recipient identity, no plaintext, no message length | Timing correlation between deposit and collection. Deletion is enforced by code, not by protocol |
| **L2** | `rotelyx-crypto` | Forward secrecy, post compromise security, membership visible in commits, post quantum epoch keys | Anything once a device is compromised |
| **L1** | `rotelyx-core` | Peer authenticated by public key, admission control before any group crypto, length capped framing | That the key belongs to the person you mean. That is what safety numbers are for |
| **L0** | `rotelyx-net` | Direct paths preferred over relayed ones at any latency, no third party infrastructure contacted | That a direct path always exists. Roughly 10 to 20 percent of NAT pairs cannot be punched |

---

## Post quantum protection

### The problem

RFC 9420 defines only classical ciphersuites. The post quantum suites are still
in draft. A conversation recorded today can be decrypted later by an adversary
with a quantum computer, which is the harvest now decrypt later attack.

### What Rotelyx does

It does **not** invent a KEM combiner. It uses
[X-Wing](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10),
which is published, peer reviewed and deployed. Its security claim:

> The shared secret is secure if SHA3 is secure **and** *either* X25519 **or**
> ML-KEM-768 is secure.

Both would have to break at once.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','actorBkg':'#1B222D','actorBorder':'#E8A33D','actorTextColor':'#DFE5EE',
  'signalColor':'#8B96A8','signalTextColor':'#DFE5EE','noteBkgColor':'#33280F',
  'noteBorderColor':'#E8A33D','noteTextColor':'#E8A33D',
  'fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
sequenceDiagram
    participant A as Alice
    participant M as MLS group state
    participant B as Bob

    Note over B: Publishes a hybrid public key<br/>1216 bytes, alongside the key package

    A->>A: Encapsulate to Bob's hybrid key
    Note right of A: X-Wing yields a 1120 byte ciphertext<br/>and a 32 byte shared secret

    A->>B: Hybrid ciphertext
    B->>B: Decapsulate, recover the same secret

    Note over A,B: Both derive a PSK bound to group id<br/>and epoch, so material captured in one<br/>epoch cannot be replayed into another

    B->>B: Stage the PSK locally
    A->>M: Commit containing a PreSharedKeyProposal
    M->>B: Every member validates the commit
    Note over M: MLS mixes the PSK into the epoch<br/>through its own unmodified key schedule

    Note over A,B: The epoch key is now post quantum secure.<br/>Zero lines of MLS were changed.
```

### Why the pre shared key input rather than a fork

Two properties fall out of using the mechanism MLS already defines:

1. **Material refreshes per epoch** instead of being fixed at group creation.
2. **No member can inject a chosen PSK silently.** The proposal is part of the
   commit that every member validates, which is the same property that makes a
   ghost member addition visible.

> [!IMPORTANT]
> This composition is the **single novel cryptographic construction** in
> Rotelyx. It is roughly forty lines. It is small on purpose, and it is the
> specific item that must be independently reviewed before any release.

---

## The blind mailbox

### What the operator sees

Exactly two things: an opaque 32 byte tag, and a payload whose length is one of
five fixed values.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart LR
    subgraph SENDER["Sender"]
        direction TB
        S1["MLS ciphertext"]
        S2["Pad to bucket"]
        S3["Derive tag<br/>BLAKE3(tag key, hour)"]
        S1 --> S2 --> S3
    end

    subgraph WIRE["<b>What crosses the wire</b>"]
        direction TB
        W1["<b>tag</b><br/>32 opaque bytes"]
        W2["<b>payload</b><br/>exactly 1 KiB, 8 KiB,<br/>64 KiB, 1 MiB or 8 MiB"]
    end

    subgraph OPERATOR["Mailbox operator holds"]
        direction TB
        O1["An opaque label"]
        O2["A fixed size blob"]
        O3["A timestamp"]
        O4["<b>Nothing else</b>"]
    end

    subgraph RECIPIENT["Recipient"]
        direction TB
        R1["Derive the same tags<br/>independently"]
        R2["Poll a window of hours"]
        R3["Collect, which deletes"]
        R4["Decrypt"]
        R1 --> R2 --> R3 --> R4
    end

    S3 --> WIRE --> OPERATOR --> RECIPIENT

    style WIRE fill:#33280F,stroke:#E8A33D,color:#E8A33D
    style OPERATOR fill:#2F1B20,stroke:#E0808C,color:#DFE5EE
    style SENDER fill:#141A23,stroke:#4FB39A,color:#DFE5EE
    style RECIPIENT fill:#141A23,stroke:#4FB39A,color:#DFE5EE
    style O4 fill:#122A26,stroke:#4FB39A,color:#4FB39A
```

### Three design decisions worth explaining

**No length prefix is written.** The padding is trailing zeroes, and the
recipient recovers the real content because the inner MLS message is self
delimiting. Writing a length field would have been the natural thing to do and
would have handed the operator exactly the information the buckets exist to
hide.

**Addressing is never transmitted.** Both sides derive the tag key from the MLS
exporter secret. Nothing about where a message is addressed travels over the
network.

**Collection is destructive.** An envelope handed over is gone. A client that
crashes mid collection loses those messages. The alternative is a mailbox that
keeps copies, which is exactly what this is trying not to be.

### What the mailbox does not solve

An operator can retain envelopes past their TTL and correlate deposits with
collections by timing. **Deletion is a promise this code makes, not one the
protocol enforces.** The mitigation is not technical: the mailbox is a single
self hostable binary, so seizing one operator compromises one community rather
than a population.

---

## Reachability and abuse resistance

Free identities mean free spam. This is the property that removes phone numbers
from the design and the same property that made Kik a haven for unsolicited
contact. Cryptography does not fix it. Scarcity does.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart TD
    START["Someone dials your endpoint"] --> BLOCK{"On your<br/>blocklist?"}

    BLOCK -->|"Yes"| DENY1["<b>Refused</b><br/>before any verification work"]
    BLOCK -->|"No"| POLICY{"Your reachability<br/>policy"}

    POLICY -->|"InvitationOnly<br/><i>default</i>"| INV{"Holds a live<br/>invitation?"}
    POLICY -->|"ProofOfWork"| POW{"Paid the work?"}
    POLICY -->|"Open"| ALLOW

    INV -->|"Yes"| ALLOW["<b>Session opens</b><br/>MLS handshake begins"]
    INV -->|"No"| DENY2["<b>Refused</b><br/>caller learns only that<br/>the connection closed"]

    POW -->|"Bound to both identities<br/>and to the hour"| ALLOW
    POW -->|"Wrong target, wrong sender,<br/>stale, or insufficient"| DENY2

    style ALLOW fill:#122A26,stroke:#4FB39A,color:#4FB39A
    style DENY1 fill:#2F1B20,stroke:#E0808C,color:#E0808C
    style DENY2 fill:#2F1B20,stroke:#E0808C,color:#E0808C
    style START fill:#33280F,stroke:#E8A33D,color:#E8A33D
```

### Why the proof of work is non transferable

The work binds to the sender, the recipient **and** the hour:

| Binding | What it prevents |
|---|---|
| **Recipient** | Work spent reaching one person cannot be reused on another. A bulk sender pays per recipient. |
| **Sender** | A spammer cannot solve once and reuse it across a fleet of throwaway identities. Each identity pays again. |
| **Hour** | Proofs cannot be stockpiled in advance, and they expire on their own. |

Together those force a choice: **reuse one identity and be blocked, or pay the
work for every new one.** That destroys the economics of bulk contact, which is
the actual threat. It does not stop a determined individual, and it is not meant
to.

### Revocation is surgical

Revoking a leaked invitation does not shut out holders of the others. Expiry is
a promise about the future. A leak is a problem right now.

### Every invitation is a different address

An endpoint that answers under one key is reachable at one address for
everybody, and anything carrying that traffic sees which address talks to which.
Two people you invited could compare notes and find they had been given the same
one. So an invitation carries an address of its own, and the code you hand out
is that address as well as the permission to use it.

One endpoint answers all of them at once, on one socket and one relay
connection, by two arrangements that are made together:

| Half | What it does | Where it lives |
|---|---|---|
| **Answering** | The TLS resolver holds every key and picks by the endpoint id in the ClientHello, which arrives before any key has to be produced | This process |
| **Being found** | The relay is asked to route the address to this connection, and does so only for a connection that signed a binding with the key itself | The relay's memory |

Neither half is useful alone: a key the relay routes but TLS cannot answer is a
door onto a wall, and a key TLS answers but no relay routes is a door nobody can
find. The API makes both, so a caller cannot do half of it.

The signature is over the pair (this connection, the alias), so a binding cannot
be replayed onto another connection, and the relay refuses an address that is
already somebody's connection or already answered elsewhere. Taking someone's
address needs their invitation's secret key.

**What this does not do.** It does not hide the *number* of addresses from the
relay carrying them, since they arrive on one connection. It does not survive a
restart: the routing lives in the relay's memory and is re-made on reconnect,
but a fresh process has to ask again. And answering at several addresses is not
serving several conversations at once, which is a separate thing this endpoint
does not do.

---

## Path selection

The transport this is derived from selects network paths by latency. Rotelyx
selects by **metadata resistance**, and the two objectives genuinely conflict.

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#E8A33D',
  'lineColor':'#8B96A8','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart LR
    subgraph UP["Latency first, upstream"]
        direction TB
        U1["Direct path<br/>200 ms"]
        U2["Relayed path<br/>20 ms"]
        U3["<b>Picks the relay</b><br/>social graph handed to<br/>the operator to save 180 ms"]
        U1 -.-> U3
        U2 --> U3
    end

    subgraph RX["Metadata first, Rotelyx"]
        direction TB
        R1["Direct path<br/>200 ms"]
        R2["Relayed path<br/>20 ms"]
        R3["<b>Picks the direct path</b><br/>slower, and nobody learns<br/>who is talking to whom"]
        R1 --> R3
        R2 -.-> R3
    end

    style U3 fill:#2F1B20,stroke:#E0808C,color:#E0808C
    style R3 fill:#122A26,stroke:#4FB39A,color:#4FB39A
    style UP fill:#141A23,stroke:#8B96A8,color:#DFE5EE
    style RX fill:#141A23,stroke:#4FB39A,color:#DFE5EE
```

Three policies are available:

| Policy | Behaviour |
|---|---|
| `PreferDirect` **(default)** | Any direct path beats any relayed path at any latency. Falls back to a relay only when no direct path exists. |
| `DirectOnceAvailable` | As above, and never returns to a relay once direct. If the direct path dies, the connection dies. |
| `Fastest` | Upstream's objective. Provided so the privacy preserving policies have something to be measured against. |

**The cost is real latency, sometimes.** A direct path across the world can be
slower than a relay two hops away, and Rotelyx will take the slow one.

---

## Contacting no third party infrastructure

This is a hard requirement, enforced **structurally** rather than by
configuration:

- `RelayPolicy` has **no variant** meaning "the library's defaults"
- `AddressLookup` has **no variant** that publishes anywhere
- `NetConfig` has **no `Default` implementation**
- Peer discovery code is **deleted from the tree**, not disabled

A wrong configuration value is a bug you find in production. A missing
constructor is a bug you find at compile time.

### Enforced by test

`crates/rotelyx-net/tests/no_foreign_infrastructure.rs` binds live endpoints,
reads back the relay maps they actually hold, scans the whole workspace for
third party hostnames, and asserts that upstream environment overrides have no
effect. **If any of that stops holding, the build fails.**

Two rules, and the difference between them matters:

1. A foreign hostname **inside a Rust string literal** is always a failure. No
   exception mechanism exists, because a string literal is the shape of
   something the program can connect to.
2. Anywhere else, comments and manifests included, the occurrence must appear in
   `foreign-names-reviewed.txt` with a reason. Author attribution and
   documentation links are legitimate, and they are also exactly where a real
   endpoint could sit waiting to be uncommented.

The earlier version of this guard skipped comments and never looked at
manifests. It was then defeated by the project's own rebranding: a rename
rewrote `iroh` inside string literals, so `use1-1.relay.n0.iroh.link` became
`use1-1.relay.n0.rotelyx_transport.link` and stopped matching any token the
guard knew. The constants survived by being renamed. **A guard that matches on a
brand name is defeated by changing the brand name.**

---
