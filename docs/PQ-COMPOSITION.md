# The Rotelyx hybrid post-quantum composition

**Version 1** &middot; 16 August 2026 &middot; Ideoa Labs

This document specifies the one novel cryptographic construction in Rotelyx. It
is written so that somebody who has never read our source can reimplement it and
check the published vectors.

Everything else in the message layer is adopted unchanged: group and message
encryption is MLS (RFC 9420) via OpenMLS, and the hybrid key encapsulation is
X-Wing. This document covers only the join between them.

> **Unaudited.** This construction has not undergone independent review. It is
> published in this form precisely so that such a review is possible.

---

## 1. Why the construction exists

RFC 9420 defines seven ciphersuites and all of them are classical. Post-quantum
ciphersuites for MLS are still in draft. A conversation recorded today is
therefore exposed to harvest-now-decrypt-later: an adversary who stores the
traffic keeps the option of reading it if a cryptographically relevant quantum
computer is ever built. Whether one is built, and when, is not a claim this
document makes.

Two options were available:

1. **Fork MLS** to add a post-quantum ciphersuite. This forfeits the benefit of
   the machine-checked symbolic analyses that exist for TreeKEM and for the
   external operations introduced in RFC 9420.
2. **Inject at a defined extension point.** MLS already accepts external
   pre-shared keys and mixes them into every epoch through its own key schedule.

Rotelyx takes the second option. No line of MLS is modified.

**What that does and does not buy.** Not modifying the protocol means the
existing analyses continue to apply to the parts that are unchanged, which is
the whole reason for choosing an extension point over a fork. It says nothing
about this composition. Whether feeding an X-Wing shared secret into the
pre-shared-key input yields an epoch secret that is post-quantum secure in the
formal sense is a separate question, it is the contribution this document
describes, and it requires its own analysis. A symbolic form of that analysis now
exists, in `formal/pq_mls_composition.pv`, and it is described in section 4.4 of
the paper. It gives an attacker the whole X25519 private key and the group
secret still holds; `formal/pq_both_broken.pv` breaks both halves and watches it
leak, which is what says the first model can express an attack at all.

A computational form followed, in `formal/xwing_combiner.cv`. Where the symbolic
model asks whether an attacker can derive the secret at all, this one asks
whether the combiner's output can be told apart from random, and answers with a
bound rather than a yes or no. The classical secret is handed over there too.

Constant-time behaviour is measured rather than modelled, in `security/ct/`,
and only for the mailbox tag comparison.

That is the composition and only the composition. The hardness of ML-KEM, the
interior of the MLS key schedule, the constant-time behaviour of the primitives
underneath, and whether this implementation matches the model it was abstracted
from are all outside it, and this document is still written to make a closer
reading possible rather than to stand in for one.

---

## 2. Notation

| Symbol | Meaning |
|---|---|
| `\|\|` | Concatenation |
| `be64(n)` | `n` encoded as a 64 bit big-endian unsigned integer, exactly 8 bytes |
| `len(x)` | Length of `x` in bytes |
| `BLAKE3_derive_key(ctx, m)` | BLAKE3 in key derivation mode with context string `ctx` and input `m` |
| `XOF(h, n)` | First `n` bytes of the extendable output of hash state `h` |

---

## 3. Inputs

| Input | Size | Origin |
|---|---|---|
| `ss` | 32 bytes | X-Wing shared secret, from encapsulation to the recipient's hybrid public key |
| `label` | variable | Fixed protocol constant, see section 4 |
| `group_id` | variable | The MLS group identifier |
| `epoch` | 8 bytes | The MLS epoch, as a 64 bit unsigned integer |

`ss` is produced by X-Wing (`draft-connolly-cfrg-xwing-kem`), which combines
ML-KEM-768 and X25519. Its security claim is that `ss` is secure if SHA3 is
secure **and** either X25519 **or** ML-KEM-768 is secure. This document assumes
`ss` and does not restate X-Wing.

---

## 4. Constants

```
PSK_CONTEXT = "rotelyx hybrid-pq psk v1"        (BLAKE3 derive_key context)
PSK_LABEL   = "rotelyx-pq-psk-v1"               (17 bytes, ASCII)
```

Both are versioned. A change to the construction takes new constants rather than
reusing these, so that an implementation of version 1 and an implementation of
version 2 cannot silently agree on a key.

---

## 5. The construction

### 5.1 Binding

```
binding = label || group_id || be64(epoch)
```

### 5.2 Derivation

```
psk = XOF(BLAKE3_derive_key(PSK_CONTEXT, ss || be64(len(binding)) || binding), 32)
```

The resulting 32 bytes are supplied to MLS as the secret for an external
pre-shared key, referenced by a `PreSharedKeyProposal` carried in a commit.

### 5.3 Reference implementation

```rust
pub fn psk_binding(label: &[u8], group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + group_id.len() + 8);
    out.extend_from_slice(label);
    out.extend_from_slice(group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

pub fn derive_psk(secret: &[u8; 32], binding: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PSK_CONTEXT);
    hasher.update(secret);
    hasher.update(&(binding.len() as u64).to_be_bytes());
    hasher.update(binding);

    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}
```

---

## 6. Why it is shaped this way

Each decision below removes a specific failure. They are stated separately so a
reviewer can attack them separately.

### 6.1 The binding is unambiguous despite a variable-length field

`binding` contains three fields and one of them, `group_id`, has no length
prefix. That is safe **only because the epoch is fixed at eight bytes and sits
last**.

Recovery works backwards: the final eight bytes are the epoch, the fixed-length
prefix is the label, and what remains between them is the group id. So if

```
label || A || be64(E)  ==  label || A' || be64(E')
```

then `be64(E) == be64(E')` because both occupy the same final eight bytes, hence
`E == E'` and therefore `A == A'`. No two distinct pairs collide.

**Placing `group_id` last would break this**, and the mistake would be invisible
in testing because collisions require adversarially chosen identifiers. The
property is pinned by `the_binding_is_unambiguous` in the test suite.

### 6.2 The binding is length-prefixed inside the hash

The hash input is `ss || be64(len(binding)) || binding`. Without the length
prefix, an implementation that later allowed a variable-length secret would
admit two different `(secret, binding)` splits producing the same byte stream.
`ss` is fixed at 32 bytes today, so this is defence against a future change
rather than a present flaw.

### 6.3 Domain separation is by BLAKE3 context, not by a prefix byte

`derive_key` mode incorporates the context string into the hash construction
itself rather than into the message. A value derived here cannot collide with
one derived under a different context even if an attacker controls the message.

Rotelyx uses three distinct contexts, and no two derive the same class of
material:

| Context | Purpose |
|---|---|
| `rotelyx hybrid-pq psk v1` | This construction |
| `rotelyx mailbox tag key v1` | Mailbox addressing, via the MLS exporter |
| `rotelyx safety-number v1` | Out of band verification digits |

### 6.4 Binding to the epoch is what prevents replay

Without the epoch, material captured from one epoch could be re-injected into
another. Because the epoch is inside the binding, a PSK derived for epoch `n`
does not verify at epoch `n+1`.

### 6.5 The binding never travels on the wire

Both the committer and every receiver derive `binding` independently from group
state they already share. Nothing about it is transmitted, so an attacker cannot
choose it.

---

## 7. What MLS does with the result

The derived `psk` is stored under a `PreSharedKeyId` whose external id **is the
binding**, and referenced by a `PreSharedKeyProposal` inside a commit. MLS then
mixes it into the epoch through its own unmodified key schedule.

Two properties follow from using the standard mechanism rather than a custom
one:

1. **Material refreshes per epoch** instead of being fixed at group creation.
2. **No member can inject a chosen PSK silently.** The proposal is part of the
   commit every member validates, which is the same property that makes a ghost
   member addition visible.

A receiving member must stage the secret locally before processing the commit.
If it has not, MLS cannot resolve the PSK and the commit **fails**. That failure
is asserted by a test, and it is what demonstrates the post-quantum layer is
load bearing rather than decorative.

---

## 8. Security claim, and its limits

**Claim.** If X-Wing's shared secret is indistinguishable from random, then the
derived pre-shared key is indistinguishable from random, and the resulting MLS
epoch secret is post-quantum secure in the sense that recovering it requires
breaking BLAKE3, or breaking the MLS key schedule, or recovering `ss`.

**This claim rests on:**

- X-Wing's own security argument, which is not restated here
- BLAKE3 in `derive_key` mode behaving as a random oracle
- MLS's key schedule incorporating pre-shared keys as RFC 9420 specifies

**It does not cover:**

- A compromised endpoint. Nothing in this document helps once an attacker can
  read memory on a participant's device
- Delivery of the X-Wing ciphertext, which is an application concern
- Whether the recipient's hybrid public key is authentic. That is established by
  the signed key package that carries it, and ultimately by out of band safety
  number comparison

---

## 9. Test vectors

Seven vectors are published in
[`crates/rotelyx-crypto/tests/pq-vectors.txt`](../crates/rotelyx-crypto/tests/pq-vectors.txt),
covering all-zero and all-one secrets, an empty group id, a 64 byte group id, the
maximum epoch, and a group id whose tail resembles an epoch.

They are verified against the implementation on every test run, so the file
cannot drift from the code.

To reproduce one by hand, compute:

```
binding = "rotelyx-pq-psk-v1" || group_id || be64(epoch)
psk     = BLAKE3_derive_key("rotelyx hybrid-pq psk v1",
                            secret || be64(len(binding)) || binding)[0..32]
```

The vector file lists `binding` alongside each case so an implementer can check
the two halves independently.

---

## 10. Review checklist

For a reviewer, the questions this construction should be attacked with:

- [ ] Can two distinct `(group_id, epoch)` pairs produce the same `binding`?
- [ ] Can an attacker influence `binding`, given it is never transmitted?
- [ ] Does the epoch binding actually prevent cross-epoch replay in MLS, or only
      in this derivation?
- [ ] Is `derive_key` context separation sufficient given the other two contexts
      Rotelyx uses?
- [ ] Does supplying a PSK via `PreSharedKeyProposal` interact with MLS's
      external commits in any way RFC 9420 does not anticipate?
- [ ] Is truncating BLAKE3's extendable output to 32 bytes appropriate for a PSK
      of the ciphersuite's hash length?

The last two are the ones we are least able to answer ourselves.

---

## References

1. Barnes, Beurdouche, Robert, Millican, Omara, Cohn-Gordon. *The Messaging
   Layer Security (MLS) Protocol.* RFC 9420, IETF, 2023.
2. Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan. *X-Wing: The
   Hybrid KEM You've Been Looking For.* IACR ePrint 2024/039.
3. Connolly, Schwabe, Westerbaan. *X-Wing: general-purpose hybrid post-quantum
   KEM.* draft-connolly-cfrg-xwing-kem-10, IETF, 2026.
4. O'Connor, Aumasson, Neves, Wilcox-O'Hearn. *BLAKE3: One Function, Fast
   Everywhere.* 2020.
