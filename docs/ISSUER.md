# The issuer, and what a client says to it

Buying capacity has three parties and the whole design is about keeping them
apart:

- the **client**, which wants a token,
- the **issuer**, which takes money and signs,
- the **mailbox**, which serves whoever holds a valid token.

The mailbox holds only public keys. The issuer holds the private halves and
never sees a mailbox. Neither is in a position to tell the other what it saw,
and this document is the contract that keeps it that way.

**The issuing service is not in this repository.** It needs a signing key, a
price, and a payment processor, none of which belong in a tree people are meant
to clone and run. What is here is the client's half, the verification, and this
contract between them.

---

## What the client already has

`rotelyx_capability::blind::Redeemer` in Rust and `TokenRequest` in the wasm
build both do RFC 9474 blind RSA:

    let (redeemer, blinded) = Redeemer::begin(&public_der)?;   // blind a fresh id
    //  ... send `blinded` to the issuer with the money ...
    let token = redeemer.finish(&public_der, &blind_signature)?;

The only missing piece was ever how those two lines reach a server. That is all
this document adds.

---

## `GET /tiers`

What is for sale, and the keys to blind against.

    200 OK
    content-type: application/json

    {
      "tiers": [
        {
          "name": "plus",
          "key": "<base64url, no padding, the RSA public key in DER>",
          "price": { "amount": 400, "currency": "USD" },
          "period_days": 30
        },
        {
          "name": "plus++",
          "key": "...",
          "price": { "amount": 1500, "currency": "USD" },
          "period_days": 30
        }
      ]
    }

`amount` is in the currency's smallest unit, as an integer. Never a float: a
price is not a quantity to do arithmetic on and 4.00 is not representable.

**`name` is advisory and `key` is authoritative.** Which tier a token grants is
decided by **which key signed it** and never by anything the client or the
issuer writes in a field. A blind issuer cannot read what it signs, so a tier
carried as data would be a tier the buyer chooses rather than one they pay for.
The mailbox is configured with one public key per tier and learns the tier from
which one verifies.

A client that does not recognise a `name` may still show the price and buy it.
It will not know what it bought until the mailbox tells it, which is correct:
the mailbox is the authority on what a tier means.

---

## `POST /issue`

    content-type: application/json

    {
      "tier": "plus",
      "blinded": "<base64url, no padding, from Redeemer::begin>",
      "payment": "<processor reference for a completed payment>"
    }

    200 OK
    { "signature": "<base64url, no padding, the blind signature>" }

`tier` selects which key signs. It is not carried into the token and the client
cannot lie its way into a better one: asking for `plus++` while paying for
`plus` is a payment check the issuer makes, and if it passes, the wrong key
signs and the mailbox grants what that key means.

Errors are a status and a reason the client can act on:

| Status | Meaning |
|---|---|
| 400 | `blinded` is not a well formed blinded message for that tier's key |
| 402 | the payment is not complete, or does not cover this tier |
| 409 | this payment reference has already been redeemed |
| 429 | too many requests from this caller |
| 503 | the issuer cannot sign right now, and the payment stands |

409 matters more than it looks. A payment reference must sign **exactly one**
blinded message, or a buyer who repeats the request gets a second token for one
payment, and there is no way to detect it afterwards: the two tokens are
unlinkable by construction, which is the property being paid for.

---

## What the issuer must not keep

The blind signature means the issuer cannot recognise the token it signed. That
holds only if it does not keep the things around it:

- **Not the blinded message beside the payment.** Together they are a record
  that a particular buyer's request produced a particular signature, and the
  unlinkability is then a promise rather than a property.
- **Not the client's address beside the payment**, for the same reason a
  mailbox does not keep one.
- The payment reference has to be kept, because 409 depends on it. Keep the
  reference and whether it was used, and nothing else.

---

## The residual nobody should discover later

**Blind signing does not defeat timing.**

The issuer knows a payment completed at a moment. The mailbox knows a token was
first presented at a moment. If those two records are ever brought together, and
purchases are rare, the pair narrows to a small set and sometimes to one. The
cryptography is intact throughout: nothing in the token gives it away, and the
correlation is entirely in the clocks.

What reduces it is nothing clever: **more buyers, and a delay between buying and
first use that the buyer chooses.** A client should be able to hold a token
rather than redeem it the moment it arrives, and should say so, because a buyer
who redeems immediately has decided something without being told they were
deciding.

What does **not** reduce it is anything the issuer can do alone, which is why it
belongs in this contract rather than in the issuer's own documentation. It is
recorded in `docs/THREAT-MODEL.md` under ADV-4.

---

## The boundary, stated once

The issuer talks to the payment processor and to clients. **It does not talk to
a mailbox, and no mailbox talks to it.** A mailbox is configured with public
keys, out of band, by its operator.

That is what makes the split worth having. An issuer that could ask a mailbox
"has this token been used" would be holding both halves, and every property
above would depend on it choosing not to.
