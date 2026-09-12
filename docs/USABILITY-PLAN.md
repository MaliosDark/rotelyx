# Five things, and the order to build them in

Rotelyx is correct and it is not yet the easiest of its kind to live with. This
is the list of what would change that, the order to do it in, and what each one
costs, so that the work survives being put down and picked up again.

Written as a plan rather than as a wish because four of the five are weeks of
work each and none of them fits in a sitting. A list of good ideas that nobody
sequenced is how a project ends up with five half-built ones.

---

## How other applications are referred to here

**By what they do, not by their name.** "A competitor", "the nearest
competitor", "those platforms". A document that names them dates quickly, reads
as a pitch rather than as engineering, and invites a correction about a product
that has moved on since. What is being compared is a design decision, and a
design decision can be described without naming who made it.

This applies to every document in this repository, not only to this one.

---

## The rule that shapes every phase

**Each phase leaves the tree shippable**, with the existing behaviour unchanged
and the existing tests green, and **no phase trades away what this project is
for**. The blind mailbox, the absence of identifiers and the refusal to let a
server learn who talks to whom are not features to be balanced against
convenience. Where a convenience needs one of them, it is written down as
refused, with the reason, rather than quietly taken.

---

## 1. Several devices for one person

**The largest thing missing, and the one nobody comparable does well.**

A person is one leaf of the MLS tree today, so their conversation lives on one
phone. Every other messenger of this kind either gives up and syncs through a
server, or copies the session to the second device and hopes.

Copying is the shape that has already cost this project: `Conversation::reopen`
assumes the worst *because* a copied blob is indistinguishable from a restored
one, and the rekey that assumption demands is what left two phones at two epochs
that neither could leave. See §5b of the threat model.

**MLS already answers this.** A person is a set of leaves rather than a leaf.
Each device has its own key material, is added by a commit the group can see, and
can be removed the same way. Two devices stop being two clones racing each other
and become two members that were always meant to be there.

So this is not only the biggest usability win. It **dissolves** the remaining
epoch hazard by construction rather than making it rarer, which is all the work
so far has done.

**What it costs.** The roster stops being a list of people and becomes a list of
people who have devices, everywhere it is read: the safety number, the
membership changes a commit makes visible, the fanout, the interface that says
who is in a conversation. Adding a device has to be an act somebody performs
deliberately, on both devices, and has to be visible to everybody in every
conversation, because a device added quietly is exactly the ghost-member attack
this protocol makes visible on purpose.

**Where it can be abandoned.** After the crypto layer can hold several leaves per
person and the tests say so, with no application calling it. That leaves the tree
exactly as it is today.

**Done when** a message sent from the phone appears on the desktop, both were
added by a commit the other side saw, and removing one from the other stops it
receiving.

---

## 2. Joining a group without the founder awake

Pairing needs the host listening at the meeting place. For two people arranging
it between themselves that is tolerable. For a group it is the thing that makes
people give up: whoever invites has to be online at the moment the newcomer
arrives, and a newcomer who arrives at the wrong time waits forever with nothing
on screen.

The mailbox can hold a knock without understanding it, which it already does for
messages. What is missing is the part where somebody who is not the founder can
answer it, and the part where an answer can wait.

**What it must not become.** A join that anybody who has the link can perform
unseen. Admission stays an act a member takes, and it stays visible in a commit.

---

## 3. Handing over history, with consent, in the open

A competitor gives a newcomer the history because its server has it. This one
cannot and should not: forward secrecy means nobody keeps the material to
rebuild a conversation, which is a promise and not a gap.

What is possible, and what nobody comparable offers: **a member chooses to hand
their copy over**, explicitly, and **the whole group is told it happened**. The
history that arrives is one person's copy with their name on it, not a fact the
group asserts.

The reason to build it is that people do this anyway by screenshot, badly and
invisibly. The reason it is third rather than first is that it is worth nothing
until 2 has made groups bearable to join.

---

## 4. An interface for bots and agents

A competitor's bot API is the reason a great deal of software talks to it at
all. `rotelyx-cli` already does most of what such an interface needs; what it
lacks is being addressed as an interface rather than as a tool somebody types
at.

**What makes this one different here.** A bot on those platforms is a token held
by a server that reads messages in the clear. A participant here is a member of
the
conversation like any other: it holds keys, it appears in the roster, and the
people in the conversation can see it is there and remove it. That is a better
answer than the one being copied, and it is the only one this architecture
allows, so it should be said plainly rather than presented as a limitation.

It also answers something asked separately: agents talking to each other, and to
people, over a channel neither a platform nor a model provider can read.

**What it must not become.** A hosted bot service, a directory of bots, or
anything that needs a name somebody registers. All three reintroduce the
identifier this project does not have.

**Built.** `--bot` on `listen` and `connect`, one JSON object per line each
way, with everything meant for a person moved to stderr so the stream stays
parseable. `docs/BOTS.md` has the interface, `examples/echo-bot.py` is a
working bot, and `scripts/bot-test` runs two processes through a relay on every
change. Calls were left out: a bot on a call needs an audio device and a sender
index, and neither belongs on a line of JSON.

---

## 5. Saying what the group layer already does better

Not code. The nearest competitor builds a group as a mesh of one-to-one
connections, so the work of changing a key grows with the number of members.
This uses MLS, where it grows with the logarithm of it. That is a real
advantage, it is already built, and it is currently buried in `ARCHITECTURE.md`
where nobody comparing two applications will find it.

Written last because a claim is worth making after the four things above have
made the product worth choosing for other reasons too.

---

## What is deliberately not on this list

**A shared tag per group.** One deposit instead of one per member, and it would
make large groups cheap. It is refused: that tag *is* the group. An operator
would see one address that a hundred devices collect from and would learn the
group's size and rhythm without reading a word, having previously been unable to
tell the group existed at all. The fanout is what buys that blindness, and the
answer to its cost is to spread it in time, not to remove it.

**Anything that needs an account, a directory or a name a server resolves.** See
§4 of the threat model.
