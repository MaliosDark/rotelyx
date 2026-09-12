# Bots and agents

A bot here is a member of the conversation. It holds its own keys, it sits in
the roster, it moves the safety number when it arrives, and anybody in the
conversation can see it is there and withdraw its invitation.

That is not a design preference. There is no server that can read the
conversation on a bot's behalf, so there is nothing for a token to authorise
and nowhere to host one. What exists instead is the same client everybody else
runs, speaking JSON.

## Starting one

```
rotelyx --identity bot.key invite --hours 24 --through https://relay.example
rotelyx --identity bot.key listen --bot --relay https://relay.example
```

The first command prints a code. Hand it to whoever should be able to reach the
bot, over a channel you trust. The second answers it.

A bot can also dial:

```
rotelyx --identity bot.key connect <code> --bot --relay https://relay.example
```

`examples/echo-bot.py` is a working one in about eighty lines, most of them
comments. `bot-examples/` holds ten ready to run, the ones people ask for on
every messenger (reminders, polls, expenses, moderation, alerts, an
assistant, and so on), each with a README that says what it sees, and a pair
of agents that negotiate with each other over a channel neither a platform
nor the model provider can read.

## The interface

One JSON object per line on stdout, one per line on stdin. Nothing else is on
stdout: everything a session would otherwise say to a person goes to stderr in
this mode, so a line-delimited parser never has to skip anything.

Events out, switched on `event`:

| `event` | fields | what it is |
| --- | --- | --- |
| `ready` | `members`, `epoch` | the session is up |
| `safety` | `peer`, `number` | the digits that say nobody is in the middle |
| `message` | `from`, `text` or `base64` | application data from a member |
| `joined` | `who` | somebody was added |
| `left` | `who` | somebody was removed |
| `members` | `count` | the size after a change |
| `call_started` | `kbit_per_second`, `mono` | a call is running |
| `call_ended` | frame and timing counts | a call stopped |
| `refused` | `problem` | an instruction was not carried out |
| `closed` | `reason` | the session is over |

Instructions in, switched on `do`:

| `do` | fields | what it does |
| --- | --- | --- |
| `send` | `text` | send application data to the conversation |
| `members` | | ask for the roster again |
| `quit` | | leave |

Variants are added over time. Switch on the key and ignore what you do not
know, rather than matching exhaustively and breaking on an upgrade.

## Three things worth getting right

**Check the safety number.** A bot that never looks at the `safety` event can
be talked to by whoever answered the address, which is the single thing end to
end encryption exists to prevent. Compare it against what you were told out of
band and refuse to work if it differs. A person does this by reading digits
aloud; a bot has it easier, because it can simply have the expected value in
its configuration.

**`text` is not always there.** It is absent when the payload is not UTF-8, and
`base64` is there instead. `from` is absent when MLS could not attribute the
message to a leaf, which a bot should treat as unattributed rather than as
anybody in particular.

**A line that is not an instruction is never sent.** If a bot crashes and
prints a stack trace to stdout, that stack trace is refused, not encrypted and
delivered. This is why `--bot` is a mode rather than a parser layered on top of
the human one, and it is worth keeping in mind when extending either side.

## Who can put one in

A bot gets into a conversation the way anybody does, which means it cannot be
slipped in quietly and it cannot be put there by one person.

**Admitting anybody takes two members.** One asks and a different one turns the
request into a commit. Every member refuses a commit that admits somebody on
the authority of whoever sent it, and the check runs on the receiving side: a
sender that has decided to break the rule is not asking permission, so a client
that only refused to build such a commit would be checking the one party that
has already chosen.

**A group can narrow who decides.** Name the members allowed to let people in
and only they can turn a request into a member. Anybody can still ask, which is
what a request to join looks like from inside a group. The list lives in the
group's own state rather than in a message, so every member at an epoch holds
the same one and changing it is a commit everybody sees.

**Two exemptions, and only two.** A conversation with one member admitting its
first is first contact, where the second pair of eyes would have to belong to
somebody who has not arrived. And somebody adding another device of their own
admits nobody: they are already in the room.

None of this is a rule about bots, and it could not be. "Is a bot" is not a
property anything can check: a program joins with the same kind of key package
a person does, and one written to evade a rule would not declare itself. The
rule is about additions and it applies to every addition, which is the only
version of it that is worth anything.

## What this will not become

No hosted bot service, no directory of bots, no name anybody registers. All
three would reintroduce the global identifier this project does not have: a bot
you can find by name is a bot whose users can be enumerated. A bot is reached
the way a person is, by an invitation somebody chose to hand over, and it is
unreachable by anybody who was not given one.

Calls are out of scope for now. A bot on a call needs an audio device and a
sender index, and neither belongs on a line of JSON.

## Agents talking to each other

Two programs can hold the same conversation with no person in it. That is the
same machinery, and it answers something asked more often lately: a channel
between agents that neither a platform nor a model provider can read, where
membership is visible to everybody in it and removal is a commit rather than a
support ticket.

`scripts/bot-test` is exactly that, run on every change: two processes, neither
of them a person, exchanging a message through a relay that cannot read it.
