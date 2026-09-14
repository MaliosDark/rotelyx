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
rotelyx --identity bot.key meet --host --name Polls --picture icon.png --bot
```

That prints a meeting code and a link. Open the link on a phone and the phone
is in a conversation with the bot: the bot is the first row on the list, with
the picture it was given, and it answers there. The code is what the phone
client itself hands out when it invites somebody, so a bot can also read one
the phone showed:

```
rotelyx --identity bot.key meet <code or link> --name Polls --bot
```

Either way the conversation is written down beside the identity, and running
`meet` again with no code carries it on. This is the mailbox transport, the
one the phone speaks: a bot on it is reachable by a phone that is asleep, and
by the browser client, and by another copy of this program.

There is a second transport, the direct one, that `listen` and `connect` speak:

```
rotelyx --identity bot.key invite --hours 24 --through https://relay.example
rotelyx --identity bot.key listen --bot --relay https://relay.example
rotelyx --identity bot.key connect <code> --bot --relay https://relay.example
```

It is what two copies of this program use between themselves, and it carries
calls. No phone dials it. Ten bots were written and tested on it before
anybody noticed that nothing a person carries in their pocket could add one;
the events and instructions below are the same on both, so a bot moves from
one to the other with a flag.

`examples/echo-bot.py` is a working one in about eighty lines, most of them
comments. `bot-examples/` holds twelve ready to run, the ones people ask for on
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
| `roster` | `members` | everybody here, by label, in answer to `members` |
| `proposed` | `by`, `who` | somebody asked to let `who` in; answer with `confirm` or `dismiss` (mailbox only) |
| `code` | `code`, `link` | where this bot is waiting, for a phone to open (`meet --host` only) |
| `call_started` | `kbit_per_second`, `mono` | a call is running |
| `call_ended` | frame and timing counts | a call stopped |
| `refused` | `problem` | an instruction was not carried out |
| `closed` | `reason` | the session is over |

Instructions in, switched on `do`:

| `do` | fields | what it does |
| --- | --- | --- |
| `send` | `text` | send application data to the conversation |
| `members` | | ask for the roster again |
| `remove` | `who` | put a member out, by label |
| `confirm` | | agree to the addition somebody proposed |
| `dismiss` | | forget that proposal; the newcomer keeps waiting |
| `call` | | ring the conversation and open the audio when somebody answers (mailbox only) |
| `hangup` | | stop talking; the conversation stays |
| `quit` | | leave |

A bot that calls needs `--relay`, because a call never takes a direct path, and
`--room auto` for a conversation of more than two, because a group call meets in
the relay's room. A bot with no sound card speaks and hears through files:
`ROTELYX_CALL_FEED` names the file its microphone reads (a FIFO, 32 bit float
mono at 48 kHz), `ROTELYX_CALL_DEAF=1` says there is no speaker, and
`ROTELYX_CALL_DUMP` writes what it would have played. `bot-examples/town`
does exactly this for forty people at once; see `docs/CODEC.md` for what is
measured with it.

Variants are added over time. Switch on the key and ignore what you do not
know, rather than matching exhaustively and breaking on an upgrade.

## Sending a picture or a file

A file travels as an ordinary message whose text is shaped for the phone to
recognise: the unit separator (`\x01`), `rx-file`, the separator, the name
percent-encoded, the separator, the media type percent-encoded, the separator,
and the bytes as base64. `Bot.send_file(name, mime, data)` in
`bot-examples/rotelyx_bot.py` builds it. A picture (`image/jpeg`, `image/png`,
`image/gif`) is drawn in the conversation; anything else is offered as a file.
The free tier's envelope is 64 KiB and the bytes travel as base64 inside it,
so keep a picture under about 44 KiB: shrink and re-encode before sending.

**Say something with it in the same message.** `send_file(name, mime, data,
caption="what this is")` adds a fifth part after the bytes: the separator and
the caption, percent-encoded. It arrives as one message, one bubble and one
notification, with the line under the picture.

Send the picture and then the sentence and you have made two messages that can
arrive in either order, and on a busy group they will sometimes arrive in the
wrong one. A build that has never heard of captions reads the first three
fields and ignores the rest, so nothing older breaks on one.

## Buttons

`Bot.send_card(title, text, buttons)` sends a message with buttons under it, up
to six. Each button is `(label, command)`: the label is what a person sees and
the command is what your bot is told when it is pressed, which nobody sees.

    bot.send_card("Where do we eat?", "Pick one.",
                  [("Pizza", "/vote 1"), ("Ramen", "/vote 2")])

A press arrives as an event of kind `tap`, with `event.tapped` carrying the
command and `event.sender` carrying who pressed it. It is an ordinary control
message in the conversation, sealed like everything else, so nothing is called
back to anywhere and no service is involved: the press goes into the group and
your bot, being a member, reads it.

Use the same words your typed commands use, as `polls/` does. A person on a
build too old to draw buttons sees the title and the text and types the command;
the two paths then stay one path.

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

**A bot is asked like anybody else, and what it answers is policy.** When a
member proposes an addition, every other member gets `proposed` and any of
them can `confirm`. The bots in `bot-examples/` agree when the proposer is
the person who brought the bot in, and refuse everybody else. Said plainly:
that person and their bot are two hands, so a person who runs a bot can let
people in on their own. The group can see the bot is there, can see who let
each person in, and can remove the bot, which is what keeps this honest. A
bot that agreed with anybody would make the rule decoration; one that agreed
with nobody would make a two-member conversation unable to grow.

**The group keeps talking while it decides.** The library underneath refuses
to encrypt a message while a proposal is waiting, at the proposer and at every
member who heard it, so from the moment somebody asked until somebody agreed
nobody could say a word, and the note saying who was asking and where they
waited never went out. Rotelyx sets Add proposals aside for the length of one
message and puts them back. Nothing else is ever set aside: a removal is
committed on the spot, so there is never a pending Remove for a message to
slip past.

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
