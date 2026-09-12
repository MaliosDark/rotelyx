# Bots, ready to run

Ten bots people ask for on every messenger, written for this one, and a pair
of agents that talk to each other. Each is a Python file with no dependencies
beyond the standard library and the Rotelyx client, and each has a README
saying what it does, what it sees, and how to run it.

A bot here is a member of the conversation. It holds its own keys, it shows in
the list beside the people, and anybody in the conversation can throw it out.
There is no token and no server of ours that reads anything on its behalf.
What that means for each bot is in its **What it sees** section, and the
honest summary is in the last column below. Read [`docs/BOTS.md`](../docs/BOTS.md)
first.

| | Bot | What it does | Needs | What it sees |
|---|---|---|---|---|
| <img src="reminders/icon.svg" width="28"> | [Reminders](reminders/) | `/remind in 10m ...` | nothing | only when spoken to |
| <img src="polls/icon.svg" width="28"> | [Polls](polls/) | `/poll Q? \| A \| B`, `/vote 2` | nothing | only when spoken to |
| <img src="expenses/icon.svg" width="28"> | [Expenses](expenses/) | `/paid 30 taxi`, `/owes` | nothing | only when spoken to |
| <img src="schedule/icon.svg" width="28"> | [Schedule](schedule/) | `/free mon 10-12`, `/when` | nothing | only when spoken to |
| <img src="welcome/icon.svg" width="28"> | [Welcome](welcome/) | greets arrivals, `/rules` | nothing | arrivals, and when spoken to |
| <img src="moderator/icon.svg" width="28"> | [Moderator](moderator/) | `/warn`, `/kick`, word list | nothing | **everything** |
| <img src="alerts/icon.svg" width="28"> | [Alerts](alerts/) | posts when a feed or page changes | the feeds | **nothing at all** |
| <img src="translate/icon.svg" width="28"> | [Translate](translate/) | `/tr es ...`, `/auto es` | a model on your network | when spoken to, or everything in `/auto` |
| <img src="assistant/icon.svg" width="28"> | [Assistant](assistant/) | `@bot ...` | a model on your network | only when spoken to |
| <img src="search/icon.svg" width="28"> | [Search](search/) | `/search word`, `/ask ...` | a model on your network | **everything, and keeps it** |
| <img src="agents/icon.svg" width="28"> | [Agents](agents/) | two agents negotiate, no person in the loop | a model on your network | everything in their own conversation |

## Running one

```sh
rotelyx-cli --identity polls.key invite --hours 24
python3 bot-examples/polls/bot.py --identity polls.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation. Letting anybody in takes two members agreeing, and the
bot is no exception.

## The model

Three bots think, and `agents/` thinks twice. They do it through
[`llm.py`](llm.py), which speaks the OpenAI-shaped chat API to whatever
`ROTELYX_LLM_URL` names, with `ROTELYX_LLM_KEY` from the environment and never
from a file. The default is the LiteLLM on this network.

**Where the model runs decides whether the conversation is still private.** A
model on a machine you control keeps it end to end encrypted in the plain
sense: nobody outside the group ever holds a message. A model behind a cloud
API means every message you hand it leaves the group, whatever the terms say.
Every bot that thinks says this in its README, and none of them offers the
cloud.

## Testing them

```sh
bot-examples/test.sh
ROTELYX_LLM_KEY=... bot-examples/agents/talk.sh
```

The first drives the six bots that need no model through a real relay, with
a program playing the person, and fails if any answers wrongly. The second
puts two agents in a conversation and prints what they say to each other.

## Writing your own

Copy the shortest one (`welcome/`, forty lines) and change what it does with
an event. [`rotelyx_bot.py`](rotelyx_bot.py) is the reading and writing of
JSON lines so that a bot is only the part that is different about it. Two
things it makes easy to get right: `bot.addressed(event)` so a bot answers
when spoken to and not otherwise, and `load_state`/`save_state` so what a bot
remembers is a file on its own machine that you can see.

Say in your README what your bot sees. It is the one thing the people adding
it cannot tell from the outside.
