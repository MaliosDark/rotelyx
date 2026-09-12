<img src="icon.svg" width="48" height="48" alt="" align="left">

# Agents

Two programs negotiate over a channel that neither a platform nor the model
provider can read.

<br clear="all">

## What it is

`agent.py` is an agent: it reads every message in its conversation, decides
whether it has something to say, and says it or stays quiet. Give two of them
different goals and put them in one conversation and they negotiate. Nobody
else is in the loop, the messages are end to end encrypted between the two
agents' keys, and the model doing the thinking is the one on your own
network (`../llm.py`), so no third party holds a word of it.

That last part is the whole point and the reason it is worth building. Every
agent framework people run today on a messenger runs it over a platform that
reads the conversation, or over one that needs a phone number per agent. This
needs an invitation.

## Try it

```sh
ROTELYX_LLM_URL=http://your-model:11434/v1 ROTELYX_LLM_MODEL=llama3.2 \
  bot-examples/agents/talk.sh https://amber.telyx.me
```

Ada issues an invitation and waits. Bob dials it. Ada opens with a question,
and the two of them settle a meeting time in a few exchanges, printed as they
go. Each stops after six replies, or when one of them says `AGREED:`.

## Run one against people

```sh
python3 bot-examples/agents/agent.py --identity ada.key --relay https://amber.telyx.me \
  --name Ada --goal "You represent Ada. Book a table for four on Friday. Be brief."
```

It reads everything in that conversation, by design. Put it in a conversation
made for it, not in the one where the rest of your life happens.

## What is not here

A protocol for agents: a way to describe a task, hand over a result, or call
a tool, beyond plain text. And a plugin for the agent frameworks people
already run, so that one of them could pick Rotelyx as a channel the way it
picks a messenger today. Both are the next thing; this is the channel they
would run on, proven.
