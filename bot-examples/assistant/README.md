<img src="icon.svg" width="48" height="48" alt="" align="left">

# Assistant

An assistant in the conversation, thinking on a machine you control.

<br clear="all">

## Commands

```
@<bot> what is the capital of Mongolia
    @<bot> summarise what we decided
    /forget                     drop what it remembers of this conversation
```

## What it sees

Only messages that mention it. Keeps the last dozen exchanges in memory, nothing on disk.

## What it needs

Needs a model on your own network: see `../llm.py`. On a cloud API the conversation is no longer private, so do not.

## Run it

```sh
rotelyx-cli --identity assistant.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/assistant/bot.py --identity assistant.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
