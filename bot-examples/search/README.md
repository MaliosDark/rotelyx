<img src="icon.svg" width="48" height="48" alt="" align="left">

# Search

Search the conversation. Read the warning first.

<br clear="all">

## Commands

```
/search invoice            lines containing the word
    /ask what did we decide about the venue      the model answers from the log
    /wipe                      delete everything it has kept
```

## What it sees

**Every message, and it keeps a copy of each.** It is the archive. Run it on your own machine, tell the group, and `/wipe` it when done.

## What it needs

`/ask` needs a model on your own network: see `../llm.py`.

## Run it

```sh
rotelyx-cli --identity search.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/search/bot.py --identity search.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
