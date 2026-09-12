<img src="icon.svg" width="48" height="48" alt="" align="left">

# Polls

The conversation has none of its own.

<br clear="all">

## Commands

```
/poll Where do we eat? | Pizza | Ramen | Tacos
    /vote 2
    /results
    /close
```

## What it sees

Only messages that mention it or start with `/`. It sees who voted what, as every poll bot does.


## Run it

```sh
rotelyx-cli --identity polls.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/polls/bot.py --identity polls.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
