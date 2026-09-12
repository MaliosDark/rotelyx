<img src="icon.svg" width="48" height="48" alt="" align="left">

# Schedule

When can we all make it.

<br clear="all">

## Commands

```
/free mon 10-12, tue 15-18        say when you can
    /when                             the slots everybody can make
    /reset                            start over
```

## What it sees

Only messages that mention it or start with `/`.


## Run it

```sh
rotelyx-cli --identity schedule.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/schedule/bot.py --identity schedule.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
