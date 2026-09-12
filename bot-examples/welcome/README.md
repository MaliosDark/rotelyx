<img src="icon.svg" width="48" height="48" alt="" align="left">

# Welcome

Greets whoever arrives and keeps the rules.

<br clear="all">

## Commands

```
/rules                  say the rules
    /setrules <text>        change them (anybody in the group)
```

## What it sees

The `joined` event, and messages that mention it or start with `/`.


## Run it

```sh
rotelyx-cli --identity welcome.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/welcome/bot.py --identity welcome.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
