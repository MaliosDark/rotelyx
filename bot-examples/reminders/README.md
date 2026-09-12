<img src="icon.svg" width="48" height="48" alt="" align="left">

# Reminders

Say when, and it says so then.

<br clear="all">

## Commands

```
/remind in 10m call the landlord
    /remind at 18:30 pick up the kids
    /remind tomorrow 9:00 send the invoice
    /reminders                      what is pending
```

## What it sees

Only messages that mention it or start with `/`. Keeps its reminders in a file on its own machine.


## Run it

```sh
rotelyx-cli --identity reminders.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/reminders/bot.py --identity reminders.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
