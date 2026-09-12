<img src="icon.svg" width="48" height="48" alt="" align="left">

# Expenses

Who owes whom, for flats, trips and dinners.

<br clear="all">

## Commands

```
/paid 42.50 groceries            you paid, split among everybody here
    /paid 30 taxi for ana beto       you paid, split among the named people
    /owes                            the balance, netted
    /settle                          wipe it, once everybody has paid up
```

## What it sees

Only messages that mention it or start with `/`. Nothing leaves the group; no account anywhere.


## Run it

```sh
rotelyx-cli --identity expenses.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/expenses/bot.py --identity expenses.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
