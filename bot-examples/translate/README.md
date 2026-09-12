<img src="icon.svg" width="48" height="48" alt="" align="left">

# Translate

Translates in the group, without the group leaving the group.

<br clear="all">

## Commands

```
/tr es I will be late
    /tr en llego tarde
    /auto es                  translate everything into Spanish from now on
    /auto off
```

## What it sees

Messages that mention it, and in `/auto` mode every message.

## What it needs

Needs a model on your own network: see `../llm.py`. Pointed at an online translator it would send every sentence out, which is why it does not offer that.

## Run it

```sh
rotelyx-cli --identity translate.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/translate/bot.py --identity translate.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
