<img src="icon.svg" width="48" height="48" alt="" align="left">

# Alerts

Tells the group when something out there changes.

<br clear="all">

## Commands

```
python3 alerts/bot.py --identity alerts.key --relay https://amber.telyx.me \
        --watch https://github.com/MaliosDark/rotelyx/releases.atom \
        --watch https://status.example.com/feed.xml \
        --every 300
```

## What it sees

**Nothing.** It only speaks. The ideal shape for a bot.

## What it needs

Needs the internet, for the feeds it watches. Only the feed URLs go out.

## Run it

```sh
rotelyx-cli --identity alerts.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/alerts/bot.py --identity alerts.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
