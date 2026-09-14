<img src="icon.svg" width="48" height="48" alt="" align="left">

# Markets

Prices and alerts, for a group that watches them. Every answer is a card with
buttons, so asking again is a tap.

<br clear="all">

## Commands

```
/price btc                  what one is worth now
/price btc eth sol          several at once
/alert btc > 70000          tell the group when it crosses
/alert eth < 2000
/alerts                     what is being watched
/forget 2                   stop watching one
/top                        the largest few, by market value
```

## What it reaches, and what it tells it

One price source, chosen by whoever runs the bot (`--source`, default
CoinGecko's public API). The bot asks it for prices and nothing else.

That source learns two things: that somebody asked about a coin, and the
address of the machine this bot runs on. It never learns the conversation, who
asked, how many people are in the group, or anything else about it, because the
bot is the only thing that speaks to it and the bot tells it nothing but a list
of coin names.

This is why it is an example rather than a feature of the application. A
messenger that fetched prices itself would be a messenger telling a company when
its users are awake and what they hold. Run this on a machine you are happy to
have asking, and say so to the group.

Watches live in a file beside the bot, not in the conversation.

## What is deliberately missing

**Wallet watching.** It needs an address, and an address pasted into a
conversation is a permanent identifier for whoever pasted it, tied to every
transaction it ever makes. That is the exact thing the rest of this project is
built to avoid, and a bot is not the place to hand it back. If you want it, run
it against your own node, keep the addresses on that machine, and have the bot
say only "something moved".

## Run it

```sh
python3 bot-examples/markets/bot.py --identity markets.key --name Markets
```

It prints a meeting code and a link. Open the link on a phone to add it to a
conversation, and remember that letting anybody in takes two members agreeing.

With a source of your own:

```sh
python3 bot-examples/markets/bot.py --identity markets.key \
    --source https://your-own-proxy/api/v3 --currency eur
```

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
