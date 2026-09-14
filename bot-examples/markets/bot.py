#!/usr/bin/env python3
"""Prices and alerts for a group that watches markets.

    /price btc                  what one is worth now, with buttons
    /price btc eth sol          several at once
    /alert btc > 70000          tell the group when it crosses
    /alert eth < 2000
    /alerts                     what is being watched
    /forget 2                   stop watching one
    /top                        the largest few, by market value

Every answer is a card with buttons, so checking again is a tap.

# What this reaches, and what it tells it

One price source, chosen by whoever runs the bot: `--source`, a URL that
answers the same shape CoinGecko's public API does. It is asked for prices and
nothing else. It learns that somebody, somewhere, asked about a coin, and the
address of the machine this bot runs on -- never the conversation, never who
asked, and never anything about the group, because the bot is the only thing
that talks to it.

That is the honest trade, and it is why this is an example rather than a
feature of the application: a messenger that fetched prices itself would be a
messenger telling a company when its users are awake. Run this on a machine you
are happy to have asking.

# The other half of what a trader wants

Wallet watching is deliberately not here. It needs an address, and an address
in a conversation is an identifier for whoever pasted it: the one thing this
project spends its whole design avoiding. If you want it, run it against your
own node and keep the addresses on the machine, not in the group.
"""

import json
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "markets"

#: How often the watches are checked, in seconds. A market moves; a bot that
#: checks every second is a bot that gets itself rate limited and tells the
#: group nothing.
EVERY = 60

#: What people type, and what the source calls it. Short names only: a group
#: says "btc", and a bot that demands "bitcoin" is a bot people stop using.
NAMES = {
    "btc": "bitcoin",
    "xbt": "bitcoin",
    "eth": "ethereum",
    "sol": "solana",
    "bnb": "binancecoin",
    "xrp": "ripple",
    "ada": "cardano",
    "doge": "dogecoin",
    "dot": "polkadot",
    "matic": "matic-network",
    "avax": "avalanche-2",
    "link": "chainlink",
    "ltc": "litecoin",
    "atom": "cosmos",
    "arb": "arbitrum",
    "op": "optimism",
    "ton": "the-open-network",
    "trx": "tron",
    "usdt": "tether",
    "usdc": "usd-coin",
}


def coin(word: str) -> str:
    """What the source calls what somebody typed."""
    word = word.strip().lower().lstrip("$")
    return NAMES.get(word, word)


def shown(name: str) -> str:
    """What to call it back. The short name when there is one."""
    for short, long in NAMES.items():
        if long == name:
            return short.upper()
    return name.upper()


def money(value: float) -> str:
    if value >= 1000:
        return f"${value:,.0f}"
    if value >= 1:
        return f"${value:,.2f}"
    return f"${value:.6f}".rstrip("0")


class Source:
    """The price source, with a short memory.

    The memory is not a nicety. A group asking the same question four times in
    a minute is one question to the source, which is the difference between a
    bot that keeps working and a bot that is refused.
    """

    def __init__(self, url: str, currency: str = "usd"):
        self.url = url.rstrip("/")
        self.currency = currency
        self._held: dict[str, tuple[float, dict]] = {}

    def prices(self, coins: list[str]) -> dict:
        """`{coin: {"price": float, "change": float}}` for what is known."""
        now = time.time()
        want = [c for c in coins if now - self._held.get(c, (0, {}))[0] > 45]
        if want:
            query = urllib.parse.urlencode({
                "ids": ",".join(sorted(set(want))),
                "vs_currencies": self.currency,
                "include_24hr_change": "true",
            })
            try:
                request = urllib.request.Request(
                    f"{self.url}/simple/price?{query}",
                    headers={"Accept": "application/json", "User-Agent": "rotelyx-markets"},
                )
                with urllib.request.urlopen(request, timeout=12) as response:
                    fresh = json.load(response)
            except Exception as e:  # noqa: BLE001
                # A source that is down is not a reason to stop: whatever is
                # still in memory is answered with, and the next turn tries
                # again.
                print(f"[markets] source: {e}", file=sys.stderr)
                fresh = {}
            for name, row in fresh.items():
                self._held[name] = (now, {
                    "price": float(row.get(self.currency) or 0),
                    "change": float(row.get(f"{self.currency}_24h_change") or 0),
                })

        return {c: held[1] for c in coins if (held := self._held.get(c))}

    def top(self, how_many: int = 8) -> list[dict]:
        query = urllib.parse.urlencode({
            "vs_currency": self.currency,
            "order": "market_cap_desc",
            "per_page": how_many,
            "page": 1,
            "price_change_percentage": "24h",
        })
        try:
            request = urllib.request.Request(
                f"{self.url}/coins/markets?{query}",
                headers={"Accept": "application/json", "User-Agent": "rotelyx-markets"},
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                return json.load(response)
        except Exception as e:  # noqa: BLE001
            print(f"[markets] source: {e}", file=sys.stderr)
            return []


def price_card(bot, source: Source, coins: list[str]) -> None:
    """What they are worth, as a card whose buttons ask again."""
    rows = source.prices(coins)
    if not rows:
        bot.say("The price source did not answer. Try again in a moment.")
        return

    lines = []
    for name in coins:
        row = rows.get(name)
        if not row:
            lines.append(f"{shown(name)}  not found")
            continue
        arrow = "▲" if row["change"] >= 0 else "▼"
        lines.append(f"{shown(name)}  {money(row['price'])}   {arrow} {abs(row['change']):.1f}% today")

    buttons = [("Again", "/price " + " ".join(shown(c) for c in coins))]
    if len(coins) == 1:
        # Somewhere to go from here, which is what a card is for.
        buttons.append(("Alert me", f"/alert {shown(coins[0])} > {rows[coins[0]]['price']:.0f}"))
    buttons.append(("Top 8", "/top"))

    bot.send_card("Prices", "\n".join(lines), buttons)


def main():
    parser = Bot.parser(description=__doc__)
    parser.add_argument(
        "--source",
        default="https://api.coingecko.com/api/v3",
        help="the price API, answering the shape CoinGecko's public one does",
    )
    parser.add_argument("--currency", default="usd", help="what to price in")
    args = parser.parse_args()

    bot = Bot.from_args(args, description=__doc__)
    source = Source(args.source, args.currency)
    watches = load_state(NAME, [])
    checked = 0.0

    for event in bot.events():
        # The watches, whenever anything happens and at most once a minute.
        # A bot with nothing to do is a bot that is not being spoken to, and
        # the client sends a keepalive through here regularly enough that this
        # is a check every minute rather than a thread and a lock.
        if watches and time.time() - checked > EVERY:
            checked = time.time()
            rows = source.prices([w["coin"] for w in watches])
            left = []
            for watch in watches:
                row = rows.get(watch["coin"])
                if not row:
                    left.append(watch)
                    continue
                price = row["price"]
                crossed = (
                    price >= watch["at"] if watch["over"] else price <= watch["at"]
                )
                if crossed:
                    way = "above" if watch["over"] else "below"
                    bot.send_card(
                        f"{shown(watch['coin'])} is {way} {money(watch['at'])}",
                        f"{money(price)} now, asked for by {watch['who']}.",
                        [("Again", f"/price {shown(watch['coin'])}"),
                         ("Watch it again", f"/alert {shown(watch['coin'])} "
                                            f"{'>' if watch['over'] else '<'} {watch['at']:.0f}")],
                    )
                else:
                    left.append(watch)
            if len(left) != len(watches):
                watches = left
                save_state(NAME, watches)

        if event.kind == "tap":
            text = event.tapped or ""
            who = event.sender or "?"
        elif event.kind == "message" and bot.addressed(event):
            text = bot.strip(event)
            who = event.sender or "?"
        else:
            continue

        if text.startswith("/price"):
            words = text.split()[1:]
            if not words:
                bot.say("Which one? /price btc")
                continue
            price_card(bot, source, [coin(w) for w in words[:6]])

        elif text.startswith("/alert"):
            words = text.split()
            if len(words) < 4 or words[2] not in ("<", ">"):
                bot.say("Say it like this: /alert btc > 70000")
                continue
            try:
                at = float(words[3].replace(",", "").lstrip("$"))
            except ValueError:
                bot.say("That price is not a number.")
                continue
            watches.append({
                "coin": coin(words[1]),
                "over": words[2] == ">",
                "at": at,
                "who": who,
            })
            save_state(NAME, watches)
            bot.send_card(
                "Watching",
                f"{shown(coin(words[1]))} {words[2]} {money(at)}. "
                f"The group is told once, when it crosses.",
                [("What is watched", "/alerts"), ("Price now", f"/price {words[1]}")],
            )

        elif text.startswith("/alerts"):
            if not watches:
                bot.say("Nothing is being watched. /alert btc > 70000")
                continue
            lines = [
                f"{i}. {shown(w['coin'])} {'>' if w['over'] else '<'} {money(w['at'])}  ({w['who']})"
                for i, w in enumerate(watches, 1)
            ]
            bot.send_card("Watching", "\n".join(lines),
                          [("Prices", "/price " + " ".join(
                              shown(w["coin"]) for w in watches[:4]))])

        elif text.startswith("/forget"):
            words = text.split()
            try:
                which = int(words[1]) - 1
                gone = watches.pop(which)
            except (IndexError, ValueError):
                bot.say("Which one? /alerts shows the numbers.")
                continue
            save_state(NAME, watches)
            bot.say(f"Stopped watching {shown(gone['coin'])}.")

        elif text.startswith("/top"):
            rows = source.top()
            if not rows:
                bot.say("The price source did not answer.")
                continue
            lines = []
            for row in rows:
                change = row.get("price_change_percentage_24h") or 0
                arrow = "▲" if change >= 0 else "▼"
                lines.append(
                    f"{(row.get('symbol') or '').upper():<5} "
                    f"{money(float(row.get('current_price') or 0)):>12}  "
                    f"{arrow} {abs(change):.1f}%")
            bot.send_card("By market value", "\n".join(lines),
                          [("Again", "/top"), ("BTC", "/price btc"),
                           ("ETH", "/price eth")])


if __name__ == "__main__":
    main()
