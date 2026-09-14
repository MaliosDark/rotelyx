#!/usr/bin/env python3
"""Who owes whom. For flats, trips and dinners.

    /paid 42.50 groceries            you paid, split among everybody here
    /paid 30 taxi for ana beto       you paid, split among the named people
    /owes                            the balance, netted
    /settle                          wipe it, once everybody has paid up

Every amount stays in the conversation and in a file on the bot's machine.
There is no account anywhere, no company in the middle, and nothing to sync.
This is the clearest case for a bot that tells nobody anything.
"""

import re
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "expenses"


def balances(entries):
    """Net position per person: positive is owed, negative owes."""
    net = {}
    for e in entries:
        share = e["amount"] / len(e["among"])
        net[e["by"]] = net.get(e["by"], 0) + e["amount"]
        for p in e["among"]:
            net[p] = net.get(p, 0) - share
    return net


def main():
    bot = Bot.from_args(description=__doc__)
    entries = load_state(NAME, [])
    people = set()

    for event in bot.events():
        if event.kind == "message" and event.sender:
            people.add(event.sender)
        if event.kind == "tap":
            text = event.tapped or ""
        elif event.kind == "message" and bot.addressed(event):
            text = bot.strip(event)
        else:
            continue
        who = event.sender or "?"

        m = re.match(r"/paid\s+([\d.]+)\s*(.*)", text)
        if m:
            amount = float(m.group(1))
            rest = m.group(2)
            among = None
            fm = re.search(r"\bfor\s+(.+)$", rest)
            if fm:
                among = fm.group(1).split()
                rest = rest[: fm.start()].strip()
            if not among:
                among = sorted(people | {who})
            entries.append({"by": who, "amount": amount, "what": rest or "?", "among": among})
            save_state(NAME, entries)
            bot.send_card(
                f"{who} paid {amount:.2f}",
                f"For {rest or 'something'}, split among {', '.join(among)}.",
                [("The balance", "/owes"), ("Settle up", "/settle")],
            )
        elif text.startswith("/owes"):
            net = balances(entries)
            if not net:
                bot.say("Nobody owes anything.")
                continue
            lines = []
            for p, v in sorted(net.items(), key=lambda kv: kv[1]):
                if abs(v) < 0.005:
                    continue
                lines.append(f"{p} {'is owed' if v > 0 else 'owes'} {abs(v):.2f}")
            bot.send_card("Who owes whom", "\n".join(lines) or "All square.",
                          [("Settle up", "/settle")])
        elif text.startswith("/settle"):
            entries = []
            save_state(NAME, entries)
            bot.say("Settled. Starting from zero.")


if __name__ == "__main__":
    main()
