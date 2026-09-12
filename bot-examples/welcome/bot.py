#!/usr/bin/env python3
"""Greets whoever arrives, and keeps the rules where they can be asked for.

    /rules                  say the rules
    /setrules <text>        change them (anybody in the group)

The bot watches for the `joined` event, which in this conversation means an
addition two members agreed to. It is the one event with a security meaning,
so it is also logged. Local; nothing is fetched.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "welcome"
DEFAULT = "Be kind. Ask before adding anybody. What is said here stays here."


def main():
    bot = Bot.from_args(description=__doc__)
    rules = load_state(NAME, DEFAULT)

    for event in bot.events():
        if event.kind == "joined" and event.who:
            bot.say(f"Welcome, {event.who}. The rules here: {rules}")
            continue
        if event.kind != "message" or not bot.addressed(event):
            continue
        text = bot.strip(event)
        if text.startswith("/setrules "):
            rules = text[10:].strip()
            save_state(NAME, rules)
            bot.say("Rules updated: " + rules)
        elif text.startswith("/rules"):
            bot.say(rules)


if __name__ == "__main__":
    main()
