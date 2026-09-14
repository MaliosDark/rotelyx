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
            # A card, so the two things a newcomer wants next are a tap away
            # rather than a command they have to be told about.
            bot.send_card(
                f"Welcome, {event.who}",
                rules,
                [("The rules again", "/rules"), ("Who is here", "/who")],
            )
            continue

        if event.kind == "tap":
            text = event.tapped or ""
        elif event.kind == "message" and bot.addressed(event):
            text = bot.strip(event)
        else:
            continue

        if text.startswith("/setrules "):
            rules = text[10:].strip()
            save_state(NAME, rules)
            bot.send_card("Rules updated", rules, [("Show them", "/rules")])
        elif text.startswith("/rules"):
            bot.send_card("The rules here", rules,
                          [("Who is here", "/who")])
        elif text.startswith("/who"):
            # What this bot actually knows: how many members the conversation
            # has. Names belong to the people who chose them, and a bot
            # listing them is a bot making a directory.
            bot.say(f"{bot.members} in this conversation, this bot included.")


if __name__ == "__main__":
    main()
