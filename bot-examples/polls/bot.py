#!/usr/bin/env python3
"""Polls, since the conversation has none of its own.

    /poll Where do we eat? | Pizza | Ramen | Tacos
    /vote 2
    /results
    /close

One poll open at a time, which is how groups actually use them. A vote is one
per member and can be changed. The bot sees who voted what, which every poll
bot everywhere does; here it is said out loud.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "polls"


def show(bot, poll):
    counts = {}
    for choice in poll["votes"].values():
        counts[choice] = counts.get(choice, 0) + 1
    lines = [poll["question"]]
    for i, option in enumerate(poll["options"], 1):
        n = counts.get(i, 0)
        lines.append(f"  {i}. {option}  {'#' * n} {n}")
    bot.say("\n".join(lines))


def main():
    bot = Bot.from_args(description=__doc__)
    poll = load_state(NAME, None)

    for event in bot.events():
        if event.kind != "message" or not bot.addressed(event):
            continue
        text = bot.strip(event)
        who = event.sender or "?"

        if text.startswith("/poll "):
            parts = [p.strip() for p in text[6:].split("|")]
            if len(parts) < 3:
                bot.say("A poll is a question and at least two options: /poll Question? | A | B")
                continue
            poll = {"question": parts[0], "options": parts[1:], "votes": {}}
            save_state(NAME, poll)
            show(bot, poll)
            bot.say("Vote with /vote <number>.")
        elif text.startswith("/vote"):
            if not poll:
                bot.say("No poll is open. Start one with /poll.")
                continue
            try:
                choice = int(text.split()[1])
                assert 1 <= choice <= len(poll["options"])
            except (IndexError, ValueError, AssertionError):
                bot.say(f"Pick a number from 1 to {len(poll['options'])}.")
                continue
            poll["votes"][who] = choice
            save_state(NAME, poll)
            bot.say(f"{who} voted.")
        elif text.startswith("/results"):
            if poll:
                show(bot, poll)
            else:
                bot.say("No poll is open.")
        elif text.startswith("/close"):
            if poll:
                show(bot, poll)
                bot.say("Closed.")
                poll = None
                save_state(NAME, None)


if __name__ == "__main__":
    main()
