#!/usr/bin/env python3
"""Keeps a group civil, and can put somebody out.

    /warn <who>             one strike; three and they are removed
    /kick <who>             remove now
    /strikes                who has how many
    /badwords a,b,c         words that earn a strike on their own

Removing a member is a commit every member sees, and it does not need a second
person: what takes two here is letting somebody in. If this bot is to be the
one who removes, name it under "Who can let people in" in the conversation as
well, and it can also confirm additions.

**This bot reads every message**, because that is what checking for words
means. Say so to the group, and prefer /warn by hand over the word list where
you can. A word list is the part most likely to be wrong.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "moderator"
LIMIT = 3


def main():
    bot = Bot.from_args(description=__doc__)
    state = load_state(NAME, {"strikes": {}, "badwords": []})

    def strike(who, why):
        n = state["strikes"].get(who, 0) + 1
        state["strikes"][who] = n
        save_state(NAME, state)
        if n >= LIMIT:
            bot.say(f"{who}: {why}. That is {n}, and {LIMIT} is the limit. Removing.")
            bot.remove(who)
            state["strikes"].pop(who, None)
            save_state(NAME, state)
        else:
            bot.say(f"{who}: {why}. Strike {n} of {LIMIT}.")

    for event in bot.events():
        # A button on one of this bot's own cards.
        if event.kind == "tap" and event.sender:
            cmd = (event.tapped or "").split()
            who = event.sender
            if cmd and cmd[0] == "/strikes":
                lines = [f"{m}: {n}" for m, n in state["strikes"].items()]
                bot.send_card("Strikes", "\n".join(lines) or "Nobody has a strike.",
                              [("The word list", "/badwords")])
            elif cmd and cmd[0] == "/badwords":
                bot.send_card(
                    f"{len(state['badwords'])} words on the list",
                    ", ".join(state["badwords"]) or "Nothing. Every message passes.",
                    [("Who has strikes", "/strikes")])
            continue

        if event.kind != "message" or not event.sender:
            continue
        text = event.text or ""
        who = event.sender

        # The word list, on every message, which is the part to be honest about.
        lowered = text.lower()
        hit = next((w for w in state["badwords"] if w and w in lowered), None)
        if hit and not bot.addressed(event):
            strike(who, f"that word is on the list")
            continue

        if not bot.addressed(event):
            continue
        cmd = bot.strip(event).split()
        if not cmd:
            continue
        if cmd[0] == "/warn" and len(cmd) > 1:
            strike(cmd[1], f"warned by {who}")
        elif cmd[0] == "/kick" and len(cmd) > 1:
            bot.say(f"{who} removes {cmd[1]}.")
            bot.remove(cmd[1])
        elif cmd[0] == "/strikes":
            lines = [f"{member}: {n}" for member, n in state["strikes"].items()]
            bot.send_card(
                "Strikes",
                "\n".join(lines) or "Nobody has a strike.",
                [("The word list", "/badwords")],
            )
        elif cmd[0] == "/badwords":
            if len(cmd) > 1:
                state["badwords"] = [
                    w.strip().lower() for w in " ".join(cmd[1:]).split(",") if w.strip()
                ]
                save_state(NAME, state)
            # What is on the list is said out loud, because a moderator that
            # watches every message should be answerable for what it watches
            # for.
            bot.send_card(
                f"{len(state['badwords'])} words on the list",
                ", ".join(state["badwords"]) or "Nothing. Every message passes.",
                [("Who has strikes", "/strikes")],
            )


if __name__ == "__main__":
    main()
