#!/usr/bin/env python3
"""When can we all make it.

    /free mon 10-12, tue 15-18        say when you can
    /when                             the slots everybody can make
    /reset                            start over

Local. Nothing is fetched and nothing is sent anywhere but the conversation.
"""

import re
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "schedule"
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def parse(spec):
    """`mon 10-12, tue 15-18` -> {(day, hour)}."""
    slots = set()
    for part in spec.split(","):
        m = re.match(r"\s*(\w{3})\w*\s+(\d{1,2})\s*-\s*(\d{1,2})", part)
        if not m or m.group(1).lower() not in DAYS:
            continue
        day = m.group(1).lower()
        for h in range(int(m.group(2)), int(m.group(3))):
            slots.add(f"{day} {h:02d}")
    return slots


def main():
    bot = Bot.from_args(description=__doc__)
    free = {k: set(v) for k, v in load_state(NAME, {}).items()}

    for event in bot.events():
        if event.kind != "message" or not bot.addressed(event):
            continue
        text = bot.strip(event)
        who = event.sender or "?"

        if text.startswith("/free"):
            slots = parse(text[5:])
            if not slots:
                bot.say("Say it like: /free mon 10-12, tue 15-18")
                continue
            free[who] = slots
            save_state(NAME, {k: sorted(v) for k, v in free.items()})
            bot.say(f"Got {who}: {len(slots)} hours. {len(free)} of you have answered.")
        elif text.startswith("/when"):
            if not free:
                bot.say("Nobody has said when they are free. /free mon 10-12")
                continue
            common = set.intersection(*free.values())
            if not common:
                bot.say(f"No hour suits all {len(free)}. Try wider.")
                continue
            ordered = sorted(common, key=lambda s: (DAYS.index(s[:3]), s[4:]))
            bot.say("Everybody can make: " + ", ".join(f"{s}:00" for s in ordered[:8]))
        elif text.startswith("/reset"):
            free = {}
            save_state(NAME, {})
            bot.say("Cleared.")


if __name__ == "__main__":
    main()
