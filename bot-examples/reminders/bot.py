#!/usr/bin/env python3
"""Reminders. Say when, and it says so then.

    /remind in 10m call the landlord
    /remind at 18:30 pick up the kids
    /remind tomorrow 9:00 send the invoice
    /reminders                      what is pending

Nothing leaves the conversation. The reminders live in a file beside the
bot's identity on the machine it runs on, and the bot needs no network but
the relay.
"""

import datetime as dt
import re
import sys
import threading

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "reminders"

def parse_when(words: str, now: dt.datetime):
    """`in 10m`, `in 2h`, `at 18:30`, `tomorrow 9:00`. Returns (when, rest)."""
    m = re.match(r"in (\d+)\s*(m|min|h|d)\b\s*(.*)", words, re.I)
    if m:
        n, unit, rest = int(m.group(1)), m.group(2).lower()[0], m.group(3)
        delta = {"m": dt.timedelta(minutes=n), "h": dt.timedelta(hours=n), "d": dt.timedelta(days=n)}[unit]
        return now + delta, rest
    m = re.match(r"(tomorrow\s+)?(?:at\s+)?(\d{1,2}):(\d{2})\s*(.*)", words, re.I)
    if m:
        when = now.replace(hour=int(m.group(2)), minute=int(m.group(3)), second=0, microsecond=0)
        if m.group(1) or when <= now:
            when += dt.timedelta(days=1)
        return when, m.group(4)
    return None, words


def main():
    bot = Bot.from_args(description=__doc__)
    pending = load_state(NAME, [])
    lock = threading.Lock()

    def tick():
        now = dt.datetime.now().timestamp()
        with lock:
            due = [r for r in pending if r["at"] <= now]
            for r in due:
                bot.say(f"Reminder for {r['for']}: {r['what']}")
                pending.remove(r)
            if due:
                save_state(NAME, pending)
        threading.Timer(15, tick).start()

    tick()

    for event in bot.events():
        if event.kind != "message" or not bot.addressed(event):
            continue
        text = bot.strip(event)
        who = event.sender or "somebody"

        if text.startswith("/reminders"):
            with lock:
                if not pending:
                    bot.say("Nothing pending.")
                for r in sorted(pending, key=lambda r: r["at"]):
                    when = dt.datetime.fromtimestamp(r["at"]).strftime("%a %H:%M")
                    bot.say(f"{when}: {r['what']} (for {r['for']})")
            continue

        if text.startswith("/remind"):
            when, what = parse_when(text[len("/remind"):].strip(), dt.datetime.now())
            if when is None or not what:
                bot.say("Say when: /remind in 10m ..., /remind at 18:30 ..., /remind tomorrow 9:00 ...")
                continue
            with lock:
                pending.append({"at": when.timestamp(), "what": what, "for": who})
                save_state(NAME, pending)
            bot.say(f"Noted. {when.strftime('%a %H:%M')}: {what}")


if __name__ == "__main__":
    main()
