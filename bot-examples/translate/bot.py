#!/usr/bin/env python3
"""Translates in the group, without the group leaving the group.

    /tr es I will be late
    /tr en llego tarde
    /auto es                  translate everything into Spanish from now on
    /auto off

Translation runs on the model `llm.py` points at, on your own network. The
same bot pointed at an online translator would send every sentence out, which
is why this one does not offer that. In /auto mode it reads every message,
because that is what translating everything means; say so to the group.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot  # noqa: E402
import llm  # noqa: E402


def translate(text: str, into: str) -> str:
    return llm.chat([
        {"role": "system", "content": f"Translate the user's message into {into}. Reply with the translation only, nothing else."},
        {"role": "user", "content": text},
    ], temperature=0.1, max_tokens=300)


def main():
    bot = Bot.from_args(description=__doc__)
    auto = None

    for event in bot.events():
        if event.kind != "message" or not event.text:
            continue
        text = bot.strip(event) if bot.addressed(event) else event.text

        if bot.addressed(event) and text.startswith("/auto"):
            arg = text[5:].strip()
            auto = None if arg in ("", "off") else arg
            bot.say(f"Translating everything into {auto}." if auto else "Auto translation off.")
            continue
        if bot.addressed(event) and text.startswith("/tr "):
            parts = text[4:].split(None, 1)
            if len(parts) < 2:
                bot.say("Say the language and the text: /tr es I will be late")
                continue
            try:
                bot.say(translate(parts[1], parts[0]))
            except Exception as e:  # noqa: BLE001
                bot.say(f"The model did not answer: {e}")
            continue
        if auto and not bot.addressed(event) and event.sender != bot.me:
            try:
                bot.say(f"[{auto}] {translate(event.text, auto)}")
            except Exception as e:  # noqa: BLE001
                bot.log(str(e))


if __name__ == "__main__":
    main()
