#!/usr/bin/env python3
"""Search the conversation. Read this before running it.

    /search invoice            lines containing the word
    /ask what did we decide about the venue      the model answers from the log
    /wipe                      delete everything it has kept

**This bot keeps a copy of every message it sees**, on its own machine, for
as long as it runs and after. That is what searching means and there is no
version of it that does not. Every other bot in this folder keeps at most a
few lines; this one is the archive, and an archive on a machine you do not
control is the thing this whole application exists to avoid. Run it on your
own machine, tell the group it is there, and /wipe it when it is done.

/ask hands the matching lines to the model in `llm.py`, on your own network.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402
import llm  # noqa: E402

NAME = "search"
KEEP = 5000


def main():
    bot = Bot.from_args(description=__doc__)
    log = load_state(NAME, [])

    for event in bot.events():
        if event.kind == "ready":
            bot.say(f"Search is here and keeps a copy of what is said, on its own machine. "
                    f"/search <word>, /ask <question>, /wipe to delete it.")
            continue
        if event.kind != "message" or not event.text or event.sender == bot.me:
            continue

        if bot.addressed(event):
            text = bot.strip(event)
            if text.startswith("/wipe"):
                log = []
                save_state(NAME, log)
                bot.say("Wiped. Nothing kept.")
            elif text.startswith("/search "):
                needle = text[8:].strip().lower()
                hits = [l for l in log if needle in l["text"].lower()][-8:]
                bot.say("\n".join(f"{l['from']}: {l['text']}" for l in hits) or "Nothing.")
            elif text.startswith("/ask "):
                question = text[5:].strip()
                words = [w for w in question.lower().split() if len(w) > 3]
                hits = [l for l in log if any(w in l["text"].lower() for w in words)][-40:]
                context = "\n".join(f"{l['from']}: {l['text']}" for l in hits) or "(nothing relevant)"
                try:
                    bot.say(llm.chat([
                        {"role": "system", "content": "Answer the question using only the conversation excerpt. If it is not there, say so."},
                        {"role": "user", "content": f"Excerpt:\n{context}\n\nQuestion: {question}"},
                    ]))
                except Exception as e:  # noqa: BLE001
                    bot.say(f"The model did not answer: {e}")
            continue

        log.append({"from": event.sender or "?", "text": event.text})
        log = log[-KEEP:]
        save_state(NAME, log)


if __name__ == "__main__":
    main()
