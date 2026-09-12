#!/usr/bin/env python3
"""An assistant in the conversation, thinking on a machine you control.

    @<bot> what is the capital of Mongolia
    @<bot> summarise what we decided
    /forget                     drop what it remembers of this conversation

It answers when spoken to and stays quiet otherwise. It keeps the last few
exchanges so a follow up makes sense, and only those: there is no transcript
on any server, and what it does hold is a file on its own machine.

The model is whatever `llm.py` points at. On your own network, this is the
sentence on the website made real: a channel that neither the platform nor
the model provider can read. Point it at a cloud API and that sentence stops
being true, so do not.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot  # noqa: E402
import llm  # noqa: E402

SYSTEM = (
    "You are a helpful assistant inside a private group conversation. Answer "
    "briefly and plainly. You only see messages that mention you. Never claim "
    "to have read anything you were not shown."
)
KEEP = 12


def main():
    ap = Bot.parser(__doc__)
    ap.add_argument("--name", default="the assistant", help="how it introduces itself")
    ap.add_argument("--persona", default="", help="extra instructions for the model")
    args = ap.parse_args()
    bot = Bot.from_args(args)

    if not llm.reachable():
        bot.log(f"no model answers at {llm.URL}. Set ROTELYX_LLM_URL, or start one.")

    history = []
    system = SYSTEM + (" " + args.persona if args.persona else "")

    for event in bot.events():
        if event.kind == "ready":
            bot.say(f"{args.name} is here. Mention @{bot.me} to ask something.")
            continue
        if event.kind != "message" or not bot.addressed(event):
            continue
        text = bot.strip(event)
        if text.startswith("/forget"):
            history.clear()
            bot.say("Forgotten.")
            continue
        who = event.sender or "somebody"
        history.append({"role": "user", "content": f"{who}: {text}"})
        history[:] = history[-KEEP:]
        try:
            answer = llm.chat([{"role": "system", "content": system}, *history])
        except Exception as e:  # noqa: BLE001
            bot.say(f"The model did not answer: {e}")
            continue
        history.append({"role": "assistant", "content": answer})
        bot.say(answer)


if __name__ == "__main__":
    main()
