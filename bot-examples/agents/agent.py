#!/usr/bin/env python3
"""An agent that talks to whoever is in the conversation, people or agents.

    python3 agents/agent.py --identity a.key --relay ... --name Ada \
        --goal "You are negotiating a meeting time. You are free Tuesday and Thursday afternoons." \
        --opens "Hello. When are you free this week?"

Unlike `assistant/`, this one does not wait to be mentioned: it reads every
message, decides whether it has something to say, and says it or stays quiet.
That is what an agent is, and it is also why it should only be put in a
conversation made for it.

Two of these in one conversation, with different goals, is two agents
negotiating over a channel that neither a platform nor a model provider can
read. `agents/talk.sh` sets that up. The model is whatever `llm.py` points at,
on your own network, which is the only arrangement under which the sentence
above is true.

The turn taking is the simplest that works: an agent answers a message from
somebody else, never its own, and stops after `--turns` exchanges so two
agents do not talk until the sun goes down.
"""

import sys
import time

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot  # noqa: E402
import llm  # noqa: E402

KEEP = 20


def main():
    ap = Bot.parser(__doc__)
    ap.add_argument("--name", required=True)
    ap.add_argument("--goal", required=True, help="what this agent is trying to do")
    ap.add_argument("--opens", help="what it says first, if it speaks first")
    ap.add_argument("--turns", type=int, default=6, help="how many replies before it stops")
    args = ap.parse_args()
    bot = Bot.from_args(args)

    system = (
        f"You are {args.name}, an agent in a private conversation. {args.goal} "
        "Reply in one or two short sentences. When the matter is settled, say "
        "'AGREED:' followed by the outcome, and nothing after that."
    )
    history = []
    replies = 0

    for event in bot.events():
        if event.kind == "ready":
            if args.opens:
                time.sleep(1.5)  # let the other side seat itself first
                bot.say(f"{args.name}: {args.opens}")
                bot.log(f"{args.name}: {args.opens}")
                history.append({"role": "assistant", "content": args.opens})
            continue
        if event.kind != "message" or not event.text:
            continue
        if event.text.startswith(f"{args.name}:"):
            continue  # its own line, echoed back by the group
        if replies >= args.turns:
            continue

        bot.log(f"  heard: {event.text}")
        history.append({"role": "user", "content": event.text})
        history[:] = history[-KEEP:]
        try:
            answer = llm.chat([{"role": "system", "content": system}, *history], temperature=0.6)
        except Exception as e:  # noqa: BLE001
            bot.log(f"model: {e}")
            continue
        history.append({"role": "assistant", "content": answer})
        bot.say(f"{args.name}: {answer}")
        bot.log(f"{args.name}: {answer}")
        replies += 1
        if "AGREED:" in answer:
            bot.log("settled; leaving")
            time.sleep(1)
            bot.quit()
            break


if __name__ == "__main__":
    main()
