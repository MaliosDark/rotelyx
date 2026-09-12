#!/usr/bin/env python3
"""A bot that is a member of the conversation.

Run it against an identity you have already made:

    rotelyx --identity bot.key invite --hours 24      # give the code to a person
    python3 examples/echo-bot.py --identity bot.key   # then run this

It holds its own keys, appears in the roster like anybody else, and the people
talking to it can see it is there and withdraw its invitation. There is no
token, no webhook, and nowhere for this to run except on a machine you control:
the conversation is end to end encrypted and a server that could read it for
you does not exist.

The interface is one JSON object per line in each direction. That is all of it.
Everything below is Python for reading lines and writing lines.
"""

import argparse
import json
import subprocess
import sys


def run(rotelyx, identity, connect=None, relay=None):
    """Start a member and hand back the process."""
    argv = [rotelyx, "--identity", identity]
    argv += ["connect", connect] if connect else ["listen"]
    if relay:
        argv += ["--relay", relay]
    argv += ["--bot"]
    return subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
    )


def say(member, text):
    """Send application data to everybody in the conversation."""
    member.stdin.write(json.dumps({"do": "send", "text": text}) + "\n")
    member.stdin.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--identity", required=True)
    ap.add_argument("--rotelyx", default="rotelyx")
    ap.add_argument("--connect", help="an invitation code, to dial instead of wait")
    ap.add_argument("--relay", help="route through this relay")
    args = ap.parse_args()

    member = run(args.rotelyx, args.identity, args.connect, args.relay)

    for line in member.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            # Nothing on that stream is supposed to be anything else, so this
            # is a version of rotelyx newer than this script rather than noise
            # to route around.
            print(f"not JSON: {line!r}", file=sys.stderr)
            continue

        kind = event.get("event")

        if kind == "ready":
            print(f"in, {event['members']} members at epoch {event['epoch']}", file=sys.stderr)

        elif kind == "message":
            # `text` is absent when what arrived was not UTF-8, and `from` is
            # absent when MLS could not attribute it to a member. Neither is an
            # error, and both are worth handling before answering a stranger.
            text = event.get("text")
            if text is None:
                continue
            who = event.get("from", "somebody")
            print(f"{who}: {text}", file=sys.stderr)
            say(member, f"you said: {text}")

        elif kind in ("joined", "left"):
            # Worth printing rather than ignoring. A membership change is the
            # one event that carries a security meaning: somebody arriving in
            # the conversation without being mentioned is the thing a person is
            # supposed to notice.
            print(f"{kind}: {event['who']}", file=sys.stderr)

        elif kind == "refused":
            print(f"refused: {event['problem']}", file=sys.stderr)

        elif kind == "closed":
            print(f"closed: {event['reason']}", file=sys.stderr)
            break

    return member.wait()


if __name__ == "__main__":
    raise SystemExit(main())
