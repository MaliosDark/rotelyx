"""The thirty lines every Rotelyx bot has in common.

A bot here is a member of the conversation. It runs the same client everybody
else runs, told to speak JSON: one object per line on stdout, one per line on
stdin. This module is the reading and the writing of those lines, so that a bot
is only the part that is different about it.

What a bot sees is everything said in the conversation it is in, because that
is what being a member means. Say so in your bot's README. The one exception
is a bot built to receive nothing, which does not need this module at all: see
`alerts/`.

Usage, in full:

    from rotelyx_bot import Bot

    bot = Bot.from_args()
    for event in bot.events():
        if event.kind == "message" and bot.addressed(event):
            bot.say(f"you said: {bot.strip(event)}")
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterator, Optional


@dataclass
class Event:
    """One line the client printed, with the fields a bot reads most."""

    kind: str
    raw: dict

    @property
    def text(self) -> Optional[str]:
        return self.raw.get("text")

    @property
    def sender(self) -> Optional[str]:
        """The label the author joined under, or None when unattributed.

        None is not "nobody in particular": treat it as unknown. It happens for
        a message the group could not attribute to a member.
        """
        return self.raw.get("from")

    @property
    def who(self) -> Optional[str]:
        """Who joined or left, on those events."""
        return self.raw.get("who")


class Bot:
    def __init__(self, argv: list[str], *, quiet: bool = False):
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.me: Optional[str] = None
        self.members: int = 0
        self.quiet = quiet

    @staticmethod
    def parser(description: str) -> argparse.ArgumentParser:
        """The flags every bot takes, so they all take the same ones."""
        ap = argparse.ArgumentParser(description=description)
        ap.add_argument("--identity", required=True, help="the bot's key file")
        ap.add_argument("--relay", required=True, help="the relay it dials through")
        ap.add_argument("--connect", help="an invitation code, to dial instead of wait")
        ap.add_argument("--rotelyx", default=os.environ.get("ROTELYX", "rotelyx-cli"))
        return ap

    @classmethod
    def from_args(cls, args=None, *, description: str = "a Rotelyx bot") -> "Bot":
        if args is None:
            args = cls.parser(description).parse_args()
        argv = [args.rotelyx, "--identity", args.identity]
        argv += ["connect", args.connect] if args.connect else ["listen"]
        argv += ["--relay", args.relay, "--bot"]
        return cls(argv)

    # ---- reading ---------------------------------------------------------

    def events(self) -> Iterator[Event]:
        """Every event until the session ends. `ready` and `members` are
        folded into `self.me` and `self.members` before being yielded."""
        for line in self._proc.stdout:
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                # Nothing on this stream is supposed to be anything else, so
                # this is a client newer than this module, not noise.
                self.log(f"not JSON: {line!r}")
                continue
            kind = raw.get("event", "")
            if kind == "ready":
                self.me = raw.get("me")
                self.members = raw.get("members", 0)
            elif kind == "members":
                self.members = raw.get("count", 0)
            elif kind in ("joined", "left", "refused", "closed"):
                # Worth a line in the log rather than silence. A membership
                # change is the one event with a security meaning.
                self.log(f"{kind}: {raw.get('who') or raw.get('problem') or raw.get('reason', '')}")
            yield Event(kind, raw)
            if kind == "closed":
                break

    def addressed(self, event: Event) -> bool:
        """Whether a message speaks to this bot: it mentions the bot's label
        or starts with `/`. Bots that answer everything are the wrong bot."""
        text = event.text or ""
        if text.startswith("/"):
            return True
        return bool(self.me) and f"@{self.me}" in text

    def strip(self, event: Event) -> str:
        """The message without the mention or the leading slash command."""
        text = (event.text or "").strip()
        if self.me:
            text = text.replace(f"@{self.me}", "").strip()
        return text

    # ---- writing ---------------------------------------------------------

    def _do(self, instruction: dict) -> None:
        self._proc.stdin.write(json.dumps(instruction) + "\n")
        self._proc.stdin.flush()

    def say(self, text: str) -> None:
        """Send to everybody in the conversation."""
        self._do({"do": "send", "text": text})

    def remove(self, who: str) -> None:
        """Put a member out. Every member sees the change."""
        self._do({"do": "remove", "who": who})

    def ask_members(self) -> None:
        self._do({"do": "members"})

    def quit(self) -> None:
        self._do({"do": "quit"})

    def log(self, line: str) -> None:
        if not self.quiet:
            print(line, file=sys.stderr, flush=True)


def store_path(name: str) -> str:
    """Where a bot keeps what it has to remember, beside its identity.

    A JSON file per bot. It is on the machine the bot runs on and nowhere
    else, which is the whole point, and it is worth knowing it is there.
    """
    base = os.environ.get("ROTELYX_BOT_STATE", os.path.expanduser("~/.local/state/rotelyx-bots"))
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"{name}.json")


def load_state(name: str, default):
    try:
        with open(store_path(name)) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_state(name: str, state) -> None:
    tmp = store_path(name) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, store_path(name))
