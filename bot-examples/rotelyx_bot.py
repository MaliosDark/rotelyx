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

Two transports, one bot. Started with `--relay`, the bot waits on the direct
transport, which another copy of the client dials and no phone does. Started
with nothing, it shows a meeting code and a link, which a phone opens; with
`--meet`, it opens a code a phone showed. Either way the events are the same.

One thing only the phone's transport has: letting a third person in takes two
members agreeing. When somebody proposes an addition the bot is asked, and by
default it agrees when the proposer is the person who brought it in, and to
nobody else. See `Bot.admits`.
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

    @property
    def tapped(self) -> Optional[str]:
        """The command behind a button somebody pressed, on a `tap` event.

        It is this bot's own word, from the card it sent: see
        `Bot.send_card`. Never anything the phone chose.
        """
        return self.raw.get("command")


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
        # Everybody here, by label, as of the last `roster` event. Ask with
        # `ask_members()`; it also arrives after every membership change.
        self.roster: list[str] = []
        self.quiet = quiet
        # The first person the bot met: whoever opened its code, or whose code
        # it opened. On the phone's transport that is who may bring others in
        # through it.
        self.owner: Optional[str] = None
        # Whether to agree when somebody proposes letting a newcomer in.
        # Called with the `proposed` event; True confirms. The default agrees
        # with the owner and nobody else. A bot with its own idea of who
        # decides (a moderator with admins, say) replaces it.
        self.admits = lambda event: (
            event.raw.get("by") is not None and event.raw.get("by") == self.owner
        )

    @staticmethod
    def parser(description: str) -> argparse.ArgumentParser:
        """The flags every bot takes, so they all take the same ones."""
        ap = argparse.ArgumentParser(description=description)
        ap.add_argument("--identity", required=True, help="the bot's key file")
        ap.add_argument("--name", help="what the bot is called in the conversation")
        # The phone's transport, and the default: a code a phone opens.
        ap.add_argument("--meet", metavar="CODE",
                        help="a meeting code or link a phone showed; without it the bot shows one")
        ap.add_argument("--mailbox", metavar="URL",
                        help="the mailbox to meet at (default: the one the phone client uses)")
        ap.add_argument("--picture", metavar="PNG",
                        help="what the bot looks like on a phone (default: the icon.png beside the bot)")
        # The direct transport, for a bot that talks to another copy of the client.
        ap.add_argument("--relay", help="wait on the direct transport, through this relay")
        ap.add_argument("--connect", help="an invitation code, to dial instead of wait (needs --relay)")
        ap.add_argument("--rotelyx", default=os.environ.get("ROTELYX", "rotelyx-cli"))
        return ap

    @classmethod
    def from_args(cls, args=None, *, description: str = "a Rotelyx bot") -> "Bot":
        if args is None:
            args = cls.parser(description).parse_args()
        argv = [args.rotelyx, "--identity", args.identity]
        if args.relay and not args.meet:
            argv += ["connect", args.connect] if args.connect else ["listen"]
            argv += ["--relay", args.relay, "--bot"]
        else:
            argv += ["meet"]
            if args.meet:
                argv += [args.meet]
            elif not cls._has_met(args.identity):
                argv += ["--host"]
            if args.name:
                argv += ["--name", args.name]
            if args.mailbox:
                argv += ["--mailbox", args.mailbox]
            picture = args.picture or cls._icon_beside(sys.argv[0])
            if picture:
                argv += ["--picture", picture]
            argv += ["--bot"]
        return cls(argv)

    @staticmethod
    def _icon_beside(script: str) -> Optional[str]:
        """The `icon.png` in the bot's own folder, if there is one.

        Every bot here ships one, rendered from its `icon.svg`, so a phone
        shows the bot the way it shows a person: a picture in the circle
        beside what it said, rather than the first letter of its name.
        """
        candidate = os.path.join(os.path.dirname(os.path.abspath(script)), "icon.png")
        return candidate if os.path.isfile(candidate) else None

    @staticmethod
    def _has_met(identity: str) -> bool:
        """Whether this identity already has a conversation written down.

        The client keeps one beside the key file, and a bot started again
        carries it on rather than showing a new code to nobody.
        """
        base, _ = os.path.splitext(identity)
        folder = base + ".conversations"
        try:
            return any(name.endswith(".chat") for name in os.listdir(folder))
        except FileNotFoundError:
            return False

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

            # A button pressed on one of this bot's cards.
            #
            # It travels as an ordinary control message, the way a read
            # receipt does, so the client hands it over as a message and it is
            # turned into its own kind here rather than in every bot.
            text = raw.get("text")
            if kind == "message" and isinstance(text, str) and text.startswith("rx-signal\x1ftap\x1f"):
                import base64
                field = text.split("\x1f")[2] if len(text.split("\x1f")) > 2 else ""
                try:
                    command = base64.b64decode(field).decode()
                except Exception:  # noqa: BLE001
                    command = ""
                if command:
                    yield Event("tap", {**raw, "command": command})
                    continue

            if kind == "ready":
                self.me = raw.get("me")
                self.members = raw.get("members", 0)
            elif kind == "members":
                self.members = raw.get("count", 0)
            elif kind == "roster":
                self.roster = list(raw.get("members") or [])
            elif kind == "safety":
                # Logged so whoever runs the bot can read it against the
                # phone: it is the one check that the conversation is with
                # the bot and not with somebody in the middle.
                self.log(f"safety number with {raw.get('peer')}: {raw.get('number')}")
                if self.owner is None:
                    self.owner = raw.get("peer")
            elif kind == "code":
                self.log(f"waiting at {raw.get('code')}")
                self.log(f"open on a phone: {raw.get('link')}")
            elif kind == "proposed":
                who, by = raw.get("who"), raw.get("by") or "somebody"
                if self.admits(Event(kind, raw)):
                    self.log(f"{by} wants to let {who} in: agreed")
                    self.confirm()
                else:
                    self.log(f"{by} wants to let {who} in: not agreed, only {self.owner} may")
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

    def send_file(self, name: str, mime: str, data: bytes, caption: str = "") -> None:
        """Send a file the way the phone does, so the phone shows it.

        A picture (`image/jpeg`, `image/png`, `image/gif`) is drawn in the
        conversation; anything else is offered as a file. The free tier's
        envelope is 64 KiB and the file travels as base64 inside it, so keep
        a picture under about 44 KiB: shrink and re-encode before sending,
        never send a camera photograph as it is.

        `caption` is what is said along with it, in the same message: one
        bubble, one notification, and no chance of the line arriving before the
        picture it is about. It is a fourth field after the bytes, which older
        applications ignore, so a captioned picture is still a picture on a
        phone that has never heard of captions.
        """
        from urllib.parse import quote
        import base64
        body = "\x01rx-file\x01" + quote(name, safe="") + "\x01" + quote(mime, safe="") + "\x01" \
            + base64.b64encode(data).decode()
        if caption:
            body += "\x01" + quote(caption, safe="")
        self._do({"do": "send", "text": body})

    def send_card(self, title: str, text: str,
                  buttons: "list[tuple[str, str]] | None" = None) -> None:
        """A message with buttons under it.

        `buttons` is a list of `(label, command)`. The label is what the person
        sees; the command is what this bot is told when it is pressed, and is
        never shown to anybody. Six at most: a card with a screen of buttons is
        a menu, which is the thing buttons exist to avoid.

        A press arrives as an ordinary control message in the conversation and
        reaches `on_tap`. Nothing runs on the phone: the command is this bot's
        own word for what was chosen.

        An application that has never seen a card shows the title and the text,
        so nothing is lost on an older build.
        """
        from urllib.parse import quote
        parts = [quote(title, safe=""), quote(text, safe="")]
        for label, command in (buttons or [])[:6]:
            parts.append(quote(label, safe="") + "\x1f" + quote(command, safe=""))
        self._do({"do": "send", "text": "\x01rx-card\x01" + "\x01".join(parts)})

    def remove(self, who: str) -> None:
        """Put a member out. Every member sees the change."""
        self._do({"do": "remove", "who": who})

    def ask_members(self) -> None:
        self._do({"do": "members"})

    def confirm(self) -> None:
        """Agree to the addition somebody proposed. See `admits`."""
        self._do({"do": "confirm"})

    def dismiss(self) -> None:
        """Forget the proposal without agreeing. The newcomer keeps waiting."""
        self._do({"do": "dismiss"})

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
