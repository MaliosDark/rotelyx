#!/usr/bin/env python3
"""A town of simulated people, living in Rotelyx groups, with the bots among them.

    python3 bot-examples/town/town.py --agents agents.json --groups 8 --size 8

What this is for: the ten bots were each tried in a conversation of their own,
and a messenger is groups. This puts synthetic people, exported from a
population simulator, into Rotelyx groups on a real mailbox, with two or three
bots in each group, and lets them talk: to each other, in character, and to the
bots, as people use bots. Whoever runs it can be added to every group and watch
from a phone. It also counts: messages, how long each takes to reach the
others, and what the mailbox does under it, which is what a load test is.

What each person is: a name, an age, a job, a city, a way of talking and a few
things on their mind, taken from the simulator. Nothing about a real person.
Their words come from a model on this network (`llm.py`); their pictures from
an image generator on this network. Nothing leaves it.

What is deliberately not here: anything the simulator's own message engine
lets its people do that a demo on somebody's phone should not. The people here
talk about dinner, work, football, the news and each other, like people do in
a group chat, and that is all they are asked to do.

Every member is a real client (`rotelyx-cli meet --bot`), one process each,
speaking to the mailbox on this machine directly, which is why the mailbox has
to excuse this address from its per-address limits for the run
(`--exempt-address`). Groups form the way they do in the app: one member
hosts, the first arrival is first contact, and everybody after that is proposed
by the host and let in by a member already there.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import queue
import random
import signal
import subprocess
import sys
import threading
import time
import zlib
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm  # noqa: E402
import voice  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.dirname(HERE)

# One request to the image generator at a time from this whole town. It is a
# machine on somebody's network, not an API with a meter, and forty groups
# asking at once is what makes it answer nobody. A group waits its turn; the
# rest of the town goes on.
PICTURE_TURN = threading.Lock()

# The model's turn is kept by `llm.py` instead, one per machine that answers.
# It was one lock for the whole town, which is right when there is one box and
# wrong when there are two: every room queued behind the slowest answer in the
# network, and reading the rooms was reading a transcript rather than watching
# people talk. See `ROTELYX_LLM_URLS`.

# The bots a group can have, and which kinds of people ask for them.
BOT_FOR_COMMUNITY = {
    "parenting": ["reminders", "polls", "schedule"],
    "food_recipes": ["polls", "expenses"],
    "sports_fans": ["polls", "welcome"],
    "local_news": ["polls", "assistant"],
    "social_club": ["schedule", "expenses", "welcome"],
    "tech": ["assistant", "polls", "markets"],
    "gaming": ["polls", "schedule"],
    "travel": ["expenses", "schedule", "translate"],
    "music": ["polls", "assistant"],
    "crypto": ["markets", "polls"],
    "investing": ["markets", "expenses"],
    "prepping": ["markets", "reminders"],
}
#: Rooms put together by who the people are rather than by where they live.
#:
#: The city grouping produced five rooms of tired parents talking about
#: groceries, which is a fair picture of a population and a useless one for
#: watching how a group behaves. These are the personas the population carries
#: that are difficult on purpose, sorted into rooms where they have something
#: to push against: a room of liars, a room of believers, a room waiting for
#: the end, a room that finds all of it funny, and a room of people who think
#: they know something.
#:
#: `predatory_groomer` exists in the population and is deliberately not used.
#: Every other difficult persona here produces an argument worth watching; that
#: one produces a script for approaching a child, which is not something to
#: generate however it is labelled.
CASTS = [
    ("The long con", [
        "romance_scammer", "charming_sociopath", "chronic_liar",
        "accidental_influencer",
    ]),
    ("True believers", [
        "cult_recruiter", "ideological_zealot", "pious_hypocrite",
        "reformed_extremist",
    ]),
    ("Before the lights go out", [
        "doomsday_prepper", "radicalized_veteran", "bored_radicalized",
        "war_profiteer",
    ]),
    ("Nothing matters anyway", [
        "edgelord_nihilist", "suicidal_comedian", "addicted_doctor",
        "trauma_reformer",
    ]),
    ("People who know things", [
        "whistleblower_hiding", "anarchist_philanthropist", "digital_nomad",
        "grieving_parent",
    ]),
]

DEFAULT_BOTS = ["polls", "markets", "expenses", "welcome"]
# In every group, whatever else is there. A group of strangers gets a
# moderator the way a room gets a door.
ALWAYS = ["moderator"]
NEEDS_MODEL = {"assistant", "translate", "search"}

# What a person might want from each bot, in their own words, and the command
# the bot understands. The model writes the words; the command is exact.
BOT_ASKS = {
    "polls": [
        ("start a poll about something the group is deciding", "/poll {q} | {a} | {b} | {c}"),
        ("vote in the open poll", "/vote {n}"),
        ("ask for the poll results", "/results"),
    ],
    "expenses": [
        ("say you paid for something shared", "/paid {amount} {what}"),
        ("ask who owes whom", "/owes"),
    ],
    "reminders": [
        ("ask for a reminder", "/remind in {m}m {what}"),
        ("ask what reminders are pending", "/reminders"),
    ],
    "schedule": [
        ("say when you are free this week", "/free {day} {h1}-{h2}"),
        ("ask when everybody can make it", "/when"),
    ],
    "welcome": [("ask for the rules", "/rules")],
    "assistant": [("ask the assistant something", "@Assistant {question}")],
    "translate": [("ask for a translation", "/tr {lang} {phrase}")],
}

#: What each simulated person is told they are.
#:
#: The first version ended "keep it clean and friendly", which produced five
#: rooms of people being pleasant at each other. That is a useless load test
#: and a useless thing to watch: the point of putting difficult personas in a
#: room is to see what a group of them does, which is the study he asked for.
#:
#: So the character is played as written -- the evasions, the grandiosity, the
#: sales pitch, the bleakness -- and the three limits that stay are the ones
#: that are not about tone: nothing sexual, nothing involving children, and no
#: instructions anybody could act on for hurting somebody. Those are not
#: politeness, and a room of liars is no reason to write them.
SYSTEM = (
    "You are {name}, {age} years old, {gender}, a {role} in {city}. {bio} "
    "You speak like this: {speech}. Your worldview: {philosophy}. "
    "You are in a group chat called \"{group}\" on Rotelyx, a private messenger "
    "with no phone numbers and no accounts, with a few other people and some "
    "helper bots. Write ONE short chat message, one to two sentences, in "
    "English, as yourself, natural and informal, no hashtags, no quotes, no "
    "narration, no name prefix. "
    "Stay in character completely, including the parts of this person that are "
    "difficult, evasive, self-serving or bleak. Do not be pleasant for the sake "
    "of it and do not lecture the others. "
    "Never anything sexual, nothing involving children, and nothing that tells "
    "anybody how to hurt somebody or how to commit a crime. Do not name real "
    "people or real companies."
)


#: How a refusal starts. Matched at the beginning of the line, except "as an
#: ai", which turns up in the middle of one often enough to be worth catching
#: wherever it is.
REFUSALS = (
    "i can't", "i cannot", "i can not", "i won't", "i will not",
    "i'm sorry", "i am sorry", "sorry, ", "i'm not able", "i am not able",
    "i'm unable", "i am unable", "i must decline", "i do not feel comfortable",
    "i don't feel comfortable", "as an ai", "i'm an ai", "i am an ai",
    "unfortunately, i", "i apologize", "i apologise",
)


def log(line: str) -> None:
    print(time.strftime("%H:%M:%S"), line, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# One member: a client process and its events
# ---------------------------------------------------------------------------


@dataclass
class Member:
    name: str
    argv: list[str]
    kind: str  # "person" or "bot"
    agent: dict = field(default_factory=dict)
    proc: Optional[subprocess.Popen] = None
    events: "queue.Queue[dict]" = field(default_factory=queue.Queue)
    ready: bool = False
    link: Optional[str] = None
    log_path: str = ""
    #: The file this member's call reads its microphone from, when it has one.
    #: A FIFO: writing into it is this member talking. See `ROTELYX_CALL_FEED`.
    feed: str = ""
    #: True between `call_started` and `call_ended`. Nothing is written to the
    #: feed outside that: opening a FIFO blocks until something reads it, and
    #: nothing reads it when there is no call.
    in_call: bool = False
    #: One utterance at a time. Two threads writing a member's feed would
    #: interleave two voices into one mouth.
    mouth: threading.Lock = field(default_factory=threading.Lock)
    #: Where this member's side of a call is written down, when a run is
    #: recording: what it said, as it was handed to the codec, and what it
    #: heard, as the codec gave it back. Empty when nothing is kept.
    recording: str = ""
    #: How many things this member has said aloud, for naming the files in
    #: the order they were said.
    utterances: int = 0
    #: Whether this member keeps the decoded track of what it heard. One per
    #: group: see `Town.recording_for`.
    listens: bool = False

    def start(self) -> None:
        err = open(self.log_path, "w") if self.log_path else subprocess.DEVNULL
        env = dict(os.environ)
        if self.recording and self.listens:
            # Everything this member's speaker would have played, as the codec
            # decoded it: 32 bit float, mono, 48 kHz, the whole call in one
            # track. The references are beside it, so the two can be compared.
            # See `rotelyx-audio`'s `ROTELYX_CALL_DUMP`.
            os.makedirs(self.recording, exist_ok=True)
            env["ROTELYX_CALL_DUMP"] = os.path.join(self.recording, "heard.f32")
        if self.feed:
            # A member with no sound card and nobody in front of it: what would
            # have gone to the microphone is read from this file, and what
            # would have gone to a speaker is dropped.
            env["ROTELYX_CALL_FEED"] = self.feed
            env["ROTELYX_CALL_DEAF"] = "1"
        self.proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
            text=True, bufsize=1, env=env,
        )
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw["_at"] = time.time()
            kind = raw.get("event")
            if kind == "ready":
                self.ready = True
            elif kind == "code":
                self.link = raw.get("link")
            elif kind == "call_started":
                self.in_call = True
                self._note({"what": "started", **raw})
            elif kind == "call_ended":
                self.in_call = False
                self._note({"what": "ended", **raw})
            self.events.put(raw)
        self.events.put({"event": "closed", "reason": "process ended", "_at": time.time()})

    def do(self, instruction: dict) -> None:
        if not self.proc or not self.proc.stdin:
            return
        try:
            self.proc.stdin.write(json.dumps(instruction) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def say(self, text: str) -> None:
        self.do({"do": "send", "text": text})

    def reply_to(self, author: str, quoted: str, text: str) -> None:
        """Answer one message in particular, the way the application's own
        reply does: the marker, who said it, the opening of what they said,
        and what is being said now, joined by the unit separator. A phone
        draws it as a quote above the answer."""
        clean = lambda s: s.replace("\x1f", " ")
        short = quoted if len(quoted) <= 90 else quoted[:90].rstrip() + "..."
        body = "\x1f".join(["rx-reply", clean(author), clean(short), clean(text)])
        self.do({"do": "send", "text": body})

    def send_file(self, name: str, mime: str, data: bytes, caption: str = "") -> None:
        """A file, and what is said with it, in one message.

        The caption is a fourth field after the bytes. A build that has never
        heard of it takes the first three and ignores the rest, so this is
        still a picture on an older phone.
        """
        from urllib.parse import quote
        body = ("\x01rx-file\x01" + quote(name, safe="") + "\x01" + quote(mime, safe="")
                + "\x01" + base64.b64encode(data).decode())
        if caption:
            body += "\x01" + quote(caption, safe="")
        self.do({"do": "send", "text": body})

    def show_picture(self, jpeg: bytes) -> None:
        """What this member looks like, for the others' screens."""
        self.do({"do": "picture", "base64": base64.b64encode(jpeg).decode()})

    def name_the_group(self, name: str, jpeg: Optional[bytes]) -> None:
        """The group's name and picture, as the phone's own signal carries
        them: everybody in the group sees both."""
        body = ("rx-signal\x1fgroup\x1f" + base64.b64encode(name.encode()).decode()
                + "\x1f" + (base64.b64encode(jpeg).decode() if jpeg else ""))
        self.do({"do": "send", "text": body})

    def _note(self, row: dict) -> None:
        """One line about this member's call, kept with the audio.

        What a call reported when it ended is the other half of the material:
        an utterance that arrived distorted and one that arrived at all are
        different faults, and only the counters tell them apart.
        """
        if not self.recording:
            return
        try:
            with open(os.path.join(self.recording, "calls.jsonl"), "a") as f:
                f.write(json.dumps({"member": self.name, **row}) + "\n")
        except OSError:
            pass

    def call(self) -> None:
        """Ring the conversation. Everybody else answers by themselves."""
        self.do({"do": "call"})

    def hangup(self) -> None:
        self.do({"do": "hangup"})

    def aloud(self, text: str) -> bool:
        """Say it in the call, if this member is in one.

        Returns whether it was said. Synthesis and the write both happen on a
        thread of their own: writing a FIFO blocks until the call has read it
        all, which is the whole duration of the utterance, and the town has a
        conversation to carry on with meanwhile.
        """
        if not (self.in_call and self.feed):
            return False

        def run() -> None:
            # Held for the write as well as the synthesis: the lock is what
            # stops one member saying two things at once.
            with self.mouth:
                try:
                    samples = voice.speak(text, voice=self.agent.get("voice", ""))
                    # Written down before it is sent, not after: this is the
                    # reference the decoded copy is compared against, and it
                    # has to be exactly what went in. See `docs/CODEC.md`.
                    if self.recording:
                        self.utterances += 1
                        base = os.path.join(self.recording, f"said-{self.utterances:04d}")
                        with open(base + ".wav", "wb") as f:
                            f.write(voice.to_wav(samples))
                        with open(base + ".json", "w") as f:
                            json.dump({
                                "said": text,
                                "at": time.time(),
                                "samples": len(samples),
                                "seconds": len(samples) / voice.RATE,
                                "synthetic": not voice.available(),
                            }, f)
                    voice.write(self.feed, samples)
                except Exception as e:  # noqa: BLE001
                    print(f"[voice] {self.name}: {e}", file=sys.stderr)

        threading.Thread(target=run, daemon=True).start()
        return True

    def stop(self) -> None:
        self.do({"do": "quit"})
        if self.proc:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------------------
# A group: people, bots, a transcript, and the numbers
# ---------------------------------------------------------------------------


@dataclass
class Group:
    name: str
    city: str
    people: list[Member]
    bots: list[Member]
    host: Member
    transcript: list[tuple[str, str]] = field(default_factory=list)  # (who, text)
    sent: int = 0
    received: int = 0
    latencies: list[float] = field(default_factory=list)
    refused: int = 0
    poll_open: bool = False
    # The group's own picture, once made, so a newcomer can be told what the
    # group is called and what it looks like as they arrive rather than only
    # the members who were there when it was first named.
    icon: Optional[bytes] = None
    # message text -> (sent at, who) for latency
    in_flight: dict = field(default_factory=dict)

    @property
    def members(self) -> list[Member]:
        return self.people + self.bots

    @property
    def second(self) -> Optional[Member]:
        """The member who lets people in: the host's first contact."""
        return self.people[1] if len(self.people) > 1 else None

    @property
    def link(self) -> Optional[str]:
        return self.host.link

    def phone_link(self, public_mailbox: str) -> Optional[str]:
        """The same meeting place, named by the address a phone reaches the
        mailbox at. The members here speak to it on this machine directly;
        a phone comes through the front door. Same server, same tags."""
        link = self.host.link
        if not link or not public_mailbox:
            return link
        return link.split("~", 1)[0] + "~" + public_mailbox


class Town:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.state = os.path.join(args.state, "town")
        os.makedirs(os.path.join(self.state, "keys"), exist_ok=True)
        os.makedirs(os.path.join(self.state, "logs"), exist_ok=True)
        self.groups: list[Group] = []
        self.looks: list[tuple] = []
        self.stop = threading.Event()
        self.images_made = 0
        self.llm_calls = 0
        self.llm_seconds = 0.0
        self.llm_failures = 0
        # One folder per run, named by when it started, so two runs never
        # write into each other's material.
        self.recordings = os.path.join(
            args.state, "recordings", time.strftime("%Y-%m-%d-%H%M%S")
        )

    # --- building ----------------------------------------------------------

    def client_argv(self, key: str, name: str, link: Optional[str], host: bool, picture: Optional[str] = None) -> list[str]:
        argv = [self.args.rotelyx, "--identity", key, "meet"]
        if link:
            argv.append(link)
        elif host:
            argv.append("--host")
        argv += ["--name", name, "--mailbox", self.args.mailbox]
        # A call never takes a direct path -- a direct path would show every
        # member this machine's address -- so without a relay there are no
        # calls at all, and without a room a call of more than two is two
        # members hearing each other and the rest hearing nothing.
        if self.args.calls:
            argv += ["--relay", self.args.relay, "--room", self.args.room]
        if picture:
            argv += ["--picture", picture]
        argv.append("--bot")
        return argv

    def bot_argv(self, bot: str, key: str, link: str) -> list[str]:
        return [sys.executable, os.path.join(EXAMPLES, bot, "bot.py"), "--identity", key,
                "--meet", link, "--mailbox", self.args.mailbox,
                "--name", bot.capitalize()]

    def form_groups(self, agents: list[dict]) -> list[list[dict]]:
        """A room per cast, `size` people in each.

        People are drawn by who they are rather than by where they live. See
        `CASTS` for what that means and what is left out of it. Falls back to
        the old grouping -- one city, the community they share -- when the
        population has none of these personas in it.
        """
        if self.args.by_city:
            return self._by_city(agents)

        by_persona: dict[str, list[dict]] = {}
        for a in agents:
            by_persona.setdefault(a.get("persona_id") or "", []).append(a)
        for people in by_persona.values():
            random.shuffle(people)

        groups = []
        for _, personas in CASTS[: self.args.groups]:
            room: list[dict] = []
            # Round robin through the personas of the room, so eight people are
            # two of each rather than eight of whichever is most common.
            while len(room) < self.args.size:
                took = False
                for persona in personas:
                    pool = by_persona.get(persona) or []
                    if not pool:
                        continue
                    room.append(pool.pop())
                    took = True
                    if len(room) == self.args.size:
                        break
                if not took:
                    break
            if len(room) >= 3:
                groups.append(room)

        return groups or self._by_city(agents)

    def _by_city(self, agents: list[dict]) -> list[list[dict]]:
        """People from one city who share a community, `size` at a time."""
        by_city: dict[str, list[dict]] = {}
        for a in agents:
            by_city.setdefault(f"{a['city']}|{a['country_code']}", []).append(a)
        cities = [c for c in by_city.values() if len(c) >= self.args.size]
        random.shuffle(cities)
        groups = []
        for members in cities[: self.args.groups]:
            random.shuffle(members)
            groups.append(members[: self.args.size])
        return groups

    def bots_for(self, people: list[dict]) -> list[str]:
        tally: dict[str, int] = {}
        for p in people:
            for c in p.get("persona_communities", []) + p.get("group_memberships", []):
                for b in BOT_FOR_COMMUNITY.get(c, []):
                    tally[b] = tally.get(b, 0) + 1
        ranked = [b for b, _ in sorted(tally.items(), key=lambda kv: -kv[1])] or list(DEFAULT_BOTS)
        if not self.args.model_bots:
            ranked = [b for b in ranked if b not in NEEDS_MODEL]
        chosen = [b for b in ranked if b not in ALWAYS][: self.args.bots]
        for b in DEFAULT_BOTS:
            if len(chosen) >= self.args.bots:
                break
            if b not in chosen:
                chosen.append(b)
        return ALWAYS + chosen

    def group_name(self, people: list[dict]) -> str:
        """What the room is called.

        A cast's own name, when the people in it are one: it says what is being
        watched without saying anything about the people, which is the point.
        Otherwise the old name, which is a city and what they have in common.
        """
        here = {p.get("persona_id") for p in people}
        for name, personas in CASTS:
            if len(here & set(personas)) >= 2:
                return name

        tally: dict[str, int] = {}
        for p in people:
            for c in p.get("persona_communities", []):
                tally[c] = tally.get(c, 0) + 1
        top = max(tally, key=tally.get) if tally else "friends"
        return f"{people[0]['city']} {top.replace('_', ' ')}"

    def build(self, agents: list[dict]) -> None:
        for n, people in enumerate(self.form_groups(agents)):
            name = self.group_name(people)
            members = []
            for a in people:
                label = a["full_name"]
                key = os.path.join(self.state, "keys", f"{n}-{a['id']}.key")
                members.append(Member(
                    name=label, argv=[], kind="person", agent=a,
                    log_path=os.path.join(self.state, "logs", f"{n}-{a['id']}.log"),
                    feed=self.feed_for(f"{n}-{a['id']}"),
                    # The first person in each group is the one that keeps a
                    # decoded track. See `recording_for`.
                    recording=self.recording_for(f"{n}-{a['id']}"),
                    # One member per group keeps what it heard. See
                    # `recording_for` for why not all of them.
                    listens=not members,
                ))
            host = members[0]
            host.argv = self.client_argv(
                os.path.join(self.state, "keys", f"{n}-{people[0]['id']}.key"),
                host.name, None, host=True)
            group = Group(name=name, city=people[0]["city"], people=members, bots=[], host=host)
            self.groups.append(group)

    def recording_for(self, who: str) -> str:
        """Where this member's side of the calls is kept, or nowhere.

        # Why not everybody

        A decoded track is 48 000 samples a second at four bytes each: 690 MB
        an hour, per member. Forty members recording each other is a disk full
        before lunch and no more information than a few of them: what a codec
        is judged on is the same speech in and out, and one listener per group
        gives that for every word said in it.

        So: everybody writes down what they *said*, which is short and only
        when they speak, and one member per group writes down what it *heard*.
        """
        if not self.args.record:
            return ""
        folder = os.path.join(self.recordings, who)
        os.makedirs(folder, exist_ok=True)
        return folder

    def feed_for(self, who: str) -> str:
        """The pipe a member talks through, made once and reused.

        A FIFO rather than a file: the call reads it at the rate a person
        speaks, and an ordinary file would be read to its end in one go and
        then be at its end for ever. Empty when this run has no calls, which
        is what leaves the member without a voice and with a real microphone
        if anybody ever starts one by hand.
        """
        if not self.args.calls:
            return ""
        folder = os.path.join(self.state, "voices")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"{who}.feed")
        if not os.path.exists(path):
            os.mkfifo(path, 0o600)
        return path

    def kept(self, key: str) -> bool:
        """Whether this key already has a conversation written down beside
        it, in which case the client carries it on rather than meeting."""
        folder = key[:-4] + ".conversations" if key.endswith(".key") else key + ".conversations"
        try:
            return any(f.endswith(".chat") for f in os.listdir(folder))
        except FileNotFoundError:
            return False

    def resume_group(self, n: int, group: Group) -> bool:
        """A town started again carries its groups on: every member reopens
        the conversation it has on disk, and whoever joined from a phone is
        still in it. Nothing is hosted, so nobody new can join until the
        town is built afresh."""
        host_key = os.path.join(self.state, "keys", f"{n}-{group.people[0].agent['id']}.key")
        if not self.kept(host_key):
            return False
        # The host carries on and opens a new meeting place beside the old
        # conversation, so a bot that was not there last time can knock.
        for m in group.people:
            key = os.path.join(self.state, "keys", f"{n}-{m.agent['id']}.key")
            m.argv = self.client_argv(key, m.name, None, host=(m is group.host))
            m.start()
        deadline = time.time() + 60
        while time.time() < deadline and not (all(m.ready for m in group.people) and group.host.link):
            self.pump(group)
            time.sleep(0.5)
        for bot in self.bots_for([m.agent for m in group.people]):
            key = os.path.join(self.state, "keys", f"{n}-bot-{bot}.key")
            if self.kept(key):
                argv = self.bot_argv(bot, key, "")
                argv = [a for a in argv if a not in ("--meet", "")]
            elif group.host.link:
                argv = self.bot_argv(bot, key, group.host.link)
            else:
                continue
            member = Member(name=bot.capitalize(), argv=argv, kind="bot",
                            log_path=os.path.join(self.state, "logs", f"{n}-bot-{bot}.log"))
            member.start()
            group.bots.append(member)
            self.await_admission(group, member, timeout=40)
        log(f"[{group.name}] carried on: {sum(m.ready for m in group.people)}/{len(group.people)} people, bots {[b.name for b in group.bots]}")
        self.dress(n, group)
        return True

    # --- looks -------------------------------------------------------------

    def dress(self, n: int, group: Group) -> None:
        """Name the group now and make its picture later.

        The name costs nothing and belongs to the group from the moment it
        exists: it used to be sent with the picture, and the picture waits in
        a queue behind every portrait of every group before it, so the
        fortieth group would have shown up on somebody's phone as "somebody
        and 11 others" for an hour. The picture follows when it is ready, and
        a newcomer is told both as they arrive.
        """
        if group.host.ready:
            group.host.name_the_group(group.name, None)
        # The group's own picture before anybody's portrait: a row on a list
        # is seen far more often than a face on a bubble.
        self.looks.insert(0, ("group", n, group, None))
        for m in group.people:
            self.looks.append(("person", n, group, m))

    def dress_next(self) -> None:
        """One picture, if any is owed: the group's first, then a person's.
        Kept on disk beside the keys, so a restarted town wears the same
        faces rather than making new ones."""
        if not self.looks or not self.args.images:
            return
        kind, n, group, member = self.looks.pop(0)
        folder = os.path.join(self.state, "looks")
        os.makedirs(folder, exist_ok=True)
        if kind == "group":
            # "-v2" because the first prompt asked for "an icon for a group
            # chat", and the generator drew a phone every single time: five
            # groups, five pictures of a phone. A group's picture should look
            # like the group, so it is asked for as a thing from the place the
            # group is about.
            path = os.path.join(folder, f"{n}-group-v2.jpg")
            topic = group.name.split(' ', 1)[-1]
            jpeg = read_or_make(path, lambda: generate_picture(
                self.args.images,
                f"a simple flat illustration standing for {topic} in {group.city}: "
                f"one object or a small scene from {group.city}, bold shapes, "
                "warm colours, square. No text, no lettering, no faces, no "
                "people, no phones and no screens.",
                side=256, budget=30 * 1024))
            group.icon = jpeg
            if jpeg and group.host.ready:
                group.host.name_the_group(group.name, jpeg)
                log(f"[{group.name}] named and pictured")
            return
        a = member.agent
        # "-anon" in the name on purpose. The earlier run cached generated
        # faces under the plain name, and those are exactly what must not be
        # worn any more: a new name means a new picture rather than a stale
        # portrait being read back off the disk.
        path = os.path.join(folder, f"{n}-{a['id']}-anon.jpg")
        jpeg = read_or_make(path, lambda: generate_picture(
            self.args.images, avatar_prompt(a), side=256, budget=30 * 1024))
        if jpeg and member.ready:
            member.show_picture(jpeg)


    def raise_group(self, n: int, group: Group) -> None:
        """Bring one group up: host, first contact, then everybody else."""
        if self.resume_group(n, group):
            return
        host = group.host
        host.start()
        deadline = time.time() + 30
        while not host.link and time.time() < deadline:
            time.sleep(0.2)
        if not host.link:
            log(f"[{group.name}] the host never showed a code")
            return
        log(f"[{group.name}] {host.name} hosts at {host.link}")

        # Everybody else knocks, one at a time, and the confirmations are
        # answered as they come: the first arrival is let in by the host
        # alone (first contact), the rest by a member already inside.
        for i, m in enumerate(group.people[1:], start=1):
            key = os.path.join(self.state, "keys", f"{n}-{m.agent['id']}.key")
            m.argv = self.client_argv(key, m.name, host.link, host=False)
            m.start()
            self.await_admission(group, m, timeout=40)

        for bot in self.bots_for([m.agent for m in group.people]):
            key = os.path.join(self.state, "keys", f"{n}-bot-{bot}.key")
            member = Member(name=bot.capitalize(), argv=self.bot_argv(bot, key, host.link), kind="bot",
                            log_path=os.path.join(self.state, "logs", f"{n}-bot-{bot}.log"))
            member.start()
            group.bots.append(member)
            self.await_admission(group, member, timeout=40)
        log(f"[{group.name}] up: {len(group.people)} people, bots {[b.name for b in group.bots]}")
        self.dress(n, group)

    def await_admission(self, group: Group, newcomer: Member, timeout: float) -> None:
        """Answer the proposals that the newcomer's knock produces, until the
        newcomer is in or the time is up."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if newcomer.kind == "bot" and not newcomer.ready:
                # A bot script keeps the client's events to itself and logs
                # what matters; the line with the safety number is the one
                # that says it is in.
                try:
                    with open(newcomer.log_path) as f:
                        if "safety number with" in f.read():
                            newcomer.ready = True
                except OSError:
                    pass
            if newcomer.ready:
                return
            self.pump(group, confirm=True)
            time.sleep(0.2)
        log(f"[{group.name}] {newcomer.name} did not get in within {timeout}s")

    # --- events ------------------------------------------------------------

    def pump(self, group: Group, confirm: bool = False) -> None:
        """Drain every member's events into the transcript and the numbers."""
        for m in group.members:
            while True:
                try:
                    ev = m.events.get_nowait()
                except queue.Empty:
                    break
                kind = ev.get("event")
                if kind == "proposed" and m.kind == "person":
                    # One person agrees when the host asks: the first one the
                    # host let in. Every member hears the proposal, and if
                    # two of them confirmed, two commits would be made for
                    # one epoch and the group would split down the middle.
                    # That is exactly what happened with everybody confirming.
                    # The bots decide for themselves (their library agrees
                    # with whoever brought them in, which is not the host).
                    if ev.get("by") == group.host.name and m is group.second:
                        m.do({"do": "confirm"})
                elif kind == "message":
                    text = ev.get("text") or ""
                    key = (ev.get("from"), text[:80])
                    sent_at = group.in_flight.pop(key, None)
                    if sent_at is not None:
                        group.latencies.append(ev["_at"] - sent_at)
                    group.received += 1
                    # The transcript is what the host hears plus what the host
                    # says: one copy of each line, not one per listener.
                    # A card from a bot. It is not a line of conversation, so
                    # it stays out of the transcript, but a poll drawn as
                    # buttons is still a poll that is open: the bot used to say
                    # "Vote with /vote" and now it draws the options instead.
                    if text.startswith("\x01rx-card\x01") and "vote" in text:
                        group.poll_open = True

                    if m is group.host and text and not text.startswith("rx-") and not text.startswith("\x01rx-"):
                        group.transcript.append((ev.get("from") or "?", text))
                        del group.transcript[:-40]
                        if "Vote with /vote" in text:
                            group.poll_open = True
                        elif "closed" in text.lower() and "poll" in text.lower():
                            group.poll_open = False
                elif kind == "joined" and m is group.host:
                    # Somebody arrived. Tell them what the group is called and
                    # what it looks like: both were announced once, when the
                    # group was first dressed, and anybody who came afterwards
                    # saw a list row named after whoever happened to be first.
                    if group.icon or group.name:
                        group.host.name_the_group(group.name, group.icon)
                elif kind == "refused":
                    group.refused += 1
                    log(f"[{group.name}] {m.name}: refused: {ev.get('problem')}")
                elif kind == "closed":
                    log(f"[{group.name}] {m.name} closed: {ev.get('reason')}")

    # --- talking -----------------------------------------------------------

    def speak(self, group: Group) -> None:
        people = [p for p in group.people if p.ready]
        if not people:
            return
        weights = [max(5.0, float(p.agent.get("social_drive") or 30)) for p in people]
        who = random.choices(people, weights=weights, k=1)[0]
        a = who.agent

        roll = random.random()
        text: Optional[str] = None
        if group.bots and roll < self.args.bot_rate:
            text = self.bot_ask(group, who)
        elif self.args.images and roll < self.args.bot_rate + self.args.image_rate:
            if self.send_picture(group, who):
                return
        if text is None:
            text = self.chat_line(group, who)
        if not text:
            return
        group.in_flight[(who.name, text[:80])] = time.time()
        group.sent += 1
        # Answering one message in particular, when there is a recent one from
        # somebody else and the line reads like an answer to it. People quote
        # in a group; a wall of unattached lines does not read like one.
        answering = None
        if len(group.transcript) >= 2 and random.random() < self.args.reply_rate:
            for author, said in reversed(group.transcript[-8:]):
                if author not in ("?", who.name) and not said.startswith("/"):
                    answering = (author, said)
                    break
        if answering:
            who.reply_to(answering[0], answering[1], text)
        else:
            who.say(text)

        # And aloud, when the group is on a call. Both, rather than one or the
        # other: the words are what he reads on his phone and the audio is
        # what the relay is being measured with, and a room where people speak
        # without the transcript is a room nobody can follow afterwards.
        who.aloud(text)
        if who is group.host:
            group.transcript.append((who.name, text))
            del group.transcript[:-40]
        log(f"[{group.name}] {who.name}: {text[:100]}")

    def prompt_for(self, group: Group, who: Member) -> list[dict]:
        a = who.agent
        recent = "\n".join(f"{n}: {t[:200]}" for n, t in group.transcript[-12:]) or "(nobody has said anything yet)"
        system = SYSTEM.format(
            name=a["full_name"], age=int(float(a.get("age") or 30)), gender=a.get("gender", ""),
            role=a.get("role", "worker"), city=a.get("city", ""), bio=(a.get("persona_bio") or "")[:240],
            speech=(a.get("persona_speech_style") or "casual")[:120],
            philosophy=a.get("philosophy") or "none in particular", group=group.name,
        )
        mind = []
        if a.get("trigger_event"):
            mind.append(f"A headline on your mind: {str(a['trigger_event'])[:120]}")
        if a.get("activity_summary"):
            mind.append(f"Today you were: {str(a['activity_summary'])[:100]}")
        if a.get("hopes"):
            mind.append("You hope for: " + ", ".join(str(h).replace('_', ' ') for h in a['hopes'][:2]))
        user = ("Recent messages in the group:\n" + recent + "\n\n" + " ".join(mind) +
                "\n\nWrite your next message. React to what was said if there is something to react to.")
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def ask_model(self, messages: list[dict], max_tokens: int = 90) -> Optional[str]:
        t = time.time()
        try:
            out = llm.chat(messages, temperature=0.9, max_tokens=max_tokens)
        except Exception as e:  # noqa: BLE001
            self.llm_failures += 1
            log(f"model: {e}")
            return None
        finally:
            self.llm_calls += 1
            self.llm_seconds += time.time() - t
        out = out.strip().strip('"').split("\n")[0].strip()
        if not out:
            return None

        # The model talking about itself instead of being the person.
        #
        # A persona that asks the model for something it will not write gets a
        # refusal back -- "I can't write a message containing...", "As an AI",
        # "I won't roleplay" -- and the town used to send that into the room as
        # that person's line. He saw one on his phone, and it is the single
        # most obvious way this looks like a machine: everybody else is in
        # character and one of them is explaining the rules of the model.
        #
        # The turn is skipped instead. Refusing is the model's right and
        # printing the refusal in the conversation is nobody's.
        low = out.lower()
        if any(low.startswith(p) for p in REFUSALS) or "as an ai" in low:
            return None

        return out[:400] or None

    def chat_line(self, group: Group, who: Member) -> Optional[str]:
        return self.ask_model(self.prompt_for(group, who))

    def bot_ask(self, group: Group, who: Member) -> Optional[str]:
        bot = random.choice(group.bots)
        asks = BOT_ASKS.get(bot.name.lower())
        if not asks:
            return None
        if bot.name.lower() == "polls":
            asks = [asks[0]] if not group.poll_open else asks[1:]
        what, template = random.choice(asks)
        a = who.agent
        if "{q}" in template:
            q = self.ask_model(self.prompt_for(group, who) + [
                {"role": "user", "content": "Instead of a message, give a short question the group could vote on, then three short options, as: question | option | option | option. Nothing else."}], 60)
            if not q or q.count("|") < 3:
                return None
            parts = [p.strip() for p in q.split("|")][:4]
            group.poll_open = True
            return "/poll " + " | ".join(parts)
        if "{question}" in template:
            q = self.ask_model(self.prompt_for(group, who) + [
                {"role": "user", "content": "Instead of a message, ask the group's assistant bot one short practical question. Only the question."}], 40)
            return template.format(question=q) if q else None
        fill = {
            "n": random.randint(1, 3), "amount": random.choice([8, 12, 15, 20, 24, 30, 42.5, 60]),
            "what": random.choice(["coffee", "the taxi", "pizza", "tickets", "groceries", "the cake"]),
            "m": random.choice([2, 5, 10, 30]), "day": random.choice(["mon", "tue", "wed", "thu", "fri"]),
            "h1": random.choice([9, 10, 15, 18]), "lang": random.choice(["es", "fr", "de", "it", "pt"]),
            "phrase": random.choice(["see you at eight", "who is bringing the drinks", "happy birthday"]),
        }
        fill["h2"] = fill["h1"] + random.choice([1, 2, 3])
        try:
            return template.format(**fill)
        except KeyError:
            return None

    # --- pictures ----------------------------------------------------------

    def send_picture(self, group: Group, who: Member) -> bool:
        idea = self.ask_model(self.prompt_for(group, who) + [
            # Whatever they would actually send. The first version asked for
            # "a phone photo, natural light, no faces", and got forty
            # variations of a coffee cup on a wet pavement: a prompt that
            # narrow describes the prompt rather than the person.
            {"role": "user", "content": "Instead of a message, describe in one line an image you would send to this group right now. Anything at all: a photo, a screenshot, a meme, a drawing, a poster, a diagram, something absurd. It should be yours, not a stock picture. You are anonymous here, so never yourself and never anybody's face, and nothing with writing in it. Only the description."}], 70)
        if not idea:
            return False
        with PICTURE_TURN:
            # Their idea, with the one rule the network itself has: nobody's
            # face. A group of people who are anonymous to each other does not
            # pass around invented portraits of anybody.
            # Their idea, with the two rules that are not theirs to break. No
            # faces, because a group of people anonymous to each other does not
            # pass around invented portraits of anybody. And no lettering: the
            # generator writes words like "cost of f living here ere is
            # bagility free" across the middle of the picture, which is the
            # "stupid images" he was looking at.
            jpeg = generate_picture(
                self.args.images,
                f"{idea}. No people's faces, nobody recognisable. "
                "No text, no words, no lettering, no captions, no watermark.")
        if not jpeg:
            return False
        caption = self.ask_model(self.prompt_for(group, who) + [
            {"role": "user", "content": f"You are sharing a photo of: {idea}. Write the one short line you would send with it."}], 40)
        # One message: the picture and the line about it together, the way a
        # person sends a photo. It used to be two, and on the other phone the
        # line could land before the picture it was about.
        who.send_file("photo.jpg", "image/jpeg", jpeg, caption or "")
        group.sent += 1
        if caption and who is group.host:
            group.transcript.append((who.name, f"[photo] {caption}"))
        self.images_made += 1
        log(f"[{group.name}] {who.name} shared a photo: {idea[:80]}")
        return True

    # --- running -----------------------------------------------------------

    def run(self) -> None:
        for n, group in enumerate(self.groups):
            self.raise_group(n, group)
        log("all groups up. Links, one per group, for a phone to open:")
        for group in self.groups:
            log(f"  {group.name}: {group.phone_link(self.args.public_mailbox)}")
        with open(os.path.join(self.state, "links.txt"), "w") as f:
            for group in self.groups:
                f.write(f"{group.name}\t{group.phone_link(self.args.public_mailbox)}\n")

        # Talking happens on a few threads so that a model taking three
        # seconds over one line does not stall the loop that answers
        # admissions and counts arrivals for forty other groups. One turn at
        # a time per group; the pool bounds how many the model is asked for at
        # once.
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=self.args.voices)
        busy: set[int] = set()
        lock = threading.Lock()

        def turn(group: Group) -> None:
            try:
                self.speak(group)
            except Exception as e:  # noqa: BLE001
                log(f"[{group.name}] turn failed: {e}")
            finally:
                with lock:
                    busy.discard(id(group))

        last_report = time.time()
        next_turn = {id(g): time.time() + random.uniform(1, self.args.pace) for g in self.groups}

        # How many more messages this group has in it before it goes quiet.
        #
        # A message every fifty seconds, all day, in every group, is not how a
        # group behaves and is not what it should look like on a phone: it
        # reads as a machine, and it buries anything a person says. Real rooms
        # go in bursts -- somebody says something, three people answer inside a
        # minute, and then nothing happens for ten.
        #
        # So each group runs a burst of a few messages a few seconds apart, and
        # then stops for minutes. The pace flag now sets the length of the
        # quiet rather than the gap between messages, which is the thing worth
        # tuning.
        burst = {id(g): random.randint(2, 5) for g in self.groups}

        def after(group) -> float:
            """When this group speaks next, and how the burst moves on."""
            left = burst[id(group)] - 1
            if left > 0:
                burst[id(group)] = left
                # Inside a burst: people answering each other.
                return random.uniform(6, 25)
            # The burst is over. A new one, after a long enough silence that
            # the phone is quiet and an arriving message means something.
            burst[id(group)] = random.randint(2, 6)
            return random.uniform(self.args.pace * 2, self.args.pace * 8)

        # When each group's call was last started. Zero means never.
        ringing: dict[int, float] = {id(g): 0.0 for g in self.groups}

        while not self.stop.is_set():
            now = time.time()
            for group in self.groups:
                self.pump(group, confirm=True)

                # The call. One member rings and everybody else answers by
                # itself, which is what the phone does too, so a person who
                # opens the link is rung exactly as a member is.
                if self.args.calls:
                    minutes = self.args.call_minutes
                    due = ringing[id(group)] == 0.0 or (
                        minutes > 0 and now - ringing[id(group)] >= minutes * 60
                    )
                    if due and group.host.ready:
                        if ringing[id(group)]:
                            for who in group.people:
                                who.hangup()
                            time.sleep(0.5)
                        ringing[id(group)] = now
                        group.host.call()
                        log(f"[{group.name}] ringing the room")
                if now >= next_turn[id(group)]:
                    next_turn[id(group)] = now + after(group)
                    with lock:
                        if id(group) in busy:
                            continue
                        busy.add(id(group))
                    pool.submit(turn, group)
            if now - last_report >= 60:
                self.report()
                last_report = now

            # The group says its name again, every few minutes.
            #
            # Once was not enough and the reason is not the phone's fault. A
            # name goes out as a message sealed for the members at that epoch;
            # somebody who was off, or who was a few commits behind, never
            # applies it and has no way to ask. He saw one group sitting in his
            # list as "somebody and 11 others" for a day because of exactly
            # that. Saying it again costs one message per group per five
            # minutes and ends the whole class of problem.
            if now - self.last_named >= 300:
                self.last_named = now
                for n, group in enumerate(self.groups):
                    if group.host.ready:
                        group.host.name_the_group(group.name, group.icon)
            if self.looks and not self.dressing:
                self.dressing = True
                pool.submit(self._dress_one)
            time.sleep(0.2)
        pool.shutdown(wait=False, cancel_futures=True)

    dressing = False

    #: When every group last said what it is called. See the loop above.
    last_named = 0.0

    def _dress_one(self) -> None:
        try:
            self.dress_next()
        except Exception as e:  # noqa: BLE001
            log(f"looks: {e}")
        finally:
            self.dressing = False

    def machines(self) -> str:
        """Which box answered how much, when there is more than one.

        Worth a line of its own: with two machines the useful question stops
        being "how long does the model take" and becomes "is the fast one
        carrying the town", and an average over both answers neither.
        """
        if len(llm.LANES) < 2:
            return ""
        parts = []
        for lane in llm.LANES:
            rate = lane.seconds / max(1, lane.calls)
            rest = "" if lane.healthy else " resting"
            parts.append(f"{lane.url.split('//')[-1]} {lane.calls}x {rate:.1f}s{rest}")
        return "| " + " ".join(parts) + " "

    def report(self, final: bool = False) -> None:
        sent = sum(g.sent for g in self.groups)
        received = sum(g.received for g in self.groups)
        lat = sorted(x for g in self.groups for x in g.latencies)
        refused = sum(g.refused for g in self.groups)
        people = sum(1 for g in self.groups for p in g.people if p.ready)
        bots = sum(1 for g in self.groups for b in g.bots if b.ready)
        def pct(p):
            return f"{lat[min(len(lat) - 1, int(len(lat) * p))]:.2f}s" if lat else "-"
        line = (f"groups {len(self.groups)} people {people} bots {bots} | sent {sent} received {received} "
                f"| latency p50 {pct(0.5)} p90 {pct(0.9)} p99 {pct(0.99)} | refused {refused} "
                f"| model calls {self.llm_calls} avg {self.llm_seconds / max(1, self.llm_calls):.1f}s failures {self.llm_failures} "
                f"{self.machines()}| pictures {self.images_made}")
        log(("FINAL " if final else "") + line)
        with open(os.path.join(self.state, "report.log"), "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")

    def shutdown(self) -> None:
        """Everybody at once.

        This used to ask each member to quit and wait up to five seconds for
        it, one after another. Sixty members is five minutes of a town that
        has already said goodbye, which is five minutes before it can be
        started again with a change in it.
        """
        self.stop.set()
        self.report(final=True)
        everybody = [m for group in self.groups for m in group.members]
        threads = [threading.Thread(target=m.stop, daemon=True) for m in everybody]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=8)


def read_or_make(path: str, make) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        pass
    with PICTURE_TURN:
        data = make()
    if data:
        with open(path, "wb") as f:
            f.write(data)
    return data


def avatar_prompt(a: dict) -> str:
    """What one of these people uses as a profile picture.

    Never a face, and never a person. This is an anonymous messenger: a
    portrait is the one thing a profile picture should not be, and a room full
    of generated faces reads as a room full of real people who did not agree to
    be there. It said "profile photo of a 36 year old male worker from
    Botswana" and produced exactly that, which is wrong twice over -- it is a
    face, and it is a face that looks like somebody's.

    So each of them gets what a person on an anonymous network actually picks:
    an object, a symbol, a scrap of a meme, something from what they care
    about. Their persona decides it, so it is theirs and not random, and two
    people who care about different things do not end up with the same picture.
    """
    interests = a.get("persona_communities") or []
    about = ", ".join(str(x).replace("_", " ") for x in interests[:3]) or "ordinary life"
    style = (a.get("persona_speech_style") or "")[:80]
    # crc32 rather than hash(): Python salts string hashing per process, so
    # hash() would give the same person a different kind of picture on every
    # restart.
    kind = AVATAR_KINDS[zlib.crc32(a["id"].encode()) % len(AVATAR_KINDS)]
    return (
        f"{kind}, about {about}, in the spirit of somebody whose humour is "
        f"{style or 'dry'}. No people, no faces, no portraits, no human "
        "figures, no text. Square, bold and readable at the size of a thumb."
    )


# What an anonymous profile picture is, in practice. Wide on purpose: a group
# where every picture is the same kind of thing is a group of one person again.
AVATAR_KINDS = [
    "a close photograph of one object somebody keeps on their desk",
    "a hand drawn doodle in marker on paper",
    "a cartoon animal mascot",
    "a flat vector icon on a single strong colour",
    "a photograph of food on a plate, from above",
    "a sticker of a plant in a pot",
    "a retro pixel art tile",
    "a pattern of shapes like a woven cloth",
    "a photograph of weather through a window",
    "a badly taken photograph of a cat asleep on something",
    "a hand painted sign of the kind a market stall has",
    "a cassette tape, a mug or a tool, photographed on a table",
    "an absurd little meme drawing with no words",
    "a map fragment with a pin in it",
    "a rubber stamp of an animal",
    "a photograph of a bicycle part or a spanner",
    "a bowl of fruit in the style of a cheap postcard",
    "a neon sign shape at night",
]


def generate_picture(url: str, prompt: str, side: int = 512, budget: int = 44 * 1024) -> Optional[bytes]:
    """A picture from the generator on this network, as a JPEG the free tier
    carries (under 44 KiB), or None."""
    try:
        # The description as given, with nothing added to it. Only the
        # technical faults are argued against, and not the subject: a style
        # forced onto every request is how forty people came to share the
        # same photograph of a coffee cup.
        body = json.dumps({"prompt": prompt,
                           "negative_prompt": "watermark, signature, blurry, low quality",
                           "width": 512, "height": 512, "steps": 4}).encode()
        req = urllib.request.Request(url.rstrip("/") + "/generate/no-watermark", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            job = json.loads(r.read().decode())
        job_id = job.get("job_id")
        if not job_id:
            return None
        for _ in range(60):
            time.sleep(2)
            with urllib.request.urlopen(url.rstrip("/") + f"/queue/{job_id}", timeout=30) as r:
                st = json.loads(r.read().decode())
            if st.get("status") in ("completed", "done"):
                images = st.get("images") or []
                if not images:
                    return None
                b64 = images[0].split(",", 1)[-1]
                return shrink_jpeg(base64.b64decode(b64), budget, side)
            if st.get("status") == "failed":
                return None
    except Exception as e:  # noqa: BLE001
        log(f"pictures: {e}")
    return None


def shrink_jpeg(png: bytes, budget: int, side: int = 512) -> Optional[bytes]:
    try:
        from PIL import Image
    except ImportError:
        return None
    im = Image.open(io.BytesIO(png)).convert("RGB")
    for side in (s for s in (512, 448, 384, 320, 256, 192) if s <= side):
        pic = im.resize((side, side)) if im.width != side else im
        for q in (82, 74, 66, 58, 50, 42):
            out = io.BytesIO()
            pic.save(out, "JPEG", quality=q, optimize=True)
            if out.tell() <= budget:
                return out.getvalue()
    return None


def ask_the_relay_for_its_room(relay: str) -> str:
    """Where this relay holds group calls, which it publishes at `/room`.

    An address, not a secret: it names the relay, which everybody in the call
    is already talking to. Read once at the start, the way the phone keeps it
    in its configuration rather than asking per call.
    """
    url = relay.rstrip("/") + "/room"
    # With a name on it: a plain urllib request is refused by some proxies in
    # front of a relay, and "403" with no explanation is a poor way to learn
    # that the relay itself was never asked.
    ask = urllib.request.Request(url, headers={"User-Agent": "rotelyx-town"})
    try:
        with urllib.request.urlopen(ask, timeout=10) as answer:
            room = answer.read().decode().strip()
    except Exception as e:  # noqa: BLE001
        sys.exit(f"asking {url} where its room is: {e}. A relay without --room holds none")
    if not room:
        sys.exit(f"{url} answered with nothing: that relay is running without --room")
    return room


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agents", required=True, help="JSON of people exported from the simulator")
    ap.add_argument("--groups", type=int, default=4)
    ap.add_argument("--size", type=int, default=6, help="people per group")
    ap.add_argument("--bots", type=int, default=2, help="bots per group")
    ap.add_argument("--model-bots", action="store_true", help="also seat the bots that need a model")
    ap.add_argument("--pace", type=float, default=45.0,
                    help="how long a group is quiet between bursts, on average (seconds)")
    ap.add_argument("--by-city", action="store_true",
                    help="group people by where they live, as the first version did, "
                         "instead of by who they are (see CASTS)")
    ap.add_argument("--voices", type=int, default=3, help="how many groups may be composing at once (the model is still asked one request at a time)")
    ap.add_argument("--bot-rate", type=float, default=0.18, help="share of turns that talk to a bot")
    ap.add_argument("--image-rate", type=float, default=0.05, help="share of turns that share a picture")
    ap.add_argument("--reply-rate", type=float, default=0.35,
                    help="share of turns that answer one message in particular")
    ap.add_argument("--images", default=os.environ.get("ROTELYX_IMAGES", ""), help="the image generator's URL, or empty for none")
    ap.add_argument("--mailbox", default=os.environ.get("ROTELYX_MAILBOX", "ws://127.0.0.1:3341/mailbox"))
    ap.add_argument("--public-mailbox", default=os.environ.get("ROTELYX_PUBLIC_MAILBOX", ""),
                    help="the same mailbox as a phone reaches it, for the links printed for phones")
    ap.add_argument("--calls", action="store_true",
                    help="the people hold a group call as well as typing: every line is "
                         "spoken into the call, which is what puts real load on the relay")
    ap.add_argument("--relay", default=os.environ.get("ROTELYX_RELAY", ""),
                    help="the relay a call routes through. Without one there are no calls: "
                         "a direct path would show every member this machine's address")
    ap.add_argument("--room", default=os.environ.get("ROTELYX_ROOM", "auto"),
                    help="where a call of more than two meets, or `auto` to ask the relay")
    ap.add_argument("--record", action="store_true",
                    help="keep the material a codec is judged on: every utterance as it was "
                         "handed to the encoder, one decoded track per group as the decoder "
                         "gave it back, and what every call reported when it ended. "
                         "About 700 MB an hour per recorded group")
    ap.add_argument("--call-minutes", type=float, default=0.0,
                    help="hang up and ring again this often, so the measurement covers "
                         "calls starting and ending rather than one call that never moves. "
                         "0 leaves one call up")
    ap.add_argument("--rotelyx", default=os.environ.get("ROTELYX", "rotelyx-cli"))
    ap.add_argument("--state", default=os.environ.get("ROTELYX_TOWN_STATE", os.path.expanduser("~/.local/state/rotelyx-town")))
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    if args.seed is not None:
        random.seed(args.seed)
    if not os.environ.get("ROTELYX_PASSPHRASE"):
        sys.exit("set ROTELYX_PASSPHRASE: it seals every member's key on disk")

    if args.calls:
        if not args.relay:
            sys.exit("--calls needs --relay: a call never takes a direct path, so without "
                     "a relay there is nowhere for the audio to go")
        if args.room == "auto":
            args.room = ask_the_relay_for_its_room(args.relay)
        if not voice.available():
            log("no speech service (ROTELYX_TTS_URL/ROTELYX_VOICE_KEY): the people will "
                "hold real calls and say tones rather than words")

    with open(args.agents) as f:
        agents = json.load(f)
    town = Town(args)
    town.build(agents)

    def bye(*_):
        log("stopping")
        town.stop.set()
    signal.signal(signal.SIGINT, bye)
    signal.signal(signal.SIGTERM, bye)
    try:
        town.run()
    finally:
        town.shutdown()


if __name__ == "__main__":
    main()
