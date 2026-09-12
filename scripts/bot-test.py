#!/usr/bin/env python3
"""Drives examples/echo-bot.py against a second member. See scripts/bot-test."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CLI = os.path.abspath("target/debug/rotelyx-cli")
RELAY = os.path.abspath("target/debug/rotelyx-relay")
PORT = int(os.environ.get("BOT_TEST_PORT", "34219"))
BOT = os.path.abspath("examples/echo-bot.py")
ENV = dict(os.environ, ROTELYX_PASSPHRASE="bot-test")


def fail(why):
    print(f"FAILED: {why}", file=sys.stderr)
    raise SystemExit(1)


def main():
    state = tempfile.mkdtemp()
    host_key = os.path.join(state, "host.key")
    guest_key = os.path.join(state, "guest.key")
    bot = guest = relay = None
    try:
        # An invitation address is reachable only through a relay, which is the
        # design: the address in a code is a rendezvous at a relay, not an IP
        # belonging to anybody. So a bot needs one named, exactly as a person
        # does.
        relay = subprocess.Popen(
            [RELAY, "--bind", f"127.0.0.1:{PORT}", "--open",
             "--identity", os.path.join(state, "relay.id")],
            env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for line in relay.stdout:
            if "relay listening" in line:
                break
        else:
            fail("the relay never came up")
        url = f"http://127.0.0.1:{PORT}"

        # The invitation is the whole of the permission: there are no accounts
        # to authenticate as, so without this the bot is unreachable.
        made = subprocess.run(
            [CLI, "--identity", host_key, "invite", "--hours", "1"],
            env=ENV, capture_output=True, text=True, check=True,
        )
        codes = re.findall(r"^\s*([A-Za-z0-9_-]{40,})\s*$", made.stdout, re.M)
        if not codes:
            fail(f"no invitation code in:\n{made.stdout}")
        code = codes[0]

        bot = subprocess.Popen(
            [sys.executable, BOT, "--identity", host_key, "--rotelyx", CLI,
             "--relay", url],
            env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        guest = subprocess.Popen(
            [CLI, "--identity", guest_key, "connect", code, "--relay", url, "--bot"],
            env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )

        heard = []
        for line in guest.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # A bot reads this with a line-delimited parser, so one stray
                # sentence on stdout breaks every bot anybody writes.
                fail(f"not JSON on stdout: {line!r}")
            heard.append(event)
            if event.get("event") == "ready":
                guest.stdin.write('{"do":"send","text":"ping"}\n')
                guest.stdin.flush()
            if event.get("event") == "message":
                break

        kinds = [e.get("event") for e in heard]
        if "ready" not in kinds:
            fail(
                f"the guest never came up: {heard}\n"
                f"guest said: {guest.stderr.read()}\n"
                f"bot said: {bot.stderr.read()}"
            )
        answers = [e for e in heard if e.get("event") == "message"]
        if not answers:
            fail(f"no answer arrived: {heard}\n{bot.stderr.read() if bot.stderr else ''}")
        if answers[0].get("text") != "you said: ping":
            fail(f"the answer was not what the bot sent: {answers[0]}")
        # The bot is a member, not a relay attendant, so what it says is
        # attributed to its leaf like anybody else's.
        if not answers[0].get("from"):
            fail(f"the bot's message was unattributed: {answers[0]}")

        print("ok: two programs held keys and talked")
    finally:
        for p in (guest, bot, relay):
            if p and p.poll() is None:
                p.kill()
        shutil.rmtree(state, ignore_errors=True)


if __name__ == "__main__":
    main()
