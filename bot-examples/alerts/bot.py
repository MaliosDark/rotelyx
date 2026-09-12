#!/usr/bin/env python3
"""Tells the group when something out there changes. Reads nothing.

    python3 alerts/bot.py --identity alerts.key --relay https://amber.telyx.me \
        --watch https://github.com/MaliosDark/rotelyx/releases.atom \
        --watch https://status.example.com/feed.xml \
        --every 300

Polls each feed, and says so when a new entry appears or a plain page
changes. It is the one kind of bot that needs to read nothing at all: it only
ever speaks. So it does not use the shared module's reader, and what it sends
is the only thing it does with the conversation.

Standard library only: urllib and a very small Atom/RSS reader.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from rotelyx_bot import Bot, load_state, save_state  # noqa: E402

NAME = "alerts"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "rotelyx-alerts"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def entries(body: str):
    """Titles and links from Atom or RSS, newest first, or None for a page."""
    items = re.findall(r"<(?:entry|item)>(.*?)</(?:entry|item)>", body, re.S)
    if not items:
        return None
    out = []
    for item in items[:10]:
        title = re.search(r"<title[^>]*>(.*?)</title>", item, re.S)
        link = re.search(r'<link[^>]*href="([^"]+)"', item) or re.search(r"<link>(.*?)</link>", item)
        out.append((re.sub(r"<[^>]+>", "", title.group(1)).strip() if title else "?",
                    link.group(1).strip() if link else ""))
    return out


def main():
    ap = Bot.parser(__doc__)
    ap.add_argument("--watch", action="append", required=True, help="a feed or page URL")
    ap.add_argument("--every", type=int, default=300, help="seconds between checks")
    args = ap.parse_args()
    bot = Bot.from_args(args)
    seen = load_state(NAME, {})

    # Only the writer side. The reader thread exists so the client's stdout
    # is drained, or it blocks; nothing read is acted on.
    import threading
    threading.Thread(target=lambda: [None for _ in bot.events()], daemon=True).start()

    while True:
        for url in args.watch:
            try:
                body = fetch(url)
            except Exception as e:  # noqa: BLE001
                bot.log(f"{url}: {e}")
                continue
            found = entries(body)
            if found is None:
                digest = hashlib.sha256(body.encode()).hexdigest()[:16]
                if seen.get(url) and seen[url] != digest:
                    bot.say(f"Changed: {url}")
                seen[url] = digest
            else:
                known = set(seen.get(url, []))
                for title, link in reversed(found):
                    key = link or title
                    if known and key not in known:
                        bot.say(f"{title}\n{link}".strip())
                seen[url] = [link or title for title, link in found]
            save_state(NAME, seen)
        time.sleep(args.every)


if __name__ == "__main__":
    main()
