"""One call to a model that runs on your own network.

Every bot here that thinks does it through this, and the reason it is a
separate file is the reason it matters: **where the model runs decides
whether the conversation is still private.** A model on a machine you control
keeps it end to end encrypted, in the plain sense that nobody outside the
group ever holds a message. A model behind a cloud API means every message you
hand it leaves the group, whatever the API's terms say.

This speaks the OpenAI-shaped chat API, because that is what Ollama, LM
Studio, llama.cpp's server, vLLM and most local runners answer to, so one
function covers all of them:

    ROTELYX_LLM_URL   default http://localhost:4000/v1   (LiteLLM, on the LAN)
    ROTELYX_LLM_MODEL default qwen3.5:0.8b
    ROTELYX_LLM_KEY   the key, from the environment and never from a file

More than one machine, when there is more than one:

    ROTELYX_LLM_URLS="http://192.168.68.24:11434|qwen3.5:9b,http://192.168.68.109:11434|qwen3.5:4b"

Each entry is a machine and the model to ask it for, and each gets **one
request at a time**: a box answers one question well and four questions
slowly. The point of listing several is that a room full of people does not
have to queue behind a single machine to say anything, which is the difference
between reading a conversation later and watching it happen. A machine that
stops answering is set aside for a minute and the others carry on.

**Never put the key in this file or any other in the repository.** It is read
from the environment and nowhere else.

A model that "thinks" before answering (the qwen3.5 family) spends the whole
token budget on the thinking and returns an empty reply, so thinking is
switched off in every request with `think: false`. LiteLLM passes that on;
Ollama's own OpenAI-shaped endpoint drops it and hands back the thinking with
no answer. So a URL that is an Ollama itself (no `/v1` on the end, port 11434
by convention) is spoken to in Ollama's native `/api/chat`, where the switch
works:

    ROTELYX_LLM_URL=http://192.168.1.10:11434   an Ollama, directly, no key

Standard library only. No SDK phones home from here.
"""

import itertools
import json
import os
import threading
import time
import urllib.request

URL = os.environ.get("ROTELYX_LLM_URL", "http://localhost:4000/v1").rstrip("/")
MODEL = os.environ.get("ROTELYX_LLM_MODEL", "qwen3.5:0.8b")
KEY = os.environ.get("ROTELYX_LLM_KEY", "")


# An Ollama spoken to directly, rather than an OpenAI-shaped gateway in front
# of one. The tell is the path: a gateway ends in `/v1`, an Ollama does not.
OLLAMA = not URL.endswith("/v1")

#: How long a machine that failed is left alone before it is asked again.
RESTING = 60.0


class Lane:
    """One machine that answers, and the promise not to ask it twice at once.

    The lock is the whole point. These are somebody's own boxes on their own
    network, not an API with a meter: one asks and answers, four at once and it
    answers nobody. Asking each machine one question at a time, and several
    machines at the same time, is what a small network can actually do.
    """

    def __init__(self, url: str, model: str):
        self.url = url.rstrip("/")
        self.model = model
        self.ollama = not self.url.endswith("/v1")
        self.lock = threading.Lock()
        #: When this machine may be asked again, after it failed.
        self.rested_at = 0.0
        self.calls = 0
        self.seconds = 0.0

    @property
    def healthy(self) -> bool:
        return time.time() >= self.rested_at

    def rest(self) -> None:
        self.rested_at = time.time() + RESTING

    def __str__(self) -> str:  # pragma: no cover - for logs
        return f"{self.url} ({self.model})"


def _lanes() -> list[Lane]:
    written = os.environ.get("ROTELYX_LLM_URLS", "").strip()
    if not written:
        return [Lane(URL, MODEL)]
    out = []
    for entry in written.split(","):
        entry = entry.strip()
        if not entry:
            continue
        url, _, model = entry.partition("|")
        out.append(Lane(url.strip(), model.strip() or MODEL))
    return out or [Lane(URL, MODEL)]


LANES = _lanes()
#: Whose turn it is to be asked first, so the same machine is not always the
#: one that carries a burst on its own.
_next = itertools.count()


def _take() -> Lane:
    """A machine to ask: a free one if there is one, otherwise wait for one.

    Never blocks on a machine that is resting while another is free, and never
    refuses to answer because every machine is busy: waiting is what a queue is
    for.
    """
    healthy = [lane for lane in LANES if lane.healthy] or list(LANES)
    start = next(_next) % len(healthy)
    order = healthy[start:] + healthy[:start]
    for lane in order:
        if lane.lock.acquire(blocking=False):
            return lane
    lane = order[0]
    lane.lock.acquire()
    return lane


def chat(messages: list[dict], *, temperature: float = 0.4, max_tokens: int = 400) -> str:
    """`messages` is the usual list of {"role": ..., "content": ...}.

    One request at a time to whichever machine answers it. When the last
    machine on the list fails, the error is raised: a caller that hears nothing
    back has to know it heard nothing, not be handed an empty string.
    """
    tried = []
    while True:
        lane = _take()
        began = time.time()
        try:
            return _ask(lane, messages, temperature=temperature, max_tokens=max_tokens)
        except Exception as e:  # noqa: BLE001
            lane.rest()
            tried.append(f"{lane}: {e}")
            if len(tried) >= len(LANES):
                raise RuntimeError("; ".join(tried)) from e
        finally:
            lane.calls += 1
            lane.seconds += time.time() - began
            lane.lock.release()


def _ask(lane: Lane, messages: list[dict], *, temperature: float, max_tokens: int) -> str:
    if lane.ollama:
        return _ollama(lane, messages, temperature=temperature, max_tokens=max_tokens)
    body = json.dumps({
        "model": lane.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
        # Answer, do not think out loud. See the note at the top.
        "think": False,
    }).encode()
    headers = {"Content-Type": "application/json"}
    if KEY:
        headers["Authorization"] = f"Bearer {KEY}"
    req = urllib.request.Request(f"{lane.url}/chat/completions", data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        out = json.loads(r.read().decode())
    message = out["choices"][0]["message"]
    content = (message.get("content") or "").strip()
    if not content and message.get("reasoning"):
        raise RuntimeError(
            f"{lane.model} spent its whole budget thinking and said nothing. Use a "
            "model that answers directly, or raise max_tokens."
        )
    return content


def _ollama(lane: Lane, messages: list[dict], *, temperature: float, max_tokens: int) -> str:
    body = json.dumps({
        "model": lane.model,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }).encode()
    req = urllib.request.Request(
        f"{lane.url}/api/chat", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        out = json.loads(r.read().decode())
    content = (out.get("message") or {}).get("content", "").strip()
    if not content:
        raise RuntimeError(f"{lane.model} answered nothing")
    return content


def _answers(lane: Lane) -> bool:
    try:
        probe = f"{lane.url}/api/tags" if lane.ollama else f"{lane.url}/models"
        req = urllib.request.Request(
            probe, headers={"Authorization": f"Bearer {KEY}"} if KEY else {}
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception:  # noqa: BLE001
        return False


def reachable() -> bool:
    """Whether anything is there to ask. One machine answering is enough."""
    return any(_answers(lane) for lane in LANES)


def where() -> str:
    """What is being asked, for a line in a log."""
    return ", ".join(str(lane) for lane in LANES)
