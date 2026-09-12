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

    ROTELYX_LLM_URL   default http://192.168.68.24:4000/v1   (LiteLLM, on the LAN)
    ROTELYX_LLM_MODEL default qwen3.5:0.8b
    ROTELYX_LLM_KEY   the key, from the environment and never from a file

**Never put the key in this file or any other in the repository.** It is read
from the environment and nowhere else.

A model that "thinks" before answering (the qwen3.5 family) spends the whole
token budget on the thinking and returns an empty reply, so thinking is
switched off in every request with `think: false`, which Ollama honours
through LiteLLM. A model without that switch ignores it.

Standard library only. No SDK phones home from here.
"""

import json
import os
import urllib.request

URL = os.environ.get("ROTELYX_LLM_URL", "http://192.168.68.24:4000/v1").rstrip("/")
MODEL = os.environ.get("ROTELYX_LLM_MODEL", "qwen3.5:0.8b")
KEY = os.environ.get("ROTELYX_LLM_KEY", "")


def chat(messages: list[dict], *, temperature: float = 0.4, max_tokens: int = 400) -> str:
    """`messages` is the usual list of {"role": ..., "content": ...}."""
    body = json.dumps({
        "model": MODEL,
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
    req = urllib.request.Request(f"{URL}/chat/completions", data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        out = json.loads(r.read().decode())
    message = out["choices"][0]["message"]
    content = (message.get("content") or "").strip()
    if not content and message.get("reasoning"):
        raise RuntimeError(
            f"{MODEL} spent its whole budget thinking and said nothing. Use a model "
            "that answers directly, or raise max_tokens."
        )
    return content


def reachable() -> bool:
    try:
        req = urllib.request.Request(f"{URL}/models", headers={"Authorization": f"Bearer {KEY}"} if KEY else {})
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception:  # noqa: BLE001
        return False
