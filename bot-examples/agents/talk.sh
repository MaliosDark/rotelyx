#!/usr/bin/env bash
# Two agents negotiate over Rotelyx, with nobody else in the conversation.
#
#   ROTELYX_LLM_KEY=... bot-examples/agents/talk.sh https://amber.telyx.me
#
# The first agent issues an invitation and listens; the second dials it.
# From then on there is no person in the loop: two programs, two goals, one
# channel that neither a platform nor the model provider can read, because the
# model is the one on your own network (see llm.py).
#
# The exchange is printed as it happens. Lines starting with the agent's name
# are what it said into the conversation; "heard" is what reached it.
set -euo pipefail
cd "$(dirname "$0")/../.."

RELAY="${1:-http://127.0.0.1:3340}"
export ROTELYX="${ROTELYX:-./target/debug/rotelyx-cli}"
export ROTELYX_PASSPHRASE="${ROTELYX_PASSPHRASE:-agents}"
STATE=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$STATE"' EXIT

[ -x "$ROTELYX" ] || cargo build -p rotelyx-cli

CODE=$("$ROTELYX" --identity "$STATE/ada.key" invite --hours 1 2>/dev/null \
	| tr -d ' ' | grep -E '^[A-Za-z0-9_-]{40,}$' | head -1)
[ -n "$CODE" ] || { echo "no invitation code" >&2; exit 1; }

only_dialogue() { grep --line-buffered -E "^(Ada:|Bob:|  heard:|settled|model:)"; }

python3 bot-examples/agents/agent.py --identity "$STATE/ada.key" --relay "$RELAY" \
	--name Ada \
	--goal "You are arranging a meeting. You are free Tuesday afternoon and Thursday morning, nothing else." \
	--opens "When are you free this week?" 2>&1 | only_dialogue &

sleep 2

python3 bot-examples/agents/agent.py --identity "$STATE/bob.key" --relay "$RELAY" --connect "$CODE" \
	--name Bob \
	--goal "You are arranging a meeting. You are free Tuesday afternoon and Wednesday, nothing else. Prefer Tuesday." \
	2>&1 | only_dialogue

wait
