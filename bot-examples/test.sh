#!/usr/bin/env bash
# Every bot that needs no model, driven through a real relay by a program
# playing the person. Each bot is given an instruction and has to answer with
# the right thing; a bot that answers something else, or nothing, fails.
#
#   bot-examples/test.sh                 against the relay on this machine
#   bot-examples/test.sh http://host:3340
set -euo pipefail
cd "$(dirname "$0")/.."

export ROTELYX="${ROTELYX:-./target/debug/rotelyx-cli}"
export ROTELYX_PASSPHRASE=bot-examples
export ROTELYX_BOT_STATE=$(mktemp -d)
STATE=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$STATE" "$ROTELYX_BOT_STATE"' EXIT
[ -x "$ROTELYX" ] || cargo build -p rotelyx-cli

# Without a relay named, start a throwaway one, so this runs in CI.
if [ -n "${1:-}" ]; then
	RELAY="$1"
else
	PORT=${BOTS_PORT:-34224}
	cargo build -p rotelyx-relay
	./target/debug/rotelyx-relay --bind "127.0.0.1:$PORT" --open \
		--identity "$STATE/relay.id" >"$STATE/relay.log" 2>&1 &
	for _ in $(seq 100); do grep -q "relay listening" "$STATE/relay.log" && break; sleep 0.1; done
	grep -q "relay listening" "$STATE/relay.log" || { cat "$STATE/relay.log" >&2; exit 1; }
	RELAY="http://127.0.0.1:$PORT"
fi

# one bot, one instruction, one expected word in the reply
check() {
	local bot="$1" ask="$2" want="$3"
	local code
	code=$("$ROTELYX" --identity "$STATE/$bot.key" invite --hours 1 2>/dev/null \
		| tr -d ' ' | grep -E '^[A-Za-z0-9_-]{40,}$' | head -1)
	python3 "bot-examples/$bot/bot.py" --identity "$STATE/$bot.key" --relay "$RELAY" \
		>/dev/null 2>"$STATE/$bot.log" &
	local pid=$!
	sleep 2
	local heard
	heard=$( { printf '{"do":"send","text":"%s"}\n' "$ask"; sleep 6; } \
		| "$ROTELYX" --identity "$STATE/$bot-person.key" connect "$code" --relay "$RELAY" --bot 2>/dev/null \
		| grep '"event":"message"' | head -3 )
	kill $pid 2>/dev/null || true
	if echo "$heard" | grep -qi "$want"; then
		printf '  %-10s ok\n' "$bot"
	else
		printf '  %-10s FAILED: asked %s, wanted %s, heard: %s\n' "$bot" "$ask" "$want" "$heard"
		cat "$STATE/$bot.log" >&2
		exit 1
	fi
}

check reminders '/remind in 1m water the plants' 'Noted'
check polls     '/poll Lunch? | Pizza | Ramen'    'Vote with'
check expenses  '/paid 30 taxi'                   'paid 30.00'
check schedule  '/free mon 10-12'                 'Got'
check welcome   '/rules'                          'Be kind'
check moderator '/strikes'                        'Nobody has a strike'
echo "ok: six bots answered through a real relay"
