#!/usr/bin/bash
set -euo pipefail

DEMO_INPUT="Check NIKE server 10.23.8.14"
EVENT_PATH="/tmp/cover-demo-event.json"
RESPONSE_PATH="/tmp/cover-demo-response.json"

printf '\033[1;36mPRIVATE INPUT\033[0m\n'
printf '\033[1m%s\033[0m\n' "$DEMO_INPUT"
sleep 1

cover monitor --show-content --once --json >"$EVENT_PATH" 2>/dev/null &
COVER_MONITOR_PID=$!
until ss -Htn state established '( sport = :19317 )' | grep -q .; do
  sleep 0.05
done

curl -sS http://127.0.0.1:19317/responses \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg input "$DEMO_INPUT" '{input:$input}')" \
  >"$RESPONSE_PATH"
wait "$COVER_MONITOR_PID"

PROTECTED_INPUT=$(jq -r '.sent.input' "$EVENT_PATH")
RESTORED_REPLY=$(jq -r '.reply' "$RESPONSE_PATH")

printf '\n\033[1;35mSENT TO THE LLM\033[0m\n'
printf '\033[1m%s\033[0m\n' "$PROTECTED_INPUT"
sleep 2

printf '\n\033[1;32mRESTORED FOR YOU\033[0m\n'
printf '\033[1m%s\033[0m\n' "$RESTORED_REPLY"
sleep 1

printf '\n\033[2mPrivate values stay local. The workflow stays unchanged.\033[0m\n'
