#!/usr/bin/bash
set -euo pipefail

COVER_DEMO_BIN_DIR=$1
export PATH="$COVER_DEMO_BIN_DIR:$PATH"

# A fixed key keeps this synthetic README recording reproducible. It is never
# used outside the isolated demo and contains no real secret material.
printf '%s\n' 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=' >/tmp/cover-demo-pseudonym.key
chmod 0600 /tmp/cover-demo-pseudonym.key

upstream >/tmp/cover-demo-upstream.log 2>&1 &
COVER_UPSTREAM_PID=$!
COVER_NO_BANNER=1 cover start >/tmp/cover-demo-proxy.log 2>&1 &
COVER_PROXY_PID=$!

cleanup() {
  kill "$COVER_PROXY_PID" "$COVER_UPSTREAM_PID" 2>/dev/null || true
  rm -f \
    /tmp/cover-demo-pseudonym.key \
    /tmp/cover-demo-redactions.log \
    /tmp/cover-demo-event.json \
    /tmp/cover-demo-response.json \
    /tmp/cover-demo-proxy.log \
    /tmp/cover-demo-upstream.log
}
trap cleanup EXIT

until curl -sS http://127.0.0.1:19317/__cover_doctor__ >/dev/null 2>&1; do
  sleep 0.05
done

PS1='❯ ' bash --noprofile --norc -i
