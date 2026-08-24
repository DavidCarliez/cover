#!/usr/bin/bash
set -euo pipefail

COVER_REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
VHS_BIN=$(command -v vhs || true)
if [[ -z "$VHS_BIN" ]]; then
  echo "vhs is required to regenerate assets/cover-demo.gif" >&2
  echo "See https://github.com/charmbracelet/vhs" >&2
  exit 1
fi

wait_for_demo_ports() {
  local attempt
  for attempt in {1..100}; do
    if ! ss -Hln '( sport = :19317 or sport = :19318 )' | grep -q .; then
      return 0
    fi
    sleep 0.05
  done
  echo "demo ports 19317-19318 are still in use" >&2
  return 1
}

wait_for_demo_ports
cd "$COVER_REPO_DIR"
PATH="$COVER_REPO_DIR/scripts/demo/bin:$PATH" "$VHS_BIN" scripts/demo/cover-demo.tape
wait_for_demo_ports
