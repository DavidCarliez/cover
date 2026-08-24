#!/usr/bin/bash
set -euo pipefail

COVER_REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COVER_DEMO_HOME_DIR=$(mktemp -d /tmp/cover-demo-home.XXXXXX)
COVER_DEMO_BIN_DIR=$(mktemp -d /tmp/cover-demo-bin.XXXXXX)
COVER_USER_HOME_PATH=$(getent passwd "$(id -u)" | cut -d: -f6)

cleanup() {
  rm -r -- "$COVER_DEMO_HOME_DIR" "$COVER_DEMO_BIN_DIR"
}
trap cleanup EXIT

mkdir -p "$COVER_DEMO_HOME_DIR/.config/cover"
cp "$COVER_REPO_DIR/scripts/demo/config.yaml" "$COVER_DEMO_HOME_DIR/.config/cover/config.yaml"
cp "$COVER_REPO_DIR/scripts/demo/session.sh" "$COVER_DEMO_BIN_DIR/session"
cp "$COVER_REPO_DIR/scripts/demo/present.sh" "$COVER_DEMO_BIN_DIR/cover-demo"
chmod 0755 "$COVER_DEMO_BIN_DIR/session" "$COVER_DEMO_BIN_DIR/cover-demo"
go build -o "$COVER_DEMO_BIN_DIR/cover" "$COVER_REPO_DIR/cmd/cover"
go build -o "$COVER_DEMO_BIN_DIR/upstream" "$COVER_REPO_DIR/scripts/demo/upstream.go"

bwrap \
  --bind / / \
  --dev-bind /dev /dev \
  --bind "$COVER_DEMO_HOME_DIR" "$COVER_USER_HOME_PATH" \
  --chdir /tmp \
  "$COVER_DEMO_BIN_DIR/session" "$COVER_DEMO_BIN_DIR"
