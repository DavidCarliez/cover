#!/usr/bin/env bash
set -euo pipefail

COVER_REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
COVER_INSTALL_TEST_DIR=$(mktemp -d /tmp/cover-install-test.XXXXXX)
cleanup() {
  rm -r -- "$COVER_INSTALL_TEST_DIR"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

VERSION="9.8.7"
TAG="v${VERSION}"
ASSET="cover_${VERSION}_linux_amd64.tar.gz"
RELEASE_DIR="$COVER_INSTALL_TEST_DIR/releases/$TAG"
PAYLOAD_DIR="$COVER_INSTALL_TEST_DIR/payload"
LATEST_TARGET="$COVER_INSTALL_TEST_DIR/latest/$TAG"
mkdir -p "$RELEASE_DIR" "$PAYLOAD_DIR" "$(dirname "$LATEST_TARGET")"
touch "$LATEST_TARGET"

cat >"$PAYLOAD_DIR/cover" <<'FAKE_COVER'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${COVER_TEST_LOG:?}"
FAKE_COVER
chmod 0755 "$PAYLOAD_DIR/cover"
tar -czf "$RELEASE_DIR/$ASSET" -C "$PAYLOAD_DIR" cover
sha256sum "$RELEASE_DIR/$ASSET" | awk -v asset="$ASSET" '{print $1 "  " asset}' >"$RELEASE_DIR/checksums.txt"

INSTALL_BIN="$COVER_INSTALL_TEST_DIR/bin"
INSTALL_LOG="$COVER_INSTALL_TEST_DIR/install.log"
OUTPUT_LOG="$COVER_INSTALL_TEST_DIR/output.log"

COVER_LATEST_URL="file://$LATEST_TARGET" \
COVER_RELEASE_BASE_URL="file://$COVER_INSTALL_TEST_DIR/releases" \
COVER_BIN_DIR="$INSTALL_BIN" \
COVER_AGENTS="openai,claude" \
COVER_TEST_LOG="$INSTALL_LOG" \
bash "$COVER_REPO_DIR/scripts/install.sh" >"$OUTPUT_LOG"

[[ -x "$INSTALL_BIN/cover" ]] || fail "installer did not create an executable"
grep -Fxq "install --agents openai,claude" "$INSTALL_LOG" || fail "agent arguments were not forwarded"
grep -Fq "Checksum verified." "$OUTPUT_LOG" || fail "successful verification was not reported"
grep -Fq "Installed Cover $TAG" "$OUTPUT_LOG" || fail "installed version was not reported"

PINNED_BIN="$COVER_INSTALL_TEST_DIR/pinned-bin"
COVER_VERSION="$VERSION" \
COVER_RELEASE_BASE_URL="file://$COVER_INSTALL_TEST_DIR/releases" \
COVER_BIN_DIR="$PINNED_BIN" \
COVER_SKIP_SETUP=1 \
bash "$COVER_REPO_DIR/scripts/install.sh" >"$COVER_INSTALL_TEST_DIR/pinned.log"

[[ -x "$PINNED_BIN/cover" ]] || fail "version-pinned install failed"
grep -Fq "Client setup skipped" "$COVER_INSTALL_TEST_DIR/pinned.log" || fail "binary-only install was not reported"

BROKEN_BIN="$COVER_INSTALL_TEST_DIR/broken-bin"
mkdir -p "$BROKEN_BIN"
printf 'existing binary\n' >"$BROKEN_BIN/cover"
printf '%064d  %s\n' 0 "$ASSET" >"$RELEASE_DIR/checksums.txt"

if COVER_VERSION="$VERSION" \
  COVER_RELEASE_BASE_URL="file://$COVER_INSTALL_TEST_DIR/releases" \
  COVER_BIN_DIR="$BROKEN_BIN" \
  COVER_SKIP_SETUP=1 \
  bash "$COVER_REPO_DIR/scripts/install.sh" >"$COVER_INSTALL_TEST_DIR/broken.log" 2>&1; then
  fail "checksum mismatch was accepted"
fi
grep -Fq "checksum verification failed" "$COVER_INSTALL_TEST_DIR/broken.log" || fail "checksum failure was unclear"
grep -Fxq "existing binary" "$BROKEN_BIN/cover" || fail "failed verification replaced the existing binary"

MOCK_BIN="$COVER_INSTALL_TEST_DIR/mock-bin"
mkdir -p "$MOCK_BIN"
cat >"$MOCK_BIN/uname" <<'FAKE_UNAME'
#!/usr/bin/env bash
if [[ "${1:-}" == "-s" ]]; then
  echo Linux
else
  echo mips64
fi
FAKE_UNAME
chmod 0755 "$MOCK_BIN/uname"

if PATH="$MOCK_BIN:$PATH" bash "$COVER_REPO_DIR/scripts/install.sh" >"$COVER_INSTALL_TEST_DIR/unsupported.log" 2>&1; then
  fail "unsupported architecture was accepted"
fi
grep -Fq "unsupported architecture: mips64" "$COVER_INSTALL_TEST_DIR/unsupported.log" || fail "unsupported architecture error was unclear"

echo "install.sh tests passed"
