#!/usr/bin/env bash
# Install a verified Cover release binary, then configure the selected clients.
#
#   curl -fsSL https://raw.githubusercontent.com/DavidCarliez/cover/main/scripts/install.sh | bash
#
# Environment overrides:
#   COVER_VERSION     release tag to install, e.g. v0.1.0 (default: latest)
#   COVER_BIN_DIR     install directory (default: ~/.local/bin)
#   COVER_AGENTS      non-interactive agent list, e.g. openai,claude,cursor
#   COVER_SKIP_SETUP  set to 1 to install the binary without configuring clients

set -euo pipefail

# The whole script runs from main at the end, so a download cut short by the
# network runs nothing instead of a partial script.
main() {

GITHUB_REPO="${COVER_GITHUB_REPO:-DavidCarliez/cover}"
LATEST_URL="${COVER_LATEST_URL:-https://github.com/${GITHUB_REPO}/releases/latest}"
RELEASE_BASE_URL="${COVER_RELEASE_BASE_URL:-https://github.com/${GITHUB_REPO}/releases/download}"
BIN_DIR="${COVER_BIN_DIR:-${HOME}/.local/bin}"

# Refuse plaintext downloads and redirects; file:// serves local test releases.
CURL_SECURE=(--proto '=https,file' --proto-redir '=https' --tlsv1.2)

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required to download Cover."

bold "Cover installer"
echo

case "$(uname -s)" in
  Linux)  RELEASE_OS="linux" ;;
  Darwin) RELEASE_OS="darwin" ;;
  MINGW*|MSYS*|CYGWIN*) RELEASE_OS="windows" ;;
  *) fail "unsupported operating system: $(uname -s). Download a release manually from https://github.com/${GITHUB_REPO}/releases." ;;
esac

case "$(uname -m)" in
  x86_64|amd64) RELEASE_ARCH="amd64" ;;
  arm64|aarch64) RELEASE_ARCH="arm64" ;;
  *) fail "unsupported architecture: $(uname -m). Download a release manually from https://github.com/${GITHUB_REPO}/releases." ;;
esac

INSTALL_WORK_DIR=$(mktemp -d /tmp/cover-install.XXXXXX)
STAGED_BIN=""
cleanup() {
  if [[ -n "$STAGED_BIN" && -e "$STAGED_BIN" ]]; then
    rm -f -- "$STAGED_BIN"
  fi
  rm -r -- "$INSTALL_WORK_DIR"
}
trap cleanup EXIT

if [[ -n "${COVER_VERSION:-}" ]]; then
  RELEASE_TAG="$COVER_VERSION"
else
  dim "Resolving the latest Cover release..."
  EFFECTIVE_URL=$(curl "${CURL_SECURE[@]}" -fsSL --retry 3 --retry-delay 1 -o /dev/null -w '%{url_effective}' "$LATEST_URL") || \
    fail "could not resolve the latest Cover release."
  RELEASE_TAG=${EFFECTIVE_URL%/}
  RELEASE_TAG=${RELEASE_TAG##*/}
fi

[[ "$RELEASE_TAG" != "latest" ]] || fail "could not determine the latest Cover release tag."

case "$RELEASE_TAG" in
  v[0-9A-Za-z]*|[0-9A-Za-z]*) ;;
  *) fail "invalid release tag: ${RELEASE_TAG}" ;;
esac
if [[ "$RELEASE_TAG" == *[!0-9A-Za-z._-]* ]]; then
  fail "invalid release tag: ${RELEASE_TAG}"
fi

RELEASE_VERSION=${RELEASE_TAG#v}
RELEASE_TAG="v${RELEASE_VERSION}"

if [[ "$RELEASE_OS" == "windows" ]]; then
  ARCHIVE_NAME="cover_${RELEASE_VERSION}_${RELEASE_OS}_${RELEASE_ARCH}.zip"
  BINARY_NAME="cover.exe"
else
  ARCHIVE_NAME="cover_${RELEASE_VERSION}_${RELEASE_OS}_${RELEASE_ARCH}.tar.gz"
  BINARY_NAME="cover"
fi

ARCHIVE_PATH="${INSTALL_WORK_DIR}/${ARCHIVE_NAME}"
CHECKSUMS_PATH="${INSTALL_WORK_DIR}/checksums.txt"
RELEASE_URL="${RELEASE_BASE_URL}/${RELEASE_TAG}"

dim "Downloading Cover ${RELEASE_TAG} for ${RELEASE_OS}/${RELEASE_ARCH}..."
curl "${CURL_SECURE[@]}" -fsSL --retry 3 --retry-delay 1 -o "$ARCHIVE_PATH" "${RELEASE_URL}/${ARCHIVE_NAME}" || \
  fail "release asset not found: ${ARCHIVE_NAME}"
curl "${CURL_SECURE[@]}" -fsSL --retry 3 --retry-delay 1 -o "$CHECKSUMS_PATH" "${RELEASE_URL}/checksums.txt" || \
  fail "checksums.txt is missing from ${RELEASE_TAG}"

EXPECTED_CHECKSUM=$(awk -v asset="$ARCHIVE_NAME" '$2 == asset || $2 == "*" asset { print $1 }' "$CHECKSUMS_PATH")
[[ -n "$EXPECTED_CHECKSUM" ]] || fail "checksums.txt has no entry for ${ARCHIVE_NAME}"
[[ "$EXPECTED_CHECKSUM" != *$'\n'* ]] || fail "checksums.txt has more than one entry for ${ARCHIVE_NAME}"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_CHECKSUM=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_CHECKSUM=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
elif command -v openssl >/dev/null 2>&1; then
  ACTUAL_CHECKSUM=$(openssl dgst -sha256 "$ARCHIVE_PATH" | awk '{print $NF}')
else
  fail "sha256sum, shasum, or openssl is required to verify the download."
fi

EXPECTED_CHECKSUM=$(printf '%s' "$EXPECTED_CHECKSUM" | tr '[:upper:]' '[:lower:]')
ACTUAL_CHECKSUM=$(printf '%s' "$ACTUAL_CHECKSUM" | tr '[:upper:]' '[:lower:]')
[[ "$ACTUAL_CHECKSUM" == "$EXPECTED_CHECKSUM" ]] || fail "checksum verification failed for ${ARCHIVE_NAME}; nothing was installed."
dim "Checksum verified."

EXTRACT_DIR="${INSTALL_WORK_DIR}/extract"
mkdir -p "$EXTRACT_DIR"
if [[ "$RELEASE_OS" == "windows" ]]; then
  command -v unzip >/dev/null 2>&1 || fail "unzip is required to extract ${ARCHIVE_NAME}."
  unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
else
  command -v tar >/dev/null 2>&1 || fail "tar is required to extract ${ARCHIVE_NAME}."
  tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
fi

[[ -f "${EXTRACT_DIR}/${BINARY_NAME}" ]] || fail "release archive does not contain ${BINARY_NAME}."

mkdir -p "$BIN_DIR"
STAGED_BIN="${BIN_DIR}/.cover-install.$$"
cp "${EXTRACT_DIR}/${BINARY_NAME}" "$STAGED_BIN"
chmod 0755 "$STAGED_BIN"
mv -f -- "$STAGED_BIN" "${BIN_DIR}/${BINARY_NAME}"
STAGED_BIN=""

bold "Installed Cover ${RELEASE_TAG} to ${BIN_DIR}/${BINARY_NAME}"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo
  echo "Note: ${BIN_DIR} is not on your PATH."
  echo "Add this to your shell profile:"
  printf '  export PATH="%s:${PATH}"\n' "$BIN_DIR"
  echo
fi

if [[ "${COVER_SKIP_SETUP:-0}" == "1" ]]; then
  dim "Client setup skipped (COVER_SKIP_SETUP=1)."
  exit 0
fi

INSTALL_ARGS=("$@")
if [[ -n "${COVER_AGENTS:-}" ]]; then
  INSTALL_ARGS+=(--agents "$COVER_AGENTS")
fi

if ((${#INSTALL_ARGS[@]} > 0)); then
  "${BIN_DIR}/${BINARY_NAME}" install "${INSTALL_ARGS[@]}"
else
  "${BIN_DIR}/${BINARY_NAME}" install
fi
}

main "$@"
