#!/usr/bin/env bash
# One-command installer for Cover.
#
#   curl -fsSL https://raw.githubusercontent.com/DavidCarliez/cover/main/scripts/install.sh | bash
#
# Environment overrides:
#   COVER_REPO    git remote (default: https://github.com/DavidCarliez/cover.git)
#   COVER_BRANCH  branch to clone (default: main)
#   COVER_BIN_DIR install directory (default: ~/.local/bin)
#   COVER_AGENTS  non-interactive agent list, e.g. openai,claude,cursor

set -euo pipefail

REPO="${COVER_REPO:-https://github.com/DavidCarliez/cover.git}"
BRANCH="${COVER_BRANCH:-main}"
BIN_DIR="${COVER_BIN_DIR:-${HOME}/.local/bin}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

bold "Cover installer"
echo

# Local dev: script file inside a checkout. curl|bash has no script path (BASH_SOURCE unset).
CLEANUP_SRC=true
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "${SCRIPT_DIR}/../go.mod" ]]; then
    SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    CLEANUP_SRC=false
  fi
fi

if [[ "${CLEANUP_SRC}" == true ]]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "Error: git is required to download Cover." >&2
    exit 1
  fi
  SRC_DIR="$(mktemp -d)"
  trap 'rm -rf "${SRC_DIR}"' EXIT
  dim "Cloning ${REPO} (${BRANCH})..."
  git clone --depth 1 --branch "${BRANCH}" "${REPO}" "${SRC_DIR}"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go is required to build Cover." >&2
  echo "Install from https://go.dev/dl/ and re-run this script." >&2
  exit 1
fi

dim "Building cover..."
(cd "${SRC_DIR}" && go build -ldflags="-s -w" -o cover ./cmd/cover)

mkdir -p "${BIN_DIR}"
install -m 0755 "${SRC_DIR}/cover" "${BIN_DIR}/cover"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo
  echo "Note: ${BIN_DIR} is not on your PATH."
  echo "Add this to your shell profile:"
  echo "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
  echo
fi

INSTALL_ARGS=()
if [[ $# -gt 0 ]]; then
  INSTALL_ARGS=("$@")
fi
if [[ -n "${COVER_AGENTS:-}" ]]; then
  INSTALL_ARGS=(--agents "${COVER_AGENTS}")
fi

# curl|bash: Go opens /dev/tty directly for interactive prompts.
if ((${#INSTALL_ARGS[@]} > 0)); then
  "${BIN_DIR}/cover" install "${INSTALL_ARGS[@]}"
else
  "${BIN_DIR}/cover" install
fi

if [[ "${CLEANUP_SRC}" == true ]]; then
  rm -rf "${SRC_DIR}"
  trap - EXIT
fi
