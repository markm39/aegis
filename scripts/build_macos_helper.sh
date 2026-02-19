#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_DIR="$ROOT/tools/aegis-macos-helper"

if ! command -v swift >/dev/null 2>&1; then
  echo "swift toolchain not found" >&2
  exit 1
fi

(cd "$HELPER_DIR" && swift build -c release)

BIN="$HELPER_DIR/.build/release/aegis-macos-helper"
if [ -x "$BIN" ]; then
  echo "built $BIN"
else
  echo "build failed" >&2
  exit 1
fi
