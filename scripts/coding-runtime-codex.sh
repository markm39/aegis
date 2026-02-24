#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFEST_PATH="${REPO_ROOT}/vendor/coding-runtime/codex-rs/Cargo.toml"

# Native path: run the vendored Codex CLI from source.
if [[ -f "$MANIFEST_PATH" ]] && command -v cargo >/dev/null 2>&1; then
    exec cargo run --manifest-path "$MANIFEST_PATH" -p codex-cli -- "$@"
fi

# Fallback path: use external codex binary if available.
if command -v codex >/dev/null 2>&1; then
    exec codex "$@"
fi

echo "Error: no coding runtime available." >&2
echo "Tried native source runtime at: $MANIFEST_PATH" >&2
echo "Install Rust (cargo) for native runtime or install codex on PATH." >&2
exit 1
