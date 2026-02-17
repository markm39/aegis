#!/usr/bin/env bash
# Smoke test for aegis CLI.
# Runs the full lifecycle with a temporary HOME directory for isolation.
#
# Usage:
#   cargo build --release && ./scripts/smoke-test.sh
#   # Or with a debug build:
#   cargo build && AEGIS=./target/debug/aegis ./scripts/smoke-test.sh

set -euo pipefail

AEGIS="${AEGIS:-./target/release/aegis}"

if [ ! -x "$AEGIS" ]; then
    echo "ERROR: aegis binary not found at $AEGIS"
    echo "Run: cargo build --release"
    exit 1
fi

TMPDIR=$(mktemp -d)
export HOME="$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

echo "=== Aegis Smoke Test ==="
echo "Binary: $AEGIS"
echo "HOME:   $HOME"
echo ""

step() {
    echo "--- $1 ---"
}

step "1. aegis setup"
$AEGIS setup
echo ""

step "2. aegis init"
$AEGIS init smoke-test --policy allow-read-only
echo ""

step "3. Create test file"
echo "hello aegis" > "$HOME/.aegis/smoke-test/sandbox/hello.txt"
echo "Created hello.txt"
echo ""

HELLO_PATH="$HOME/.aegis/smoke-test/sandbox/hello.txt"

step "4. aegis run"
$AEGIS run --config smoke-test -- cat "$HELLO_PATH"
echo ""

step "5. aegis audit query"
$AEGIS audit query smoke-test --last 20
echo ""

step "6. aegis audit sessions"
$AEGIS audit sessions smoke-test
echo ""

step "7. aegis audit export (jsonl)"
$AEGIS audit export smoke-test --format jsonl | head -5
echo ""

step "8. aegis audit verify"
$AEGIS audit verify smoke-test
echo ""

step "9. aegis report (json)"
$AEGIS report smoke-test --format json | head -20
echo ""

step "10. aegis audit policy-history"
$AEGIS audit policy-history smoke-test
echo ""

step "11. aegis status"
$AEGIS status smoke-test
echo ""

step "12. aegis policy validate"
$AEGIS policy validate --path "$HOME/.aegis/smoke-test/policies/default.cedar"
echo ""

step "13. aegis wrap"
mkdir -p "$TMPDIR/wrap-project"
$AEGIS wrap --dir "$TMPDIR/wrap-project" -- sh -c "echo wrapped > $TMPDIR/wrap-project/output.txt"
if [ -f "$TMPDIR/wrap-project/output.txt" ]; then
    echo "Wrap output: $(cat "$TMPDIR/wrap-project/output.txt")"
else
    echo "ERROR: wrap output file not created"
    exit 1
fi
echo ""

step "14. aegis run (auto-init)"
$AEGIS run -- echo "auto-init-test"
echo ""

step "15. aegis status (auto-init config)"
$AEGIS status echo
echo ""

echo "=== All smoke tests passed ==="
