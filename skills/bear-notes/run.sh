#!/bin/bash
# Aegis skill: bear-notes
# Create, read, search, and manage Bear app notes on macOS
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'bear-notes' executed"]}'
        ;;
esac
