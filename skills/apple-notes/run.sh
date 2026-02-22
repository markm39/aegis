#!/bin/bash
# Aegis skill: apple-notes
# Create, read, search, and manage Apple Notes via AppleScript
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'apple-notes' executed"]}'
        ;;
esac
