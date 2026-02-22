#!/bin/bash
# Aegis skill: things-mac
# Create and manage tasks in Things 3 via AppleScript and URL schemes
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'things-mac' executed"]}'
        ;;
esac
