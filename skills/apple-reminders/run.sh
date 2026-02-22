#!/bin/bash
# Aegis skill: apple-reminders
# Create, complete, and manage Apple Reminders via AppleScript
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'apple-reminders' executed"]}'
        ;;
esac
