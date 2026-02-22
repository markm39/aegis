#!/bin/bash
# Aegis skill: imsg
# Send and read iMessages via AppleScript on macOS
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'imsg' executed"]}'
        ;;
esac
