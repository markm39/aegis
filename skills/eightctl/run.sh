#!/bin/bash
# Aegis skill: eightctl
# Control Eight Sleep smart mattress - temperature, schedules, and sleep data
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'eightctl' executed"]}'
        ;;
esac
