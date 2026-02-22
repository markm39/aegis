#!/bin/bash
# Aegis skill: blucli
# Control BluOS speakers and streamers - playback, presets, and grouping
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'blucli' executed"]}'
        ;;
esac
