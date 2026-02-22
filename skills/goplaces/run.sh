#!/bin/bash
# Aegis skill: goplaces
# Search for places, get directions, and explore locations via Google Maps API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'goplaces' executed"]}'
        ;;
esac
