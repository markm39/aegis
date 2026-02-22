#!/bin/bash
# Aegis skill: camsnap
# Capture photos from connected cameras and webcams
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'camsnap' executed"]}'
        ;;
esac
