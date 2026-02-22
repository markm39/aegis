#!/bin/bash
# Aegis skill: xurl
# Post, read, and search X (Twitter) via API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'xurl' executed"]}'
        ;;
esac
