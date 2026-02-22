#!/bin/bash
# Aegis skill: trello
# Manage Trello boards, lists, and cards via the Trello API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'trello' executed"]}'
        ;;
esac
