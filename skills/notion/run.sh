#!/bin/bash
# Aegis skill: notion
# Interact with Notion pages, databases, and blocks via the Notion API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'notion' executed"]}'
        ;;
esac
