#!/bin/bash
# Aegis skill: canvas
# Create and edit collaborative documents with LLM assistance
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'canvas' executed"]}'
        ;;
esac
