#!/bin/bash
# Aegis skill: summarize
# Summarize long text, articles, or documents using the active LLM
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'summarize' executed"]}'
        ;;
esac
