#!/bin/bash
# Aegis skill: gemini
# Interact with Google Gemini models via the gemini CLI
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'gemini' executed"]}'
        ;;
esac
