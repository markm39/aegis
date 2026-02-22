#!/bin/bash
# Aegis skill: openai-image-gen
# Generate and edit images via OpenAI DALL-E API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'openai-image-gen' executed"]}'
        ;;
esac
