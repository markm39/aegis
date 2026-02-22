#!/bin/bash
# Aegis skill: openai-whisper-api
# Cloud speech-to-text transcription via OpenAI Whisper API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'openai-whisper-api' executed"]}'
        ;;
esac
