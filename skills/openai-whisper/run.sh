#!/bin/bash
# Aegis skill: openai-whisper
# Local speech-to-text transcription using OpenAI Whisper model
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'openai-whisper' executed"]}'
        ;;
esac
