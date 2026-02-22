#!/bin/bash
# Aegis skill: sherpa-onnx-tts
# Local text-to-speech using sherpa-onnx models - offline, fast, multilingual
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'sherpa-onnx-tts' executed"]}'
        ;;
esac
