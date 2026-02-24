#!/bin/bash
set -euo pipefail
INPUT=$(cat)
AUDIO_FILE=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MODEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // "base"')

if [ -z "$AUDIO_FILE" ]; then
  echo '{"result": "Usage: /whisper <audio_file> [model]\nModels: tiny, base, small, medium, large", "artifacts": [], "messages": []}'
  exit 0
fi

if [ ! -f "$AUDIO_FILE" ]; then
  RESULT_JSON=$(echo "File not found: $AUDIO_FILE" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

if ! command -v whisper &>/dev/null; then
  echo '{"result": "whisper is not installed. Install with: pip install openai-whisper", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT=$(whisper "$AUDIO_FILE" --model "$MODEL" --output_format txt 2>&1 | head -200)
RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
