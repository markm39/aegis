#!/bin/bash
set -euo pipefail
INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')

if [ -z "$FILE" ]; then
  echo '{"result": "Usage: /whisperapi <audio_file>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ ! -f "$FILE" ]; then
  RESULT_JSON=$(echo "File not found: $FILE" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo '{"result": "OPENAI_API_KEY not set. Get one at platform.openai.com", "artifacts": [], "messages": []}'
  exit 0
fi

RESP=$(curl -s -X POST "https://api.openai.com/v1/audio/transcriptions" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -F "file=@$FILE" \
  -F "model=whisper-1" 2>&1)

TEXT=$(echo "$RESP" | jq -r '.text // empty' 2>/dev/null)
if [ -n "$TEXT" ]; then
  RESULT="## Transcription\n\n$TEXT"
else
  ERR=$(echo "$RESP" | jq -r '.error.message // "Transcription failed"')
  RESULT="Error: $ERR"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
