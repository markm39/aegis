#!/bin/bash
set -euo pipefail
INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$PROMPT" ]; then
  echo '{"result": "Usage: /gemini <your question or prompt>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${GOOGLE_API_KEY:-}" ]; then
  echo '{"result": "GOOGLE_API_KEY not set. Get one at aistudio.google.com/apikey", "artifacts": [], "messages": []}'
  exit 0
fi

ESCAPED_PROMPT=$(echo "$PROMPT" | jq -Rs .)
RESP=$(curl -s -X POST \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$GOOGLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"contents\":[{\"parts\":[{\"text\":$ESCAPED_PROMPT}]}]}" 2>&1)

TEXT=$(echo "$RESP" | jq -r '.candidates[0].content.parts[0].text // empty' 2>/dev/null)
if [ -n "$TEXT" ]; then
  RESULT="$TEXT"
else
  ERR=$(echo "$RESP" | jq -r '.error.message // "Request failed"' 2>/dev/null)
  RESULT="Error: $ERR"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
