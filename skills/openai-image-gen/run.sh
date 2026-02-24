#!/bin/bash
set -euo pipefail
INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$PROMPT" ]; then
  echo '{"result": "Usage: /imagegen <description of image>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo '{"result": "OPENAI_API_KEY not set. Get one at platform.openai.com", "artifacts": [], "messages": []}'
  exit 0
fi

RESP=$(curl -s -X POST "https://api.openai.com/v1/images/generations" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"dall-e-3\",\"prompt\":\"$PROMPT\",\"n\":1,\"size\":\"1024x1024\"}" 2>&1)

URL=$(echo "$RESP" | jq -r '.data[0].url // empty' 2>/dev/null)
if [ -n "$URL" ]; then
  RESULT="Image generated!\n\nURL: $URL\n\nRevised prompt: $(echo "$RESP" | jq -r '.data[0].revised_prompt // "N/A"')"
else
  ERR=$(echo "$RESP" | jq -r '.error.message // "Unknown error"')
  RESULT="Failed to generate image: $ERR"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
