#!/bin/bash
set -euo pipefail
INPUT=$(cat)
MODEL_KEY=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MODEL_INPUT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "$MODEL_KEY" ]; then
  echo '{"result": "Usage: /banana <model_key> <input>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${BANANA_API_KEY:-}" ]; then
  echo '{"result": "BANANA_API_KEY not set. Get one at banana.dev", "artifacts": [], "messages": []}'
  exit 0
fi

RESP=$(curl -s -X POST "https://api.banana.dev/start/v4" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg key "$BANANA_API_KEY" --arg model "$MODEL_KEY" --arg prompt "$MODEL_INPUT" '{apiKey:$key,modelKey:$model,modelInputs:{prompt:$prompt}}')" 2>&1)

RESULT=$(echo "$RESP" | jq -r '.modelOutputs[0] // .message // "No output"' 2>/dev/null || echo "$RESP")
RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
