#!/bin/bash
set -euo pipefail
INPUT=$(cat)
QUESTION=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$QUESTION" ]; then
  echo '{"result": "Usage: /oracle <your question>", "artifacts": [], "messages": []}'
  exit 0
fi

ESCAPED=$(echo "$QUESTION" | jq -Rs .)
RESULT="## Oracle Responses\n\n"
FOUND=false

# Try OpenAI
if [ -n "${OPENAI_API_KEY:-}" ]; then
  FOUND=true
  RESP=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":$ESCAPED}],\"max_tokens\":500}" 2>&1)
  TEXT=$(echo "$RESP" | jq -r '.choices[0].message.content // "Error"' 2>/dev/null)
  RESULT="$RESULT### OpenAI (GPT-4o-mini)\n$TEXT\n\n"
fi

# Try Anthropic
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  FOUND=true
  RESP=$(curl -s -X POST "https://api.anthropic.com/v1/messages" \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":500,\"messages\":[{\"role\":\"user\",\"content\":$ESCAPED}]}" 2>&1)
  TEXT=$(echo "$RESP" | jq -r '.content[0].text // "Error"' 2>/dev/null)
  RESULT="$RESULT### Anthropic (Claude Haiku)\n$TEXT\n\n"
fi

# Try Google Gemini
if [ -n "${GOOGLE_API_KEY:-}" ]; then
  FOUND=true
  RESP=$(curl -s -X POST \
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$GOOGLE_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"contents\":[{\"parts\":[{\"text\":$ESCAPED}]}]}" 2>&1)
  TEXT=$(echo "$RESP" | jq -r '.candidates[0].content.parts[0].text // "Error"' 2>/dev/null)
  RESULT="$RESULT### Google (Gemini Flash)\n$TEXT\n\n"
fi

if [ "$FOUND" = false ]; then
  RESULT="No LLM API keys found. Set one or more of: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
