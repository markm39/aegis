#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TO=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MSG=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "$TO" ] || [ -z "$MSG" ]; then
  echo '{"result": "Usage: /whatsapp <phone_number> <message>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${WHATSAPP_API_TOKEN:-}" ] || [ -z "${WHATSAPP_PHONE_ID:-}" ]; then
  echo '{"result": "WHATSAPP_API_TOKEN and WHATSAPP_PHONE_ID not set. Get them from Meta Business Suite.", "artifacts": [], "messages": []}'
  exit 0
fi

RESP=$(curl -s -X POST "https://graph.facebook.com/v18.0/$WHATSAPP_PHONE_ID/messages" \
  -H "Authorization: Bearer $WHATSAPP_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg to "$TO" --arg msg "$MSG" '{messaging_product:"whatsapp",to:$to,type:"text",text:{body:$msg}}')" 2>&1)

if echo "$RESP" | jq -e '.messages[0].id' &>/dev/null; then
  RESULT="Message sent to $TO"
else
  ERR=$(echo "$RESP" | jq -r '.error.message // "Send failed"')
  RESULT="Error: $ERR"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
