#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TO=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MSG=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "$TO" ] || [ -z "$MSG" ]; then
  echo '{"result": "Usage: /call <phone_number> <message_to_speak>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${TWILIO_ACCOUNT_SID:-}" ] || [ -z "${TWILIO_AUTH_TOKEN:-}" ] || [ -z "${TWILIO_PHONE_NUMBER:-}" ]; then
  echo '{"result": "Twilio credentials not set. Export TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_PHONE_NUMBER.", "artifacts": [], "messages": []}'
  exit 0
fi

TWIML="<Response><Say>$MSG</Say></Response>"
ENCODED_TWIML=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TWIML'))")

RESP=$(curl -s -X POST "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Calls.json" \
  -u "$TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN" \
  -d "To=$TO" \
  -d "From=$TWILIO_PHONE_NUMBER" \
  -d "Twiml=$TWIML" 2>&1)

SID=$(echo "$RESP" | jq -r '.sid // empty' 2>/dev/null)
if [ -n "$SID" ]; then
  RESULT="Call initiated to $TO (SID: $SID)"
else
  ERR=$(echo "$RESP" | jq -r '.message // "Call failed"')
  RESULT="Error: $ERR"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
