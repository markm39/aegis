#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "status"')

if [ -z "${EIGHT_SLEEP_EMAIL:-}" ] || [ -z "${EIGHT_SLEEP_PASSWORD:-}" ]; then
  echo '{"result": "EIGHT_SLEEP_EMAIL and EIGHT_SLEEP_PASSWORD not set.", "artifacts": [], "messages": []}'
  exit 0
fi

# Eight Sleep API requires OAuth token
TOKEN=$(curl -s -X POST "https://client-api.8slp.net/v1/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EIGHT_SLEEP_EMAIL\",\"password\":\"$EIGHT_SLEEP_PASSWORD\"}" | jq -r '.session.token // empty' 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo '{"result": "Failed to authenticate with Eight Sleep. Check credentials.", "artifacts": [], "messages": []}'
  exit 0
fi

AUTH="Authorization: Bearer $TOKEN"
API="https://client-api.8slp.net/v1"

case "$SUBCMD" in
  status)
    RESULT=$(curl -s -H "$AUTH" "$API/users/me" | jq '{email: .user.email, devices: [.user.devices[]?.id]}' 2>/dev/null || echo "Failed to get status")
    ;;
  temp|temperature)
    LEVEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    SIDE=$(echo "$INPUT" | jq -r '.parameters.args[2] // "left"')
    if [ -z "$LEVEL" ]; then
      RESULT="Usage: /eightsleep temp <level -10 to 10> [left|right]"
    else
      RESULT="Temperature control requires device-specific API calls. Level: $LEVEL, Side: $SIDE"
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: status, temp"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
