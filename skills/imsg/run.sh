#!/bin/bash
set -euo pipefail
INPUT=$(cat)
RECIPIENT=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MESSAGE=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "$RECIPIENT" ] || [ -z "$MESSAGE" ]; then
  echo '{"result": "Usage: /imessage <phone_or_email> <message>", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT=$(osascript -e "
  tell application \"Messages\"
    set targetService to 1st account whose service type = iMessage
    set targetBuddy to participant \"$RECIPIENT\" of targetService
    send \"$MESSAGE\" to targetBuddy
    return \"Message sent to $RECIPIENT\"
  end tell
" 2>&1)

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
