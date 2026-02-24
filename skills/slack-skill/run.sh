#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "channels"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "${SLACK_BOT_TOKEN:-}" ]; then
  echo '{"result": "SLACK_BOT_TOKEN not set. Export your Slack bot token to use this skill.", "artifacts": [], "messages": []}'
  exit 0
fi

API="https://slack.com/api"
AUTH="Authorization: Bearer $SLACK_BOT_TOKEN"

case "$SUBCMD" in
  channels|list)
    RESULT=$(curl -s -H "$AUTH" "$API/conversations.list?limit=20&types=public_channel,private_channel" | jq -r '.channels[] | "#\(.name)  [\(.num_members) members]"' 2>/dev/null | head -20 || echo "Failed to list channels")
    ;;
  send|post)
    CHANNEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    MSG=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')
    if [ -z "$CHANNEL" ] || [ -z "$MSG" ]; then
      RESULT="Usage: /slack send <channel> <message>"
    else
      BODY=$(jq -n --arg ch "$CHANNEL" --arg txt "$MSG" '{channel:$ch,text:$txt}')
      RESP=$(curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" -d "$BODY" "$API/chat.postMessage")
      OK=$(echo "$RESP" | jq -r '.ok')
      if [ "$OK" = "true" ]; then
        RESULT="Message sent to #$CHANNEL"
      else
        ERR=$(echo "$RESP" | jq -r '.error // "unknown error"')
        RESULT="Failed to send: $ERR"
      fi
    fi
    ;;
  read|history)
    CHANNEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    if [ -z "$CHANNEL" ]; then
      RESULT="Usage: /slack read <channel_id>"
    else
      RESULT=$(curl -s -H "$AUTH" "$API/conversations.history?channel=$CHANNEL&limit=10" | jq -r '.messages[]? | "\(.user // "bot"): \(.text)"' 2>/dev/null | head -20 || echo "Failed to read channel")
    fi
    ;;
  search)
    if [ -z "$REST" ]; then
      RESULT="Usage: /slack search <query>"
    else
      ENCODED=$(echo -n "$REST" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")
      RESULT=$(curl -s -H "$AUTH" "$API/search.messages?query=$ENCODED&count=5" | jq -r '.messages.matches[]? | "\(.channel.name): \(.text)"' 2>/dev/null | head -15 || echo "Search failed")
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: channels, send, read, search"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
