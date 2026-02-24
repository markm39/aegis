#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "guilds"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "${DISCORD_BOT_TOKEN:-}" ]; then
  echo '{"result": "DISCORD_BOT_TOKEN not set. Export your Discord bot token to use this skill.", "artifacts": [], "messages": []}'
  exit 0
fi

API="https://discord.com/api/v10"
AUTH="Authorization: Bot $DISCORD_BOT_TOKEN"

case "$SUBCMD" in
  guilds|servers)
    RESULT=$(curl -s -H "$AUTH" "$API/users/@me/guilds" | jq -r '.[] | "\(.name)  [id: \(.id)]"' 2>/dev/null | head -20 || echo "Failed to list guilds")
    ;;
  channels)
    GUILD=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    if [ -z "$GUILD" ]; then
      RESULT="Usage: /discord channels <guild_id>"
    else
      RESULT=$(curl -s -H "$AUTH" "$API/guilds/$GUILD/channels" | jq -r '.[] | select(.type == 0) | "#\(.name)  [id: \(.id)]"' 2>/dev/null | head -20 || echo "Failed to list channels")
    fi
    ;;
  send)
    CHANNEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    MSG=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')
    if [ -z "$CHANNEL" ] || [ -z "$MSG" ]; then
      RESULT="Usage: /discord send <channel_id> <message>"
    else
      BODY=$(jq -n --arg content "$MSG" '{content: $content}')
      RESP=$(curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" -d "$BODY" "$API/channels/$CHANNEL/messages")
      if echo "$RESP" | jq -e '.id' &>/dev/null; then
        RESULT="Message sent to channel $CHANNEL"
      else
        RESULT="Failed: $(echo "$RESP" | jq -r '.message // "unknown error"')"
      fi
    fi
    ;;
  read)
    CHANNEL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    if [ -z "$CHANNEL" ]; then
      RESULT="Usage: /discord read <channel_id>"
    else
      RESULT=$(curl -s -H "$AUTH" "$API/channels/$CHANNEL/messages?limit=10" | jq -r '.[] | "\(.author.username): \(.content)"' 2>/dev/null | head -20 || echo "Failed to read")
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: guilds, channels, send, read"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
