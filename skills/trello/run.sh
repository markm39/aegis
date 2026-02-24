#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "boards"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "${TRELLO_API_KEY:-}" ] || [ -z "${TRELLO_TOKEN:-}" ]; then
  echo '{"result": "TRELLO_API_KEY and TRELLO_TOKEN not set. Get them at trello.com/power-ups/admin", "artifacts": [], "messages": []}'
  exit 0
fi

API="https://api.trello.com/1"
AUTH="key=$TRELLO_API_KEY&token=$TRELLO_TOKEN"

case "$SUBCMD" in
  boards|list)
    RESULT=$(curl -s "$API/members/me/boards?$AUTH&fields=name,url" | jq -r '.[] | "\(.name)  [\(.id)]"' 2>/dev/null | head -20 || echo "Failed to list boards")
    ;;
  cards)
    BOARD=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    if [ -z "$BOARD" ]; then
      RESULT="Usage: /trello cards <board_id>"
    else
      RESULT=$(curl -s "$API/boards/$BOARD/cards?$AUTH&fields=name,idList,due" | jq -r '.[] | "\(.name)"' 2>/dev/null | head -30 || echo "Failed to list cards")
    fi
    ;;
  create)
    LIST_ID=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    NAME=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')
    if [ -z "$LIST_ID" ] || [ -z "$NAME" ]; then
      RESULT="Usage: /trello create <list_id> <card_name>"
    else
      CARD_NAME_ENC=$(echo -n "$NAME" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")
      RESP=$(curl -s -X POST "$API/cards?$AUTH&idList=$LIST_ID&name=$CARD_NAME_ENC")
      if echo "$RESP" | jq -e '.id' &>/dev/null; then
        RESULT="Card created: $NAME"
      else
        RESULT="Failed to create card"
      fi
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: boards, cards, create"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
