#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "search"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${TEXT}'))" 2>/dev/null || echo "$TEXT")

case "$SUBCMD" in
  create|new)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /bear create <note text>"
    else
      open "bear://x-callback-url/create?text=$ENCODED" 2>/dev/null
      RESULT="Created new Bear note"
    fi
    ;;
  search|find)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /bear search <query>"
    else
      open "bear://x-callback-url/search?term=$ENCODED" 2>/dev/null
      RESULT="Opened Bear search for: $TEXT"
    fi
    ;;
  open)
    open "bear://x-callback-url/open-note?title=$ENCODED" 2>/dev/null
    RESULT="Opened Bear note: $TEXT"
    ;;
  tags)
    open "bear://x-callback-url/tags" 2>/dev/null
    RESULT="Opened Bear tags view"
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: create, search, open, tags"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
