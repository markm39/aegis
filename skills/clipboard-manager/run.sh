#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "get"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

case "$SUBCMD" in
  get|read|paste)
    CONTENT=$(pbpaste 2>/dev/null || xclip -selection clipboard -o 2>/dev/null || echo "Clipboard access failed")
    RESULT="Clipboard contents:\n\n${CONTENT:0:4000}"
    ;;
  set|write|copy)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /clipboard set <text to copy>"
    else
      echo -n "$TEXT" | pbcopy 2>/dev/null || echo -n "$TEXT" | xclip -selection clipboard 2>/dev/null
      RESULT="Copied to clipboard: ${TEXT:0:100}$([ ${#TEXT} -gt 100 ] && echo '...')"
    fi
    ;;
  clear)
    echo -n "" | pbcopy 2>/dev/null || echo -n "" | xclip -selection clipboard 2>/dev/null
    RESULT="Clipboard cleared"
    ;;
  count|len)
    CONTENT=$(pbpaste 2>/dev/null || echo "")
    CHARS=${#CONTENT}
    WORDS=$(echo "$CONTENT" | wc -w | tr -d ' ')
    LINES=$(echo "$CONTENT" | wc -l | tr -d ' ')
    RESULT="Clipboard: $CHARS chars, $WORDS words, $LINES lines"
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: get, set, clear, count"
    ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
