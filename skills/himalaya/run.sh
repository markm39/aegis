#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v himalaya &>/dev/null; then
  echo '{"result": "himalaya is not installed. Install with: brew install himalaya", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls|inbox) RESULT=$(himalaya list --page-size 15 2>&1) ;;
  read|show)
    if [ -z "$REST" ]; then
      RESULT="Usage: /email read <message_id>"
    else
      RESULT=$(himalaya read "$REST" 2>&1 | head -100)
    fi
    ;;
  send)
    TO=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    SUBJECT=$(echo "$INPUT" | jq -r '.parameters.args[2] // ""')
    BODY=$(echo "$INPUT" | jq -r '.parameters.args[3:] | join(" ")')
    if [ -z "$TO" ] || [ -z "$SUBJECT" ]; then
      RESULT="Usage: /email send <to> <subject> <body>"
    else
      RESULT=$(echo "$BODY" | himalaya send --to "$TO" --subject "$SUBJECT" 2>&1 || echo "Failed to send. Check himalaya config.")
    fi
    ;;
  folders)  RESULT=$(himalaya folders 2>&1) ;;
  *)        RESULT="Unknown subcommand: $SUBCMD. Use: list, read, send, folders" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
