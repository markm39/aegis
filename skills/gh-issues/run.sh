#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v gh &>/dev/null; then
  echo '{"result": "GitHub CLI (gh) is not installed. Install with: brew install gh", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls)    RESULT=$(gh issue list --limit 20 $REST 2>&1) ;;
  view|show)  RESULT=$(gh issue view "$REST" 2>&1) ;;
  create|new)
    TITLE=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    BODY=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')
    if [ -z "$TITLE" ]; then
      RESULT="Usage: /ghissues create <title> [body]"
    else
      RESULT=$(gh issue create --title "$TITLE" --body "${BODY:-No description}" 2>&1)
    fi
    ;;
  close)      RESULT=$(gh issue close "$REST" 2>&1) ;;
  search)     RESULT=$(gh issue list --search "$REST" --limit 10 2>&1) ;;
  *)          RESULT="Unknown subcommand: $SUBCMD. Use: list, view, create, close, search" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
