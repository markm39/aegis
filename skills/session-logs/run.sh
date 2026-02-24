#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
QUERY=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

SESSIONS_DIR="${HOME}/.aegis/sessions"

if [ ! -d "$SESSIONS_DIR" ]; then
  echo '{"result": "No sessions directory found at ~/.aegis/sessions", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls)
    RESULT="## Recent Sessions\n\n"
    RESULT="$RESULT$(ls -lt "$SESSIONS_DIR" 2>/dev/null | head -20)"
    ;;
  search|find)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /sessionlogs search <keyword>"
    else
      RESULT="## Search results for: $QUERY\n\n"
      MATCHES=$(grep -rl "$QUERY" "$SESSIONS_DIR" 2>/dev/null | head -10)
      if [ -n "$MATCHES" ]; then
        for f in $MATCHES; do
          BASENAME=$(basename "$f")
          RESULT="$RESULT- $BASENAME\n"
        done
      else
        RESULT="${RESULT}No sessions matching: $QUERY"
      fi
    fi
    ;;
  show|view)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /sessionlogs show <session_id_or_filename>"
    else
      # Try direct match or partial
      FILE=$(find "$SESSIONS_DIR" -name "*${QUERY}*" 2>/dev/null | head -1)
      if [ -n "$FILE" ] && [ -f "$FILE" ]; then
        RESULT=$(head -c 6000 "$FILE")
      else
        RESULT="Session not found: $QUERY"
      fi
    fi
    ;;
  stats)
    TOTAL=$(ls "$SESSIONS_DIR" 2>/dev/null | wc -l | tr -d ' ')
    RECENT=$(find "$SESSIONS_DIR" -mtime -1 2>/dev/null | wc -l | tr -d ' ')
    SIZE=$(du -sh "$SESSIONS_DIR" 2>/dev/null | awk '{print $1}')
    RESULT="## Session Stats\n\n- Total sessions: $TOTAL\n- Last 24h: $RECENT\n- Total size: ${SIZE:-unknown}"
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, search, show, stats"
    ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
