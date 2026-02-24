#!/bin/bash
set -euo pipefail
INPUT=$(cat)
PERIOD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "today"')

AEGIS_DIR="${HOME}/.aegis"
SESSIONS_DIR="$AEGIS_DIR/sessions"

if [ ! -d "$AEGIS_DIR" ]; then
  echo '{"result": "No Aegis data directory found at ~/.aegis", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT="## Token Usage Summary\n\n"

# Count session files
if [ -d "$SESSIONS_DIR" ]; then
  TOTAL_SESSIONS=$(ls "$SESSIONS_DIR" 2>/dev/null | wc -l | tr -d ' ')
  RESULT="$RESULT- Total sessions: $TOTAL_SESSIONS\n"

  case "$PERIOD" in
    today)
      TODAY=$(date +%Y-%m-%d)
      COUNT=$(find "$SESSIONS_DIR" -name "*.json" -newer /tmp/.aegis_today_marker 2>/dev/null | wc -l | tr -d ' ' || echo "0")
      touch -t "$(date +%Y%m%d)0000" /tmp/.aegis_today_marker 2>/dev/null
      COUNT=$(find "$SESSIONS_DIR" -name "*.json" -newer /tmp/.aegis_today_marker 2>/dev/null | wc -l | tr -d ' ' || echo "0")
      RESULT="$RESULT- Sessions today: $COUNT\n"
      ;;
    week)
      COUNT=$(find "$SESSIONS_DIR" -name "*.json" -mtime -7 2>/dev/null | wc -l | tr -d ' ' || echo "0")
      RESULT="$RESULT- Sessions this week: $COUNT\n"
      ;;
    month)
      COUNT=$(find "$SESSIONS_DIR" -name "*.json" -mtime -30 2>/dev/null | wc -l | tr -d ' ' || echo "0")
      RESULT="$RESULT- Sessions this month: $COUNT\n"
      ;;
  esac
else
  RESULT="$RESULT- No sessions directory found\n"
fi

# Check disk usage
DISK_USAGE=$(du -sh "$AEGIS_DIR" 2>/dev/null | awk '{print $1}')
RESULT="$RESULT- Aegis data size: ${DISK_USAGE:-unknown}\n"

# List recent audit database size if it exists
if [ -f "$AEGIS_DIR/audit.db" ]; then
  DB_SIZE=$(ls -lh "$AEGIS_DIR/audit.db" | awk '{print $5}')
  RESULT="$RESULT- Audit database: $DB_SIZE\n"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
