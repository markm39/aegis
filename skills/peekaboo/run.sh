#!/bin/bash
set -euo pipefail
INPUT=$(cat)
MODE=$(echo "$INPUT" | jq -r '.parameters.args[0] // "full"')
FILENAME=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')

if [ -z "$FILENAME" ]; then
  FILENAME="$HOME/Desktop/screenshot-$(date +%Y%m%d-%H%M%S).png"
fi

case "$MODE" in
  full|screen)
    screencapture -x "$FILENAME" 2>&1
    RESULT="Screenshot saved to: $FILENAME"
    ;;
  window|win)
    screencapture -w -x "$FILENAME" 2>&1
    RESULT="Window screenshot saved to: $FILENAME (click a window to capture)"
    ;;
  area|region|select)
    screencapture -s -x "$FILENAME" 2>&1
    RESULT="Area screenshot saved to: $FILENAME"
    ;;
  clipboard|clip)
    screencapture -c -x 2>&1
    RESULT="Screenshot copied to clipboard"
    ;;
  *)
    RESULT="Unknown mode: $MODE. Use: full, window, area, clipboard"
    ;;
esac

ARTIFACTS="[]"
if [ -f "$FILENAME" ]; then
  SIZE=$(stat -f%z "$FILENAME" 2>/dev/null || stat -c%s "$FILENAME" 2>/dev/null || echo "unknown")
  ARTIFACTS="[{\"type\": \"file\", \"path\": \"$FILENAME\", \"size\": \"$SIZE bytes\"}]"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": $ARTIFACTS, \"messages\": []}"
