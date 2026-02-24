#!/bin/bash
set -euo pipefail
INPUT=$(cat)
FILENAME=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')

if [ -z "$FILENAME" ]; then
  FILENAME="$HOME/Desktop/webcam-$(date +%Y%m%d-%H%M%S).jpg"
fi

if command -v imagesnap &>/dev/null; then
  imagesnap -w 1.0 "$FILENAME" 2>&1
  if [ -f "$FILENAME" ]; then
    RESULT="Webcam photo saved to: $FILENAME"
  else
    RESULT="Failed to capture webcam photo"
  fi
elif command -v ffmpeg &>/dev/null; then
  ffmpeg -f avfoundation -framerate 1 -i "0" -frames:v 1 "$FILENAME" -y 2>&1
  RESULT="Webcam photo saved to: $FILENAME"
else
  echo '{"result": "No webcam capture tool found. Install with: brew install imagesnap", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
ARTIFACTS="[]"
if [ -f "$FILENAME" ]; then
  ARTIFACTS="[{\"type\": \"file\", \"path\": \"$FILENAME\"}]"
fi
echo "{\"result\": $RESULT_JSON, \"artifacts\": $ARTIFACTS, \"messages\": []}"
