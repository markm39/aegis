#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TRANSFORM=$(echo "$INPUT" | jq -r '.parameters.args[0] // "help"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.raw // ""' | sed "s|^/tt $TRANSFORM ||;s|^/transform $TRANSFORM ||")

case "$TRANSFORM" in
  upper|up)    RESULT=$(echo "$TEXT" | tr '[:lower:]' '[:upper:]') ;;
  lower|lo)    RESULT=$(echo "$TEXT" | tr '[:upper:]' '[:lower:]') ;;
  reverse|rev) RESULT=$(echo "$TEXT" | rev) ;;
  b64|base64)  RESULT=$(echo -n "$TEXT" | base64) ;;
  b64d|decode) RESULT=$(echo "$TEXT" | base64 -d 2>&1) ;;
  md5)         RESULT=$(echo -n "$TEXT" | md5 2>/dev/null || echo -n "$TEXT" | md5sum 2>/dev/null | awk '{print $1}') ;;
  sha256)      RESULT=$(echo -n "$TEXT" | shasum -a 256 | awk '{print $1}') ;;
  count|wc)    RESULT="Characters: $(echo -n "$TEXT" | wc -c | tr -d ' ')\nWords: $(echo "$TEXT" | wc -w | tr -d ' ')\nLines: $(echo "$TEXT" | wc -l | tr -d ' ')" ;;
  urlencode)   RESULT=$(echo -n "$TEXT" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))") ;;
  urldecode)   RESULT=$(echo -n "$TEXT" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))") ;;
  help|*)      RESULT="Available transforms: upper, lower, reverse, base64, b64d (decode), md5, sha256, count, urlencode, urldecode\nUsage: /tt <transform> <text>" ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
