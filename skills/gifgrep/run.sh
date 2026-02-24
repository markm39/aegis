#!/bin/bash
set -euo pipefail
INPUT=$(cat)
QUERY=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$QUERY" ]; then
  echo '{"result": "Usage: /gif <search query>", "artifacts": [], "messages": []}'
  exit 0
fi

ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY'))")
# Use Tenor's free API (with default key for anonymous access)
TENOR_KEY="${TENOR_API_KEY:-AIzaSyAyimkuYQYF_FXVALexPuGQctUWRURdCYQ}"
RESP=$(curl -s "https://tenor.googleapis.com/v2/search?q=$ENCODED&key=$TENOR_KEY&limit=5&media_filter=gif" 2>&1)

RESULT=$(echo "$RESP" | jq -r '.results[]? | "\(.content_description // .title // "GIF")\n  \(.media_formats.gif.url // .url)\n"' 2>/dev/null | head -20)
if [ -z "$RESULT" ]; then
  RESULT="No GIFs found for: $QUERY"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
