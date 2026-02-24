#!/bin/bash
set -euo pipefail
INPUT=$(cat)
QUERY=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$QUERY" ]; then
  echo '{"result": "Usage: /places <search query, e.g. coffee shops near me>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${GOOGLE_MAPS_API_KEY:-}" ]; then
  echo '{"result": "GOOGLE_MAPS_API_KEY not set. Get one at console.cloud.google.com", "artifacts": [], "messages": []}'
  exit 0
fi

ENCODED=$(echo -n "$QUERY" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")
RESP=$(curl -s "https://maps.googleapis.com/maps/api/place/textsearch/json?query=$ENCODED&key=$GOOGLE_MAPS_API_KEY" 2>&1)

RESULT=$(echo "$RESP" | jq -r '.results[:8][] | "\(.name)\n  Rating: \(.rating // "N/A") | \(.formatted_address)\n"' 2>/dev/null || echo "Search failed")
if [ -z "$RESULT" ]; then RESULT="No places found for: $QUERY"; fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
