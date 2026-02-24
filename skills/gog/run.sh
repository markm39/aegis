#!/bin/bash
set -euo pipefail
INPUT=$(cat)
QUERY=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$QUERY" ]; then
  echo '{"result": "Usage: /google <search query>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${GOOGLE_API_KEY:-}" ] || [ -z "${GOOGLE_CSE_ID:-}" ]; then
  # Fall back to scraping
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY'))")
  RESULT=$(curl -s -L --max-time 10 -H "User-Agent: Mozilla/5.0" \
    "https://www.google.com/search?q=$ENCODED" 2>&1 | \
    python3 -c "
import sys, html, re
c = sys.stdin.read()
titles = re.findall(r'<h3[^>]*>([^<]+)</h3>', c)
for i, t in enumerate(titles[:8]):
    print(f'{i+1}. {html.unescape(t)}')
if not titles:
    print('No results parsed. Set GOOGLE_API_KEY and GOOGLE_CSE_ID for reliable results.')
" 2>&1)
else
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY'))")
  RESULT=$(curl -s "https://www.googleapis.com/customsearch/v1?key=$GOOGLE_API_KEY&cx=$GOOGLE_CSE_ID&q=$ENCODED&num=8" | \
    jq -r '.items[]? | "\(.title)\n  \(.link)\n  \(.snippet // "")\n"' 2>/dev/null | head -40 || echo "Search failed")
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
