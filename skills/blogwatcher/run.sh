#!/bin/bash
set -euo pipefail
INPUT=$(cat)
URL=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
LIMIT=$(echo "$INPUT" | jq -r '.parameters.args[1] // "10"')

if [ -z "$URL" ]; then
  echo '{"result": "Usage: /rss <feed_url> [limit]\n\nExample: /rss https://news.ycombinator.com/rss 5", "artifacts": [], "messages": []}'
  exit 0
fi

FEED=$(curl -s -L --max-time 15 "$URL" 2>&1)

if [ -z "$FEED" ]; then
  echo '{"result": "Failed to fetch feed. Check the URL.", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT=$(echo "$FEED" | python3 -c "
import sys, xml.etree.ElementTree as ET, html
limit = int('$LIMIT')
content = sys.stdin.read()
try:
    root = ET.fromstring(content)
except ET.ParseError:
    print('Failed to parse feed XML')
    sys.exit(0)

items = root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry')
output = []
for item in items[:limit]:
    title = item.findtext('title') or item.findtext('{http://www.w3.org/2005/Atom}title') or 'Untitled'
    link = item.findtext('link') or ''
    if not link:
        link_el = item.find('{http://www.w3.org/2005/Atom}link')
        if link_el is not None:
            link = link_el.get('href', '')
    pubdate = item.findtext('pubDate') or item.findtext('{http://www.w3.org/2005/Atom}published') or ''
    title = html.unescape(title.strip())
    output.append(f'- [{title}]({link})')
    if pubdate:
        output.append(f'  {pubdate}')

if output:
    print('\n'.join(output))
else:
    print('No items found in feed')
" 2>&1)

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
