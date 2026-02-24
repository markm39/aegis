#!/bin/bash
set -euo pipefail
INPUT=$(cat)
URL=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
MODE=$(echo "$INPUT" | jq -r '.parameters.args[1] // "text"')

if [ -z "$URL" ]; then
  echo '{"result": "Usage: /scrape <url> [text|links|all]", "artifacts": [], "messages": []}'
  exit 0
fi

HTML=$(curl -s -L --max-time 15 -H "User-Agent: Mozilla/5.0" "$URL" 2>&1 | head -c 100000)

if [ -z "$HTML" ]; then
  echo '{"result": "Failed to fetch URL. Check the address.", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT=$(echo "$HTML" | python3 -c "
import sys, re, html as htmlmod
from html.parser import HTMLParser

content = sys.stdin.read()
mode = '$MODE'

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.links = []
        self.skip = False
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'noscript'):
            self.skip = True
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if href.startswith('http'):
                self.links.append(href)
    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript'):
            self.skip = False
    def handle_data(self, data):
        if not self.skip:
            t = data.strip()
            if t:
                self.text.append(t)

parser = TextExtractor()
parser.feed(content)

if mode == 'links':
    unique = list(dict.fromkeys(parser.links))
    for link in unique[:30]:
        print(link)
elif mode == 'text':
    print(' '.join(parser.text)[:6000])
else:
    print('## Text')
    print(' '.join(parser.text)[:4000])
    print()
    print('## Links')
    unique = list(dict.fromkeys(parser.links))
    for link in unique[:20]:
        print(f'- {link}')
" 2>&1)

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
