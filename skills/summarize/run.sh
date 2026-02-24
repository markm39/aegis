#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TARGET=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$TARGET" ]; then
  echo '{"result": "Usage: /tldr <text, file path, or URL to summarize>", "artifacts": [], "messages": []}'
  exit 0
fi

# Determine if input is a URL, file, or raw text
CONTENT=""
if [[ "$TARGET" =~ ^https?:// ]]; then
  CONTENT=$(curl -s -L --max-time 15 "$TARGET" | python3 -c "
import sys, re, html
text = sys.stdin.read()
text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
text = re.sub(r'<[^>]+>', ' ', text)
text = html.unescape(text)
text = re.sub(r'\s+', ' ', text).strip()
print(text[:6000])
" 2>&1)
elif [ -f "$TARGET" ]; then
  CONTENT=$(head -c 6000 "$TARGET")
else
  CONTENT="$TARGET"
fi

if [ -z "$CONTENT" ]; then
  echo '{"result": "Could not extract content to summarize.", "artifacts": [], "messages": []}'
  exit 0
fi

# Use python for extractive summary (temp file avoids heredoc-in-subshell quoting)
PYTMP=$(mktemp /tmp/aegis_summarize_XXXXXX.py)
trap "rm -f $PYTMP" EXIT
cat > "$PYTMP" << 'PYEOF'
import os, sys

text = os.environ.get('SUMMARIZE_CONTENT', '')

# Simple extractive summarization: score sentences by word frequency
sentences = [s.strip() for s in text.replace('\n', ' ').split('.') if len(s.strip()) > 20]
if not sentences:
    print(text[:500])
    sys.exit(0)

words = text.lower().split()
freq = {}
for w in words:
    w = w.strip('.,!?;:()[]"\'')
    if len(w) > 3:
        freq[w] = freq.get(w, 0) + 1

scored = []
for s in sentences:
    score = sum(freq.get(w.lower().strip('.,!?'), 0) for w in s.split())
    scored.append((score, s))

scored.sort(reverse=True)
top = scored[:5]
# Re-order by original position
top_sentences = [s for _, s in sorted(top, key=lambda x: sentences.index(x[1]))]
summary = '. '.join(top_sentences) + '.'
print(f"## Summary\n\n{summary}\n\n---\nOriginal: {len(text)} chars -> Summary: {len(summary)} chars")
PYEOF
RESULT=$(SUMMARIZE_CONTENT="$CONTENT" python3 "$PYTMP")

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
