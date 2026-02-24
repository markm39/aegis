#!/bin/bash
set -euo pipefail
INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
PAGES=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')

if [ -z "$FILE" ]; then
  echo '{"result": "Usage: /pdf <file.pdf> [page_range, e.g. 1-5]", "artifacts": [], "messages": []}'
  exit 0
fi

if [ ! -f "$FILE" ]; then
  RESULT_JSON=$(echo "File not found: $FILE" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

# Try pdftotext first, then python
if command -v pdftotext &>/dev/null; then
  if [ -n "$PAGES" ]; then
    FIRST=$(echo "$PAGES" | cut -d- -f1)
    LAST=$(echo "$PAGES" | cut -d- -f2)
    RESULT=$(pdftotext -f "$FIRST" -l "$LAST" "$FILE" - 2>&1 | head -c 8000)
  else
    RESULT=$(pdftotext "$FILE" - 2>&1 | head -c 8000)
  fi
elif python3 -c "import PyPDF2" 2>/dev/null; then
  RESULT=$(python3 -c "
import PyPDF2, sys
reader = PyPDF2.PdfReader('$FILE')
pages = range(len(reader.pages))
if '$PAGES':
    parts = '$PAGES'.split('-')
    start = int(parts[0]) - 1
    end = int(parts[-1]) if len(parts) > 1 else start + 1
    pages = range(start, min(end, len(reader.pages)))
text = ''
for i in pages:
    text += reader.pages[i].extract_text() + '\n'
print(text[:8000])
" 2>&1)
else
  RESULT="No PDF reader available. Install with: brew install poppler (for pdftotext) or pip install PyPDF2"
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
