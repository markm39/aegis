#!/bin/bash
set -euo pipefail
INPUT=$(cat)
DESC=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$DESC" ]; then
  echo '{"result": "Usage: /canvas <description of diagram>\n\nExamples:\n  /canvas box with text Hello\n  /canvas flowchart: start -> process -> end\n  /canvas table 3x3", "artifacts": [], "messages": []}'
  exit 0
fi

# Simple ASCII diagram generator (temp file avoids heredoc-in-subshell quoting)
PYTMP=$(mktemp /tmp/aegis_canvas_XXXXXX.py)
trap "rm -f $PYTMP" EXIT
cat > "$PYTMP" << 'PYEOF'
import os, sys, re

desc = os.environ.get('CANVAS_DESC', '')

def box(text, width=None):
    lines = text.split('\\n') if '\\n' in text else [text]
    w = width or max(len(l) for l in lines) + 2
    result = ['+-' + '-' * w + '-+']
    for l in lines:
        result.append('| ' + l.ljust(w) + ' |')
    result.append('+-' + '-' * w + '-+')
    return '\n'.join(result)

def flowchart(steps):
    parts = [s.strip() for s in steps.split('->')]
    lines = []
    for i, part in enumerate(parts):
        lines.append(box(part, 20))
        if i < len(parts) - 1:
            lines.append('        |')
            lines.append('        v')
    return '\n'.join(lines)

def table(rows, cols):
    w = 10
    sep = '+' + (('-' * w + '+') * cols)
    lines = [sep]
    for r in range(rows):
        cells = '|' + (''.join(f' R{r+1}C{c+1}'.ljust(w) + '|' for c in range(cols)))
        lines.append(cells)
        lines.append(sep)
    return '\n'.join(lines)

dl = desc.lower()
if 'flowchart' in dl or '->' in dl:
    content = desc.split(':', 1)[-1] if ':' in desc else desc
    print(flowchart(content))
elif 'table' in dl:
    m = re.search(r'(\d+)x(\d+)', desc)
    if m:
        print(table(int(m.group(1)), int(m.group(2))))
    else:
        print(table(3, 3))
elif 'box' in dl:
    text = desc.replace('box', '').replace('with text', '').strip()
    print(box(text or 'Hello'))
else:
    print(box(desc, 40))
PYEOF
RESULT=$(CANVAS_DESC="$DESC" python3 "$PYTMP")

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
