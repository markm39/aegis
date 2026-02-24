#!/bin/bash
set -euo pipefail
INPUT=$(cat)
URL=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
EXPECTED=$(echo "$INPUT" | jq -r '.parameters.args[1] // "200"')

if [ -z "$URL" ]; then
  echo '{"result": "Usage: /healthcheck <url> [expected_status_code]\n\nExample: /healthcheck https://api.example.com/health 200", "artifacts": [], "messages": []}'
  exit 0
fi

START=$(python3 -c "import time; print(time.time())")

RESP=$(curl -s -o /dev/null -w "%{http_code} %{time_total} %{size_download} %{ssl_verify_result}" \
  -L --max-time 15 "$URL" 2>&1)

STATUS=$(echo "$RESP" | awk '{print $1}')
TIME=$(echo "$RESP" | awk '{print $2}')
SIZE=$(echo "$RESP" | awk '{print $3}')
SSL=$(echo "$RESP" | awk '{print $4}')

if [ "$STATUS" = "000" ]; then
  RESULT="FAIL: Could not connect to $URL"
elif [ "$STATUS" = "$EXPECTED" ]; then
  RESULT="OK: $URL\n  Status: $STATUS (expected $EXPECTED)\n  Latency: ${TIME}s\n  Size: ${SIZE} bytes\n  SSL: $([ "$SSL" = "0" ] && echo "valid" || echo "warning: code $SSL")"
else
  RESULT="FAIL: $URL\n  Status: $STATUS (expected $EXPECTED)\n  Latency: ${TIME}s\n  Size: ${SIZE} bytes"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
