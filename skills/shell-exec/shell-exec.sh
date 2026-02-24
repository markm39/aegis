#!/bin/bash
set -euo pipefail
INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.parameters.raw // ""' | sed 's|^/sh ||;s|^/exec ||;s|^/run ||')

if [ -z "$CMD" ]; then
  echo '{"result": "Usage: /sh <command>", "artifacts": [], "messages": []}'
  exit 0
fi

TMPOUT=$(mktemp)
TMPERR=$(mktemp)
trap "rm -f $TMPOUT $TMPERR" EXIT

TIMEOUT_CMD="timeout"
if ! command -v timeout &>/dev/null; then
  if command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout"
  else
    TIMEOUT_CMD=""
  fi
fi

EXIT_CODE=0
if [ -n "$TIMEOUT_CMD" ]; then
  $TIMEOUT_CMD 25 bash -c "$CMD" >"$TMPOUT" 2>"$TMPERR" || EXIT_CODE=$?
else
  bash -c "$CMD" >"$TMPOUT" 2>"$TMPERR" || EXIT_CODE=$?
fi

STDOUT=$(head -c 8000 "$TMPOUT")
STDERR=$(head -c 2000 "$TMPERR")

RESULT="Exit code: $EXIT_CODE"
if [ -n "$STDOUT" ]; then
  RESULT="$RESULT\n\n--- stdout ---\n$STDOUT"
fi
if [ -n "$STDERR" ]; then
  RESULT="$RESULT\n\n--- stderr ---\n$STDERR"
fi

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
