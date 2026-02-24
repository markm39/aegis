#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TASK=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')
WORKSPACE=$(echo "$INPUT" | jq -r '.context.workspace_path // "."')

if [ -z "$TASK" ]; then
  echo '{"result": "Usage: /delegate <task description for the coding agent>", "artifacts": [], "messages": []}'
  exit 0
fi

# Try claude first, then codex
if command -v claude &>/dev/null; then
  RESULT=$(cd "$WORKSPACE" && echo "$TASK" | timeout 120 claude --print 2>&1 | head -c 8000)
elif command -v codex &>/dev/null; then
  RESULT=$(cd "$WORKSPACE" && codex --quiet "$TASK" 2>&1 | head -c 8000)
else
  echo '{"result": "No coding agent found. Install claude (Claude Code) or codex (OpenAI Codex CLI).", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
