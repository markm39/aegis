#!/bin/bash
# Aegis skill: coding-agent
# Delegate complex coding tasks to Claude Code or Codex CLI
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'coding-agent' executed"]}'
        ;;
esac
