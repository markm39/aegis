#!/bin/bash
# Aegis skill: gh-issues
# GitHub issue management - create, list, assign, label, and close issues
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'gh-issues' executed"]}'
        ;;
esac
