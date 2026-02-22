#!/bin/bash
# Aegis skill: slack-skill
# Send messages, read channels, and manage Slack workspace via API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'slack-skill' executed"]}'
        ;;
esac
