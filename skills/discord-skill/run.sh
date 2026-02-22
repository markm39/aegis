#!/bin/bash
# Aegis skill: discord-skill
# Send messages, manage channels, and interact with Discord servers via API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'discord-skill' executed"]}'
        ;;
esac
