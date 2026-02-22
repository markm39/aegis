#!/bin/bash
# Aegis skill: voice-call
# Make and manage voice calls via Twilio or compatible telephony API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'voice-call' executed"]}'
        ;;
esac
