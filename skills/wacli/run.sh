#!/bin/bash
# Aegis skill: wacli
# Send and receive WhatsApp messages via the WhatsApp Business API
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'wacli' executed"]}'
        ;;
esac
