#!/bin/bash
# Aegis skill: openhue
# Control Philips Hue lights - brightness, color, scenes, and room groups
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'openhue' executed"]}'
        ;;
esac
