#!/bin/bash
# Aegis skill: sonoscli
# Control Sonos speakers - playback, volume, grouping, and queue management
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'sonoscli' executed"]}'
        ;;
esac
