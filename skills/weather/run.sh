#!/bin/bash
# Aegis skill: weather
# Get current weather and forecasts for any location via OpenWeatherMap
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'weather' executed"]}'
        ;;
esac
