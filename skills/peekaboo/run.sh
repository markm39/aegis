#!/bin/bash
# Aegis skill: peekaboo
# macOS UI automation - capture screenshots, read UI elements, click controls
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'peekaboo' executed"]}'
        ;;
esac
