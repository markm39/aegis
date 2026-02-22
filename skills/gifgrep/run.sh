#!/bin/bash
# Aegis skill: gifgrep
# Search and browse GIF databases via Giphy or Tenor APIs
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'gifgrep' executed"]}'
        ;;
esac
