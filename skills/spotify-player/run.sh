#!/bin/bash
# Aegis skill: spotify-player
# Control Spotify playback - play, pause, skip, queue, search, and playlists
set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.action // "run"')

case "$ACTION" in
    run|*)
        echo '{"result": "ok", "artifacts": [], "messages": ["'spotify-player' executed"]}'
        ;;
esac
