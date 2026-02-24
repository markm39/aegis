#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v sonos &>/dev/null; then
  echo '{"result": "sonos CLI is not installed. Install with: pip install soco-cli", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls|discover) RESULT=$(sonos discover 2>&1 || echo "No Sonos speakers found") ;;
  play)   RESULT=$(sonos ${REST:-""} play 2>&1 && echo "Playing") ;;
  pause)  RESULT=$(sonos ${REST:-""} pause 2>&1 && echo "Paused") ;;
  stop)   RESULT=$(sonos ${REST:-""} stop 2>&1 && echo "Stopped") ;;
  next)   RESULT=$(sonos ${REST:-""} next 2>&1 && echo "Next track") ;;
  prev)   RESULT=$(sonos ${REST:-""} previous 2>&1 && echo "Previous track") ;;
  volume|vol)
    SPEAKER=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    LEVEL=$(echo "$INPUT" | jq -r '.parameters.args[2] // ""')
    if [ -z "$LEVEL" ]; then
      RESULT=$(sonos $SPEAKER volume 2>&1)
    else
      RESULT=$(sonos $SPEAKER volume "$LEVEL" 2>&1 && echo "Volume set to $LEVEL")
    fi
    ;;
  status|info)  RESULT=$(sonos ${REST:-""} track 2>&1) ;;
  group)
    RESULT=$(sonos ${REST:-""} groups 2>&1 || echo "No groups found")
    ;;
  *)      RESULT="Unknown subcommand: $SUBCMD. Use: list, play, pause, stop, next, prev, volume, status, group" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
