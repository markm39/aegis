#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v openhue &>/dev/null; then
  echo '{"result": "openhue is not installed. Install with: brew install openhue/cli/openhue", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls)    RESULT=$(openhue get lights 2>&1) ;;
  on)         RESULT=$(openhue set light "$REST" --on true 2>&1 && echo "Light on: $REST") ;;
  off)        RESULT=$(openhue set light "$REST" --on false 2>&1 && echo "Light off: $REST") ;;
  color)
    LIGHT=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    COLOR=$(echo "$INPUT" | jq -r '.parameters.args[2] // ""')
    RESULT=$(openhue set light "$LIGHT" --color "$COLOR" 2>&1 && echo "Set $LIGHT to $COLOR")
    ;;
  brightness|dim)
    LIGHT=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    LEVEL=$(echo "$INPUT" | jq -r '.parameters.args[2] // "50"')
    RESULT=$(openhue set light "$LIGHT" --brightness "$LEVEL" 2>&1 && echo "Set $LIGHT brightness to $LEVEL%")
    ;;
  scenes)     RESULT=$(openhue get scenes 2>&1) ;;
  scene)      RESULT=$(openhue set scene "$REST" 2>&1 && echo "Activated scene: $REST") ;;
  rooms)      RESULT=$(openhue get rooms 2>&1) ;;
  *)          RESULT="Unknown subcommand: $SUBCMD. Use: list, on, off, color, brightness, scenes, scene, rooms" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
