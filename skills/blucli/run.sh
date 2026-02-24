#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "status"')
DEVICE=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')

if ! command -v blueutil &>/dev/null; then
  echo '{"result": "blueutil is not installed. Install with: brew install blueutil", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  status|st)
    POWER=$(blueutil --power 2>&1)
    DISC=$(blueutil --discoverable 2>&1)
    RESULT="Bluetooth power: $POWER, discoverable: $DISC"
    ;;
  list|ls|paired)
    RESULT=$(blueutil --paired --format json 2>&1 | jq -r '.[] | "\(.name // .address)  [\(if .connected then "connected" else "disconnected" end)]"' 2>/dev/null || blueutil --paired 2>&1)
    ;;
  connect|con)
    if [ -z "$DEVICE" ]; then
      RESULT="Usage: /bluetooth connect <device_address>"
    else
      RESULT=$(blueutil --connect "$DEVICE" 2>&1 && echo "Connected to $DEVICE")
    fi
    ;;
  disconnect|dis)
    if [ -z "$DEVICE" ]; then
      RESULT="Usage: /bluetooth disconnect <device_address>"
    else
      RESULT=$(blueutil --disconnect "$DEVICE" 2>&1 && echo "Disconnected from $DEVICE")
    fi
    ;;
  on)   RESULT=$(blueutil --power 1 2>&1 && echo "Bluetooth enabled") ;;
  off)  RESULT=$(blueutil --power 0 2>&1 && echo "Bluetooth disabled") ;;
  *)    RESULT="Unknown subcommand: $SUBCMD. Use: status, list, connect, disconnect, on, off" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
