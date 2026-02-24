#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TRACKING=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
CARRIER=$(echo "$INPUT" | jq -r '.parameters.args[1] // "auto"')

if [ -z "$TRACKING" ]; then
  echo '{"result": "Usage: /order <tracking_number> [ups|fedex|usps|auto]\n\nExample: /order 1Z999AA10123456784 ups", "artifacts": [], "messages": []}'
  exit 0
fi

# Auto-detect carrier from tracking number format
if [ "$CARRIER" = "auto" ]; then
  if [[ "$TRACKING" =~ ^1Z ]]; then
    CARRIER="ups"
  elif [[ "$TRACKING" =~ ^[0-9]{12,22}$ ]]; then
    CARRIER="usps"
  elif [[ "$TRACKING" =~ ^[0-9]{12,15}$ ]]; then
    CARRIER="fedex"
  else
    CARRIER="unknown"
  fi
fi

case "$CARRIER" in
  ups)
    URL="https://www.ups.com/track?tracknum=$TRACKING"
    RESULT="UPS Tracking: $TRACKING\nTrack at: $URL\n\n(Direct API access requires UPS developer credentials. Set UPS_API_KEY for programmatic tracking.)"
    ;;
  fedex)
    URL="https://www.fedex.com/fedextrack/?trknbr=$TRACKING"
    RESULT="FedEx Tracking: $TRACKING\nTrack at: $URL\n\n(Direct API access requires FedEx developer credentials.)"
    ;;
  usps)
    URL="https://tools.usps.com/go/TrackConfirmAction?tLabels=$TRACKING"
    RESULT="USPS Tracking: $TRACKING\nTrack at: $URL\n\n(Direct API access requires USPS Web Tools registration.)"
    ;;
  *)
    RESULT="Could not identify carrier for: $TRACKING\nSpecify carrier: /order $TRACKING [ups|fedex|usps]"
    ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
