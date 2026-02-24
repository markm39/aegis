#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TEXT=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$TEXT" ]; then
  echo '{"result": "Usage: /tts-eleven <text to speak>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${ELEVENLABS_API_KEY:-}" ]; then
  echo '{"result": "ELEVENLABS_API_KEY not set. Get one at elevenlabs.io", "artifacts": [], "messages": []}'
  exit 0
fi

VOICE_ID="${ELEVENLABS_VOICE_ID:-21m00Tcm4TlvDq8ikWAM}"
OUTFILE="$HOME/Desktop/tts-$(date +%Y%m%d-%H%M%S).mp3"

HTTP_CODE=$(curl -s -o "$OUTFILE" -w "%{http_code}" \
  -X POST "https://api.elevenlabs.io/v1/text-to-speech/$VOICE_ID" \
  -H "xi-api-key: $ELEVENLABS_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg t "$TEXT" '{text:$t,model_id:"eleven_monolingual_v1"}')")

if [ "$HTTP_CODE" = "200" ] && [ -f "$OUTFILE" ]; then
  SIZE=$(stat -f%z "$OUTFILE" 2>/dev/null || stat -c%s "$OUTFILE" 2>/dev/null || echo "unknown")
  RESULT="Audio generated: $OUTFILE ($SIZE bytes)"
  echo "{\"result\": $(echo "$RESULT" | jq -Rs .), \"artifacts\": [{\"type\": \"file\", \"path\": \"$OUTFILE\"}], \"messages\": []}"
else
  rm -f "$OUTFILE"
  RESULT="TTS failed (HTTP $HTTP_CODE)"
  echo "{\"result\": $(echo "$RESULT" | jq -Rs .), \"artifacts\": [], \"messages\": []}"
fi
