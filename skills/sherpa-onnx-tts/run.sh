#!/bin/bash
set -euo pipefail
INPUT=$(cat)
TEXT=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$TEXT" ]; then
  echo '{"result": "Usage: /localtts <text to speak> [output_file.wav]", "artifacts": [], "messages": []}'
  exit 0
fi

# Check for sherpa-onnx-offline-tts
if command -v sherpa-onnx-offline-tts &>/dev/null; then
  OUTFILE="${HOME}/Desktop/tts-$(date +%Y%m%d-%H%M%S).wav"
  sherpa-onnx-offline-tts \
    --output-filename="$OUTFILE" \
    "$TEXT" 2>&1
  if [ -f "$OUTFILE" ]; then
    SIZE=$(stat -f%z "$OUTFILE" 2>/dev/null || stat -c%s "$OUTFILE" 2>/dev/null || echo "unknown")
    RESULT="Audio saved to: $OUTFILE ($SIZE bytes)"
    ARTIFACTS="[{\"type\": \"file\", \"path\": \"$OUTFILE\"}]"
  else
    RESULT="TTS generation failed"
    ARTIFACTS="[]"
  fi
elif command -v say &>/dev/null; then
  # macOS fallback: use built-in 'say' command
  OUTFILE="${HOME}/Desktop/tts-$(date +%Y%m%d-%H%M%S).aiff"
  say -o "$OUTFILE" "$TEXT" 2>&1
  if [ -f "$OUTFILE" ]; then
    SIZE=$(stat -f%z "$OUTFILE" 2>/dev/null || echo "unknown")
    RESULT="Audio saved to: $OUTFILE ($SIZE bytes) [using macOS say]"
    ARTIFACTS="[{\"type\": \"file\", \"path\": \"$OUTFILE\"}]"
  else
    RESULT="TTS failed"
    ARTIFACTS="[]"
  fi
else
  echo '{"result": "No TTS engine found. Install sherpa-onnx or use macOS (which has built-in say command).", "artifacts": [], "messages": []}'
  exit 0
fi

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": $ARTIFACTS, \"messages\": []}"
