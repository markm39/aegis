#!/bin/bash
set -euo pipefail
INPUT=$(cat)
VIDEO=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
INTERVAL=$(echo "$INPUT" | jq -r '.parameters.args[1] // "1"')
OUTDIR=$(echo "$INPUT" | jq -r '.parameters.args[2] // ""')

if [ -z "$VIDEO" ]; then
  echo '{"result": "Usage: /vidframes <video_file> [interval_secs] [output_dir]", "artifacts": [], "messages": []}'
  exit 0
fi

if ! command -v ffmpeg &>/dev/null; then
  echo '{"result": "ffmpeg is not installed. Install with: brew install ffmpeg", "artifacts": [], "messages": []}'
  exit 0
fi

if [ ! -f "$VIDEO" ]; then
  RESULT_JSON=$(echo "File not found: $VIDEO" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

if [ -z "$OUTDIR" ]; then
  OUTDIR="./frames-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTDIR"

RESULT=$(ffmpeg -i "$VIDEO" -vf "fps=1/$INTERVAL" "$OUTDIR/frame_%04d.png" -y 2>&1)
COUNT=$(ls "$OUTDIR"/frame_*.png 2>/dev/null | wc -l | tr -d ' ')
RESULT="Extracted $COUNT frames to $OUTDIR (every ${INTERVAL}s)"

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [{\"type\": \"directory\", \"path\": \"$OUTDIR\"}], \"messages\": []}"
