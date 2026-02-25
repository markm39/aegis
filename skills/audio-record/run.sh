#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "status"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

STATE_DIR="$HOME/.aegis/audio-record"
PID_FILE="$STATE_DIR/recording.pid"
META_FILE="$STATE_DIR/recording.meta"
RECORDINGS_DIR="$HOME/aegis/recordings"

mkdir -p "$STATE_DIR" "$RECORDINGS_DIR"

# Parse --device and --duration flags from remaining args
parse_flags() {
    DEVICE="blackhole"
    DURATION=""
    OUTPUT=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --device) DEVICE="${2:-blackhole}"; shift 2 ;;
            --duration) DURATION="${2:-}"; shift 2 ;;
            --output) OUTPUT="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done
}

# Find audio device index by name
find_device_index() {
    local name="$1"
    case "$name" in
        blackhole|bh)
            ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
                | grep -i "blackhole" | head -1 \
                | sed 's/.*\[\([0-9]*\)\].*/\1/' ;;
        mic|microphone)
            ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
                | grep -i "MacBook Pro Microphone" | head -1 \
                | sed 's/.*\[\([0-9]*\)\].*/\1/' ;;
        teams)
            ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
                | grep -i "Teams Audio" | head -1 \
                | sed 's/.*\[\([0-9]*\)\].*/\1/' ;;
        *)
            # Try as raw index
            echo "$name" ;;
    esac
}

case "$SUBCMD" in
    start)
        # Check if already recording
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            META=$(cat "$META_FILE" 2>/dev/null || echo "{}")
            RESULT="Already recording. Output: $(echo "$META" | jq -r '.output // "unknown"'). Use /record stop first."
        else
            # shellcheck disable=SC2086
            parse_flags $REST

            DEVICE_INDEX=$(find_device_index "$DEVICE")
            if [ -z "$DEVICE_INDEX" ]; then
                echo '{"result": "Could not find audio device. Available: blackhole, mic, teams", "artifacts": [], "messages": []}'
                exit 0
            fi

            # Default output path
            if [ -z "$OUTPUT" ]; then
                OUTPUT="$RECORDINGS_DIR/$(date +%Y-%m-%d_%H%M%S).opus"
            fi
            # Expand ~ in output path
            OUTPUT="${OUTPUT/#\~/$HOME}"
            mkdir -p "$(dirname "$OUTPUT")"

            # Build ffmpeg command
            FFMPEG_ARGS=(-f avfoundation -i ":${DEVICE_INDEX}" -c:a libopus -b:a 64k -y)
            if [ -n "$DURATION" ]; then
                # Convert duration like "50m" to seconds for ffmpeg -t
                if [[ "$DURATION" =~ ^([0-9]+)m$ ]]; then
                    SECS=$(( ${BASH_REMATCH[1]} * 60 ))
                    FFMPEG_ARGS+=(-t "$SECS")
                elif [[ "$DURATION" =~ ^([0-9]+)h$ ]]; then
                    SECS=$(( ${BASH_REMATCH[1]} * 3600 ))
                    FFMPEG_ARGS+=(-t "$SECS")
                elif [[ "$DURATION" =~ ^([0-9]+)s?$ ]]; then
                    FFMPEG_ARGS+=(-t "${BASH_REMATCH[1]}")
                else
                    FFMPEG_ARGS+=(-t "$DURATION")
                fi
            fi
            FFMPEG_ARGS+=("$OUTPUT")

            # Launch ffmpeg in background
            ffmpeg "${FFMPEG_ARGS[@]}" </dev/null >/dev/null 2>"$STATE_DIR/ffmpeg.log" &
            FFMPEG_PID=$!
            echo "$FFMPEG_PID" > "$PID_FILE"
            jq -n --arg output "$OUTPUT" --arg device "$DEVICE" --arg started "$(date -Iseconds)" \
                '{output: $output, device: $device, started: $started}' > "$META_FILE"

            RESULT="Recording started. Device: ${DEVICE} (index ${DEVICE_INDEX}). Output: ${OUTPUT}"
            if [ -n "$DURATION" ]; then
                RESULT="$RESULT. Duration: ${DURATION}"
            else
                RESULT="$RESULT. Recording indefinitely -- use /record stop to finish."
            fi
        fi
        ;;

    stop)
        if [ ! -f "$PID_FILE" ]; then
            RESULT="No recording in progress."
        else
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                # Send SIGINT for graceful ffmpeg shutdown (finalizes file)
                kill -INT "$PID" 2>/dev/null || true
                # Wait up to 5 seconds for it to finish
                for _ in $(seq 1 10); do
                    kill -0 "$PID" 2>/dev/null || break
                    sleep 0.5
                done
                # Force kill if still alive
                kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
            fi
            META=$(cat "$META_FILE" 2>/dev/null || echo "{}")
            OUTPUT_FILE=$(echo "$META" | jq -r '.output // "unknown"')
            STARTED=$(echo "$META" | jq -r '.started // "unknown"')
            rm -f "$PID_FILE" "$META_FILE"

            if [ -f "$OUTPUT_FILE" ]; then
                SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
                RESULT="Recording stopped. File: ${OUTPUT_FILE} (${SIZE}). Started: ${STARTED}"
            else
                RESULT="Recording stopped but output file not found at ${OUTPUT_FILE}. Check $STATE_DIR/ffmpeg.log for errors."
            fi
        fi
        ;;

    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            META=$(cat "$META_FILE" 2>/dev/null || echo "{}")
            OUTPUT_FILE=$(echo "$META" | jq -r '.output // "unknown"')
            DEVICE=$(echo "$META" | jq -r '.device // "unknown"')
            STARTED=$(echo "$META" | jq -r '.started // "unknown"')
            RESULT="Recording in progress. Device: ${DEVICE}. Output: ${OUTPUT_FILE}. Started: ${STARTED}"
        else
            rm -f "$PID_FILE" "$META_FILE" 2>/dev/null
            RESULT="No recording in progress."
        fi
        ;;

    devices)
        DEVICES=$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
            | grep -A100 "audio devices:" \
            | grep "^\[AVFoundation" \
            | sed 's/.*\[\([0-9]*\)\] \(.*\)/  [\1] \2/')
        RESULT="Available audio devices:\n${DEVICES}"
        ;;

    *)
        RESULT="Unknown subcommand: $SUBCMD. Use: start, stop, status, devices"
        ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
