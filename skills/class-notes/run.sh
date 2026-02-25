#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "status"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

RECORDINGS_DIR="$HOME/aegis/recordings"
NOTES_DIR="$HOME/aegis/notes"
STATE_DIR="$HOME/.aegis/audio-record"
PID_FILE="$STATE_DIR/recording.pid"
META_FILE="$STATE_DIR/recording.meta"
DATE=$(date +%Y-%m-%d)

# Parse --class flag
CLASS=""
parse_class() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --class) CLASS="${2:-}"; shift 2 ;;
            physics|phys) CLASS="physics"; shift ;;
            numtheory|nt|numbertheory|"number-theory") CLASS="numtheory"; shift ;;
            *) shift ;;
        esac
    done
}

# shellcheck disable=SC2086
parse_class $REST

case "$SUBCMD" in
    start)
        if [ -z "$CLASS" ]; then
            RESULT="Usage: /classnotes start [physics|numtheory] or /classnotes start --class physics"
        else
            CLASS_DIR="$RECORDINGS_DIR/$CLASS"
            mkdir -p "$CLASS_DIR"
            OUTPUT="$CLASS_DIR/${DATE}.opus"

            # Determine duration based on class
            case "$CLASS" in
                physics) DURATION="55m" ;;    # MWF 11:00-11:50
                numtheory) DURATION="80m" ;;  # TR 12:00-1:15
                *) DURATION="60m" ;;
            esac

            # Find BlackHole device index
            BH_INDEX=$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
                | grep -i "blackhole" | head -1 \
                | sed 's/.*\[\([0-9]*\)\].*/\1/')

            if [ -z "$BH_INDEX" ]; then
                # Fall back to built-in mic
                BH_INDEX=$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
                    | grep -i "MacBook Pro Microphone" | head -1 \
                    | sed 's/.*\[\([0-9]*\)\].*/\1/')
                DEVICE_NAME="MacBook Pro Microphone"
            else
                DEVICE_NAME="BlackHole 2ch"
            fi

            # Convert duration to seconds
            SECS=$(echo "$DURATION" | sed 's/m//' | awk '{print $1 * 60}')

            mkdir -p "$STATE_DIR"
            ffmpeg -f avfoundation -i ":${BH_INDEX}" -c:a libopus -b:a 64k -t "$SECS" -y "$OUTPUT" \
                </dev/null >/dev/null 2>"$STATE_DIR/ffmpeg.log" &
            FFMPEG_PID=$!
            echo "$FFMPEG_PID" > "$PID_FILE"
            jq -n --arg output "$OUTPUT" --arg device "$DEVICE_NAME" \
                   --arg started "$(date -Iseconds)" --arg class "$CLASS" \
                '{output: $output, device: $device, started: $started, class: $class}' > "$META_FILE"

            RESULT="Recording $CLASS class started.\nDevice: $DEVICE_NAME (index $BH_INDEX)\nOutput: $OUTPUT\nDuration: $DURATION\nUse /classnotes stop to end early."
        fi
        ;;

    stop)
        if [ ! -f "$PID_FILE" ]; then
            RESULT="No recording in progress."
        else
            PID=$(cat "$PID_FILE")
            META=$(cat "$META_FILE" 2>/dev/null || echo "{}")
            CLASS_NAME=$(echo "$META" | jq -r '.class // "unknown"')
            OUTPUT_FILE=$(echo "$META" | jq -r '.output // "unknown"')

            if kill -0 "$PID" 2>/dev/null; then
                kill -INT "$PID" 2>/dev/null || true
                for _ in $(seq 1 10); do
                    kill -0 "$PID" 2>/dev/null || break
                    sleep 0.5
                done
                kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
            fi
            rm -f "$PID_FILE" "$META_FILE"

            if [ -f "$OUTPUT_FILE" ]; then
                SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
                RESULT="$CLASS_NAME recording stopped. File: $OUTPUT_FILE ($SIZE).\nUse /classnotes transcribe --class $CLASS_NAME to transcribe."
            else
                RESULT="Recording stopped but file not found at $OUTPUT_FILE."
            fi
        fi
        ;;

    transcribe)
        if [ -z "$CLASS" ]; then
            RESULT="Usage: /classnotes transcribe --class [physics|numtheory]"
        else
            AUDIO_FILE="$RECORDINGS_DIR/$CLASS/${DATE}.opus"
            if [ ! -f "$AUDIO_FILE" ]; then
                # Try to find most recent recording for this class
                AUDIO_FILE=$(ls -t "$RECORDINGS_DIR/$CLASS/"*.opus 2>/dev/null | head -1)
            fi
            if [ -z "$AUDIO_FILE" ] || [ ! -f "$AUDIO_FILE" ]; then
                RESULT="No recording found for $CLASS. Expected: $RECORDINGS_DIR/$CLASS/${DATE}.opus"
            else
                TRANSCRIPT_DIR="$NOTES_DIR/$CLASS"
                mkdir -p "$TRANSCRIPT_DIR"
                TRANSCRIPT_FILE="$TRANSCRIPT_DIR/${DATE}-transcript.txt"

                # Check for whisper CLI
                if command -v whisper &>/dev/null; then
                    whisper "$AUDIO_FILE" --model base --output_format txt --output_dir "$TRANSCRIPT_DIR" 2>/dev/null
                    # Whisper outputs as filename.txt
                    WHISPER_OUT="$TRANSCRIPT_DIR/$(basename "${AUDIO_FILE%.*}").txt"
                    if [ -f "$WHISPER_OUT" ]; then
                        mv "$WHISPER_OUT" "$TRANSCRIPT_FILE"
                    fi
                elif [ -n "${OPENAI_API_KEY:-}" ]; then
                    # Use OpenAI Whisper API
                    curl -s "https://api.openai.com/v1/audio/transcriptions" \
                        -H "Authorization: Bearer $OPENAI_API_KEY" \
                        -F "file=@$AUDIO_FILE" \
                        -F "model=whisper-1" \
                        -F "response_format=text" \
                        > "$TRANSCRIPT_FILE" 2>/dev/null
                else
                    RESULT="No transcription tool available. Install whisper CLI or set OPENAI_API_KEY."
                    RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
                    echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
                    exit 0
                fi

                if [ -f "$TRANSCRIPT_FILE" ] && [ -s "$TRANSCRIPT_FILE" ]; then
                    LINES=$(wc -l < "$TRANSCRIPT_FILE")
                    CHARS=$(wc -c < "$TRANSCRIPT_FILE")
                    RESULT="Transcription complete: $TRANSCRIPT_FILE ($LINES lines, $CHARS bytes).\nUse /classnotes summarize --class $CLASS to generate notes."
                else
                    RESULT="Transcription failed or produced empty output. Check $STATE_DIR/ffmpeg.log for audio issues."
                fi
            fi
        fi
        ;;

    summarize)
        if [ -z "$CLASS" ]; then
            RESULT="Usage: /classnotes summarize --class [physics|numtheory]"
        else
            TRANSCRIPT_FILE="$NOTES_DIR/$CLASS/${DATE}-transcript.txt"
            if [ ! -f "$TRANSCRIPT_FILE" ]; then
                TRANSCRIPT_FILE=$(ls -t "$NOTES_DIR/$CLASS/"*-transcript.txt 2>/dev/null | head -1)
            fi
            if [ -z "$TRANSCRIPT_FILE" ] || [ ! -f "$TRANSCRIPT_FILE" ]; then
                RESULT="No transcript found for $CLASS. Run /classnotes transcribe --class $CLASS first."
            else
                # Return the transcript content so the LLM can summarize it
                CONTENT=$(head -c 50000 "$TRANSCRIPT_FILE")
                RESULT="Transcript for $CLASS ($(wc -l < "$TRANSCRIPT_FILE") lines):\n\n${CONTENT}\n\n--- End of transcript ---\nPlease summarize the key concepts, formulas, and important points from this lecture."
            fi
        fi
        ;;

    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            META=$(cat "$META_FILE" 2>/dev/null || echo "{}")
            CLASS_NAME=$(echo "$META" | jq -r '.class // "unknown"')
            OUTPUT_FILE=$(echo "$META" | jq -r '.output // "unknown"')
            STARTED=$(echo "$META" | jq -r '.started // "unknown"')
            RESULT="Recording in progress: $CLASS_NAME class. Output: $OUTPUT_FILE. Started: $STARTED"
        else
            rm -f "$PID_FILE" "$META_FILE" 2>/dev/null
            # List recent recordings
            RECENT=$(find "$RECORDINGS_DIR" -name "*.opus" -mtime -7 2>/dev/null | sort -r | head -10)
            if [ -n "$RECENT" ]; then
                RESULT="No recording in progress.\n\nRecent recordings:\n${RECENT}"
            else
                RESULT="No recording in progress. No recent recordings found."
            fi
        fi
        ;;

    *)
        RESULT="Unknown subcommand: $SUBCMD. Use: start, stop, transcribe, summarize, status"
        ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
