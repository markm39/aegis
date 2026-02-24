#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "status"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v spotify_player &>/dev/null; then
  # Fall back to AppleScript for macOS
  case "$SUBCMD" in
    play)   osascript -e 'tell application "Spotify" to play' 2>&1; RESULT="Playing" ;;
    pause)  osascript -e 'tell application "Spotify" to pause' 2>&1; RESULT="Paused" ;;
    next)   osascript -e 'tell application "Spotify" to next track' 2>&1; RESULT="Skipped to next" ;;
    prev)   osascript -e 'tell application "Spotify" to previous track' 2>&1; RESULT="Previous track" ;;
    status)
      RESULT=$(osascript -e '
        tell application "Spotify"
          set t to name of current track
          set a to artist of current track
          set al to album of current track
          set s to player state as text
          return s & ": " & t & " by " & a & " (" & al & ")"
        end tell
      ' 2>&1)
      ;;
    *)      RESULT="spotify_player not installed. Basic controls via Spotify.app: play, pause, next, prev, status" ;;
  esac
  RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

case "$SUBCMD" in
  play)    RESULT=$(spotify_player playback play 2>&1 && echo "Playing") ;;
  pause)   RESULT=$(spotify_player playback pause 2>&1 && echo "Paused") ;;
  next)    RESULT=$(spotify_player playback next 2>&1 && echo "Next track") ;;
  prev)    RESULT=$(spotify_player playback previous 2>&1 && echo "Previous track") ;;
  status)  RESULT=$(spotify_player get key playback 2>&1) ;;
  search)
    if [ -z "$REST" ]; then
      RESULT="Usage: /spotify search <query>"
    else
      RESULT=$(spotify_player search "$REST" --limit 5 2>&1)
    fi
    ;;
  *)       RESULT="Unknown subcommand: $SUBCMD. Use: play, pause, next, prev, status, search" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
