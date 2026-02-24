#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "today"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

case "$SUBCMD" in
  add|create|new)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /things add <task title>"
    else
      ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TEXT'))")
      open "things:///add?title=$ENCODED" 2>/dev/null
      RESULT="Added to Things: $TEXT"
    fi
    ;;
  today)
    RESULT=$(osascript -e '
      tell application "Things3"
        set output to ""
        repeat with t in to dos of list "Today"
          if status of t is open then
            set output to output & "[ ] " & name of t & linefeed
          end if
        end repeat
        if output is "" then return "No tasks for today"
        return output
      end tell
    ' 2>&1)
    ;;
  inbox)
    RESULT=$(osascript -e '
      tell application "Things3"
        set output to ""
        repeat with t in to dos of list "Inbox"
          if status of t is open then
            set output to output & "[ ] " & name of t & linefeed
          end if
        end repeat
        if output is "" then return "Inbox is empty"
        return output
      end tell
    ' 2>&1)
    ;;
  search)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /things search <query>"
    else
      RESULT=$(osascript -e "
        tell application \"Things3\"
          set output to \"\"
          set matches to (every to do whose name contains \"$TEXT\" and status is open)
          repeat with t in matches
            set output to output & \"[ ] \" & name of t & linefeed
          end repeat
          if output is \"\" then return \"No tasks matching: $TEXT\"
          return output
        end tell
      " 2>&1)
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: add, today, inbox, search"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
