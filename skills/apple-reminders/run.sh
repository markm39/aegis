#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

case "$SUBCMD" in
  list|ls)
    LIST_NAME="${TEXT:-Reminders}"
    RESULT=$(osascript -e "
      tell application \"Reminders\"
        try
          set output to \"\"
          set rl to list \"$LIST_NAME\"
          repeat with r in (reminders of rl whose completed is false)
            set output to output & \"[ ] \" & name of r & linefeed
          end repeat
          if output is \"\" then return \"No incomplete reminders in $LIST_NAME\"
          return output
        on error
          return \"List not found: $LIST_NAME. Available lists: \" & (name of every list as text)
        end try
      end tell
    " 2>&1)
    ;;
  create|add|new)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /reminders create <reminder text>"
    else
      RESULT=$(osascript -e "
        tell application \"Reminders\"
          tell list \"Reminders\"
            make new reminder with properties {name:\"$TEXT\"}
          end tell
          return \"Reminder created: $TEXT\"
        end tell
      " 2>&1)
    fi
    ;;
  complete|done)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /reminders complete <reminder name>"
    else
      RESULT=$(osascript -e "
        tell application \"Reminders\"
          set matches to (every reminder whose name contains \"$TEXT\" and completed is false)
          if (count of matches) > 0 then
            set completed of item 1 of matches to true
            return \"Completed: \" & name of item 1 of matches
          else
            return \"No matching incomplete reminder: $TEXT\"
          end if
        end tell
      " 2>&1)
    fi
    ;;
  lists)
    RESULT=$(osascript -e '
      tell application "Reminders"
        return name of every list as text
      end tell
    ' 2>&1)
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, create, complete, lists"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
