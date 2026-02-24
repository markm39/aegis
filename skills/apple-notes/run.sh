#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
TEXT=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

case "$SUBCMD" in
  list|ls)
    RESULT=$(osascript -e '
      tell application "Notes"
        set output to ""
        repeat with n in (notes of default account)
          set output to output & name of n & "  [" & modification date of n & "]" & linefeed
        end repeat
        return output
      end tell
    ' 2>&1 | head -50)
    ;;
  create|new)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /notes create <note text>"
    else
      RESULT=$(osascript -e "
        tell application \"Notes\"
          make new note at folder \"Notes\" of default account with properties {body:\"$TEXT\"}
          return \"Note created successfully\"
        end tell
      " 2>&1)
    fi
    ;;
  search|find)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /notes search <query>"
    else
      RESULT=$(osascript -e "
        tell application \"Notes\"
          set output to \"\"
          set matches to (every note of default account whose name contains \"$TEXT\")
          repeat with n in matches
            set output to output & name of n & linefeed
          end repeat
          if output is \"\" then
            return \"No notes matching: $TEXT\"
          end if
          return output
        end tell
      " 2>&1)
    fi
    ;;
  show|read)
    if [ -z "$TEXT" ]; then
      RESULT="Usage: /notes show <note_name>"
    else
      RESULT=$(osascript -e "
        tell application \"Notes\"
          set matches to (every note of default account whose name contains \"$TEXT\")
          if (count of matches) > 0 then
            return plaintext of item 1 of matches
          else
            return \"Note not found: $TEXT\"
          end if
        end tell
      " 2>&1 | head -100)
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, create, search, show"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
