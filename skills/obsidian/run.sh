#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "recent"')
QUERY=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

# Find Obsidian vault
VAULT="${OBSIDIAN_VAULT:-}"
if [ -z "$VAULT" ]; then
  # Common locations
  for v in "$HOME/Documents/Obsidian" "$HOME/Obsidian" "$HOME/Documents/vault" "$HOME/vault"; do
    if [ -d "$v" ]; then
      VAULT="$v"
      break
    fi
  done
fi

if [ -z "$VAULT" ] || [ ! -d "$VAULT" ]; then
  echo '{"result": "Obsidian vault not found. Set OBSIDIAN_VAULT env var to your vault path.", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  search|find)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /vault search <query>"
    else
      RESULT=$(grep -rl "$QUERY" "$VAULT" --include="*.md" 2>/dev/null | head -15 | while read -r f; do
        REL=$(echo "$f" | sed "s|$VAULT/||")
        echo "- $REL"
      done)
      if [ -z "$RESULT" ]; then RESULT="No notes matching: $QUERY"; fi
    fi
    ;;
  read|show)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /vault read <note_path>"
    else
      FILE="$VAULT/$QUERY"
      if [ ! -f "$FILE" ] && [ ! -f "$FILE.md" ]; then
        # Try fuzzy find
        FILE=$(find "$VAULT" -name "*${QUERY}*" -name "*.md" 2>/dev/null | head -1)
      elif [ -f "$FILE.md" ]; then
        FILE="$FILE.md"
      fi
      if [ -f "$FILE" ]; then
        RESULT=$(head -c 6000 "$FILE")
      else
        RESULT="Note not found: $QUERY"
      fi
    fi
    ;;
  list|ls)
    DIR="${QUERY:-.}"
    RESULT=$(find "$VAULT/$DIR" -name "*.md" -maxdepth 2 2>/dev/null | sed "s|$VAULT/||" | sort | head -30)
    if [ -z "$RESULT" ]; then RESULT="No notes found in: $DIR"; fi
    ;;
  recent)
    RESULT=$(find "$VAULT" -name "*.md" -mtime -7 2>/dev/null | sed "s|$VAULT/||" | head -20)
    if [ -z "$RESULT" ]; then RESULT="No recently modified notes"; fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: search, read, list, recent"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
