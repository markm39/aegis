#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
QUERY=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

# AegisHub is a local registry -- scan installed skills
SKILLS_DIR="${AEGIS_SKILLS_DIR:-./skills}"
if [ ! -d "$SKILLS_DIR" ]; then
  SKILLS_DIR="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")/.."
fi

case "$SUBCMD" in
  list|ls)
    RESULT="## Installed Skills\n\n"
    for dir in "$SKILLS_DIR"/*/; do
      if [ -f "$dir/manifest.toml" ]; then
        NAME=$(grep '^name' "$dir/manifest.toml" | head -1 | sed 's/name = "//;s/"//')
        DESC=$(grep '^description' "$dir/manifest.toml" | head -1 | sed 's/description = "//;s/"//')
        CAT=$(grep '^category' "$dir/manifest.toml" | head -1 | sed 's/category = "//;s/"//')
        RESULT="$RESULT- **$NAME** [$CAT]: $DESC\n"
      fi
    done
    ;;
  search|find)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /hub search <keyword>"
    else
      RESULT="## Search results for: $QUERY\n\n"
      for dir in "$SKILLS_DIR"/*/; do
        if [ -f "$dir/manifest.toml" ] && grep -qi "$QUERY" "$dir/manifest.toml" 2>/dev/null; then
          NAME=$(grep '^name' "$dir/manifest.toml" | head -1 | sed 's/name = "//;s/"//')
          DESC=$(grep '^description' "$dir/manifest.toml" | head -1 | sed 's/description = "//;s/"//')
          RESULT="$RESULT- **$NAME**: $DESC\n"
        fi
      done
    fi
    ;;
  info|show)
    if [ -z "$QUERY" ]; then
      RESULT="Usage: /hub info <skill_name>"
    else
      MANIFEST="$SKILLS_DIR/$QUERY/manifest.toml"
      if [ -f "$MANIFEST" ]; then
        RESULT=$(cat "$MANIFEST")
      else
        RESULT="Skill not found: $QUERY"
      fi
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, search, info"
    ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
