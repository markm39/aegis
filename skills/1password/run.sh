#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v op &>/dev/null; then
  echo '{"result": "1Password CLI (op) is not installed. Install with: brew install 1password-cli", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls)
    RESULT=$(op item list --format=json 2>&1 | jq -r '.[] | "\(.title)  [\(.category)]  \(.vault.name)"' 2>/dev/null | head -30 || echo "Failed to list items. Run: op signin")
    ;;
  get|show)
    if [ -z "$REST" ]; then
      RESULT="Usage: /1pass get <item_name>"
    else
      RESULT=$(op item get "$REST" --format=json 2>&1 | jq '{title: .title, category: .category, fields: [.fields[] | select(.value != null and .value != "") | {label: .label, value: (if .type == "CONCEALED" then "********" else .value end)}]}' 2>/dev/null || echo "Item not found or not signed in: $REST")
    fi
    ;;
  search|find)
    RESULT=$(op item list --format=json 2>&1 | jq -r --arg q "$REST" '.[] | select(.title | ascii_downcase | contains($q | ascii_downcase)) | "\(.title)  [\(.category)]"' 2>/dev/null | head -20 || echo "Search failed. Run: op signin")
    ;;
  vaults)
    RESULT=$(op vault list --format=json 2>&1 | jq -r '.[].name' 2>/dev/null || echo "Failed to list vaults")
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, get, search, vaults"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
