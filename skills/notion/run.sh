#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "search"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "${NOTION_API_KEY:-}" ]; then
  echo '{"result": "NOTION_API_KEY not set. Get an integration token at notion.so/my-integrations", "artifacts": [], "messages": []}'
  exit 0
fi

API="https://api.notion.com/v1"
HEADERS=(-H "Authorization: Bearer $NOTION_API_KEY" -H "Notion-Version: 2022-06-28" -H "Content-Type: application/json")

case "$SUBCMD" in
  search|find)
    if [ -z "$REST" ]; then
      RESULT="Usage: /notion search <query>"
    else
      BODY=$(jq -n --arg q "$REST" '{query: $q, page_size: 10}')
      RESULT=$(curl -s -X POST "${HEADERS[@]}" -d "$BODY" "$API/search" | jq -r '.results[] | "\(.object): \(.properties.title.title[0].plain_text // .properties.Name.title[0].plain_text // "Untitled")  [id: \(.id)]"' 2>/dev/null | head -15 || echo "Search failed")
    fi
    ;;
  page)
    PAGE_ID=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    if [ -z "$PAGE_ID" ]; then
      RESULT="Usage: /notion page <page_id>"
    else
      RESULT=$(curl -s "${HEADERS[@]}" "$API/pages/$PAGE_ID" | jq '{id: .id, created: .created_time, last_edited: .last_edited_time, url: .url}' 2>/dev/null || echo "Page not found: $PAGE_ID")
    fi
    ;;
  databases|dbs)
    RESULT=$(curl -s -X POST "${HEADERS[@]}" -d '{"filter":{"property":"object","value":"database"},"page_size":10}' "$API/search" | jq -r '.results[] | "\(.title[0].plain_text // "Untitled")  [id: \(.id)]"' 2>/dev/null | head -15 || echo "No databases found")
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: search, page, databases"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
