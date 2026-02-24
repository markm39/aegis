#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
SERVER=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')

# Check for MCP config files in common locations
MCP_CONFIGS=(
  "$HOME/.config/claude/mcp.json"
  "$HOME/.claude/mcp_servers.json"
  ".mcp.json"
  "mcp.json"
)

case "$SUBCMD" in
  list|ls)
    RESULT="## MCP Server Configurations\n\n"
    FOUND=false
    for cfg in "${MCP_CONFIGS[@]}"; do
      if [ -f "$cfg" ]; then
        FOUND=true
        RESULT="$RESULT### $cfg\n"
        RESULT="$RESULT$(jq -r 'to_entries[] | "- \(.key): \(.value.command // .value.url // "configured")"' "$cfg" 2>/dev/null)\n\n"
      fi
    done
    if [ "$FOUND" = false ]; then
      RESULT="No MCP configuration files found.\n\nSearched:\n$(printf '  %s\n' "${MCP_CONFIGS[@]}")"
    fi
    ;;
  status)
    RESULT="MCP server status checking requires an active connection. Use /mcp list to see configured servers."
    ;;
  connect)
    if [ -z "$SERVER" ]; then
      RESULT="Usage: /mcp connect <server_name>"
    else
      RESULT="MCP server connection must be initiated by the host application. Server '$SERVER' is configured but connection is managed by the runtime."
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: list, status, connect"
    ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
