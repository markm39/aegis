#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if ! command -v tmux &>/dev/null; then
  echo '{"result": "tmux is not installed. Install with: brew install tmux", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  list|ls)      RESULT=$(tmux list-sessions 2>&1 || echo "No active sessions") ;;
  windows|win)  RESULT=$(tmux list-windows ${REST:+-t "$REST"} 2>&1 || echo "No windows") ;;
  new|create)   RESULT=$(tmux new-session -d -s "${REST:-aegis-session}" 2>&1 && echo "Created session: ${REST:-aegis-session}") ;;
  send)
    TARGET=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
    KEYS=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')
    RESULT=$(tmux send-keys -t "$TARGET" "$KEYS" Enter 2>&1 && echo "Sent to $TARGET: $KEYS")
    ;;
  kill)         RESULT=$(tmux kill-session -t "$REST" 2>&1 && echo "Killed session: $REST") ;;
  attach|a)     RESULT="Cannot attach from non-interactive context. Use: tmux attach -t $REST" ;;
  *)            RESULT="Unknown subcommand: $SUBCMD. Use: list, windows, new, send, kill" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
