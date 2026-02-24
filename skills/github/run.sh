#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "pr"')
SUBCMD2=$(echo "$INPUT" | jq -r '.parameters.args[1] // "list"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[2:] | join(" ")')

if ! command -v gh &>/dev/null; then
  echo '{"result": "GitHub CLI (gh) is not installed. Install with: brew install gh", "artifacts": [], "messages": []}'
  exit 0
fi

case "$SUBCMD" in
  pr)
    case "$SUBCMD2" in
      list|ls)   RESULT=$(gh pr list --limit 15 $REST 2>&1) ;;
      view|show) RESULT=$(gh pr view "$REST" 2>&1) ;;
      create)    RESULT=$(gh pr create --fill $REST 2>&1) ;;
      merge)     RESULT=$(gh pr merge "$REST" 2>&1) ;;
      checks)    RESULT=$(gh pr checks "$REST" 2>&1) ;;
      *)         RESULT="PR subcommands: list, view, create, merge, checks" ;;
    esac
    ;;
  repo)
    case "$SUBCMD2" in
      view)  RESULT=$(gh repo view $REST 2>&1) ;;
      clone) RESULT=$(gh repo clone "$REST" 2>&1) ;;
      list)  RESULT=$(gh repo list $REST --limit 10 2>&1) ;;
      *)     RESULT="Repo subcommands: view, clone, list" ;;
    esac
    ;;
  gist)
    case "$SUBCMD2" in
      list)   RESULT=$(gh gist list --limit 10 2>&1) ;;
      create) RESULT=$(gh gist create $REST 2>&1) ;;
      view)   RESULT=$(gh gist view "$REST" 2>&1) ;;
      *)      RESULT="Gist subcommands: list, create, view" ;;
    esac
    ;;
  status) RESULT=$(gh status 2>&1) ;;
  *)      RESULT="Unknown subcommand: $SUBCMD. Use: pr, repo, gist, status" ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
