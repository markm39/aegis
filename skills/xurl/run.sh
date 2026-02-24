#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "timeline"')
REST=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

if [ -z "${X_BEARER_TOKEN:-}" ]; then
  echo '{"result": "X_BEARER_TOKEN not set. Get one at developer.x.com", "artifacts": [], "messages": []}'
  exit 0
fi

API="https://api.x.com/2"
AUTH="Authorization: Bearer $X_BEARER_TOKEN"

case "$SUBCMD" in
  search|find)
    if [ -z "$REST" ]; then
      RESULT="Usage: /tweet search <query>"
    else
      ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REST'))")
      RESULT=$(curl -s -H "$AUTH" "$API/tweets/search/recent?query=$ENCODED&max_results=10&tweet.fields=author_id,created_at" | \
        jq -r '.data[]? | "\(.created_at): \(.text)"' 2>/dev/null | head -20 || echo "Search failed")
    fi
    ;;
  post|send)
    if [ -z "$REST" ]; then
      RESULT="Usage: /tweet post <tweet text>"
    else
      RESULT="Posting requires OAuth 1.0a user context. Use the X app or a full OAuth integration."
    fi
    ;;
  user)
    if [ -z "$REST" ]; then
      RESULT="Usage: /tweet user <username>"
    else
      RESULT=$(curl -s -H "$AUTH" "$API/users/by/username/$REST?user.fields=description,public_metrics" | \
        jq -r '.data | "Name: \(.name)\nUsername: @\(.username)\nBio: \(.description)\nFollowers: \(.public_metrics.followers_count)\nTweets: \(.public_metrics.tweet_count)"' 2>/dev/null || echo "User not found")
    fi
    ;;
  *)
    RESULT="Unknown subcommand: $SUBCMD. Use: search, post, user"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
