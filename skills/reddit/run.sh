#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "feed"')

# Reddit requires a non-default User-Agent
UA="aegis-reddit-skill/1.0"

case "$SUBCMD" in
    feed|hot)
        SUBREDDIT=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
        if [ -z "$SUBREDDIT" ]; then
            URL="https://www.reddit.com/.json?limit=15"
        else
            # Strip r/ prefix if present
            SUBREDDIT="${SUBREDDIT#r/}"
            URL="https://www.reddit.com/r/${SUBREDDIT}.json?limit=15"
        fi
        RESP=$(curl -s -A "$UA" "$URL" 2>/dev/null)
        if echo "$RESP" | jq -e '.data.children' &>/dev/null; then
            RESULT=$(echo "$RESP" | jq -r '.data.children[] | .data | "[\(.score)] \(.title)\n  \(.url)\n  \(.num_comments) comments | r/\(.subreddit) | u/\(.author)\n"' 2>/dev/null)
        else
            RESULT="Failed to fetch Reddit feed. Response: $(echo "$RESP" | head -c 200)"
        fi
        ;;

    search)
        QUERY=$(echo "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')
        if [ -z "$QUERY" ]; then
            RESULT="Usage: /reddit search <query>"
        else
            ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY'))" 2>/dev/null || echo "$QUERY")
            SUBREDDIT_FILTER=$(echo "$INPUT" | jq -r '.parameters.args | if length > 2 then .[-1] else "" end')
            if [ -n "$SUBREDDIT_FILTER" ] && [[ "$SUBREDDIT_FILTER" != "$QUERY" ]]; then
                URL="https://www.reddit.com/r/${SUBREDDIT_FILTER}/search.json?q=${ENCODED}&restrict_sr=1&limit=10"
            else
                URL="https://www.reddit.com/search.json?q=${ENCODED}&limit=10"
            fi
            RESP=$(curl -s -A "$UA" "$URL" 2>/dev/null)
            if echo "$RESP" | jq -e '.data.children' &>/dev/null; then
                RESULT=$(echo "$RESP" | jq -r '.data.children[] | .data | "[\(.score)] \(.title)\n  https://reddit.com\(.permalink)\n  \(.num_comments) comments | r/\(.subreddit)\n"' 2>/dev/null)
            else
                RESULT="No results or API error. Response: $(echo "$RESP" | head -c 200)"
            fi
        fi
        ;;

    read)
        POST_URL=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
        if [ -z "$POST_URL" ]; then
            RESULT="Usage: /reddit read <post_url_or_permalink>"
        else
            # Normalize URL: add .json suffix
            POST_URL="${POST_URL%.json}"
            POST_URL="${POST_URL%/}"
            if [[ "$POST_URL" == http* ]]; then
                JSON_URL="${POST_URL}.json"
            else
                JSON_URL="https://www.reddit.com${POST_URL}.json"
            fi
            RESP=$(curl -s -A "$UA" "$JSON_URL?limit=20" 2>/dev/null)
            if echo "$RESP" | jq -e '.[0].data.children[0]' &>/dev/null; then
                POST=$(echo "$RESP" | jq -r '.[0].data.children[0].data | "## \(.title)\nby u/\(.author) in r/\(.subreddit) | \(.score) points | \(.num_comments) comments\n\n\(.selftext // .url // "(no text)")"')
                COMMENTS=$(echo "$RESP" | jq -r '.[1].data.children[:10][] | select(.data.body != null) | .data | "  u/\(.author) [\(.score)]: \(.body | split("\n") | join(" ") | .[0:300])\n"' 2>/dev/null || echo "(no comments)")
                RESULT="${POST}\n\n--- Top Comments ---\n${COMMENTS}"
            else
                RESULT="Could not fetch post. Check the URL."
            fi
        fi
        ;;

    post)
        if [ -z "${REDDIT_CLIENT_ID:-}" ] || [ -z "${REDDIT_CLIENT_SECRET:-}" ]; then
            RESULT="Posting requires Reddit OAuth credentials. Set REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USERNAME, and REDDIT_PASSWORD environment variables."
        else
            SUBREDDIT=$(echo "$INPUT" | jq -r '.parameters.args[1] // ""')
            TITLE=$(echo "$INPUT" | jq -r '.parameters.args[2] // ""')
            BODY=$(echo "$INPUT" | jq -r '.parameters.args[3:] | join(" ")')
            if [ -z "$SUBREDDIT" ] || [ -z "$TITLE" ]; then
                RESULT="Usage: /reddit post <subreddit> <title> [body]"
            else
                # Get OAuth token
                TOKEN=$(curl -s -X POST -u "${REDDIT_CLIENT_ID}:${REDDIT_CLIENT_SECRET}" \
                    -d "grant_type=password&username=${REDDIT_USERNAME}&password=${REDDIT_PASSWORD}" \
                    "https://www.reddit.com/api/v1/access_token" | jq -r '.access_token // ""')
                if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
                    RESULT="OAuth authentication failed. Check your credentials."
                else
                    SUBMIT_RESP=$(curl -s -X POST \
                        -H "Authorization: bearer $TOKEN" \
                        -H "User-Agent: $UA" \
                        -d "sr=${SUBREDDIT}&kind=self&title=${TITLE}&text=${BODY}" \
                        "https://oauth.reddit.com/api/submit")
                    if echo "$SUBMIT_RESP" | jq -e '.json.data.url' &>/dev/null; then
                        POST_URL=$(echo "$SUBMIT_RESP" | jq -r '.json.data.url')
                        RESULT="Post submitted: $POST_URL"
                    else
                        ERR=$(echo "$SUBMIT_RESP" | jq -r '.json.errors // "unknown error"' 2>/dev/null)
                        RESULT="Failed to post: $ERR"
                    fi
                fi
            fi
        fi
        ;;

    *)
        RESULT="Unknown subcommand: $SUBCMD. Use: feed, search, read, post"
        ;;
esac

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
