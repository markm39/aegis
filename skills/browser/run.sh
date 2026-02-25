#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/mcp-client.sh"
source "$SCRIPT_DIR/lib/format.sh"

# Parse SkillInput from stdin.
INPUT=$(cat)
ACTION=$(printf '%s' "$INPUT" | jq -r '.action // ""')
ARG1=$(printf '%s' "$INPUT" | jq -r '.parameters.args[0] // ""')
ARG2=$(printf '%s' "$INPUT" | jq -r '.parameters.args[1] // ""')
REST=$(printf '%s' "$INPUT" | jq -r '.parameters.args[1:] | join(" ")')

STATE_DIR="${AEGIS_STATE_DIR:-$HOME/.aegis}"

case "$ACTION" in

  browse|goto|nav)
    if [ -z "$ARG1" ]; then
      output_result "Usage: /browse <url>

Navigate to a URL and return the page's accessibility snapshot."
      exit 0
    fi

    URL="$ARG1"
    # Add https:// if no protocol specified.
    if [[ ! "$URL" =~ ^https?:// ]]; then
      URL="https://$URL"
    fi

    ensure_bridge

    # Navigate.
    RESPONSE=$(mcp_call "browser_navigate" "{\"url\": $(printf '%s' "$URL" | jq -Rs .)}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Navigation failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Get accessibility snapshot.
    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    if is_mcp_error "$SNAPSHOT"; then
      # Navigation succeeded but snapshot failed -- still report what we can.
      NAV_TEXT=$(extract_mcp_text "$RESPONSE")
      output_result "Navigated to $URL

$NAV_TEXT

(Snapshot unavailable: $(extract_error "$SNAPSHOT"))"
      exit 0
    fi

    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Navigated to $URL

$CONTENT"
    ;;

  browser-click|bclick)
    if [ -z "$ARG1" ]; then
      output_result "Usage: /browser-click <ref>

Click an element by its ref from a previous /browse or /browser-snapshot.
Example: /browser-click e42"
      exit 0
    fi

    ensure_bridge

    REF="$ARG1"
    RESPONSE=$(mcp_call "browser_click" "{\"element\": \"Element $REF\", \"ref\": $(printf '%s' "$REF" | jq -Rs .)}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Click failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Return updated snapshot after the click.
    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Clicked element $REF

$CONTENT"
    ;;

  browser-type|btype)
    if [ -z "$ARG1" ] || [ -z "$REST" ]; then
      output_result "Usage: /browser-type <ref> <text...>

Type text into an element by its ref.
Example: /browser-type e15 Hello world"
      exit 0
    fi

    ensure_bridge

    REF="$ARG1"
    TEXT="$REST"
    RESPONSE=$(mcp_call "browser_type" "{\"element\": \"Input $REF\", \"ref\": $(printf '%s' "$REF" | jq -Rs .), \"text\": $(printf '%s' "$TEXT" | jq -Rs .)}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Type failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    RESULT_TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "Typed into element $REF: \"$TEXT\"

$RESULT_TEXT"
    ;;

  browser-screenshot|bshot)
    ensure_bridge

    RESPONSE=$(mcp_call "browser_take_screenshot" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Screenshot failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Extract base64 image data.
    IMAGE_DATA=$(extract_mcp_image "$RESPONSE")
    if [ -n "$IMAGE_DATA" ]; then
      SCREENSHOT_FILE="$STATE_DIR/browser-screenshot-$(date +%Y%m%d-%H%M%S).png"
      printf '%s' "$IMAGE_DATA" | base64 -d > "$SCREENSHOT_FILE" 2>/dev/null || true
      output_with_artifact "Screenshot captured and saved to $SCREENSHOT_FILE" \
        "screenshot.png" "image/png" "$SCREENSHOT_FILE" "$IMAGE_DATA"
    else
      # No image data -- try extracting text content instead.
      TEXT=$(extract_mcp_text "$RESPONSE")
      output_result "Screenshot taken.

$TEXT"
    fi
    ;;

  browser-snapshot|bsnap)
    ensure_bridge

    RESPONSE=$(mcp_call "browser_snapshot" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Snapshot failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    CONTENT=$(extract_mcp_text "$RESPONSE")
    output_result "$CONTENT"
    ;;

  browser-back|bback)
    ensure_bridge

    RESPONSE=$(mcp_call "browser_navigate_back" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Back navigation failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Return updated snapshot.
    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Navigated back.

$CONTENT"
    ;;

  browser-forward|bfwd)
    ensure_bridge

    RESPONSE=$(mcp_call "browser_navigate_forward" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Forward navigation failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Navigated forward.

$CONTENT"
    ;;

  browser-scroll|bscroll)
    DIRECTION="${ARG1:-down}"

    ensure_bridge

    SCROLL_TOOL="browser_scroll_down"
    if [ "$DIRECTION" = "up" ]; then
      SCROLL_TOOL="browser_scroll_up"
    fi

    RESPONSE=$(mcp_call "$SCROLL_TOOL" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Scroll failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Scrolled $DIRECTION.

$CONTENT"
    ;;

  browser-close|bclose)
    if is_bridge_running; then
      stop_bridge
      output_result "Browser session closed."
    else
      output_result "No browser session is running."
    fi
    ;;

  browser-tabs|btabs)
    ensure_bridge

    RESPONSE=$(mcp_call "browser_tabs" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Tab list failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    CONTENT=$(extract_mcp_text "$RESPONSE")
    output_result "$CONTENT"
    ;;

  browser-select-tab|btab)
    if [ -z "$ARG1" ]; then
      output_result "Usage: /browser-select-tab <index>

Switch to a browser tab by its index (from /browser-tabs)."
      exit 0
    fi

    ensure_bridge

    INDEX="$ARG1"
    RESPONSE=$(mcp_call "browser_tab_select" "{\"index\": $INDEX}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Tab switch failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    SNAPSHOT=$(mcp_call "browser_snapshot" "{}")
    CONTENT=$(extract_mcp_text "$SNAPSHOT")
    output_result "Switched to tab $INDEX.

$CONTENT"
    ;;

  *)
    output_result "Browser automation skill -- available commands:

  /browse <url>              Navigate to a URL and show page content
  /browser-click <ref>       Click an element by ref (e.g., e42)
  /browser-type <ref> <text> Type into an element
  /browser-screenshot        Take a full-page screenshot
  /browser-snapshot          Get current page accessibility tree
  /browser-back              Go back in history
  /browser-forward           Go forward in history
  /browser-scroll <up|down>  Scroll the page
  /browser-tabs              List open tabs
  /browser-select-tab <i>    Switch to a tab
  /browser-close             Close browser session

Short aliases: /bclick, /btype, /bshot, /bsnap, /bback, /bfwd, /bscroll, /btabs, /btab, /bclose

The browser session persists across commands. Start with /browse, then interact with the page."
    ;;

esac
