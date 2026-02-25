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
ARG3=$(printf '%s' "$INPUT" | jq -r '.parameters.args[2] // ""')
ARG4=$(printf '%s' "$INPUT" | jq -r '.parameters.args[3] // ""')
ALL_ARGS=$(printf '%s' "$INPUT" | jq -r '.parameters.args | join(" ")')

STATE_DIR="${AEGIS_STATE_DIR:-$HOME/.aegis}"

case "$ACTION" in

  sim-open|sopen)
    ensure_bridge

    RESPONSE=$(mcp_call "open_simulator" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Failed to open simulator: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")

    # Get the booted simulator ID.
    ID_RESPONSE=$(mcp_call "get_booted_sim_id" "{}")
    SIM_ID=$(extract_mcp_text "$ID_RESPONSE")

    if [ -n "$SIM_ID" ]; then
      output_result "Simulator opened.

UDID: $SIM_ID

$TEXT"
    else
      output_result "Simulator opened.

$TEXT"
    fi
    ;;

  sim-id|sid)
    ensure_bridge

    RESPONSE=$(mcp_call "get_booted_sim_id" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Failed to get simulator ID: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "$TEXT"
    ;;

  sim-describe|sdesc)
    ensure_bridge

    RESPONSE=$(mcp_call "ui_describe_all" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Failed to describe UI: $(extract_error "$RESPONSE")"
      exit 0
    fi

    CONTENT=$(extract_mcp_text "$RESPONSE")
    output_result "$CONTENT"
    ;;

  sim-describe-point|spoint)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
      output_result "Usage: /sim-describe-point <x> <y>

Describe the UI element at the given coordinates.
Example: /sim-describe-point 200 300"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "ui_describe_point" "$(jq -n --argjson x "$ARG1" --argjson y "$ARG2" '{x: $x, y: $y}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Failed to describe point: $(extract_error "$RESPONSE")"
      exit 0
    fi

    CONTENT=$(extract_mcp_text "$RESPONSE")
    output_result "Element at ($ARG1, $ARG2):

$CONTENT"
    ;;

  sim-tap|stap)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
      output_result "Usage: /sim-tap <x> <y>

Tap at the given coordinates.
Example: /sim-tap 200 300"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "ui_tap" "$(jq -n --argjson x "$ARG1" --argjson y "$ARG2" '{x: $x, y: $y}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Tap failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Return updated UI state after the tap.
    DESCRIBE=$(mcp_call "ui_describe_all" "{}")
    CONTENT=$(extract_mcp_text "$DESCRIBE")
    output_result "Tapped at ($ARG1, $ARG2).

$CONTENT"
    ;;

  sim-type|stype)
    if [ -z "$ALL_ARGS" ]; then
      output_result "Usage: /sim-type <text...>

Type text into the currently focused element.
Example: /sim-type Hello world"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "ui_type" "$(jq -n --arg text "$ALL_ARGS" '{text: $text}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Type failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    RESULT_TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "Typed: \"$ALL_ARGS\"

$RESULT_TEXT"
    ;;

  sim-swipe|sswipe)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ] || [ -z "$ARG3" ] || [ -z "$ARG4" ]; then
      output_result "Usage: /sim-swipe <x1> <y1> <x2> <y2>

Swipe from (x1, y1) to (x2, y2).
Example: /sim-swipe 200 500 200 100  (swipe up)"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "ui_swipe" "$(jq -n \
      --argjson x_start "$ARG1" --argjson y_start "$ARG2" \
      --argjson x_end "$ARG3" --argjson y_end "$ARG4" \
      '{x_start: $x_start, y_start: $y_start, x_end: $x_end, y_end: $y_end}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Swipe failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Return updated UI state after the swipe.
    DESCRIBE=$(mcp_call "ui_describe_all" "{}")
    CONTENT=$(extract_mcp_text "$DESCRIBE")
    output_result "Swiped from ($ARG1, $ARG2) to ($ARG3, $ARG4).

$CONTENT"
    ;;

  sim-view|sview)
    ensure_bridge

    RESPONSE=$(mcp_call "ui_view" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "View failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # ui_view returns both an image and text description.
    IMAGE_DATA=$(extract_mcp_image "$RESPONSE")
    TEXT=$(extract_mcp_text "$RESPONSE")

    if [ -n "$IMAGE_DATA" ]; then
      VIEW_FILE="$STATE_DIR/ios-sim-view-$(date +%Y%m%d-%H%M%S).jpg"
      printf '%s' "$IMAGE_DATA" | base64 -d > "$VIEW_FILE" 2>/dev/null || true
      output_with_artifact "Simulator view captured and saved to $VIEW_FILE

$TEXT" \
        "sim-view.jpg" "image/jpeg" "$VIEW_FILE" "$IMAGE_DATA"
    else
      output_result "$TEXT"
    fi
    ;;

  sim-screenshot|sshot)
    ensure_bridge

    OUTPUT_PATH="${ARG1:-$STATE_DIR/ios-sim-screenshot-$(date +%Y%m%d-%H%M%S).png}"

    RESPONSE=$(mcp_call "screenshot" "$(jq -n --arg output_path "$OUTPUT_PATH" '{output_path: $output_path}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Screenshot failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    # Extract base64 image data if present.
    IMAGE_DATA=$(extract_mcp_image "$RESPONSE")
    if [ -n "$IMAGE_DATA" ]; then
      printf '%s' "$IMAGE_DATA" | base64 -d > "$OUTPUT_PATH" 2>/dev/null || true
      output_with_artifact "Screenshot saved to $OUTPUT_PATH" \
        "screenshot.png" "image/png" "$OUTPUT_PATH" "$IMAGE_DATA"
    else
      TEXT=$(extract_mcp_text "$RESPONSE")
      output_result "Screenshot saved to $OUTPUT_PATH

$TEXT"
    fi
    ;;

  sim-record|srec)
    ensure_bridge

    if [ -n "$ARG1" ]; then
      RESPONSE=$(mcp_call "record_video" "$(jq -n --arg output_path "$ARG1" '{output_path: $output_path}')")
    else
      RESPONSE=$(mcp_call "record_video" "{}")
    fi

    if is_mcp_error "$RESPONSE"; then
      output_error "Recording failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "Recording started.

$TEXT

Use /sim-stop-record to stop."
    ;;

  sim-stop-record|sstop)
    ensure_bridge

    RESPONSE=$(mcp_call "stop_recording" "{}")
    if is_mcp_error "$RESPONSE"; then
      output_error "Stop recording failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "Recording stopped.

$TEXT"
    ;;

  sim-install|sinst)
    if [ -z "$ARG1" ]; then
      output_result "Usage: /sim-install <path/to/app.app>

Install an .app bundle on the booted simulator.
Example: /sim-install ~/build/MyApp.app"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "install_app" "$(jq -n --arg app_path "$ARG1" '{app_path: $app_path}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Install failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "App installed: $ARG1

$TEXT"
    ;;

  sim-launch|slaunch)
    if [ -z "$ARG1" ]; then
      output_result "Usage: /sim-launch <bundle_id>

Launch an app by its bundle ID on the booted simulator.
Example: /sim-launch com.example.MyApp"
      exit 0
    fi

    ensure_bridge

    RESPONSE=$(mcp_call "launch_app" "$(jq -n --arg bundle_id "$ARG1" '{bundle_id: $bundle_id}')")
    if is_mcp_error "$RESPONSE"; then
      output_error "Launch failed: $(extract_error "$RESPONSE")"
      exit 0
    fi

    TEXT=$(extract_mcp_text "$RESPONSE")
    output_result "Launched $ARG1

$TEXT"
    ;;

  sim-close|sclose)
    if is_bridge_running; then
      stop_bridge
      output_result "iOS Simulator bridge stopped."
    else
      output_result "No iOS Simulator bridge is running."
    fi
    ;;

  *)
    output_result "iOS Simulator automation skill -- available commands:

  /sim-open                          Boot and open iOS Simulator
  /sim-id                            Get booted simulator UDID
  /sim-describe                      Get full accessibility tree
  /sim-describe-point <x> <y>        Describe element at coordinates
  /sim-tap <x> <y>                   Tap at coordinates
  /sim-type <text...>                Type text into focused element
  /sim-swipe <x1> <y1> <x2> <y2>    Swipe gesture
  /sim-view                          Screenshot with description
  /sim-screenshot [path]             Save screenshot to file
  /sim-record [path]                 Start video recording
  /sim-stop-record                   Stop video recording
  /sim-install <path>                Install .app bundle
  /sim-launch <bundle_id>            Launch app by bundle ID
  /sim-close                         Stop simulator bridge

Short aliases: /sopen, /sid, /sdesc, /spoint, /stap, /stype, /sswipe, /sview, /sshot, /srec, /sstop, /sinst, /slaunch, /sclose

The simulator bridge persists across commands. Start with /sim-open, then interact with the UI."
    ;;

esac
