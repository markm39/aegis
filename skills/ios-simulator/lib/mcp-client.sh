#!/bin/bash
# mcp-client.sh -- MCP bridge lifecycle and HTTP communication helpers.
#
# The bridge (mcp-bridge.mjs) runs as a persistent background process that
# manages the ios-simulator-mcp server. This file provides functions to start,
# stop, health-check, and call tools through the bridge.

STATE_DIR="${AEGIS_STATE_DIR:-$HOME/.aegis}"
PID_FILE="$STATE_DIR/ios-sim-mcp.pid"
PORT_FILE="$STATE_DIR/ios-sim-mcp.port"
LOG_FILE="$STATE_DIR/ios-sim-mcp.log"
LOCK_FILE="$STATE_DIR/ios-sim-mcp.lock"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if the bridge process is running and responsive.
is_bridge_running() {
    if [ ! -f "$PID_FILE" ] || [ ! -f "$PORT_FILE" ]; then
        return 1
    fi

    local pid
    pid=$(cat "$PID_FILE" 2>/dev/null) || return 1
    local port
    port=$(cat "$PORT_FILE" 2>/dev/null) || return 1

    # Check process is alive.
    if ! kill -0 "$pid" 2>/dev/null; then
        cleanup_state_files
        return 1
    fi

    # HTTP health check.
    local health
    health=$(curl -sf --max-time 3 "http://127.0.0.1:$port/health" 2>/dev/null) || {
        # Process alive but not responding -- stale.
        kill "$pid" 2>/dev/null || true
        cleanup_state_files
        return 1
    }

    # Check that MCP is initialized (status == "ok").
    local status
    status=$(printf '%s' "$health" | jq -r '.status // ""' 2>/dev/null)
    if [ "$status" = "ok" ]; then
        return 0
    fi

    # Status is "starting" -- bridge is alive but MCP not ready yet.
    return 1
}

# Start the MCP bridge process.
start_bridge() {
    mkdir -p "$STATE_DIR"

    # Check for node.
    if ! command -v node &>/dev/null; then
        output_error "Node.js is required for iOS Simulator automation. Install from https://nodejs.org or: brew install node"
        exit 0
    fi

    # Check for npx.
    if ! command -v npx &>/dev/null; then
        output_error "npx is required for iOS Simulator automation. It should come with Node.js. Install from https://nodejs.org or: brew install node"
        exit 0
    fi

    # Check for Xcode CLI tools.
    if ! command -v xcrun &>/dev/null; then
        output_error "Xcode Command Line Tools are required for iOS Simulator automation. Install with: xcode-select --install"
        exit 0
    fi

    # Start the bridge as a background process.
    nohup node "$SCRIPT_DIR/mcp-bridge.mjs" >> "$LOG_FILE" 2>&1 &
    local bridge_pid=$!
    disown "$bridge_pid" 2>/dev/null || true

    # Wait for the bridge to become ready.
    local max_wait=60
    local waited=0
    while [ $waited -lt $max_wait ]; do
        # Check if process died.
        if ! kill -0 "$bridge_pid" 2>/dev/null; then
            cleanup_state_files
            local log_tail=""
            if [ -f "$LOG_FILE" ]; then
                log_tail=$(tail -10 "$LOG_FILE" 2>/dev/null)
            fi
            output_error "iOS Simulator bridge failed to start. Log:\n$log_tail"
            exit 0
        fi

        # Check if bridge is ready.
        if [ -f "$PORT_FILE" ]; then
            local port
            port=$(cat "$PORT_FILE" 2>/dev/null) || true
            if [ -n "$port" ]; then
                local health
                health=$(curl -sf --max-time 2 "http://127.0.0.1:$port/health" 2>/dev/null) || true
                local status
                status=$(printf '%s' "$health" | jq -r '.status // ""' 2>/dev/null)
                if [ "$status" = "ok" ]; then
                    return 0
                fi
            fi
        fi

        if [ $waited -eq 10 ]; then
            echo "Installing ios-simulator-mcp (first time may take a moment)..." >&2
        fi

        sleep 1
        waited=$((waited + 1))
    done

    # Timed out.
    kill "$bridge_pid" 2>/dev/null || true
    cleanup_state_files
    output_error "iOS Simulator bridge did not start within ${max_wait}s. Check $LOG_FILE"
    exit 0
}

# Ensure the bridge is running, starting it if needed.
# Uses flock to prevent race conditions from concurrent invocations.
ensure_bridge() {
    if is_bridge_running; then
        return 0
    fi

    # Acquire lock to prevent concurrent startup.
    mkdir -p "$STATE_DIR"
    (
        flock -n 200 || {
            # Another process is starting the bridge. Wait for it.
            flock -w 120 200 || {
                output_error "Timed out waiting for iOS Simulator bridge lock"
                exit 0
            }
            # Lock acquired after waiting -- bridge should be ready now.
            if is_bridge_running; then
                return 0
            fi
            # Bridge didn't start -- fall through to start it ourselves.
        }

        # Double-check after acquiring lock.
        if is_bridge_running; then
            return 0
        fi

        start_bridge
    ) 200>"$LOCK_FILE"
}

# Stop the bridge process.
stop_bridge() {
    if [ -f "$PORT_FILE" ]; then
        local port
        port=$(cat "$PORT_FILE" 2>/dev/null)
        if [ -n "$port" ]; then
            # Try graceful shutdown via HTTP.
            curl -sf --max-time 5 -X POST "http://127.0.0.1:$port/stop" >/dev/null 2>&1 || true
        fi
    fi

    # Wait briefly for graceful exit.
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$pid" ]; then
            local waited=0
            while kill -0 "$pid" 2>/dev/null && [ $waited -lt 5 ]; do
                sleep 1
                waited=$((waited + 1))
            done
            # Force kill if still alive.
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi

    cleanup_state_files
}

cleanup_state_files() {
    rm -f "$PID_FILE" "$PORT_FILE" "$LOCK_FILE"
}

# Call an iOS Simulator MCP tool via the bridge HTTP API.
# Usage: mcp_call <tool_name> <arguments_json>
# Returns: raw JSON response from the bridge.
mcp_call() {
    local tool_name="$1"
    local arguments="${2:-{}}"
    local port
    port=$(cat "$PORT_FILE" 2>/dev/null)

    if [ -z "$port" ]; then
        echo '{"error": "Bridge not running (no port file)"}'
        return 1
    fi

    local payload
    payload=$(jq -n --arg tool "$tool_name" --argjson args "$arguments" \
        '{tool: $tool, arguments: $args}')

    local response
    response=$(curl -sf --max-time 60 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "http://127.0.0.1:$port/call" 2>&1)

    local curl_exit=$?
    if [ $curl_exit -ne 0 ]; then
        echo "{\"error\": \"Bridge request failed (curl exit $curl_exit): $response\"}"
        return 1
    fi

    echo "$response"
}

# Check if an MCP tool response indicates an error.
is_mcp_error() {
    local response="$1"
    # Check for bridge-level errors.
    if printf '%s' "$response" | jq -e '.error' >/dev/null 2>&1; then
        return 0
    fi
    # Check for MCP tool-level errors (isError flag in content).
    if printf '%s' "$response" | jq -e '.isError // false' 2>/dev/null | grep -q true; then
        return 0
    fi
    return 1
}

# Extract error message from a response.
extract_error() {
    local response="$1"
    # Bridge-level error.
    local bridge_err
    bridge_err=$(printf '%s' "$response" | jq -r '.error // empty' 2>/dev/null)
    if [ -n "$bridge_err" ]; then
        echo "$bridge_err"
        return
    fi
    # MCP tool error -- extract from content.
    local tool_err
    tool_err=$(printf '%s' "$response" | jq -r '.content[]? | select(.type == "text") | .text // empty' 2>/dev/null)
    if [ -n "$tool_err" ]; then
        echo "$tool_err"
        return
    fi
    echo "Unknown error"
}
