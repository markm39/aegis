#!/bin/bash
# format.sh -- SkillOutput JSON formatting helpers for the iOS Simulator skill.
#
# All output from the skill must be valid JSON matching the SkillOutput schema:
#   { "result": <string>, "artifacts": [...], "messages": [...] }

# Output a simple text result.
output_result() {
    local text="$1"
    local result_json
    result_json=$(printf '%s' "$text" | jq -Rs .)
    printf '{"result": %s, "artifacts": [], "messages": []}\n' "$result_json"
}

# Output an error message (prefixed with "Error:").
output_error() {
    local text="$1"
    local result_json
    result_json=$(printf '%s' "Error: $text" | jq -Rs .)
    printf '{"result": %s, "artifacts": [], "messages": []}\n' "$result_json"
}

# Output a result with a single artifact (for screenshots).
# Usage: output_with_artifact <text> <artifact_name> <content_type> <file_path> <base64_content>
output_with_artifact() {
    local text="$1"
    local artifact_name="$2"
    local content_type="$3"
    local file_path="$4"
    local base64_content="$5"

    local result_json
    result_json=$(printf '%s' "$text" | jq -Rs .)

    local artifact
    artifact=$(jq -n \
        --arg name "$artifact_name" \
        --arg ct "$content_type" \
        --arg path "$file_path" \
        --arg content "$base64_content" \
        '{name: $name, content_type: $ct, path: $path, content: $content}')

    printf '{"result": %s, "artifacts": [%s], "messages": []}\n' "$result_json" "$artifact"
}

# Extract the readable text content from an MCP tool response.
# MCP responses wrap tool results as: { "content": [{ "type": "text", "text": "..." }] }
extract_mcp_text() {
    local response="$1"
    printf '%s' "$response" | jq -r '.content[]? | select(.type == "text") | .text // empty' 2>/dev/null
}

# Extract base64 image data from an MCP screenshot response.
# Screenshot responses have: { "content": [{ "type": "image", "data": "base64..." }] }
extract_mcp_image() {
    local response="$1"
    printf '%s' "$response" | jq -r '.content[]? | select(.type == "image") | .data // empty' 2>/dev/null
}
