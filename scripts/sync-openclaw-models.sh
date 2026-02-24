#!/usr/bin/env bash
# sync-openclaw-models.sh
#
# Extract current model catalog from the openclaw-mirror repo and print a
# summary for manual reference when updating crates/aegis-types/src/providers.rs.
#
# Usage:
#   ./scripts/sync-openclaw-models.sh [path-to-openclaw-mirror]
#
# Default mirror path: ../openclaw-mirror (sibling directory to aegis)

set -euo pipefail

MIRROR="${1:-../openclaw-mirror}"

if [[ ! -d "$MIRROR" ]]; then
    echo "Error: openclaw-mirror not found at $MIRROR"
    echo "Usage: $0 [path-to-openclaw-mirror]"
    exit 1
fi

ZEN="$MIRROR/src/agents/opencode-zen-models.ts"
AUTH="$MIRROR/src/commands/onboard-auth.models.ts"
DEFAULTS="$MIRROR/src/config/defaults.ts"

echo "=== OpenClaw Model Catalog ==="
echo ""

# Extract default model aliases
if [[ -f "$DEFAULTS" ]]; then
    echo "--- Default Aliases (from defaults.ts) ---"
    grep -A1 'opus:\|sonnet:\|gpt:\|gemini:' "$DEFAULTS" 2>/dev/null | head -20
    echo ""
fi

# Extract context windows
if [[ -f "$ZEN" ]]; then
    echo "--- Context Windows (from opencode-zen-models.ts) ---"
    sed -n '/MODEL_CONTEXT_WINDOWS/,/^};/p' "$ZEN"
    echo ""
    echo "--- Max Tokens ---"
    sed -n '/MODEL_MAX_TOKENS/,/^};/p' "$ZEN"
    echo ""
    echo "--- Static Fallback Models ---"
    sed -n '/getOpencodeZenStaticFallbackModels/,/return/p' "$ZEN"
    echo ""
fi

# Extract xAI defaults
if [[ -f "$AUTH" ]]; then
    echo "--- xAI Defaults (from onboard-auth.models.ts) ---"
    grep -E 'XAI_DEFAULT|XAI_DEFAULT_CONTEXT|XAI_DEFAULT_MAX' "$AUTH" 2>/dev/null
    echo ""
    echo "--- ZAI Defaults ---"
    grep -E 'ZAI_DEFAULT_MODEL' "$AUTH" 2>/dev/null
    echo ""
fi

echo "=== Done ==="
echo "Update crates/aegis-types/src/providers.rs to match the above."
