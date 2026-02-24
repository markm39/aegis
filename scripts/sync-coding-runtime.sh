#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE="${CODEX_MIRROR_DIR:-${HOME}/codex-mirror}"
DEST="${REPO_ROOT}/vendor/coding-runtime"
CHECK_MODE=0

usage() {
    cat <<USAGE
Usage: $0 [--source PATH] [--check]

Sync the local Codex mirror into vendor/coding-runtime with pinned provenance.

Options:
  --source PATH   Override mirror path (default: \$CODEX_MIRROR_DIR or ~/codex-mirror)
  --check         Dry-run: fail if vendor/coding-runtime is out of sync
  -h, --help      Show this help text
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)
            SOURCE="$2"
            shift 2
            ;;
        --check)
            CHECK_MODE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -d "$SOURCE" ]]; then
    echo "Error: source mirror directory does not exist: $SOURCE" >&2
    exit 1
fi

if [[ ! -d "$SOURCE/codex-rs" ]]; then
    echo "Error: source mirror is missing codex-rs/: $SOURCE" >&2
    exit 1
fi

UPSTREAM_SHA="unknown"
if git -C "$SOURCE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    UPSTREAM_SHA="$(git -C "$SOURCE" rev-parse HEAD)"
fi

UPDATED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

RSYNC_EXCLUDES=(
    --omit-dir-times
    --exclude '.git/'
    --exclude '.github/'
    --exclude '.vscode/'
    --exclude '.devcontainer/'
    --exclude 'node_modules/'
    --exclude 'VENDOR_MANIFEST.yaml'
    --exclude 'UPSTREAM_Codex.md'
)

mkdir -p "$DEST"

if [[ "$CHECK_MODE" -eq 1 ]]; then
    drift_file="$(mktemp)"
    trap 'rm -f "$drift_file"' EXIT

    rsync -ain --delete "${RSYNC_EXCLUDES[@]}" "$SOURCE/" "$DEST/" >"$drift_file"

    if [[ -s "$drift_file" ]]; then
        echo "vendor/coding-runtime is out of sync with $SOURCE" >&2
        echo "Run: scripts/sync-coding-runtime.sh --source '$SOURCE'" >&2
        cat "$drift_file" >&2
        exit 1
    fi

    if [[ -f "$DEST/VENDOR_MANIFEST.yaml" ]] && ! grep -q "^upstream_sha: ${UPSTREAM_SHA}$" "$DEST/VENDOR_MANIFEST.yaml"; then
        echo "vendor/coding-runtime manifest upstream_sha does not match source ($UPSTREAM_SHA)" >&2
        echo "Run: scripts/sync-coding-runtime.sh --source '$SOURCE'" >&2
        exit 1
    fi

    echo "vendor/coding-runtime is in sync (${UPSTREAM_SHA})"
    exit 0
fi

rsync -a --delete "${RSYNC_EXCLUDES[@]}" "$SOURCE/" "$DEST/"

top_dirs="$(find "$DEST" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)"

{
    echo "version: 1"
    echo "upstream_name: codex"
    echo "upstream_source: ${SOURCE}"
    echo "upstream_sha: ${UPSTREAM_SHA}"
    echo "synced_at_utc: ${UPDATED_AT_UTC}"
    echo "sync_script: scripts/sync-coding-runtime.sh"
    echo "layout: neutral-vendor-path"
    echo "vendor_path: vendor/coding-runtime"
    echo "included_top_level_dirs:"
    for dir in $top_dirs; do
        echo "  - ${dir}"
    done
    echo "excluded_paths:"
    echo "  - .git/"
    echo "  - .github/"
    echo "  - .vscode/"
    echo "  - .devcontainer/"
    echo "  - node_modules/"
    echo "local_patches: []"
} >"$DEST/VENDOR_MANIFEST.yaml"

cat >"$DEST/UPSTREAM_Codex.md" <<UPSTREAM
# Upstream Attribution: Codex

This directory contains vendored source snapshots from the OpenAI Codex project.

- Upstream project: https://github.com/openai/codex
- Local mirror source: \`${SOURCE}\`
- Sync mechanism: \`scripts/sync-coding-runtime.sh\`
- Pinned revision: see \`VENDOR_MANIFEST.yaml\` (\`upstream_sha\`)

## Why the neutral path name

Aegis intentionally stores this under \`vendor/coding-runtime/\` instead of an
upstream-branded path so internal runtime wiring stays product-neutral while
still preserving explicit provenance.

## Licensing

- Upstream Codex source files retain their original license notices.
- Root license/notice files from upstream are mirrored in this snapshot.
- Aegis-specific glue code and wrappers are maintained in Aegis crates/scripts.

## Local modification policy

Local edits inside \`vendor/coding-runtime/\` should be avoided when possible.
If a local patch is unavoidable, record it in \`VENDOR_MANIFEST.yaml\` under
\`local_patches\`.
UPSTREAM

echo "Synced coding runtime from ${SOURCE}"
echo "Upstream SHA: ${UPSTREAM_SHA}"
echo "Manifest: ${DEST}/VENDOR_MANIFEST.yaml"
