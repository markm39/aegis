#!/bin/sh
# Aegis Probe installer
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh

set -eu

AEGIS_REPO="markm39/aegis"
AEGIS_INSTALL_DIR="${AEGIS_INSTALL_DIR:-/usr/local/bin}"
AEGIS_VERSION="${AEGIS_VERSION:-}"
AEGIS_NO_MODIFY_PATH="${AEGIS_NO_MODIFY_PATH:-0}"

if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    RESET='\033[0m'
else
    BOLD=''
    GREEN=''
    YELLOW=''
    RED=''
    RESET=''
fi

info() {
    printf "${BOLD}==> %s${RESET}\n" "$1"
}

success() {
    printf "${GREEN}==> %s${RESET}\n" "$1"
}

warn() {
    printf "${YELLOW}Warning: %s${RESET}\n" "$1"
}

error() {
    printf "${RED}Error: %s${RESET}\n" "$1" >&2
    exit 1
}

usage() {
    cat <<EOF
Aegis Probe installer

Usage:
  curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh

Options:
  --uninstall    Remove aegis-probe and any generated shell completions
  --help         Show this help

Environment variables:
  AEGIS_INSTALL_DIR    Install directory (default: /usr/local/bin)
  AEGIS_VERSION        Release version to install (default: latest)
  AEGIS_NO_MODIFY_PATH Set to 1 to suppress PATH hints
EOF
    exit 0
}

detect_completion_target() {
    SHELL_NAME=$(basename "${SHELL:-/bin/zsh}")
    case "$SHELL_NAME" in
        zsh)
            COMPLETION_DIR="/usr/local/share/zsh/site-functions"
            COMPLETION_FILE="_aegis-probe"
            COMPLETION_SHELL="zsh"
            ;;
        bash)
            COMPLETION_DIR="/usr/local/etc/bash_completion.d"
            COMPLETION_FILE="aegis-probe"
            COMPLETION_SHELL="bash"
            ;;
        fish)
            COMPLETION_DIR="${HOME}/.config/fish/completions"
            COMPLETION_FILE="aegis-probe.fish"
            COMPLETION_SHELL="fish"
            ;;
        *)
            COMPLETION_DIR=""
            COMPLETION_FILE=""
            COMPLETION_SHELL=""
            ;;
    esac
}

run_or_sudo() {
    "$@" 2>/dev/null || sudo "$@"
}

install_file() {
    SRC="$1"
    DEST_DIR="$2"
    DEST_FILE="$3"

    if [ ! -d "$DEST_DIR" ]; then
        run_or_sudo mkdir -p "$DEST_DIR"
    fi

    if [ -w "$DEST_DIR" ]; then
        cp "$SRC" "$DEST_DIR/$DEST_FILE"
    else
        sudo cp "$SRC" "$DEST_DIR/$DEST_FILE"
    fi
}

do_uninstall() {
    detect_completion_target
    info "Uninstalling aegis-probe"

    for path in \
        "$AEGIS_INSTALL_DIR/aegis-probe" \
        "/usr/local/share/zsh/site-functions/_aegis-probe" \
        "/usr/local/etc/bash_completion.d/aegis-probe" \
        "${HOME}/.config/fish/completions/aegis-probe.fish"; do
        if [ -f "$path" ]; then
            run_or_sudo rm -f "$path"
            printf "  Removed %s\n" "$path"
        fi
    done

    success "Aegis Probe removed"
    exit 0
}

download() {
    URL="$1"
    DEST="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$DEST"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$DEST" "$URL"
    else
        error "Neither curl nor wget is available."
    fi
}

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${AEGIS_REPO}/releases/latest" | \
            grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${AEGIS_REPO}/releases/latest" | \
            grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' || true
    fi
}

resolve_target() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$OS/$ARCH" in
        Darwin/arm64)
            TARGET="universal-apple-darwin"
            FALLBACK_TARGET="aarch64-apple-darwin"
            ;;
        Darwin/x86_64)
            TARGET="universal-apple-darwin"
            FALLBACK_TARGET="x86_64-apple-darwin"
            ;;
        Linux/x86_64)
            TARGET="x86_64-unknown-linux-gnu"
            FALLBACK_TARGET=""
            ;;
        *)
            TARGET=""
            FALLBACK_TARGET=""
            ;;
    esac
}

verify_checksum() {
    ARCHIVE="$1"
    ASSET_NAME="$2"
    VERSION="$3"
    TMPDIR="$4"
    CHECKSUMS_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/checksums-sha256.txt"
    CHECKSUMS_FILE="$TMPDIR/checksums.txt"

    if ! download "$CHECKSUMS_URL" "$CHECKSUMS_FILE" 2>/dev/null; then
        return 0
    fi

    EXPECTED_HASH=$(grep "$ASSET_NAME" "$CHECKSUMS_FILE" | cut -d' ' -f1 || true)
    if [ -z "$EXPECTED_HASH" ]; then
        return 0
    fi

    if command -v shasum >/dev/null 2>&1; then
        ACTUAL_HASH=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
    else
        ACTUAL_HASH=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
    fi
    [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ] || error "Checksum mismatch for $(basename "$ARCHIVE")"
}

download_release() {
    VERSION="$1"
    TMPDIR="$2"
    resolve_target

    if [ -z "$TARGET" ]; then
        return 1
    fi

    ARCHIVE="$TMPDIR/aegis-probe.tar.gz"
    PRIMARY_ASSET="aegis-probe-${VERSION}-${TARGET}.tar.gz"
    PRIMARY_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/${PRIMARY_ASSET}"
    FALLBACK_URL=""
    FALLBACK_ASSET=""
    if [ -n "$FALLBACK_TARGET" ]; then
        FALLBACK_ASSET="aegis-probe-${VERSION}-${FALLBACK_TARGET}.tar.gz"
        FALLBACK_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/${FALLBACK_ASSET}"
    fi

    if download "$PRIMARY_URL" "$ARCHIVE" 2>/dev/null; then
        ASSET_NAME="$PRIMARY_ASSET"
    elif [ -n "$FALLBACK_URL" ] && download "$FALLBACK_URL" "$ARCHIVE" 2>/dev/null; then
        ASSET_NAME="$FALLBACK_ASSET"
    else
        return 1
    fi

    verify_checksum "$ARCHIVE" "$ASSET_NAME" "$VERSION" "$TMPDIR"
    tar xzf "$ARCHIVE" -C "$TMPDIR"
    [ -f "$TMPDIR/aegis-probe" ] || return 1
    chmod +x "$TMPDIR/aegis-probe"
    return 0
}

build_from_source() {
    TMPDIR="$1"

    if ! command -v cargo >/dev/null 2>&1; then
        error "No compatible release archive found and cargo is unavailable."
    fi

    info "Building aegis-probe from source"
    if [ -n "$AEGIS_VERSION" ]; then
        cargo install --locked --git "https://github.com/${AEGIS_REPO}.git" \
            --tag "v${AEGIS_VERSION}" \
            --root "$TMPDIR/root" aegis-probe
    else
        cargo install --locked --git "https://github.com/${AEGIS_REPO}.git" \
            --root "$TMPDIR/root" aegis-probe
    fi
    cp "$TMPDIR/root/bin/aegis-probe" "$TMPDIR/aegis-probe"
}

install_completions() {
    BIN="$1"
    detect_completion_target

    if [ -z "$COMPLETION_SHELL" ]; then
        return 0
    fi

    TMP_COMPLETION=$(mktemp)
    "$BIN" completions "$COMPLETION_SHELL" > "$TMP_COMPLETION"
    if [ -s "$TMP_COMPLETION" ]; then
        install_file "$TMP_COMPLETION" "$COMPLETION_DIR" "$COMPLETION_FILE"
    fi
    rm -f "$TMP_COMPLETION"
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --uninstall) do_uninstall ;;
            --help|-h) usage ;;
        esac
    done

    printf "\n${BOLD}Aegis Probe Installer${RESET}\n"
    printf "Security testing for AI agents and models\n\n"

    if [ -z "$AEGIS_VERSION" ]; then
        info "Resolving latest release"
        AEGIS_VERSION=$(get_latest_version)
    fi

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT INT TERM

    if [ -n "$AEGIS_VERSION" ]; then
        info "Downloading aegis-probe v${AEGIS_VERSION}"
        if ! download_release "$AEGIS_VERSION" "$TMPDIR"; then
            warn "No compatible release archive found for this platform"
            build_from_source "$TMPDIR"
        fi
    else
        warn "Could not resolve a release version"
        build_from_source "$TMPDIR"
    fi

    info "Installing aegis-probe to ${AEGIS_INSTALL_DIR}"
    install_file "$TMPDIR/aegis-probe" "$AEGIS_INSTALL_DIR" "aegis-probe"
    run_or_sudo chmod 755 "$AEGIS_INSTALL_DIR/aegis-probe"

    install_completions "$AEGIS_INSTALL_DIR/aegis-probe"

    success "aegis-probe installed"
    printf "\n"
    printf "  Binary: %s/aegis-probe\n" "$AEGIS_INSTALL_DIR"
    printf "  Version: %s\n" "$("$AEGIS_INSTALL_DIR/aegis-probe" --version | head -1)"
    printf "\n"
    printf "Get started:\n"
    printf "  aegis-probe list --probes-dir probes\n"
    printf "  aegis-probe run --agent-binary claude --category prompt_injection\n"
    printf "  aegis-probe registry status\n"
    if [ "$AEGIS_NO_MODIFY_PATH" != "1" ]; then
        printf "\n"
        printf "If %s is not on your PATH, add it before running aegis-probe.\n" "$AEGIS_INSTALL_DIR"
    fi
}

main "$@"
