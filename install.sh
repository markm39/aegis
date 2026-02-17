#!/bin/sh
# Aegis installer
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh
#
# Environment variables:
#   AEGIS_INSTALL_DIR   Where to install the binary (default: /usr/local/bin)
#   AEGIS_VERSION       Version to install (default: latest release)
#   AEGIS_NO_MODIFY_PATH  Set to 1 to skip PATH modification hints
#
# Flags:
#   --uninstall         Remove aegis and its completions/man page
#   --help              Show this help

set -eu

AEGIS_REPO="markm39/aegis"
AEGIS_INSTALL_DIR="${AEGIS_INSTALL_DIR:-/usr/local/bin}"
AEGIS_MAN_DIR="${AEGIS_MAN_DIR:-/usr/local/share/man/man1}"
AEGIS_VERSION="${AEGIS_VERSION:-}"

# Colors (only when stdout is a terminal)
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
Aegis installer

Usage:
  curl -sSf https://raw.githubusercontent.com/markm39/aegis/main/install.sh | sh

Options:
  --uninstall    Remove aegis and its completions/man page
  --help         Show this help

Environment variables:
  AEGIS_INSTALL_DIR   Install directory (default: /usr/local/bin)
  AEGIS_VERSION       Version to install (default: latest)
EOF
    exit 0
}

# Detect shell completions directory
detect_completions_dir() {
    SHELL_NAME=$(basename "${SHELL:-/bin/zsh}")
    case "$SHELL_NAME" in
        zsh)
            COMPLETIONS_DIR="/usr/local/share/zsh/site-functions"
            COMPLETIONS_FILE="_aegis"
            COMPLETIONS_SHELL="zsh"
            ;;
        bash)
            COMPLETIONS_DIR="/usr/local/etc/bash_completion.d"
            COMPLETIONS_FILE="aegis"
            COMPLETIONS_SHELL="bash"
            ;;
        fish)
            COMPLETIONS_DIR="${HOME}/.config/fish/completions"
            COMPLETIONS_FILE="aegis.fish"
            COMPLETIONS_SHELL="fish"
            ;;
        *)
            COMPLETIONS_DIR=""
            COMPLETIONS_FILE=""
            COMPLETIONS_SHELL=""
            ;;
    esac
}

# Run a command, using sudo if needed for the target directory
maybe_sudo() {
    if [ -w "$(dirname "$1")" ] 2>/dev/null; then
        "$@"
    else
        info "Need permissions for $(dirname "$1") -- requesting sudo"
        sudo "$@"
    fi
}

# Install a file to a directory, creating it if needed
install_file() {
    SRC="$1"
    DEST_DIR="$2"
    DEST_FILE="$3"

    if [ ! -d "$DEST_DIR" ]; then
        maybe_sudo mkdir -p "$DEST_DIR"
    fi

    if [ -w "$DEST_DIR" ]; then
        cp "$SRC" "$DEST_DIR/$DEST_FILE"
    else
        sudo cp "$SRC" "$DEST_DIR/$DEST_FILE"
    fi
}

do_uninstall() {
    info "Uninstalling aegis"

    detect_completions_dir

    TARGETS="$AEGIS_INSTALL_DIR/aegis"
    [ -n "$COMPLETIONS_DIR" ] && TARGETS="$TARGETS $COMPLETIONS_DIR/$COMPLETIONS_FILE"
    TARGETS="$TARGETS $AEGIS_MAN_DIR/aegis.1"

    FOUND=0
    for f in $TARGETS; do
        if [ -f "$f" ]; then
            FOUND=1
            maybe_sudo rm -f "$f"
            printf "  Removed %s\n" "$f"
        fi
    done

    # Also try removing completions for other shells
    for f in \
        /usr/local/share/zsh/site-functions/_aegis \
        /usr/local/etc/bash_completion.d/aegis \
        "${HOME}/.config/fish/completions/aegis.fish"; do
        if [ -f "$f" ]; then
            FOUND=1
            maybe_sudo rm -f "$f"
            printf "  Removed %s\n" "$f"
        fi
    done

    if [ "$FOUND" -eq 0 ]; then
        warn "No aegis installation found"
    else
        success "Aegis uninstalled"
    fi
    exit 0
}

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${AEGIS_REPO}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${AEGIS_REPO}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' || true
    fi
}

download() {
    URL="$1"
    DEST="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$DEST" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$DEST" "$URL" 2>/dev/null
    else
        error "Neither curl nor wget found. Install one and try again."
    fi
}

try_download_binary() {
    VERSION="$1"
    TMPDIR="$2"

    # Try universal binary first, then arch-specific
    UNIVERSAL_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/aegis-${VERSION}-universal-apple-darwin.tar.gz"
    ARCH_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/aegis-${VERSION}-${TARGET}.tar.gz"
    CHECKSUMS_URL="https://github.com/${AEGIS_REPO}/releases/download/v${VERSION}/checksums-sha256.txt"

    TARBALL="$TMPDIR/aegis.tar.gz"

    # Try universal first
    if download "$UNIVERSAL_URL" "$TARBALL"; then
        DOWNLOAD_URL="$UNIVERSAL_URL"
    elif download "$ARCH_URL" "$TARBALL"; then
        DOWNLOAD_URL="$ARCH_URL"
    else
        return 1
    fi

    # Verify checksum if available
    CHECKSUMS_FILE="$TMPDIR/checksums.txt"
    if download "$CHECKSUMS_URL" "$CHECKSUMS_FILE" 2>/dev/null; then
        EXPECTED_HASH=$(grep "$(basename "$DOWNLOAD_URL")" "$CHECKSUMS_FILE" | cut -d' ' -f1)
        if [ -n "$EXPECTED_HASH" ]; then
            ACTUAL_HASH=$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)
            if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
                error "Checksum mismatch. Expected: $EXPECTED_HASH Got: $ACTUAL_HASH"
            fi
        fi
    fi

    tar xzf "$TARBALL" -C "$TMPDIR"
    if [ ! -f "$TMPDIR/aegis" ]; then
        return 1
    fi

    chmod +x "$TMPDIR/aegis"
    return 0
}

build_from_source() {
    TMPDIR="$1"

    if ! command -v cargo >/dev/null 2>&1; then
        warn "Rust toolchain not found."
        printf "  Install it with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n"
        printf "  Then re-run this installer.\n"
        error "Cannot install without pre-built binary or Rust toolchain."
    fi

    info "Building from source (this may take a few minutes)"
    CLONE_DIR="$TMPDIR/aegis-src"

    if [ -n "$AEGIS_VERSION" ]; then
        git clone --depth 1 --branch "v${AEGIS_VERSION}" "https://github.com/${AEGIS_REPO}.git" "$CLONE_DIR" 2>/dev/null || \
            git clone --depth 1 "https://github.com/${AEGIS_REPO}.git" "$CLONE_DIR"
    else
        git clone --depth 1 "https://github.com/${AEGIS_REPO}.git" "$CLONE_DIR"
    fi

    (cd "$CLONE_DIR" && cargo build --release -p aegis-cli)
    cp "$CLONE_DIR/target/release/aegis" "$TMPDIR/aegis"
    chmod +x "$TMPDIR/aegis"
}

main() {
    # Parse flags
    for arg in "$@"; do
        case "$arg" in
            --uninstall) do_uninstall ;;
            --help|-h) usage ;;
        esac
    done

    printf "\n${BOLD}Aegis Installer${RESET}\n"
    printf "Zero-trust runtime for AI agents\n\n"

    # Platform check
    OS=$(uname -s)
    if [ "$OS" != "Darwin" ]; then
        warn "Aegis is designed for macOS (Seatbelt sandbox features require macOS)."
        printf "  On other platforms, use: cargo install aegis-cli\n"
        printf "  Core features (policy, audit, observation) will work.\n"
        printf "  Kernel-level sandboxing will not be available.\n\n"

        if ! command -v cargo >/dev/null 2>&1; then
            error "Rust toolchain required on non-macOS. Install from https://rustup.rs"
        fi

        info "Installing via cargo"
        cargo install aegis-cli
        success "Aegis installed via cargo"
        exit 0
    fi

    # Architecture detection
    ARCH=$(uname -m)
    case "$ARCH" in
        arm64)  TARGET="aarch64-apple-darwin" ;;
        x86_64) TARGET="x86_64-apple-darwin" ;;
        *)      error "Unsupported architecture: $ARCH" ;;
    esac

    info "Detected macOS $ARCH"

    # Version resolution
    if [ -z "$AEGIS_VERSION" ]; then
        info "Checking for latest release"
        AEGIS_VERSION=$(get_latest_version)
    fi

    # Check for existing installation
    if command -v aegis >/dev/null 2>&1; then
        EXISTING=$(aegis --version 2>/dev/null | head -1 || echo "unknown")
        if [ -n "$AEGIS_VERSION" ]; then
            printf "  Existing: %s\n" "$EXISTING"
            printf "  Installing: v%s\n" "$AEGIS_VERSION"
        else
            printf "  Existing: %s\n" "$EXISTING"
            printf "  Installing: latest from source\n"
        fi
    fi

    # Create temp directory
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    # Try downloading pre-built binary
    INSTALLED_FROM="binary"
    if [ -n "$AEGIS_VERSION" ]; then
        info "Downloading aegis v${AEGIS_VERSION}"
        if ! try_download_binary "$AEGIS_VERSION" "$TMPDIR"; then
            warn "No pre-built binary available for v${AEGIS_VERSION}"
            build_from_source "$TMPDIR"
            INSTALLED_FROM="source"
        fi
    else
        warn "No releases found"
        build_from_source "$TMPDIR"
        INSTALLED_FROM="source"
    fi

    # Install binary
    info "Installing to ${AEGIS_INSTALL_DIR}/aegis"
    install_file "$TMPDIR/aegis" "$AEGIS_INSTALL_DIR" "aegis"
    if [ -f "$AEGIS_INSTALL_DIR/aegis" ]; then
        chmod +x "$AEGIS_INSTALL_DIR/aegis" 2>/dev/null || sudo chmod +x "$AEGIS_INSTALL_DIR/aegis"
    fi

    AEGIS_BIN="$AEGIS_INSTALL_DIR/aegis"

    # Install shell completions
    detect_completions_dir
    if [ -n "$COMPLETIONS_DIR" ] && [ -n "$COMPLETIONS_SHELL" ]; then
        info "Installing ${COMPLETIONS_SHELL} completions"
        COMP_TMP="$TMPDIR/completion"
        "$AEGIS_BIN" completions "$COMPLETIONS_SHELL" > "$COMP_TMP" 2>/dev/null || true
        if [ -s "$COMP_TMP" ]; then
            install_file "$COMP_TMP" "$COMPLETIONS_DIR" "$COMPLETIONS_FILE"
        fi
    fi

    # Install man page
    info "Installing man page"
    MAN_TMP="$TMPDIR/aegis.1"
    "$AEGIS_BIN" manpage > "$MAN_TMP" 2>/dev/null || true
    if [ -s "$MAN_TMP" ]; then
        install_file "$MAN_TMP" "$AEGIS_MAN_DIR" "aegis.1"
    fi

    # Run setup
    info "Running aegis setup"
    "$AEGIS_BIN" setup 2>/dev/null || true

    # Summary
    VERSION_STR=$("$AEGIS_BIN" --version 2>/dev/null | head -1 || echo "aegis")
    printf "\n"
    success "$VERSION_STR installed successfully (from $INSTALLED_FROM)"
    printf "\n"
    printf "  Binary:      %s\n" "$AEGIS_INSTALL_DIR/aegis"
    [ -n "$COMPLETIONS_DIR" ] && printf "  Completions: %s/%s\n" "$COMPLETIONS_DIR" "$COMPLETIONS_FILE"
    printf "  Man page:    %s/aegis.1\n" "$AEGIS_MAN_DIR"
    printf "\n"
    printf "Get started:\n"
    printf "  aegis init            # interactive setup wizard\n"
    printf "  aegis wrap -- claude  # observe any command\n"
    printf "  aegis pilot -- claude # supervise with auto-approval\n"
    printf "\n"
}

main "$@"
