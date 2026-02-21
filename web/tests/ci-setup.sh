#!/usr/bin/env bash
#
# CI setup script for Playwright browser tests.
#
# Installs Playwright browsers and their system dependencies
# for headless execution in CI environments.
#
# Usage:
#   chmod +x tests/ci-setup.sh
#   ./tests/ci-setup.sh

set -euo pipefail

echo "Installing Playwright browsers and system dependencies..."

npx playwright install --with-deps chromium firefox

echo "Playwright browsers installed successfully."
