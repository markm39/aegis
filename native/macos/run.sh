#!/bin/bash
# Build AegisMac and run it as a proper .app bundle.
# Notifications require a bundle identifier, which only exists inside an .app.
set -euo pipefail

cd "$(dirname "$0")"

echo "Building AegisMac..."
swift build

APP_DIR=".build/AegisMac.app/Contents"
mkdir -p "$APP_DIR/MacOS"

cp .build/debug/AegisMac "$APP_DIR/MacOS/AegisMac"
cp Sources/AegisMac/Info.plist "$APP_DIR/Info.plist"

if [ -f Sources/AegisMac/AegisMac.entitlements ]; then
    cp Sources/AegisMac/AegisMac.entitlements "$APP_DIR/AegisMac.entitlements"
fi

echo "Launching AegisMac.app..."
open .build/AegisMac.app
