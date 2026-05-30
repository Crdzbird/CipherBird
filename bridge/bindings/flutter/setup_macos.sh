#!/bin/bash
# Bootstrap macOS platform support for the CryptoLib Flutter GUI app.
#
# This script creates a temporary Flutter project, copies the macOS platform
# files into this project, then installs dependencies.
#
# Usage:
#   cd bridge/flutter
#   chmod +x setup_macos.sh
#   ./setup_macos.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR=$(mktemp -d)

echo "Creating temporary Flutter project for macOS scaffolding..."
cd "$TEMP_DIR"
flutter create --platforms=macos --org=com.cryptolib temp_project

echo "Copying macOS platform files..."
if [ -d "$SCRIPT_DIR/macos" ]; then
  rm -rf "$SCRIPT_DIR/macos"
fi
cp -R "$TEMP_DIR/temp_project/macos" "$SCRIPT_DIR/macos"

# Copy other flutter infrastructure files if missing
for f in .gitignore .metadata; do
  if [ ! -f "$SCRIPT_DIR/$f" ] && [ -f "$TEMP_DIR/temp_project/$f" ]; then
    cp "$TEMP_DIR/temp_project/$f" "$SCRIPT_DIR/$f"
  fi
done

echo "Cleaning up..."
rm -rf "$TEMP_DIR"

echo "Patching entitlements for file access..."
# Ensure file access entitlements are present
ENTITLEMENTS_DEBUG="$SCRIPT_DIR/macos/Runner/DebugProfile.entitlements"
ENTITLEMENTS_RELEASE="$SCRIPT_DIR/macos/Runner/Release.entitlements"

# Add file access entitlements using PlistBuddy
for ENT in "$ENTITLEMENTS_DEBUG" "$ENTITLEMENTS_RELEASE"; do
  /usr/libexec/PlistBuddy -c "Add :com.apple.security.files.user-selected.read-write bool true" "$ENT" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :com.apple.security.files.downloads.read-write bool true" "$ENT" 2>/dev/null || true
done

echo "Running flutter pub get..."
cd "$SCRIPT_DIR"
flutter pub get

echo ""
echo "Setup complete! You can now run the app with:"
echo "  cd $SCRIPT_DIR"
echo "  CRYPTOLIB_PATH=/path/to/libcryptolib_c.dylib flutter run -d macos"
echo ""
echo "Or for development with the default path:"
echo "  flutter run -d macos"
