#!/usr/bin/env bash
# Replace the committed engines with the ones a given engines workflow run
# built and attested, so the repository ships CI output rather than
# workstation output. Usage: scripts/release/import_engines.sh <run-id>
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="${1:?usage: import_engines.sh <run-id>}"
REPO="${GITHUB_REPOSITORY:-Crdzbird/CipherBird}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
gh run download "$RUN" --repo "$REPO" --dir "$WORK"
P="$ROOT/bridge/bindings/cipherbird"
D="$ROOT/bridge/bindings/cipherbird_dart"
cp "$WORK/engine-android/arm64-v8a/libcipherbird.so" "$P/android/src/main/jniLibs/arm64-v8a/libcipherbird.so"
cp "$WORK/engine-android/x86_64/libcipherbird.so" "$P/android/src/main/jniLibs/x86_64/libcipherbird.so"
ditto -x -k "$WORK/engine-apple/CipherBird.xcframework.zip" "$WORK/apple"
rm -rf "$P/ios/cipherbird/CipherBird.xcframework" "$P/macos/cipherbird/CipherBird.xcframework"
cp -R "$WORK/apple/CipherBird.xcframework" "$P/ios/cipherbird/CipherBird.xcframework"
cp -R "$WORK/apple/CipherBird.xcframework" "$P/macos/cipherbird/CipherBird.xcframework"
cp "$WORK/engine-web/cipherbird.js" "$WORK/engine-web/cipherbird.wasm" "$P/assets/"
cp "$WORK/engine-web/cipherbird.js" "$WORK/engine-web/cipherbird.wasm" "$D/lib/assets/"
cp "$WORK/engine-desktop/libcryptolib_c.dylib" "$D/native/darwin-arm64/libcipherbird.dylib"
python3 "$ROOT/scripts/web/gen_integrity.py" "$P"
bash "$ROOT/scripts/sync_dart_package.sh"
bash "$ROOT/scripts/release/verify_attestations.sh"
