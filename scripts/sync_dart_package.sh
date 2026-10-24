#!/usr/bin/env bash
# Mirror the Flutter plugin's Dart sources into the pure-Dart package.
# bridge/bindings/cipherbird/lib is the single source of truth; the pure-Dart
# package bridge/bindings/cipherbird_dart gets an identical lib/src, a barrel
# with the same export list, and the same tests with package:test imports.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/bridge/bindings/cipherbird"
DST="$ROOT/bridge/bindings/cipherbird_dart"
rm -rf "$DST/lib/src" "$DST/test"
mkdir -p "$DST/lib" "$DST/test"
cp -R "$SRC/lib/src" "$DST/lib/src"
rm -rf "$DST/lib/src/hardware"
find "$DST/lib/src" -name '*.dart' -exec sed -i '' "s#package:cipherbird/src/#package:cipherbird_dart/src/#g" {} +
sed -i '' "s/const String _packageName = 'cipherbird';/const String _packageName = 'cipherbird_dart';/" \
  "$DST/lib/src/platform/web/engine_loader.dart"
(cd "$DST" && dart format lib test > /dev/null)
rm -rf "$DST/lib/assets"
mkdir -p "$DST/lib/assets"
cp "$SRC/assets/cipherbird.js" "$SRC/assets/cipherbird.wasm" "$SRC/assets/cipherbird_worker.js" "$SRC/assets/cipherbird_boot.js" "$DST/lib/assets/"
sed 's/^library;$/library;/' "$SRC/lib/cipherbird.dart" > "$DST/lib/cipherbird_dart.dart"
for t in "$SRC"/test/*_test.dart; do
  case "$(basename "$t")" in hardware_test.dart|device_fips_test.dart|web_crypto_fips_test.dart) continue ;; esac
  sed -e "s#package:flutter_test/flutter_test.dart#package:test/test.dart#" \
      -e "s#package:cipherbird/cipherbird.dart#package:cipherbird_dart/cipherbird_dart.dart#" \
      -e "s#package:cipherbird/src/#package:cipherbird_dart/src/#g" \
      -e "s#assets/packages/cipherbird/assets/#packages/cipherbird_dart/assets/#g" \
      "$t" > "$DST/test/$(basename "$t")"
done
sed -e "s#assets/packages/cipherbird/assets/#packages/cipherbird_dart/assets/#g" \
    -e "s#cipherbird:web_setup#cipherbird_dart:web_setup#g" \
    -e "s#package:cipherbird/src/#package:cipherbird_dart/src/#g" \
    "$SRC/bin/web_setup.dart" > "$DST/bin/web_setup.dart"
echo "synced $(find "$DST/lib/src" -name '*.dart' | wc -l | tr -d ' ') source files and $(ls "$DST"/test | wc -l | tr -d ' ') tests"
