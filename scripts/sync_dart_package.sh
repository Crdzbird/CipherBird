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
sed 's/^library;$/library;/' "$SRC/lib/cipherbird.dart" > "$DST/lib/cipherbird_dart.dart"
for t in "$SRC"/test/*_test.dart; do
  sed -e "s#package:flutter_test/flutter_test.dart#package:test/test.dart#" \
      -e "s#package:cipherbird/cipherbird.dart#package:cipherbird_dart/cipherbird_dart.dart#" \
      "$t" > "$DST/test/$(basename "$t")"
done
echo "synced $(find "$DST/lib/src" -name '*.dart' | wc -l | tr -d ' ') source files and $(ls "$DST"/test | wc -l | tr -d ' ') tests"
