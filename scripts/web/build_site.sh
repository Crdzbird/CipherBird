#!/usr/bin/env bash
# Assemble the demo site into one folder ready for GitHub Pages:
#   scripts/web/build_site.sh <out-dir> [--showcase]
# Copies site/ (without its tests), the committed web engine from the Flutter
# plugin's assets and its integrity digests, which are checked against the
# copied bytes so a stale or edited engine fails the build. --showcase also
# builds the Flutter showcase into <out-dir>/showcase/.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:?usage: build_site.sh <out-dir> [--showcase]}"
SHOWCASE="${2:-}"
ASSETS="$ROOT/bridge/bindings/cipherbird/assets"
DIGESTS="$ROOT/bridge/bindings/cipherbird/lib/src/engine_integrity.dart"

case "$OUT" in
  ""|"/"|"$ROOT"|"$HOME") echo "refusing to replace $OUT" >&2; exit 1 ;;
esac
rm -rf -- "${OUT:?}"
mkdir -p "$OUT/engine"
rsync -a --exclude test --exclude README.md --exclude package.json "$ROOT/site/" "$OUT/"
cp "$ASSETS/cipherbird.js" "$ASSETS/cipherbird.wasm" "$OUT/engine/"
touch "$OUT/.nojekyll"

digest() {
  grep -A1 "static const String $1 =" "$DIGESTS" | grep -o "sha384-[A-Za-z0-9+/=]*"
}
sri() {
  printf 'sha384-%s' "$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}
ENGINE_SRI="$(digest engine)"
WASM_SRI="$(digest wasm)"
[ "$(sri "$OUT/engine/cipherbird.js")" = "$ENGINE_SRI" ] || { echo "cipherbird.js does not match its recorded digest" >&2; exit 1; }
[ "$(sri "$OUT/engine/cipherbird.wasm")" = "$WASM_SRI" ] || { echo "cipherbird.wasm does not match its recorded digest" >&2; exit 1; }
printf '{\n  "engine": "%s",\n  "wasm": "%s",\n  "wasmBytes": %s\n}\n' \
  "$ENGINE_SRI" "$WASM_SRI" "$(wc -c < "$OUT/engine/cipherbird.wasm" | tr -d ' ')" > "$OUT/engine/integrity.json"

if [ "$SHOWCASE" = "--showcase" ]; then
  BASE_HREF="${SHOWCASE_BASE_HREF:-/showcase/}"
  (cd "$ROOT/bridge/bindings/cipherbird/example" && flutter pub get >/dev/null && flutter build web --release --base-href "$BASE_HREF")
  cp -R "$ROOT/bridge/bindings/cipherbird/example/build/web" "$OUT/showcase"
fi
echo "site assembled in $OUT"
