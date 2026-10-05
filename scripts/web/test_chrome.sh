#!/usr/bin/env bash
# Run the plugin's test suite in Chrome against the bundled WebAssembly engine.
# The engine is served from assets/ with CORS headers on a local port and the
# tests receive its URL through the CIPHERBIRD_LIBRARY compile-time define.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="$ROOT/bridge/bindings/cipherbird"
PORT="${PORT:-8766}"
python3 "$ROOT/scripts/web/serve_engine.py" "$PORT" "$PKG/assets" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1
cd "$PKG"
flutter test --platform chrome \
    --dart-define=CIPHERBIRD_LIBRARY="http://127.0.0.1:$PORT/cipherbird.js" "$@"
