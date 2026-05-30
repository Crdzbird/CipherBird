#!/usr/bin/env bash
# Generate SHA-256 checksums for the release artifacts present in the tree.
# The resulting SHA256SUMS is what you sign (cosign / minisign / GPG) and publish
# alongside the binaries so consumers can verify integrity + provenance.
#
# Usage: scripts/release/checksums.sh [output_file]   (default: SHA256SUMS)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="${1:-SHA256SUMS}"

sha() { command -v sha256sum >/dev/null && sha256sum "$@" || shasum -a 256 "$@"; }

# Candidate release artifacts (only those that exist are hashed).
CANDIDATES=(
  build/selfcontained/libcryptolib_c.dylib
  build/android-arm64-v8a/libcryptolib_c.so
  build/android-x86_64/libcryptolib_c.so
  bridge/bindings/cryptolib-node/prebuilds/darwin-arm64/libcryptolib_c.dylib
  bridge/bindings/cryptolib-jvm/native/darwin-arm64/libcryptolib_c.dylib
  bridge/bindings/cryptolib-dotnet/runtimes/osx-arm64/native/libcryptolib_c.dylib
)
PRESENT=()
for f in "${CANDIDATES[@]}"; do [ -f "$f" ] && PRESENT+=("$f"); done

# The xcframework is a directory — checksum a deterministic tar of it.
if [ -d CryptoLib.xcframework ]; then
  tar --uid 0 --gid 0 --numeric-owner -cf build/CryptoLib.xcframework.tar CryptoLib.xcframework 2>/dev/null \
    || tar -cf build/CryptoLib.xcframework.tar CryptoLib.xcframework
  PRESENT+=(build/CryptoLib.xcframework.tar)
fi

[ ${#PRESENT[@]} -gt 0 ] || { echo "No release artifacts found (build them first)."; exit 1; }
sha "${PRESENT[@]}" > "$OUT"
echo "Wrote $OUT:"
cat "$OUT"
