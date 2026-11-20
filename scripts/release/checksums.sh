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
  build/selfcontained/libcipherbird_c.dylib
  build/android-arm64-v8a/libcipherbird_c.so
  build/android-x86_64/libcipherbird_c.so
  bridge/bindings/cipherbird-node/prebuilds/darwin-arm64/libcipherbird.dylib
  bridge/bindings/cipherbird-jvm/native/darwin-arm64/libcipherbird.dylib
  bridge/bindings/cipherbird-dotnet/runtimes/osx-arm64/native/libcipherbird.dylib
)
PRESENT=()
for f in "${CANDIDATES[@]}"; do [ -f "$f" ] && PRESENT+=("$f"); done

# The xcframework is a directory — checksum a deterministic tar of it.
if [ -d CipherBird.xcframework ]; then
  tar --uid 0 --gid 0 --numeric-owner -cf build/CipherBird.xcframework.tar CipherBird.xcframework 2>/dev/null \
    || tar -cf build/CipherBird.xcframework.tar CipherBird.xcframework
  PRESENT+=(build/CipherBird.xcframework.tar)
fi

[ ${#PRESENT[@]} -gt 0 ] || { echo "No release artifacts found (build them first)."; exit 1; }
sha "${PRESENT[@]}" > "$OUT"
echo "Wrote $OUT:"
cat "$OUT"
