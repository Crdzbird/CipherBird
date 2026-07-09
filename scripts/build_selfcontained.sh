#!/usr/bin/env bash
# Build a SELF-CONTAINED desktop libcryptolib_c (macOS host) — every dependency
# (libsodium, BLAKE3, liboqs, OpenSSL libcrypto, blst) statically linked in, so
# the resulting dylib runs with no Homebrew/system crypto libs installed. This
# is the binary the npm / JVM / .NET bundles should ship.
#
# Usage: scripts/build_selfcontained.sh [out_dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-build/selfcontained}"
mkdir -p "$OUT"

BREW_LIB=/opt/homebrew/lib
OSSL=/opt/homebrew/opt/openssl@3

# 1. Build libblake3.a from the vendored source (Homebrew ships only a dylib).
BL_SRC_TARBALL="$(ls third_party/*/src/blake3-*.tar.gz 2>/dev/null | head -1)"
[ -n "$BL_SRC_TARBALL" ] || { echo "blake3 source tarball not found"; exit 1; }
if [ ! -f build/host-deps/blake3-build/libblake3.a ]; then
    mkdir -p build/host-deps
    tar xzf "$BL_SRC_TARBALL" -C build/host-deps
    # find, not an ls glob: under `set -euo pipefail` an unmatched glob makes ls
    # exit 1 and silently kills the script (same bug as c649831).
    BL_SRC="$(find build/host-deps -maxdepth 1 -type d -iname 'blake3-*' | head -1)"
    cmake -S "$BL_SRC/c" -B build/host-deps/blake3-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
    cmake --build build/host-deps/blake3-build >/dev/null
fi
BLAKE3_A=build/host-deps/blake3-build/libblake3.a

# 2. Link the bridge against all static archives.
SECP=/opt/homebrew/opt/secp256k1

clang++ -std=c++20 -O2 -dynamiclib \
    -DCRYPTOLIB_HAS_BLAKE3=1 -DCRYPTOLIB_HAS_PQ=1 -DCRYPTOLIB_HAS_BLS=1 -DCRYPTOLIB_HAS_OPENSSL=1 -DCRYPTOLIB_HAS_SECP256K1=1 -DCRYPTOLIB_BUILD_SHARED \
    -I include -I /opt/homebrew/include -I "$OSSL/include" -I "$SECP/include" \
    -install_name "@rpath/libcryptolib_c.dylib" \
    bridge/cryptolib_c.cpp \
    "$BREW_LIB/libsodium.a" "$BLAKE3_A" "$BREW_LIB/liboqs.a" \
    "$OSSL/lib/libcrypto.a" "$BREW_LIB/libblst.a" "$SECP/lib/libsecp256k1.a" \
    -o "$OUT/libcryptolib_c.dylib"

echo "→ $OUT/libcryptolib_c.dylib"
echo "=== external (non-system) dependencies — should be NONE ==="
otool -L "$OUT/libcryptolib_c.dylib" | tail -n +2 | grep -vE "/usr/lib/|/System/" || echo "  (self-contained ✓)"
