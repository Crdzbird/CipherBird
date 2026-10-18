#!/usr/bin/env bash
# Build the desktop (macOS arm64) libcryptolib_c.dylib from the same pinned,
# hash-verified dependency set the iOS and Android engines use, so every
# shipped slice carries one version of libsodium, OpenSSL (trimmed, no-dso),
# liboqs (minimal), blst and libsecp256k1. Output: build/desktop/libcryptolib_c.dylib
set -euo pipefail
source "$( cd "$( dirname "${BASH_SOURCE[0]}" )/../ios/lib" && pwd )/common.sh"
SLICE=macosx
DEPS="$(slice_prefix "$SLICE")"
for dep in libsodium blake3 secp256k1 blst openssl liboqs; do
    "$REPO_ROOT/scripts/ios/deps/build_$dep.sh" "$SLICE"
done
for lib in libsodium libblake3 liboqs libcrypto libblst libsecp256k1; do
    [[ -f "$DEPS/lib/$lib.a" ]] || die "missing $DEPS/lib/$lib.a"
done
OUT="$REPO_ROOT/build/desktop"
mkdir -p "$OUT"
log "Linking libcryptolib_c.dylib against the pinned macosx dependency set"
$(arch_clangxx "$SLICE" arm64) -std=c++20 -O2 -dynamiclib \
    -DCRYPTOLIB_HAS_BLAKE3=1 -DCRYPTOLIB_HAS_PQ=1 -DCRYPTOLIB_HAS_BLS=1 \
    -DCRYPTOLIB_HAS_OPENSSL=1 -DCRYPTOLIB_HAS_SECP256K1=1 -DCRYPTOLIB_BUILD_SHARED \
    -I "$REPO_ROOT/include" -I "$DEPS/include" \
    -install_name "@rpath/libcryptolib_c.dylib" \
    "$REPO_ROOT/bridge/cryptolib_c.cpp" \
    "$DEPS/lib/libsodium.a" "$DEPS/lib/libblake3.a" "$DEPS/lib/liboqs.a" \
    "$DEPS/lib/libcrypto.a" "$DEPS/lib/libblst.a" "$DEPS/lib/libsecp256k1.a" \
    -framework Security -framework Foundation \
    -o "$OUT/libcryptolib_c.dylib" > "$OUT/link.log" 2>&1 \
    || { cat "$OUT/link.log"; die "desktop dylib link failed"; }
EXTERNAL="$(otool -L "$OUT/libcryptolib_c.dylib" | tail -n +2 | grep -vE '/usr/lib/|/System/|@rpath/libcryptolib_c.dylib' || true)"
[[ -z "$EXTERNAL" ]] || die "desktop dylib links external libraries: $EXTERNAL"
SYMS="$(nm -gU "$OUT/libcryptolib_c.dylib" | grep -c ' T _cryptolib_')"
HDR="$(grep -c '^CRYPTO_API' "$REPO_ROOT/bridge/cryptolib_c.h")"
[[ "$SYMS" == "$HDR" ]] || die "symbol count $SYMS does not match header $HDR"
ok "Built $OUT/libcryptolib_c.dylib ($SYMS symbols, $(du -h "$OUT/libcryptolib_c.dylib" | cut -f1))"
