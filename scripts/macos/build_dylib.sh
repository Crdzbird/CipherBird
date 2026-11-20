#!/usr/bin/env bash
# Build the desktop (macOS arm64) libcipherbird_c.dylib from the same pinned,
# hash-verified dependency set the iOS and Android engines use, so every
# shipped slice carries one version of libsodium, OpenSSL (trimmed, no-dso),
# liboqs (minimal), blst and libsecp256k1. Output: build/desktop/libcipherbird_c.dylib
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
log "Linking libcipherbird_c.dylib against the pinned macosx dependency set"
$(arch_clangxx "$SLICE" arm64) -std=c++20 -O2 -dynamiclib \
    -DCIPHERBIRD_HAS_BLAKE3=1 -DCIPHERBIRD_HAS_PQ=1 -DCIPHERBIRD_HAS_SODIUM_CRYPTO=1 -DCIPHERBIRD_HAS_STEGO=1 -DCIPHERBIRD_HAS_MEDIA_ENTROPY=1 -DCIPHERBIRD_HAS_NATIVE_COMBINERS=1 -DCIPHERBIRD_HAS_BLS=1 \
    -DCIPHERBIRD_HAS_OPENSSL=1 -DCIPHERBIRD_HAS_SECP256K1=1 -DCIPHERBIRD_BUILD_SHARED \
    -I "$REPO_ROOT/include" -I "$DEPS/include" \
    -install_name "@rpath/libcipherbird_c.dylib" \
    "$REPO_ROOT/bridge/cipherbird_c.cpp" \
    "$DEPS/lib/libsodium.a" "$DEPS/lib/libblake3.a" "$DEPS/lib/liboqs.a" \
    "$DEPS/lib/libcrypto.a" "$DEPS/lib/libblst.a" "$DEPS/lib/libsecp256k1.a" \
    -framework Security -framework Foundation \
    -o "$OUT/libcipherbird_c.dylib" > "$OUT/link.log" 2>&1 \
    || { cat "$OUT/link.log"; die "desktop dylib link failed"; }
EXTERNAL="$(otool -L "$OUT/libcipherbird_c.dylib" | tail -n +2 | grep -vE '/usr/lib/|/System/|@rpath/libcipherbird_c.dylib' || true)"
[[ -z "$EXTERNAL" ]] || die "desktop dylib links external libraries: $EXTERNAL"
SYMS="$(nm -gU "$OUT/libcipherbird_c.dylib" | grep -c ' T _cipherbird_')"
HDR="$(grep '^CRYPTO_API' "$REPO_ROOT/bridge/cipherbird_c.h" | grep -vc _for_testing)"
[[ "$SYMS" == "$HDR" ]] || die "symbol count $SYMS does not match header $HDR"
ok "Built $OUT/libcipherbird_c.dylib ($SYMS symbols, $(du -h "$OUT/libcipherbird_c.dylib" | cut -f1))"
