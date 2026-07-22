#!/usr/bin/env bash
# Build a single self-contained STATIC archive: build/static/libcryptolib_c.a
#
# It merges the C-ABI bridge object with every dependency's static archive
# (libsodium, BLAKE3, liboqs, OpenSSL libcrypto, blst, libsecp256k1) into ONE
# .a. A consumer linking it (e.g. the Go binding with `-tags cryptolib_static`)
# gets a fully self-contained binary — no libcryptolib_c.dylib/.so to ship or
# locate at run time.
#
# Usage: scripts/build_static_archive.sh [out_dir]   (macOS host)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-build/static}"
mkdir -p "$OUT" build/host-deps

BREW_LIB=/opt/homebrew/lib
OSSL=/opt/homebrew/opt/openssl@3
SECP=/opt/homebrew/opt/secp256k1

# Prefer a SEALED (no-sock no-dso) libcrypto so the static binary carries no
# latent socket/dlopen code. Built on demand from pinned OpenSSL source. Set
# CRYPTOLIB_SEALED_OPENSSL=0 to skip it and use the system libcrypto (which
# retains OpenSSL's BIO sockets — dormant but present).
LIBCRYPTO_A="build/host-deps/openssl-nosock/lib/libcrypto.a"
if [ ! -f "$LIBCRYPTO_A" ] && [ "${CRYPTOLIB_SEALED_OPENSSL:-1}" = "1" ]; then
    bash scripts/build_openssl_nosock.sh
fi
if [ ! -f "$LIBCRYPTO_A" ]; then
    echo "!! sealed libcrypto unavailable — using system libcrypto (retains BIO sockets)"
    LIBCRYPTO_A="$OSSL/lib/libcrypto.a"
fi

# 1. Vendored BLAKE3 static archive (Homebrew ships only a dylib).
BLAKE3_A=build/host-deps/blake3-build/libblake3.a
if [ ! -f "$BLAKE3_A" ]; then
    BL_SRC_TARBALL="$(ls third_party/*/src/blake3-*.tar.gz 2>/dev/null | head -1)"
    [ -n "$BL_SRC_TARBALL" ] || { echo "blake3 source tarball not found"; exit 1; }
    tar xzf "$BL_SRC_TARBALL" -C build/host-deps
    BL_SRC="$(ls -d build/host-deps/BLAKE3-* build/host-deps/blake3-* 2>/dev/null | head -1)"
    cmake -S "$BL_SRC/c" -B build/host-deps/blake3-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
    cmake --build build/host-deps/blake3-build >/dev/null
fi

# 2. Compile the bridge to an object file (no link). Same exploit-mitigation
#    flags as the CMake shared-lib build (portable subset for the host arch).
clang++ -std=c++20 -O2 -fPIC -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -c \
    -DCRYPTOLIB_HAS_BLAKE3=1 -DCRYPTOLIB_HAS_PQ=1 -DCRYPTOLIB_HAS_BLS=1 \
    -DCRYPTOLIB_HAS_OPENSSL=1 -DCRYPTOLIB_HAS_SECP256K1=1 \
    -I include -I /opt/homebrew/include -I "$OSSL/include" -I "$SECP/include" \
    bridge/cryptolib_c.cpp -o "$OUT/cryptolib_c.o"

# 3. Merge the object + every dependency archive into one static library.
#    libtool -static dedups and merges archives + objects on macOS.
libtool -static -o "$OUT/libcryptolib_c.a" \
    "$OUT/cryptolib_c.o" \
    "$BREW_LIB/libsodium.a" "$BLAKE3_A" "$BREW_LIB/liboqs.a" \
    "$LIBCRYPTO_A" "$BREW_LIB/libblst.a" "$SECP/lib/libsecp256k1.a" \
    2>/dev/null

rm -f "$OUT/cryptolib_c.o"
SIZE="$(du -h "$OUT/libcryptolib_c.a" | cut -f1)"
echo "→ $OUT/libcryptolib_c.a ($SIZE, self-contained)"
