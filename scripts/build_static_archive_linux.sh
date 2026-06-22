#!/usr/bin/env bash
# Linux counterpart of build_static_archive.sh: produces the SAME merged,
# self-contained archive build/static/libcryptolib_c.a on Linux that the macOS
# script produces with Homebrew + libtool.
#
# macOS gets its deps from Homebrew; Debian/Ubuntu has static packages only for
# libsodium and OpenSSL, so this builds the rest from source (BLAKE3 from the
# vendored tarball, liboqs, blst, and libsecp256k1 WITH the recovery module that
# the distro package omits), then merges everything into one archive with GNU ar
# (Linux has no `libtool -static`).
#
# Prereqs (Debian/Ubuntu):
#   apt-get install -y clang cmake ninja-build git pkg-config \
#       build-essential ca-certificates libsodium-dev libssl-dev
#
# Usage: scripts/build_static_archive_linux.sh [out_dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-build/static}"
DEPS="$ROOT/build/linux-deps"           # staged from-source deps (lib/ + include/)
HOST="$ROOT/build/host-deps"            # scratch build trees
mkdir -p "$OUT" "$DEPS/lib" "$DEPS/include" "$HOST"

LIBOQS_VERSION="${LIBOQS_VERSION:-0.15.0}"   # matches scripts/{android,ios}/lib/common.sh
SECP_VERSION="${SECP_VERSION:-v0.6.0}"        # bitcoin-core/secp256k1 (cmake + recovery)

PIC="-DCMAKE_POSITION_INDEPENDENT_CODE=ON"

# 1. System static archives (libsodium + OpenSSL libcrypto).
sodium_dir="$(pkg-config --variable=libdir libsodium 2>/dev/null || true)"
SODIUM_A="${sodium_dir:-/usr/lib/x86_64-linux-gnu}/libsodium.a"
crypto_dir="$(pkg-config --variable=libdir libcrypto 2>/dev/null || true)"
CRYPTO_A="${crypto_dir:-/usr/lib/x86_64-linux-gnu}/libcrypto.a"
[ -f "$SODIUM_A" ] || { echo "libsodium.a not found ($SODIUM_A) — apt install libsodium-dev"; exit 1; }
[ -f "$CRYPTO_A" ] || { echo "libcrypto.a not found ($CRYPTO_A) — apt install libssl-dev"; exit 1; }

# 2. BLAKE3 from the vendored tarball.
BLAKE3_A="$HOST/blake3-build/libblake3.a"
if [ ! -f "$BLAKE3_A" ]; then
    T="$(ls third_party/*/src/blake3-*.tar.gz 2>/dev/null | head -1)"
    [ -n "$T" ] || { echo "blake3 source tarball not found under third_party/"; exit 1; }
    tar xzf "$T" -C "$HOST"
    # find (not ls GLOB1 GLOB2) so a non-matching glob doesn't fail under pipefail.
    BL="$(find "$HOST" -maxdepth 1 -type d -iname 'blake3-*' | head -1)"
    [ -n "$BL" ] || { echo "extracted BLAKE3 dir not found under $HOST"; exit 1; }
    cmake -S "$BL/c" -B "$HOST/blake3-build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF $PIC >/dev/null
    cmake --build "$HOST/blake3-build" >/dev/null
    cp "$BL/c/blake3.h" "$DEPS/include/"
fi

# 3. liboqs (ML-KEM / ML-DSA / SLH-DSA).
OQS_A="$DEPS/lib/liboqs.a"
if [ ! -f "$OQS_A" ]; then
    rm -rf "$HOST/liboqs-src"
    git clone --depth 1 -b "$LIBOQS_VERSION" https://github.com/open-quantum-safe/liboqs "$HOST/liboqs-src"
    cmake -S "$HOST/liboqs-src" -B "$HOST/liboqs-build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
        $PIC -DCMAKE_INSTALL_PREFIX="$DEPS" >/dev/null
    cmake --build "$HOST/liboqs-build" >/dev/null
    cmake --install "$HOST/liboqs-build" >/dev/null
fi

# 4. blst (BLS12-381). Built -fPIC so it links into a Go PIE.
BLST_A="$DEPS/lib/libblst.a"
if [ ! -f "$BLST_A" ]; then
    rm -rf "$HOST/blst-src"
    git clone --depth 1 https://github.com/supranational/blst "$HOST/blst-src"
    ( cd "$HOST/blst-src" && ./build.sh -fPIC )
    cp "$HOST/blst-src/libblst.a" "$BLST_A"
    cp "$HOST/blst-src/bindings/blst.h" "$HOST/blst-src/bindings/blst_aux.h" "$DEPS/include/"
fi

# 5. libsecp256k1 WITH the recovery module (distro package omits it).
SECP_A="$DEPS/lib/libsecp256k1.a"
if [ ! -f "$SECP_A" ]; then
    rm -rf "$HOST/secp-src"
    git clone --depth 1 -b "$SECP_VERSION" https://github.com/bitcoin-core/secp256k1 "$HOST/secp-src"
    cmake -S "$HOST/secp-src" -B "$HOST/secp-build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF $PIC \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
        -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DSECP256K1_BUILD_EXAMPLES=OFF -DCMAKE_INSTALL_PREFIX="$DEPS" >/dev/null
    cmake --build "$HOST/secp-build" >/dev/null
    cmake --install "$HOST/secp-build" >/dev/null
fi

# 6. Compile the C-ABI bridge to an object (no link), mirroring the macOS flags.
clang++ -std=c++20 -O2 -fPIC -c \
    -DCRYPTOLIB_HAS_BLAKE3=1 -DCRYPTOLIB_HAS_PQ=1 -DCRYPTOLIB_HAS_BLS=1 \
    -DCRYPTOLIB_HAS_OPENSSL=1 -DCRYPTOLIB_HAS_SECP256K1=1 \
    -I include -I "$DEPS/include" \
    bridge/cryptolib_c.cpp -o "$OUT/cryptolib_c.o"

# 7. Merge the object + every dependency archive into one static library. GNU ar
#    has no libtool, so use an MRI script (addmod object, addlib archives).
rm -f "$OUT/libcryptolib_c.a"
ar -M <<EOF
create $OUT/libcryptolib_c.a
addmod $OUT/cryptolib_c.o
addlib $SODIUM_A
addlib $BLAKE3_A
addlib $OQS_A
addlib $CRYPTO_A
addlib $BLST_A
addlib $SECP_A
save
end
EOF
rm -f "$OUT/cryptolib_c.o"
echo "→ $OUT/libcryptolib_c.a ($(du -h "$OUT/libcryptolib_c.a" | cut -f1), self-contained)"
