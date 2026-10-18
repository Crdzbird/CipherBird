#!/usr/bin/env bash
# Build the static dependency set for a native Linux x86_64 host from the
# hash-pinned tarballs and the pinned blst commit, into
# third_party/linux/x86_64 for -DCRYPTOLIB_DEPS_ROOT. Used by the CI
# constant-time job; the recipes mirror scripts/android/deps.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/lib/toolchain_pins.sh"
LIBSODIUM_VERSION="1.0.22"
BLAKE3_VERSION="1.5.4"
OPENSSL_VERSION="3.5.9"
LIBOQS_VERSION="0.15.0"
SECP256K1_VERSION="0.7.1"
SRC_DIR="$REPO_ROOT/third_party/linux/src"
PREFIX="$REPO_ROOT/third_party/linux/x86_64"
BUILD_ROOT="$REPO_ROOT/build/linux-deps"
JOBS="$(nproc 2>/dev/null || echo 4)"
mkdir -p "$SRC_DIR" "$PREFIX/lib" "$PREFIX/include" "$BUILD_ROOT"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

fetch_tarball() {
    local url="$1" name="$2" archive="$SRC_DIR/$2"
    if [[ ! -f "$archive" ]]; then
        for mirror in "$REPO_ROOT/third_party/android/src/$name" "$REPO_ROOT/third_party/ios/src/$name"; do
            [[ -f "$mirror" ]] && cp "$mirror" "$archive" && break
        done
    fi
    if [[ ! -f "$archive" ]]; then
        log "Downloading $name"
        curl -fsSL -o "$archive.part" "$url" || { rm -f "$archive.part"; die "download failed: $url"; }
        mv "$archive.part" "$archive"
    fi
    verify_source_sha256 "$archive" || { rm -f "$archive"; die "refusing to build from an unverified $name"; }
    echo "$archive"
}

unpack() {
    local archive="$1" work="$2"
    rm -rf "$work"; mkdir -p "$work/src"
    tar -xf "$archive" -C "$work/src" --strip-components=1
}

if [[ ! -f "$PREFIX/lib/libsodium.a" ]]; then
    log "libsodium $LIBSODIUM_VERSION"
    A="$(fetch_tarball "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "libsodium-${LIBSODIUM_VERSION}.tar.gz")"
    W="$BUILD_ROOT/libsodium"; unpack "$A" "$W"
    (cd "$W/src" && CFLAGS="-O2 -fPIC" ./configure --prefix="$PREFIX" --disable-shared --enable-static > "$W/configure.log" 2>&1 \
        && make -j"$JOBS" > "$W/make.log" 2>&1 && make install > "$W/install.log" 2>&1) || { tail -40 "$W"/*.log; die "libsodium failed"; }
fi

if [[ ! -f "$PREFIX/lib/libblake3.a" ]]; then
    log "blake3 $BLAKE3_VERSION"
    A="$(fetch_tarball "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "blake3-${BLAKE3_VERSION}.tar.gz")"
    W="$BUILD_ROOT/blake3"; unpack "$A" "$W"
    cmake -S "$W/src/c" -B "$W/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib > "$W/cmake.log" 2>&1 \
        && cmake --build "$W/build" --target install -j"$JOBS" > "$W/build.log" 2>&1 || { tail -40 "$W"/*.log; die "blake3 failed"; }
fi

if [[ ! -f "$PREFIX/lib/libcrypto.a" ]]; then
    log "openssl $OPENSSL_VERSION (libcrypto only)"
    A="$(fetch_tarball "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" "openssl-${OPENSSL_VERSION}.tar.gz")"
    W="$BUILD_ROOT/openssl"; unpack "$A" "$W"
    (cd "$W/src" && ./Configure linux-x86_64 no-shared no-dso no-hw no-engine no-tests no-apps no-docs \
        no-ssl3 no-ssl3-method no-weak-ssl-ciphers no-zlib $(cat "$REPO_ROOT/scripts/lib_openssl_trim.txt") \
        --prefix="$W/install" --libdir=lib > "$W/configure.log" 2>&1 \
        && make -j"$JOBS" build_libs > "$W/make.log" 2>&1 && make install_dev > "$W/install.log" 2>&1) || { tail -60 "$W"/*.log; die "openssl failed"; }
    cp "$W/install/lib/libcrypto.a" "$PREFIX/lib/"
    cp -R "$W/install/include/"* "$PREFIX/include/"
fi

if [[ ! -f "$PREFIX/lib/liboqs.a" ]]; then
    log "liboqs $LIBOQS_VERSION"
    A="$(fetch_tarball "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "liboqs-${LIBOQS_VERSION}.tar.gz")"
    W="$BUILD_ROOT/liboqs"; unpack "$A" "$W"
    ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;KEM_ntruprime_sntrup761;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
    for hash in sha2 shake; do
        for lvl in 128s 128f 192s 192f 256s 256f; do ALGS+=";SIG_slh_dsa_pure_${hash}_${lvl}"; done
    done
    cmake -S "$W/src" -B "$W/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=ON \
        -DOPENSSL_ROOT_DIR="$PREFIX" -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.a" -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
        -DOQS_DIST_BUILD=ON -DOQS_MINIMAL_BUILD="$ALGS" -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib > "$W/cmake.log" 2>&1 \
        && cmake --build "$W/build" --target install -j"$JOBS" > "$W/build.log" 2>&1 || { tail -60 "$W"/*.log; die "liboqs failed"; }
fi

if [[ ! -f "$PREFIX/lib/libblst.a" ]]; then
    log "blst $BLST_TAG"
    BLST_SRC="$SRC_DIR/blst"
    fetch_blst_pinned "$BLST_SRC" || die "could not fetch blst $BLST_TAG"
    W="$BUILD_ROOT/blst"; rm -rf "$W"; mkdir -p "$W" "$PREFIX/include/blst"
    cp "$BLST_SRC/bindings/blst.h" "$BLST_SRC/bindings/blst_aux.h" "$PREFIX/include/blst/"
    cc -O2 -fPIC -fno-builtin -D__BLST_PORTABLE__ -c "$BLST_SRC/build/assembly.S" -o "$W/assembly.o"
    cc -O2 -fPIC -fno-builtin -D__BLST_PORTABLE__ -I"$BLST_SRC/bindings" -c "$BLST_SRC/src/server.c" -o "$W/server.o"
    ar rcs "$PREFIX/lib/libblst.a" "$W/assembly.o" "$W/server.o"
fi

if [[ ! -f "$PREFIX/lib/libsecp256k1.a" ]]; then
    log "secp256k1 $SECP256K1_VERSION"
    A="$(fetch_tarball "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz" "secp256k1-${SECP256K1_VERSION}.tar.gz")"
    W="$BUILD_ROOT/secp256k1"; unpack "$A" "$W"
    (cd "$W/src" && ./autogen.sh > "$W/autogen.log" 2>&1 && CFLAGS="-O2 -fPIC" ./configure --prefix="$PREFIX" \
        --disable-shared --enable-static --enable-module-recovery --with-ecmult-window=12 --with-ecmult-gen-kb=22 \
        --disable-benchmark --disable-tests --disable-exhaustive-tests --with-pic > "$W/configure.log" 2>&1 \
        && make -j"$JOBS" > "$W/make.log" 2>&1 && make install > "$W/install.log" 2>&1) || { tail -60 "$W"/*.log; die "secp256k1 failed"; }
fi

ls "$PREFIX/lib"
