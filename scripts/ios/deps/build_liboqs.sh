#!/usr/bin/env bash
# Cross-compile liboqs (post-quantum) for one slice.
# Depends on libcrypto (OpenSSL) already being installed in the slice prefix.
# Usage: build_liboqs.sh <slice>

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "liboqs"; then
    ok "liboqs already built for $SLICE"
    exit 0
fi

# Require OpenSSL first
if [[ ! -f "$(slice_prefix "$SLICE")/lib/libcrypto.a" ]]; then
    die "libcrypto.a missing — run build_openssl.sh $SLICE first"
fi

log "Building liboqs $LIBOQS_VERSION for $SLICE (PQ algorithms only)"

ARCHIVE_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "liboqs-${LIBOQS_VERSION}.tar.gz")"

PREFIX="$(slice_prefix "$SLICE")"
WORK="$BUILD_ROOT/deps/liboqs/$SLICE"

rm -rf "$WORK"
mkdir -p "$WORK/src"
extract_to "$ARCHIVE" "$WORK/src"

case "$SLICE" in
    iphoneos)         PLATFORM=OS ;;
    iphonesimulator)  PLATFORM=SIMULATOR ;;
    macosx)           PLATFORM=MAC ;;
esac

# Minimal algorithm whitelist — only what pq.hpp actually uses.
# OQS_MINIMAL_BUILD takes liboqs *build identifiers* (e.g. KEM_ml_kem_768),
# NOT runtime names (ML-KEM-768). The latter match nothing and silently
# produce a liboqs with every algorithm disabled.
ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024"
ALGS+=";SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
# SLH-DSA 'pure' variants (both SHA2 and SHAKE, levels 128/192/256, s+f)
for hash in sha2 shake; do
    for lvl in 128s 128f 192s 192f 256s 256f; do
        ALGS+=";SIG_slh_dsa_pure_${hash}_${lvl}"
    done
done

log "liboqs: configuring with minimal alg set"
cmake -B "$WORK/build" -S "$WORK/src" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_ROOT/cmake/ios.toolchain.cmake" \
    -DIOS_PLATFORM="$PLATFORM" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$PREFIX" \
    -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.a" \
    -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
    -DOQS_DIST_BUILD=ON \
    -DOQS_MINIMAL_BUILD="$ALGS" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    > "$WORK/cmake.log" 2>&1 || { tail -60 "$WORK/cmake.log"; die "liboqs configure failed"; }

cmake --build "$WORK/build" --target install -j"$(sysctl -n hw.ncpu)" \
    > "$WORK/build.log" 2>&1 || { tail -60 "$WORK/build.log"; die "liboqs build failed"; }

mark_built "$SLICE" "liboqs"
ok "liboqs installed to $PREFIX"
