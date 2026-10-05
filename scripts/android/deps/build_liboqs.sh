#!/usr/bin/env bash
# Cross-compile liboqs for one Android ABI.
set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"
if is_built "$ABI" "liboqs"; then ok "liboqs already built for $ABI"; exit 0; fi

[[ -f "$(abi_prefix "$ABI")/lib/libcrypto.a" ]] \
    || die "libcrypto.a missing — run build_openssl.sh $ABI first"

log "Building liboqs $LIBOQS_VERSION for Android/$ABI"

ARCHIVE_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "liboqs-${LIBOQS_VERSION}.tar.gz")"

PREFIX="$(abi_prefix "$ABI")"
WORK="$BUILD_ROOT/deps/liboqs/$ABI"
rm -rf "$WORK"; mkdir -p "$WORK/src"
extract_to "$ARCHIVE" "$WORK/src"

# OQS_MINIMAL_BUILD takes liboqs *build identifiers* (e.g. KEM_ml_kem_768),
# NOT the runtime algorithm names (ML-KEM-768). Using the latter silently
# matches nothing and produces a liboqs with every algorithm disabled.
ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;KEM_ntruprime_sntrup761;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
for hash in sha2 shake; do
    for lvl in 128s 128f 192s 192f 256s 256f; do
        ALGS+=";SIG_slh_dsa_pure_${hash}_${lvl}"
    done
done

cmake -S "$WORK/src" -B "$WORK/build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$PREFIX" \
    -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.a" \
    -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
    -DOQS_DIST_BUILD=ON \
    -DOQS_MINIMAL_BUILD="$ALGS" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    > "$WORK/cmake.log" 2>&1 || { tail -60 "$WORK/cmake.log"; die "cmake failed"; }

cmake --build "$WORK/build" --target install -j"$(sysctl -n hw.ncpu)" \
    > "$WORK/build.log" 2>&1 || { tail -60 "$WORK/build.log"; die "build failed"; }

mark_built "$ABI" "liboqs"
ok "liboqs installed to $PREFIX"
