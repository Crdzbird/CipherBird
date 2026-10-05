#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built secp256k1; then ok "secp256k1 already built"; exit 0; fi
log "Building libsecp256k1 $SECP256K1_VERSION for wasm32"
ARCHIVE="$(fetch_tarball "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz" "secp256k1-${SECP256K1_VERSION}.tar.gz")"
WORK="$BUILD_ROOT/deps/secp256k1"
extract_fresh "$ARCHIVE" "$WORK/src"
emcmake cmake -S "$WORK/src" -B "$WORK/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_EXAMPLES=OFF \
    -DSECP256K1_ENABLE_MODULE_RECOVERY=ON -DSECP256K1_ASM=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" > "$WORK/cmake.log" 2>&1 \
    || { tail -40 "$WORK/cmake.log"; die "cmake failed"; }
cmake --build "$WORK/build" --target install -j"$JOBS" > "$WORK/build.log" 2>&1 \
    || { tail -40 "$WORK/build.log"; die "build failed"; }
flatten_lib64
mark_built secp256k1
ok "secp256k1 installed to $PREFIX"
