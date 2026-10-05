#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built blake3; then ok "blake3 already built"; exit 0; fi
log "Building BLAKE3 $BLAKE3_VERSION for wasm32"
ARCHIVE="$(fetch_tarball "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "blake3-${BLAKE3_VERSION}.tar.gz")"
WORK="$BUILD_ROOT/deps/blake3"
extract_fresh "$ARCHIVE" "$WORK/src"
emcmake cmake -S "$WORK/src/c" -B "$WORK/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBLAKE3_SIMD_TYPE=none \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" > "$WORK/cmake.log" 2>&1 \
    || { tail -40 "$WORK/cmake.log"; die "cmake failed"; }
cmake --build "$WORK/build" --target install -j"$JOBS" > "$WORK/build.log" 2>&1 \
    || { tail -40 "$WORK/build.log"; die "build failed"; }
flatten_lib64
mark_built blake3
ok "blake3 installed to $PREFIX"
