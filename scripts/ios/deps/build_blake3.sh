#!/usr/bin/env bash
# Cross-compile libblake3 (BLAKE3 C library) for one slice.
# Usage: build_blake3.sh <slice>

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "blake3"; then
    ok "blake3 already built for $SLICE"
    exit 0
fi

log "Building BLAKE3 $BLAKE3_VERSION for $SLICE"

ARCHIVE_URL="https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "blake3-${BLAKE3_VERSION}.tar.gz")"

PREFIX="$(slice_prefix "$SLICE")"
WORK="$BUILD_ROOT/deps/blake3/$SLICE"

rm -rf "$WORK"
mkdir -p "$WORK/src"
extract_to "$ARCHIVE" "$WORK/src"

# BLAKE3 C source lives in c/
cd "$WORK/src/c"

# Deployment target for SIMULATOR build
case "$SLICE" in
    iphoneos)         PLATFORM=OS ;;
    iphonesimulator)  PLATFORM=SIMULATOR ;;
    macosx)           PLATFORM=MAC ;;
esac

cmake -B "$WORK/build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_ROOT/cmake/ios.toolchain.cmake" \
    -DIOS_PLATFORM="$PLATFORM" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    > "$WORK/cmake.log" 2>&1 || { tail -40 "$WORK/cmake.log"; die "blake3 configure failed"; }

cmake --build "$WORK/build" --target install -j"$(sysctl -n hw.ncpu)" \
    > "$WORK/build.log" 2>&1 || { tail -40 "$WORK/build.log"; die "blake3 build failed"; }

# Some BLAKE3 releases install to lib64 on darwin — normalise to lib
if [[ -d "$PREFIX/lib64" && ! -d "$PREFIX/lib" ]]; then
    mv "$PREFIX/lib64" "$PREFIX/lib"
elif [[ -d "$PREFIX/lib64" ]]; then
    cp -R "$PREFIX/lib64/"* "$PREFIX/lib/" && rm -rf "$PREFIX/lib64"
fi

mark_built "$SLICE" "blake3"
ok "blake3 installed to $PREFIX"
