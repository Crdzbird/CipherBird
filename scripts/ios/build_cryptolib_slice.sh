#!/usr/bin/env bash
# Build cryptolib_c as a static archive for ONE slice, then merge in all its
# static dependencies so the resulting .a is a single self-contained blob.
#
# Usage: build_cryptolib_slice.sh <slice>
#   slice = iphoneos | iphonesimulator | macosx

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

DEPS="$(slice_prefix "$SLICE")"
BUILD="$BUILD_ROOT/$SLICE"

# Sanity check: all deps must be present
for dep in libsodium libblake3 liboqs libcrypto libblst; do
    if [[ ! -f "$DEPS/lib/${dep}.a" ]]; then
        die "missing $DEPS/lib/${dep}.a — did you run build_all.sh or the dep scripts first?"
    fi
done

case "$SLICE" in
    iphoneos)         PLATFORM=OS ;;
    iphonesimulator)  PLATFORM=SIMULATOR ;;
    macosx)           PLATFORM=MAC ;;
esac

log "Configuring cryptolib_c for $SLICE (platform=$PLATFORM, static)"

rm -rf "$BUILD/cmake"
mkdir -p "$BUILD"
cmake -B "$BUILD/cmake" -S "$REPO_ROOT" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_ROOT/cmake/ios.toolchain.cmake" \
    -DIOS_PLATFORM="$PLATFORM" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCRYPTOLIB_STATIC=ON \
    -DCRYPTOLIB_DEPS_ROOT="$DEPS" \
    -DCRYPTOLIB_BUILD_EXAMPLE=OFF \
    -DCRYPTOLIB_BUILD_TESTS=OFF \
    > "$BUILD/cmake.log" 2>&1 || { tail -60 "$BUILD/cmake.log"; die "cryptolib configure failed"; }

log "Building cryptolib_c.a for $SLICE"
cmake --build "$BUILD/cmake" --target cryptolib_c -j"$(sysctl -n hw.ncpu)" \
    > "$BUILD/build.log" 2>&1 || { tail -60 "$BUILD/build.log"; die "cryptolib build failed"; }

# Locate the output archive
BRIDGE_A="$BUILD/cmake/libcryptolib_c.a"
[[ -f "$BRIDGE_A" ]] || die "expected $BRIDGE_A not found"

# Merge bridge + all deps into one self-contained archive.
# libtool -static is the macOS-native way; ar/ranlib would work too but
# libtool handles the MH_OBJECT cases correctly for fat archives.
MERGED="$BUILD/libcryptolib_c_merged.a"
log "Merging bridge + deps into $MERGED"
libtool -static -o "$MERGED" \
    "$BRIDGE_A" \
    "$DEPS/lib/libsodium.a" \
    "$DEPS/lib/libblake3.a" \
    "$DEPS/lib/liboqs.a" \
    "$DEPS/lib/libcrypto.a" \
    "$DEPS/lib/libblst.a" \
    2>"$BUILD/libtool.log" || { cat "$BUILD/libtool.log"; die "libtool merge failed"; }

ok "Built $MERGED ($(du -h "$MERGED" | awk '{print $1}'))"
file "$MERGED" | sed 's/^/   /'
