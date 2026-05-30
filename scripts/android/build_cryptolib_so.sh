#!/usr/bin/env bash
# Build libcryptolib_c.so (SHARED) for one Android ABI, linking in the
# prebuilt static deps. Output goes to build/android/<abi>/libcryptolib_c.so.
set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"

DEPS="$(abi_prefix "$ABI")"
BUILD="$BUILD_ROOT/$ABI"

for dep in libsodium libblake3 liboqs libcrypto libblst; do
    [[ -f "$DEPS/lib/${dep}.a" ]] \
        || die "missing $DEPS/lib/${dep}.a — run build_all.sh first"
done

rm -rf "$BUILD/cmake"; mkdir -p "$BUILD"

log "Configuring cryptolib_c (shared .so) for Android/$ABI"
cmake -B "$BUILD/cmake" -S "$REPO_ROOT" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCRYPTOLIB_DEPS_ROOT="$DEPS" \
    -DCRYPTOLIB_BUILD_EXAMPLE=OFF \
    -DCRYPTOLIB_BUILD_TESTS=OFF \
    > "$BUILD/cmake.log" 2>&1 || { tail -60 "$BUILD/cmake.log"; die "cmake failed"; }

log "Building libcryptolib_c.so for Android/$ABI"
cmake --build "$BUILD/cmake" --target cryptolib_c -j"$(sysctl -n hw.ncpu)" \
    > "$BUILD/build.log" 2>&1 || { tail -60 "$BUILD/build.log"; die "build failed"; }

SO="$BUILD/cmake/libcryptolib_c.so"
[[ -f "$SO" ]] || die "expected $SO not found"

# Optional: strip to reduce size
"$NDK_TOOLCHAIN/bin/llvm-strip" --strip-unneeded "$SO" 2>/dev/null || true

# Copy to a predictable per-ABI output location
OUT="$BUILD/libcryptolib_c.so"
cp "$SO" "$OUT"

ok "Built $OUT ($(du -h "$OUT" | awk '{print $1}'))"
file "$OUT" | sed 's/^/   /'
