#!/usr/bin/env bash
# Cross-compile libsodium for one Android ABI.
# Usage: build_libsodium.sh <abi>  (abi: arm64-v8a | armeabi-v7a | x86_64 | x86)

set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"
if is_built "$ABI" "libsodium"; then ok "libsodium already built for $ABI"; exit 0; fi

log "Building libsodium $LIBSODIUM_VERSION for Android/$ABI (API $ANDROID_API)"

ARCHIVE_URL="https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "libsodium-${LIBSODIUM_VERSION}.tar.gz")"

PREFIX="$(abi_prefix "$ABI")"
WORK="$BUILD_ROOT/deps/libsodium/$ABI"
mkdir -p "$PREFIX/lib" "$PREFIX/include"

rm -rf "$WORK"
mkdir -p "$WORK/src"
extract_to "$ARCHIVE" "$WORK/src"

(
    cd "$WORK/src"
    export CC; CC="$(abi_cc "$ABI")"
    export CXX; CXX="$(abi_cxx "$ABI")"
    export AR="$NDK_TOOLCHAIN/bin/llvm-ar"
    export RANLIB="$NDK_TOOLCHAIN/bin/llvm-ranlib"
    export STRIP="$NDK_TOOLCHAIN/bin/llvm-strip"
    export CFLAGS="-O2 -fPIC -DANDROID"
    export LDFLAGS=""

    ./configure \
        --host="$(abi_triple "$ABI")" \
        --prefix="$WORK/install" \
        --disable-shared --enable-static \
        --disable-soname-versions \
        > "$WORK/configure.log" 2>&1 || { tail -40 "$WORK/configure.log"; die "configure failed"; }
    make -j"$(sysctl -n hw.ncpu)" > "$WORK/make.log" 2>&1 \
        || { tail -40 "$WORK/make.log"; die "make failed"; }
    make install > "$WORK/install.log" 2>&1
)

cp "$WORK/install/lib/libsodium.a" "$PREFIX/lib/"
cp -R "$WORK/install/include/"* "$PREFIX/include/"

mark_built "$ABI" "libsodium"
ok "libsodium installed to $PREFIX"
