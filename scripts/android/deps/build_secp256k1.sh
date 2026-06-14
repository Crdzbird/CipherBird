#!/usr/bin/env bash
# Cross-compile libsecp256k1 (bitcoin-core) for one Android ABI.
# Recovery module enabled (needed by crypto::ec::Secp256k1::recover / ecrecover).
# Usage: build_secp256k1.sh <abi>  (abi: arm64-v8a | armeabi-v7a | x86_64 | x86)

set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"
if is_built "$ABI" "libsecp256k1"; then ok "libsecp256k1 already built for $ABI"; exit 0; fi

log "Building libsecp256k1 $SECP256K1_VERSION for Android/$ABI (API $ANDROID_API)"

# GitHub source archive (extracts to secp256k1-<ver>/; needs ./autogen.sh).
ARCHIVE_URL="https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "secp256k1-${SECP256K1_VERSION}.tar.gz")"

PREFIX="$(abi_prefix "$ABI")"
WORK="$BUILD_ROOT/deps/secp256k1/$ABI"
mkdir -p "$PREFIX/lib" "$PREFIX/include"

rm -rf "$WORK"
mkdir -p "$WORK/src"
extract_to "$ARCHIVE" "$WORK/src"

(
    cd "$WORK/src"
    ./autogen.sh > "$WORK/autogen.log" 2>&1 || { tail -40 "$WORK/autogen.log"; die "autogen failed"; }
    export CC; CC="$(abi_cc "$ABI")"
    export AR="$NDK_TOOLCHAIN/bin/llvm-ar"
    export RANLIB="$NDK_TOOLCHAIN/bin/llvm-ranlib"
    export STRIP="$NDK_TOOLCHAIN/bin/llvm-strip"
    export CFLAGS="-O2 -fPIC -DANDROID"
    export LDFLAGS=""

    ./configure \
        --host="$(abi_triple "$ABI")" \
        --prefix="$WORK/install" \
        --disable-shared --enable-static \
        --enable-module-recovery \
        --disable-benchmark \
        --disable-tests \
        --disable-exhaustive-tests \
        --with-pic \
        > "$WORK/configure.log" 2>&1 || { tail -60 "$WORK/configure.log"; die "configure failed"; }
    make -j"$(sysctl -n hw.ncpu)" > "$WORK/make.log" 2>&1 \
        || { tail -60 "$WORK/make.log"; die "make failed"; }
    make install > "$WORK/install.log" 2>&1
)

cp "$WORK/install/lib/libsecp256k1.a" "$PREFIX/lib/"
cp -R "$WORK/install/include/"* "$PREFIX/include/"

mark_built "$ABI" "libsecp256k1"
ok "libsecp256k1 installed to $PREFIX"
