#!/usr/bin/env bash
# Cross-compile OpenSSL libcrypto for one Android ABI.
# OpenSSL 3.x ships with "android-*" Configure targets that understand NDK.
set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"
if is_built "$ABI" "openssl"; then ok "openssl already built for $ABI"; exit 0; fi

log "Building OpenSSL $OPENSSL_VERSION for Android/$ABI (libcrypto only)"

ARCHIVE_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "openssl-${OPENSSL_VERSION}.tar.gz")"

PREFIX="$(abi_prefix "$ABI")"
WORK="$BUILD_ROOT/deps/openssl/$ABI"
rm -rf "$WORK"; mkdir -p "$WORK/src" "$PREFIX/lib" "$PREFIX/include"
extract_to "$ARCHIVE" "$WORK/src"

# Map our ABI names to OpenSSL target names
openssl_target() {
    case "$1" in
        arm64-v8a)    echo "android-arm64" ;;
        armeabi-v7a)  echo "android-arm" ;;
        x86_64)       echo "android-x86_64" ;;
        x86)          echo "android-x86" ;;
    esac
}

(
    cd "$WORK/src"
    # OpenSSL's Configure discovers the NDK via ANDROID_NDK_ROOT + PATH
    export ANDROID_NDK_ROOT="$NDK"
    export PATH="$NDK_TOOLCHAIN/bin:$PATH"

    ./Configure "$(openssl_target "$ABI")" \
        -D__ANDROID_API__="$ANDROID_API" \
        no-shared no-dso no-hw no-engine no-tests no-apps no-docs \
        no-ssl3 no-ssl3-method no-weak-ssl-ciphers no-zlib \
        --prefix="$WORK/install" \
        > "$WORK/configure.log" 2>&1 || { tail -40 "$WORK/configure.log"; die "configure failed"; }
    make -j"$(sysctl -n hw.ncpu)" build_libs > "$WORK/make.log" 2>&1 \
        || { tail -80 "$WORK/make.log"; die "build failed"; }
    make install_dev > "$WORK/install.log" 2>&1
)

cp "$WORK/install/lib/libcrypto.a" "$PREFIX/lib/"
cp -R "$WORK/install/include/"* "$PREFIX/include/"

mark_built "$ABI" "openssl"
ok "openssl installed to $PREFIX"
