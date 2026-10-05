#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built openssl; then ok "openssl already built"; exit 0; fi
log "Building OpenSSL $OPENSSL_VERSION libcrypto for wasm32 (no sockets, no threads, no dso)"
ARCHIVE="$(fetch_tarball "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" "openssl-${OPENSSL_VERSION}.tar.gz")"
WORK="$BUILD_ROOT/deps/openssl"
extract_fresh "$ARCHIVE" "$WORK/src"
(
    cd "$WORK/src"
    emconfigure ./Configure linux-generic32 no-asm no-threads no-shared no-dso no-hw no-engine \
        no-tests no-apps no-docs no-sock no-zlib no-ssl3 no-ssl3-method no-weak-ssl-ciphers \
        no-stdio no-ui-console --prefix="$WORK/install" > "$WORK/configure.log" 2>&1 \
        || { tail -40 "$WORK/configure.log"; die "configure failed"; }
    sed -i.bak 's|^CROSS_COMPILE=.*$|CROSS_COMPILE=|' Makefile
    emmake make -j"$JOBS" build_libs > "$WORK/make.log" 2>&1 || { tail -80 "$WORK/make.log"; die "build failed"; }
    emmake make install_dev > "$WORK/install.log" 2>&1
)
cp "$WORK/install/lib/libcrypto.a" "$PREFIX/lib/"
cp -R "$WORK/install/include/"* "$PREFIX/include/"
mark_built openssl
ok "openssl installed to $PREFIX"
