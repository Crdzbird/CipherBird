#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built libsodium; then ok "libsodium already built"; exit 0; fi
log "Building libsodium $LIBSODIUM_VERSION for wasm32"
ARCHIVE="$(fetch_tarball "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "libsodium-${LIBSODIUM_VERSION}.tar.gz")"
WORK="$BUILD_ROOT/deps/libsodium"
extract_fresh "$ARCHIVE" "$WORK/src"
(
    cd "$WORK/src"
    emconfigure ./configure --host=wasm32-unknown-emscripten \
        --disable-shared --enable-static --disable-ssp --disable-asm --without-pthreads \
        --prefix="$WORK/install" > "$WORK/configure.log" 2>&1 \
        || { tail -40 "$WORK/configure.log"; die "configure failed"; }
    emmake make -j"$JOBS" > "$WORK/make.log" 2>&1 || { tail -40 "$WORK/make.log"; die "make failed"; }
    emmake make install > "$WORK/install.log" 2>&1
)
cp "$WORK/install/lib/libsodium.a" "$PREFIX/lib/"
cp -R "$WORK/install/include/"* "$PREFIX/include/"
mark_built libsodium
ok "libsodium installed to $PREFIX"
