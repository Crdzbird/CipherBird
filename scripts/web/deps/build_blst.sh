#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built blst; then ok "blst already built"; exit 0; fi
log "Building blst (portable, no assembly) for wasm32"
BLST_SRC="$SRC_DIR/blst"
if [[ ! -d "$BLST_SRC" ]]; then
    if [[ -d "$REPO_ROOT/third_party/ios/src/blst" ]]; then
        cp -R "$REPO_ROOT/third_party/ios/src/blst" "$BLST_SRC"
    else
        git clone --depth 1 https://github.com/supranational/blst.git "$BLST_SRC" >/dev/null 2>&1
    fi
fi
WORK="$BUILD_ROOT/deps/blst"
rm -rf "$WORK"; mkdir -p "$WORK" "$PREFIX/include/blst"
cp "$BLST_SRC/bindings/blst.h" "$BLST_SRC/bindings/blst_aux.h" "$PREFIX/include/blst/"
emcc -O2 -fno-builtin -D__BLST_PORTABLE__ -D__BLST_NO_ASM__ -I"$BLST_SRC/bindings" \
    -c "$BLST_SRC/src/server.c" -o "$WORK/server.o" > "$WORK/c.log" 2>&1 \
    || { tail -30 "$WORK/c.log"; die "blst compile failed"; }
emar rcs "$PREFIX/lib/libblst.a" "$WORK/server.o"
mark_built blst
ok "blst installed to $PREFIX"
