#!/usr/bin/env bash
# Cross-compile blst for one Android ABI.
set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"

ABI="${1:?Usage: $0 <abi>}"
if is_built "$ABI" "blst"; then ok "blst already built for $ABI"; exit 0; fi

log "Building blst for Android/$ABI"

BLST_SRC="$SRC_DIR/blst"
IOS_BLST_SRC="$REPO_ROOT/third_party/ios/src/blst"
if [[ ! -d "$BLST_SRC" ]]; then
    if [[ -d "$IOS_BLST_SRC" ]]; then
        cp -R "$IOS_BLST_SRC" "$BLST_SRC"
    else
        log "Cloning blst..."
        git clone --depth 1 https://github.com/supranational/blst.git "$BLST_SRC" >/dev/null 2>&1
    fi
fi

PREFIX="$(abi_prefix "$ABI")"
WORK="$BUILD_ROOT/deps/blst/$ABI"
rm -rf "$WORK"; mkdir -p "$WORK" "$PREFIX/include/blst"

cp "$BLST_SRC/bindings/blst.h" "$BLST_SRC/bindings/blst_aux.h" "$PREFIX/include/blst/"

CC_CMD="$(abi_cc "$ABI")"
CFLAGS_COMMON="-O2 -fPIC -fno-builtin -D__BLST_PORTABLE__"

cd "$WORK"
$CC_CMD $CFLAGS_COMMON -c "$BLST_SRC/build/assembly.S" -o "$WORK/assembly.o" \
    > "$WORK/asm.log" 2>&1 || { tail -30 "$WORK/asm.log"; die "asm failed"; }
$CC_CMD $CFLAGS_COMMON -c "$BLST_SRC/src/server.c" -o "$WORK/server.o" \
    -I"$BLST_SRC/bindings" \
    > "$WORK/c.log" 2>&1 || { tail -30 "$WORK/c.log"; die "C build failed"; }

"$NDK_TOOLCHAIN/bin/llvm-ar" rcs "$PREFIX/lib/libblst.a" "$WORK/assembly.o" "$WORK/server.o"
mkdir -p "$PREFIX/lib"
"$NDK_TOOLCHAIN/bin/llvm-ar" rcs "$PREFIX/lib/libblst.a" "$WORK/assembly.o" "$WORK/server.o"

mark_built "$ABI" "blst"
ok "blst installed to $PREFIX"
