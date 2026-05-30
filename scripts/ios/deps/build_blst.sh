#!/usr/bin/env bash
# Cross-compile blst (BLS12-381) for one slice.
# blst's own build.sh only takes flags, so we invoke cc directly with its
# assembly + server.c sources, per-arch, then lipo-merge.
# Usage: build_blst.sh <slice>

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "blst"; then
    ok "blst already built for $SLICE"
    exit 0
fi

log "Building blst for $SLICE"

BLST_SRC="$SRC_DIR/blst"
if [[ ! -d "$BLST_SRC" ]]; then
    log "Cloning blst (shallow)..."
    git clone --depth 1 https://github.com/supranational/blst.git "$BLST_SRC" >/dev/null 2>&1
fi

PREFIX="$(slice_prefix "$SLICE")"
WORK_BASE="$BUILD_ROOT/deps/blst/$SLICE"
ARCHES=($(slice_arches "$SLICE"))

mkdir -p "$PREFIX/lib" "$PREFIX/include/blst"

# Install headers (shared across all arches)
cp "$BLST_SRC/bindings/blst.h" "$BLST_SRC/bindings/blst_aux.h" "$PREFIX/include/blst/"

PER_ARCH_LIBS=()
for arch in "${ARCHES[@]}"; do
    work="$WORK_BASE/$arch"
    rm -rf "$work"
    mkdir -p "$work"
    cd "$work"

    cc_cmd="$(arch_clang "$SLICE" "$arch")"
    log "blst: compiling for $SLICE/$arch"

    # Compile the two source files that blst's own build.sh uses:
    #   build/assembly.S  — handwritten asm, pre-generated
    #   src/server.c      — all C routines
    # -D__BLST_PORTABLE__ disables adx/bmi2 intrinsics not available on iOS/arm64.
    CFLAGS_COMMON="-O2 -fPIC -fno-builtin -D__BLST_PORTABLE__"

    $cc_cmd $CFLAGS_COMMON -c "$BLST_SRC/build/assembly.S" -o "$work/assembly.o" \
        > "$work/asm.log" 2>&1 || { tail -30 "$work/asm.log"; die "blst asm failed"; }
    $cc_cmd $CFLAGS_COMMON -c "$BLST_SRC/src/server.c" -o "$work/server.o" \
        -I"$BLST_SRC/bindings" \
        > "$work/c.log" 2>&1 || { tail -30 "$work/c.log"; die "blst C build failed"; }

    ar rcs "$work/libblst.a" "$work/assembly.o" "$work/server.o"
    PER_ARCH_LIBS+=("$work/libblst.a")
done

log "Lipo-merging blst arches: ${ARCHES[*]}"
lipo -create "${PER_ARCH_LIBS[@]}" -output "$PREFIX/lib/libblst.a"

mark_built "$SLICE" "blst"
ok "blst installed to $PREFIX"
