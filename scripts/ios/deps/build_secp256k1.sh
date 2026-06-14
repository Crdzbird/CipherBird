#!/usr/bin/env bash
# Cross-compile libsecp256k1 (bitcoin-core) for one iOS/macOS slice.
# Recovery module enabled (needed by crypto::ec::Secp256k1::recover / ecrecover).
# Usage: build_secp256k1.sh <slice>
#   slice = iphoneos | iphonesimulator | macosx

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "libsecp256k1"; then
    ok "libsecp256k1 already built for $SLICE"
    exit 0
fi

log "Building libsecp256k1 $SECP256K1_VERSION for $SLICE"

# GitHub source archive (extracts to secp256k1-<ver>/; needs ./autogen.sh).
ARCHIVE_URL="https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "secp256k1-${SECP256K1_VERSION}.tar.gz")"

PREFIX="$(slice_prefix "$SLICE")"
WORK_BASE="$BUILD_ROOT/deps/secp256k1/$SLICE"
ARCHES=($(slice_arches "$SLICE"))

mkdir -p "$PREFIX/lib" "$PREFIX/include"

PER_ARCH_LIBS=()
for arch in "${ARCHES[@]}"; do
    work="$WORK_BASE/$arch"
    rm -rf "$work"
    mkdir -p "$work"
    extract_to "$ARCHIVE" "$work/src"

    log "secp256k1: autogen+configure+make $SLICE/$arch"
    (
        cd "$work/src"
        ./autogen.sh > "$work/autogen.log" 2>&1 || { tail -40 "$work/autogen.log"; die "secp256k1 autogen failed"; }
        export CC; CC="$(arch_clang "$SLICE" "$arch")"
        export CFLAGS="-O2 -fPIC"
        export LDFLAGS=""
        ./configure \
            --host="$(arch_triple "$SLICE" "$arch")" \
            --prefix="$work/install" \
            --disable-shared \
            --enable-static \
            --enable-module-recovery \
            --disable-benchmark \
            --disable-tests \
            --disable-exhaustive-tests \
            --with-pic \
            > "$work/configure.log" 2>&1 || { tail -60 "$work/configure.log"; die "secp256k1 configure failed"; }
        make -j"$(sysctl -n hw.ncpu)" > "$work/make.log" 2>&1 || { tail -60 "$work/make.log"; die "secp256k1 build failed"; }
        make install > "$work/install.log" 2>&1
    )
    PER_ARCH_LIBS+=("$work/install/lib/libsecp256k1.a")

    # First arch provides the headers (identical across arches)
    if [[ "$arch" == "${ARCHES[0]}" ]]; then
        cp -R "$work/install/include/"* "$PREFIX/include/"
    fi
done

log "Lipo-merging libsecp256k1 arches: ${ARCHES[*]}"
lipo -create "${PER_ARCH_LIBS[@]}" -output "$PREFIX/lib/libsecp256k1.a"

mark_built "$SLICE" "libsecp256k1"
ok "libsecp256k1 installed to $PREFIX"
