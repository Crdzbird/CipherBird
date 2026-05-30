#!/usr/bin/env bash
# Cross-compile libsodium for one iOS/macOS slice.
# Usage: build_libsodium.sh <slice>
#   slice = iphoneos | iphonesimulator | macosx

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "libsodium"; then
    ok "libsodium already built for $SLICE"
    exit 0
fi

log "Building libsodium $LIBSODIUM_VERSION for $SLICE"

ARCHIVE_URL="https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "libsodium-${LIBSODIUM_VERSION}.tar.gz")"

PREFIX="$(slice_prefix "$SLICE")"
WORK_BASE="$BUILD_ROOT/deps/libsodium/$SLICE"
ARCHES=($(slice_arches "$SLICE"))

mkdir -p "$PREFIX/lib" "$PREFIX/include"

# Per-arch build, collect the .a files, then lipo into a universal archive
PER_ARCH_LIBS=()
for arch in "${ARCHES[@]}"; do
    work="$WORK_BASE/$arch"
    rm -rf "$work"
    mkdir -p "$work"
    extract_to "$ARCHIVE" "$work/src"

    log "libsodium: configure+make $SLICE/$arch"
    (
        cd "$work/src"
        export CC; CC="$(arch_clang "$SLICE" "$arch")"
        export CFLAGS="-O2 -fPIC"
        export LDFLAGS=""
        ./configure \
            --host="$(arch_triple "$SLICE" "$arch")" \
            --prefix="$work/install" \
            --disable-shared \
            --enable-static \
            --disable-soname-versions \
            > "$work/configure.log" 2>&1 || { tail -40 "$work/configure.log"; die "libsodium configure failed"; }
        make -j"$(sysctl -n hw.ncpu)" > "$work/make.log" 2>&1 || { tail -40 "$work/make.log"; die "libsodium build failed"; }
        make install > "$work/install.log" 2>&1
    )
    PER_ARCH_LIBS+=("$work/install/lib/libsodium.a")

    # First arch provides the headers (identical across arches)
    if [[ "$arch" == "${ARCHES[0]}" ]]; then
        cp -R "$work/install/include/"* "$PREFIX/include/"
    fi
done

log "Lipo-merging libsodium arches: ${ARCHES[*]}"
lipo -create "${PER_ARCH_LIBS[@]}" -output "$PREFIX/lib/libsodium.a"

mark_built "$SLICE" "libsodium"
ok "libsodium installed to $PREFIX"
