#!/usr/bin/env bash
# Build blst (BLS12-381) from a pinned release and install it where the build
# looks for it: <prefix>/lib/libblst.a and <prefix>/include/blst/blst.h. The
# sources include <blst/blst.h>, and CMakeLists.txt finds BLST_INCLUDE_DIR by
# that path, so the headers must live in a blst/ subdirectory.
#
# Usage: scripts/ci/install_blst.sh [prefix]   (default: /opt/homebrew)
set -euo pipefail

BLST_TAG="v0.3.17"
BLST_COMMIT="54e6e55674722fc2797ebb4bbb71b26d881eb4b8"
PREFIX="${1:-/opt/homebrew}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --quiet --depth 1 --branch "$BLST_TAG" \
    https://github.com/supranational/blst.git "$WORK/blst"
GOT="$(git -C "$WORK/blst" rev-parse HEAD)"
if [ "$GOT" != "$BLST_COMMIT" ]; then
    echo "blst $BLST_TAG resolved to $GOT, expected $BLST_COMMIT" >&2
    exit 1
fi
(cd "$WORK/blst" && ./build.sh)

SUDO=""
mkdir -p "$PREFIX/lib" "$PREFIX/include/blst" 2>/dev/null || true
if [ ! -w "$PREFIX/lib" ] || [ ! -w "$PREFIX/include/blst" ]; then SUDO="sudo"; fi
$SUDO mkdir -p "$PREFIX/lib" "$PREFIX/include/blst"
$SUDO cp "$WORK/blst/libblst.a" "$PREFIX/lib/"
$SUDO cp "$WORK/blst/bindings/blst.h" "$WORK/blst/bindings/blst_aux.h" \
    "$PREFIX/include/blst/"
echo "blst $BLST_TAG installed to $PREFIX"
