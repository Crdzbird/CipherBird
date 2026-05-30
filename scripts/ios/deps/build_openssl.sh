#!/usr/bin/env bash
# Cross-compile OpenSSL (libcrypto) for one slice.
# We only need libcrypto for liboqs (AES/SHA primitives); libssl is not used.
# Build minimal config to keep .a size reasonable.
# Usage: build_openssl.sh <slice>

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../lib/common.sh"

SLICE="${1:-}"
[[ -z "$SLICE" ]] && die "Usage: $0 <iphoneos|iphonesimulator|macosx>"

if is_built "$SLICE" "openssl"; then
    ok "openssl already built for $SLICE"
    exit 0
fi

log "Building OpenSSL $OPENSSL_VERSION for $SLICE (libcrypto only, minimal)"

ARCHIVE_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
ARCHIVE="$(fetch_tarball "$ARCHIVE_URL" "openssl-${OPENSSL_VERSION}.tar.gz")"

PREFIX="$(slice_prefix "$SLICE")"
WORK_BASE="$BUILD_ROOT/deps/openssl/$SLICE"
ARCHES=($(slice_arches "$SLICE"))

mkdir -p "$PREFIX/lib" "$PREFIX/include"

# Configure targets: OpenSSL has built-in target names for each SDK
openssl_target() {
    local slice="$1" arch="$2"
    case "$slice" in
        iphoneos)
            [[ "$arch" == "arm64" ]] && echo "ios64-cross" || echo "ios-cross"
            ;;
        iphonesimulator)
            [[ "$arch" == "arm64" ]] && echo "iossimulator-arm64-xcrun" || echo "darwin64-x86_64-cc"
            ;;
        macosx)
            [[ "$arch" == "arm64" ]] && echo "darwin64-arm64-cc" || echo "darwin64-x86_64-cc"
            ;;
    esac
}

PER_ARCH_CRYPTO=()
for arch in "${ARCHES[@]}"; do
    work="$WORK_BASE/$arch"
    rm -rf "$work"
    mkdir -p "$work"
    extract_to "$ARCHIVE" "$work/src"

    target="$(openssl_target "$SLICE" "$arch")"
    log "openssl: Configure $target for $SLICE/$arch"
    (
        cd "$work/src"
        export CROSS_TOP="$(xcrun --sdk "$(slice_sdk "$SLICE")" --show-sdk-platform-path)/Developer"
        export CROSS_SDK="$(basename "$(xcrun --sdk "$(slice_sdk "$SLICE")" --show-sdk-path)")"

        ./Configure "$target" \
            no-shared no-dso no-hw no-engine no-tests no-apps no-docs \
            no-ssl3 no-ssl3-method no-weak-ssl-ciphers no-zlib \
            --prefix="$work/install" \
            > "$work/configure.log" 2>&1 || { tail -40 "$work/configure.log"; die "openssl configure failed"; }

        # Patch out version-min that openssl hardcodes — we set our own
        # (safe no-op if the pattern isn't there)
        if [[ "$SLICE" == "iphoneos" || "$SLICE" == "iphonesimulator" ]]; then
            sed -i.bak -e 's/-mios-version-min=[0-9.]*//g' \
                       -e 's/-mios-simulator-version-min=[0-9.]*//g' Makefile 2>/dev/null || true
        fi

        make -j"$(sysctl -n hw.ncpu)" build_libs > "$work/make.log" 2>&1 \
            || { tail -80 "$work/make.log"; die "openssl build failed"; }
        make install_dev > "$work/install.log" 2>&1
    )
    PER_ARCH_CRYPTO+=("$work/install/lib/libcrypto.a")

    # Headers from first arch only (identical across arches)
    if [[ "$arch" == "${ARCHES[0]}" ]]; then
        cp -R "$work/install/include/"* "$PREFIX/include/"
    fi
done

log "Lipo-merging libcrypto arches: ${ARCHES[*]}"
lipo -create "${PER_ARCH_CRYPTO[@]}" -output "$PREFIX/lib/libcrypto.a"

mark_built "$SLICE" "openssl"
ok "openssl installed to $PREFIX (libcrypto.a only)"
