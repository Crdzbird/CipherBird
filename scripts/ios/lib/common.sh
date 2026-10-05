#!/usr/bin/env bash
# Shared environment for cryptolib iOS build scripts.
#
# Provides: REPO_ROOT, SRC_DIR, DEPS_ROOT, log, die, slice-aware helpers.
# Expects callers to set SLICE (iphoneos | iphonesimulator | macosx).

set -euo pipefail

# Repo layout — resolved relative to THIS file so callers can invoke from anywhere
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
SRC_DIR="$REPO_ROOT/third_party/ios/src"
DEPS_ROOT="$REPO_ROOT/third_party/ios"
BUILD_ROOT="$REPO_ROOT/build/ios"

mkdir -p "$SRC_DIR" "$DEPS_ROOT" "$BUILD_ROOT"

# Version pins — change here to upgrade a dependency
LIBSODIUM_VERSION="1.0.20"
BLAKE3_VERSION="1.5.4"
OPENSSL_VERSION="3.3.2"
# liboqs 0.13+ introduced the FIPS 203/204/205 naming (ML-KEM, ML-DSA, SLH-DSA)
# that pq.hpp uses. 0.12 still uses the pre-standardization names.
LIBOQS_VERSION="0.15.0"
# secp256k1 (bitcoin-core) for EVM/BTC interop — keep in sync with the Homebrew
# pin used on desktop so every platform ships the same ECDSA implementation.
SECP256K1_VERSION="0.7.1"

# ─── Console helpers ────────────────────────────────────────────────────────
BOLD=$'\033[1m'
GRN=$'\033[32m'
YLW=$'\033[33m'
RED=$'\033[31m'
CYN=$'\033[36m'
RST=$'\033[0m'

log()  { printf "%s==>%s %s\n" "$CYN$BOLD" "$RST" "$*" >&2; }
ok()   { printf "%s✓%s %s\n"   "$GRN"      "$RST" "$*" >&2; }
warn() { printf "%s!%s %s\n"   "$YLW"      "$RST" "$*" >&2; }
die()  { printf "%s✗%s %s\n"   "$RED"      "$RST" "$*" >&2; exit 1; }

# ─── Slice helpers ──────────────────────────────────────────────────────────
# slice_sdk iphoneos           -> iphoneos
# slice_sdk iphonesimulator    -> iphonesimulator
# slice_sdk macosx             -> macosx
slice_sdk() { echo "$1"; }

# Architectures to build for each slice.
# Note: simulator is arm64-only — Apple Silicon Macs run the arm64 simulator
# natively and Rosetta handles anything else. Keeping simulator single-arch
# avoids per-arch cross-compile + lipo complexity in liboqs.
slice_arches() {
    case "$1" in
        iphoneos)         echo "arm64" ;;
        iphonesimulator)  echo "arm64" ;;
        macosx)           echo "arm64" ;;
        *)                die "Unknown slice: $1" ;;
    esac
}

# Minimum deployment target per slice (matches cmake/ios.toolchain.cmake)
slice_min_version() {
    case "$1" in
        iphoneos|iphonesimulator)  echo "15.0" ;;
        macosx)                    echo "12.0" ;;
        *)                         die "Unknown slice: $1" ;;
    esac
}

# clang -m<sdk>-version-min=<version> flag
slice_version_flag() {
    local slice="$1"
    local v; v="$(slice_min_version "$slice")"
    case "$slice" in
        iphoneos)         echo "-miphoneos-version-min=$v" ;;
        iphonesimulator)  echo "-mios-simulator-version-min=$v" ;;
        macosx)           echo "-mmacosx-version-min=$v" ;;
    esac
}

# Per-arch autotools host triple (used by --host= in configure scripts)
arch_triple() {
    local slice="$1" arch="$2"
    case "$slice" in
        iphoneos)         echo "${arch}-apple-darwin" ;;
        iphonesimulator)  echo "${arch}-apple-darwin" ;;
        macosx)           echo "${arch}-apple-darwin" ;;
    esac
}

# ─── Tool discovery ─────────────────────────────────────────────────────────
require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "Required tool '$1' not found in PATH"
}

require_tool xcrun
require_tool cmake
require_tool lipo
require_tool libtool

XCRUN="$(command -v xcrun)"

sdk_path() {
    "$XCRUN" --sdk "$1" --show-sdk-path
}

# Return the arch-specific clang command with the right sysroot/version flag.
# Use: CC="$(arch_clang iphoneos arm64)"
arch_clang() {
    local slice="$1" arch="$2"
    echo "$XCRUN --sdk $(slice_sdk "$slice") clang -arch $arch -isysroot $(sdk_path "$slice") $(slice_version_flag "$slice")"
}

arch_clangxx() {
    local slice="$1" arch="$2"
    echo "$XCRUN --sdk $(slice_sdk "$slice") clang++ -arch $arch -isysroot $(sdk_path "$slice") $(slice_version_flag "$slice")"
}

# ─── Source acquisition ─────────────────────────────────────────────────────
# fetch_tarball <url> <local-name>
# Downloads to third_party/ios/src/<local-name> and extracts on demand.
fetch_tarball() {
    local url="$1" name="$2"
    local archive="$SRC_DIR/$name"
    if [[ ! -f "$archive" ]]; then
        log "Downloading $name..."
        curl -fL --progress-bar -o "$archive" "$url"
    fi
    echo "$archive"
}

# Extract a tarball into a specific directory, skip if already done
extract_to() {
    local archive="$1" target="$2"
    if [[ -d "$target" && -n "$(ls -A "$target" 2>/dev/null)" ]]; then
        return 0
    fi
    mkdir -p "$target"
    tar -xf "$archive" -C "$target" --strip-components=1
}

# ─── Idempotency stamps ─────────────────────────────────────────────────────
stamp_file() { echo "$DEPS_ROOT/$1/.${2}.built"; }

is_built() {
    local slice="$1" name="$2"
    [[ -f "$(stamp_file "$slice" "$name")" ]]
}

mark_built() {
    local slice="$1" name="$2"
    mkdir -p "$DEPS_ROOT/$slice"
    touch "$(stamp_file "$slice" "$name")"
}

# Per-slice install prefix (where headers and .a files end up)
slice_prefix() {
    local slice="$1"
    echo "$DEPS_ROOT/$slice"
}
