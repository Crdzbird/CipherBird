#!/usr/bin/env bash
# Shared environment for cryptolib Android NDK build scripts.
# Expects callers to set ABI (arm64-v8a | armeabi-v7a | x86_64 | x86).

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"

SRC_DIR="$REPO_ROOT/third_party/android/src"
DEPS_ROOT="$REPO_ROOT/third_party/android"
BUILD_ROOT="$REPO_ROOT/build/android"
mkdir -p "$SRC_DIR" "$DEPS_ROOT" "$BUILD_ROOT"

# Version pins (kept in sync with iOS scripts)
LIBSODIUM_VERSION="1.0.20"
BLAKE3_VERSION="1.5.4"
OPENSSL_VERSION="3.3.2"
LIBOQS_VERSION="0.15.0"
SECP256K1_VERSION="0.7.1"

# Minimum Android API we target. 24 = Android 7.0 Nougat (covers >99% of
# devices in use as of 2025, per Google Play distribution stats).
ANDROID_API="24"

# Find the NDK. Accept env override, else probe the standard Android Studio
# locations for the newest r25-or-greater install.
if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
    NDK="$ANDROID_NDK_ROOT"
elif [[ -d "$HOME/Library/Android/sdk/ndk" ]]; then
    NDK="$(ls -d "$HOME"/Library/Android/sdk/ndk/*/ 2>/dev/null | sort -V | tail -1 | sed 's:/$::')"
elif [[ -d "/opt/homebrew/share/android-commandlinetools/ndk" ]]; then
    NDK="$(ls -d /opt/homebrew/share/android-commandlinetools/ndk/*/ 2>/dev/null | sort -V | tail -1 | sed 's:/$::')"
else
    echo "ERROR: Android NDK not found. Set ANDROID_NDK_ROOT." >&2
    exit 1
fi

[[ -f "$NDK/build/cmake/android.toolchain.cmake" ]] \
    || { echo "ERROR: NDK at $NDK lacks android.toolchain.cmake" >&2; exit 1; }

# Host tag (where the NDK binaries actually run)
HOST_ARCH="$(uname -m)"
case "$(uname -s)-$HOST_ARCH" in
    Darwin-*)   NDK_HOST_TAG="darwin-x86_64" ;;  # universal2 bin in modern NDKs
    Linux-*)    NDK_HOST_TAG="linux-x86_64" ;;
    *)          echo "ERROR: unsupported host OS"; exit 1 ;;
esac
NDK_TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$NDK_HOST_TAG"

# ─── Colours ────────────────────────────────────────────────────────────────
BOLD=$'\033[1m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[31m'
CYN=$'\033[36m'; RST=$'\033[0m'
log()  { printf "%s==>%s %s\n" "$CYN$BOLD" "$RST" "$*" >&2; }
ok()   { printf "%s✓%s %s\n"   "$GRN"      "$RST" "$*" >&2; }
warn() { printf "%s!%s %s\n"   "$YLW"      "$RST" "$*" >&2; }
die()  { printf "%s✗%s %s\n"   "$RED"      "$RST" "$*" >&2; exit 1; }

# ─── ABI → triple mapping (for autotools --host=) ───────────────────────────
abi_triple() {
    case "$1" in
        arm64-v8a)    echo "aarch64-linux-android" ;;
        armeabi-v7a)  echo "armv7a-linux-androideabi" ;;
        x86_64)       echo "x86_64-linux-android" ;;
        x86)          echo "i686-linux-android" ;;
        *)            die "Unknown ABI: $1" ;;
    esac
}

# Compiler prefix (for invoking clang directly with API suffix)
abi_cc() {
    local abi="$1"
    case "$abi" in
        arm64-v8a)    echo "$NDK_TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang" ;;
        armeabi-v7a)  echo "$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi${ANDROID_API}-clang" ;;
        x86_64)       echo "$NDK_TOOLCHAIN/bin/x86_64-linux-android${ANDROID_API}-clang" ;;
        x86)          echo "$NDK_TOOLCHAIN/bin/i686-linux-android${ANDROID_API}-clang" ;;
    esac
}

abi_cxx() {
    local abi="$1"
    case "$abi" in
        arm64-v8a)    echo "$NDK_TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang++" ;;
        armeabi-v7a)  echo "$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi${ANDROID_API}-clang++" ;;
        x86_64)       echo "$NDK_TOOLCHAIN/bin/x86_64-linux-android${ANDROID_API}-clang++" ;;
        x86)          echo "$NDK_TOOLCHAIN/bin/i686-linux-android${ANDROID_API}-clang++" ;;
    esac
}

# Install prefix per ABI
abi_prefix() { echo "$DEPS_ROOT/$1"; }

# ─── Idempotency ────────────────────────────────────────────────────────────
is_built()    { [[ -f "$DEPS_ROOT/$1/.$2.built" ]]; }
mark_built()  { mkdir -p "$DEPS_ROOT/$1"; touch "$DEPS_ROOT/$1/.$2.built"; }

# ─── Source fetch (shared with iOS) ─────────────────────────────────────────
fetch_tarball() {
    local url="$1" name="$2"
    local archive="$SRC_DIR/$name"
    # Fall back to the shared iOS source cache if a copy is already there
    local ios_cache="$REPO_ROOT/third_party/ios/src/$name"
    if [[ -f "$ios_cache" && ! -f "$archive" ]]; then
        cp "$ios_cache" "$archive"
    fi
    if [[ ! -f "$archive" ]]; then
        log "Downloading $name..."
        curl -fL --progress-bar -o "$archive" "$url"
    fi
    echo "$archive"
}

extract_to() {
    local archive="$1" target="$2"
    if [[ -d "$target" && -n "$(ls -A "$target" 2>/dev/null)" ]]; then
        return 0
    fi
    mkdir -p "$target"
    tar -xf "$archive" -C "$target" --strip-components=1
}
