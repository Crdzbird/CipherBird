# Shared helpers for the WebAssembly (Emscripten) build of the engine.
# Sources are the same tarballs the Android and iOS builds use.

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
SRC_DIR="$REPO_ROOT/third_party/android/src"
DEPS_ROOT="$REPO_ROOT/third_party/web"
BUILD_ROOT="$REPO_ROOT/build/web"
PREFIX="$DEPS_ROOT/wasm32"
mkdir -p "$SRC_DIR" "$PREFIX/lib" "$PREFIX/include" "$BUILD_ROOT"

LIBSODIUM_VERSION="1.0.20"
BLAKE3_VERSION="1.5.4"
OPENSSL_VERSION="3.3.2"
LIBOQS_VERSION="0.15.0"
SECP256K1_VERSION="0.7.1"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

log()  { printf "==> %s\n" "$*" >&2; }
ok()   { printf "ok  %s\n" "$*" >&2; }
die()  { printf "err %s\n" "$*" >&2; exit 1; }

command -v emcc >/dev/null 2>&1 || die "emcc not found; install emscripten (brew install emscripten)"

is_built()   { [[ -f "$PREFIX/.$1.built" ]]; }
mark_built() { touch "$PREFIX/.$1.built"; }

fetch_tarball() {
    local url="$1" name="$2"
    local archive="$SRC_DIR/$name"
    local ios_cache="$REPO_ROOT/third_party/ios/src/$name"
    if [[ -f "$ios_cache" && ! -f "$archive" ]]; then
        cp "$ios_cache" "$archive"
    fi
    if [[ ! -f "$archive" ]]; then
        log "Downloading $name"
        curl -fL --progress-bar -o "$archive" "$url"
    fi
    echo "$archive"
}

extract_fresh() {
    local archive="$1" target="$2"
    rm -rf "$target"
    mkdir -p "$target"
    tar -xf "$archive" -C "$target" --strip-components=1
}

flatten_lib64() {
    if [[ -d "$PREFIX/lib64" ]]; then
        cp -R "$PREFIX/lib64/"* "$PREFIX/lib/"
        rm -rf "$PREFIX/lib64"
    fi
}
