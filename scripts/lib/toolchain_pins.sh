# Pinned toolchains and sources shared by every platform build. The sha256
# manifest next to this file is the only accepted content for each tarball;
# fetch_tarball refuses anything else. Record these in the SBOM when they change.
BLST_TAG="v0.3.17"
BLST_COMMIT="54e6e55674722fc2797ebb4bbb71b26d881eb4b8"
ANDROID_NDK_VERSION="30.0.16248370"
EMSCRIPTEN_VERSION="6.0.9"
SOURCES_SHA256="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sources.sha256"

verify_source_sha256() {
    local archive="$1" name
    name="$(basename "$archive")"
    local expected
    expected="$(grep -E "  ${name}\$" "$SOURCES_SHA256" | cut -d' ' -f1)"
    if [[ -z "$expected" ]]; then
        echo "no pinned sha256 for $name in $SOURCES_SHA256" >&2
        return 1
    fi
    local actual
    actual="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
    if [[ "$actual" != "$expected" ]]; then
        echo "sha256 mismatch for $name: expected $expected, got $actual" >&2
        return 1
    fi
}

fetch_blst_pinned() {
    local dest="$1"
    if [[ -d "$dest/.git" ]]; then
        local have
        have="$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)"
        [[ "$have" == "$BLST_COMMIT" ]] && return 0
        rm -rf "$dest"
    fi
    rm -rf "$dest"
    git clone --quiet --depth 1 --branch "$BLST_TAG" https://github.com/supranational/blst.git "$dest"
    local got
    got="$(git -C "$dest" rev-parse HEAD)"
    if [[ "$got" != "$BLST_COMMIT" ]]; then
        echo "blst $BLST_TAG resolved to $got, expected $BLST_COMMIT" >&2
        return 1
    fi
}

require_emscripten_version() {
    local have
    have="$(emcc --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ "$have" != "$EMSCRIPTEN_VERSION" ]]; then
        echo "Emscripten $EMSCRIPTEN_VERSION is required, found ${have:-none}" >&2
        return 1
    fi
}
