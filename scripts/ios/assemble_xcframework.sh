#!/usr/bin/env bash
# Package per-slice merged archives into CryptoLib.xcframework.
#
# Accepts 0 or more slice names as arguments (defaults to all three).
# Only slices whose merged archive exists are included.
#
# Usage:
#   ./assemble_xcframework.sh                          # iphoneos+iphonesimulator+macosx
#   ./assemble_xcframework.sh iphoneos iphonesimulator # iOS only

set -euo pipefail
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/lib/common.sh"

SLICES=("$@")
if [[ ${#SLICES[@]} -eq 0 ]]; then
    SLICES=(iphoneos iphonesimulator macosx)
fi

# Staging: xcodebuild -create-xcframework wants a directory of headers, not
# a single .h file. Create a staging dir with cryptolib_c.h inside.
HEADERS_STAGE="$BUILD_ROOT/xcframework_headers"
rm -rf "$HEADERS_STAGE"
mkdir -p "$HEADERS_STAGE"
cp "$REPO_ROOT/bridge/cryptolib_c.h" "$HEADERS_STAGE/cryptolib_c.h"

# module.modulemap so Swift can import CryptoLibC
cat > "$HEADERS_STAGE/module.modulemap" <<EOF
module CryptoLibC {
    header "cryptolib_c.h"
    export *
}
EOF

# Build up -library/-headers args
XCFW_ARGS=()
FOUND_ANY=0
for slice in "${SLICES[@]}"; do
    archive="$BUILD_ROOT/$slice/libcryptolib_c_merged.a"
    if [[ -f "$archive" ]]; then
        XCFW_ARGS+=(-library "$archive" -headers "$HEADERS_STAGE")
        FOUND_ANY=1
        log "Including slice: $slice ($(du -h "$archive" | awk '{print $1}'))"
    else
        warn "Skipping slice '$slice' — $archive not found"
    fi
done

[[ "$FOUND_ANY" -eq 1 ]] || die "No slice archives found — run build_all.sh first"

OUTPUT="$REPO_ROOT/CryptoLib.xcframework"
log "Assembling $OUTPUT"
rm -rf "$OUTPUT"

xcodebuild -create-xcframework "${XCFW_ARGS[@]}" -output "$OUTPUT" \
    > "$BUILD_ROOT/xcframework.log" 2>&1 \
    || { cat "$BUILD_ROOT/xcframework.log"; die "xcodebuild -create-xcframework failed"; }

ok "Built $OUTPUT"

# Summary
log "Contents:"
ls -la "$OUTPUT"/
for slice_dir in "$OUTPUT"/*/; do
    identifier="$(basename "$slice_dir")"
    printf "    %s%s%s\n" "$BOLD" "$identifier" "$RST"
    find "$slice_dir" -maxdepth 2 -type f | sed 's|^|        |'
done
