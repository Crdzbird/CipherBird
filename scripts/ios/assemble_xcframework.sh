#!/usr/bin/env bash
# Package per-slice merged archives into CryptoLib.xcframework.
#
# Each slice's static archive is wrapped in a static .framework (CryptoLibC)
# before being added to the xcframework. A *framework* xcframework (vs a bare
# *library* one) is what Swift Package Manager's binaryTarget links reliably —
# static-library xcframeworks compile but are NOT auto-linked into the final
# product, causing "Undefined symbol" at link time. The framework form also
# lets the CocoaPods podspec drop its -force_load hack.
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

FW_NAME="CryptoLibC"

slice_supported_platform() {
    case "$1" in
        iphoneos)         echo "iPhoneOS" ;;
        iphonesimulator)  echo "iPhoneSimulator" ;;
        macosx)           echo "MacOSX" ;;
    esac
}

# Wrap a slice's static archive in a DYNAMIC framework. Echoes the .framework
# path.
#
# A dynamic framework (vs a static one) is what makes this work end-to-end for a
# dart:ffi plugin distributed via SPM: Swift Package Manager links AND EMBEDS
# dynamic-framework binaryTargets reliably (static ones are not propagated to
# the app link → "Undefined symbol"), and because the whole archive is
# force-loaded into the dylib every C-ABI symbol is present and exported, so
# DynamicLibrary.process() resolves them at runtime. The dylib is self-contained
# (libsodium / liboqs / blst / OpenSSL / secp256k1 / BLAKE3 statically inside).
_framework_info_plist() {
    local slice="$1" out="$2"
    local platform min_key min_ver
    platform="$(slice_supported_platform "$slice")"
    min_ver="$(slice_min_version "$slice")"
    if [[ "$slice" == "macosx" ]]; then min_key="LSMinimumSystemVersion"; else min_key="MinimumOSVersion"; fi
    cat > "$out" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>${FW_NAME}</string>
    <key>CFBundleIdentifier</key><string>com.cryptolib.${FW_NAME}</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>${FW_NAME}</string>
    <key>CFBundlePackageType</key><string>FMWK</string>
    <key>CFBundleShortVersionString</key><string>3.0.0</string>
    <key>CFBundleVersion</key><string>3.0.0</string>
    <key>CFBundleSupportedPlatforms</key><array><string>${platform}</string></array>
    <key>${min_key}</key><string>${min_ver}</string>
</dict>
</plist>
EOF
}

# Wrap a slice's static archive in a DYNAMIC framework. Echoes the .framework
# path. iOS slices get a FLAT framework; macOS gets a VERSIONED bundle
# (Versions/A/… with the canonical symlinks) — macOS rejects flat frameworks
# ("does not contain a binary artifact").
#
# A dynamic framework (vs a static one) is what makes this work end-to-end for a
# dart:ffi plugin distributed via SPM: Swift Package Manager links AND EMBEDS
# dynamic-framework binaryTargets reliably (static ones are not propagated to
# the app link → "Undefined symbol"), and because the whole archive is
# force-loaded into the dylib every C-ABI symbol is present and exported, so
# DynamicLibrary.process() resolves them at runtime. The dylib is self-contained
# (libsodium / liboqs / blst / OpenSSL / secp256k1 / BLAKE3 statically inside).
make_static_framework() {
    local slice="$1" archive="$2"
    local fwdir="$BUILD_ROOT/$slice/${FW_NAME}.framework"
    rm -rf "$fwdir"

    local arch cc
    arch="$(slice_arches "$slice")"     # single arch per slice (arm64)
    cc="$(arch_clang "$slice" "$arch")" # xcrun --sdk … clang -arch … -isysroot … -m…-version-min

    local modulemap
    modulemap="framework module ${FW_NAME} {
    header \"cryptolib_c.h\"
    export *
}"

    if [[ "$slice" == "macosx" ]]; then
        # Versioned bundle.
        local vdir="$fwdir/Versions/A"
        mkdir -p "$vdir/Headers" "$vdir/Modules" "$vdir/Resources"
        # shellcheck disable=SC2086
        $cc -dynamiclib \
            -Wl,-force_load,"$archive" \
            -framework Security -framework Foundation -lc++ \
            -install_name "@rpath/${FW_NAME}.framework/Versions/A/${FW_NAME}" \
            -o "$vdir/${FW_NAME}" \
            2>"$BUILD_ROOT/$slice/dylink.log" \
            || { cat "$BUILD_ROOT/$slice/dylink.log"; die "dynamic framework link failed for $slice"; }
        cp "$REPO_ROOT/bridge/cryptolib_c.h" "$vdir/Headers/cryptolib_c.h"
        printf '%s\n' "$modulemap" > "$vdir/Modules/module.modulemap"
        _framework_info_plist "$slice" "$vdir/Resources/Info.plist"
        ( cd "$fwdir/Versions" && ln -sfn A Current )
        ( cd "$fwdir" && ln -sfn "Versions/Current/${FW_NAME}" "${FW_NAME}" \
              && ln -sfn Versions/Current/Headers Headers \
              && ln -sfn Versions/Current/Modules Modules \
              && ln -sfn Versions/Current/Resources Resources )
    else
        # Flat bundle (iOS device + simulator).
        mkdir -p "$fwdir/Headers" "$fwdir/Modules"
        # shellcheck disable=SC2086
        $cc -dynamiclib \
            -Wl,-force_load,"$archive" \
            -framework Security -framework Foundation -lc++ \
            -install_name "@rpath/${FW_NAME}.framework/${FW_NAME}" \
            -o "$fwdir/${FW_NAME}" \
            2>"$BUILD_ROOT/$slice/dylink.log" \
            || { cat "$BUILD_ROOT/$slice/dylink.log"; die "dynamic framework link failed for $slice"; }
        cp "$REPO_ROOT/bridge/cryptolib_c.h" "$fwdir/Headers/cryptolib_c.h"
        printf '%s\n' "$modulemap" > "$fwdir/Modules/module.modulemap"
        _framework_info_plist "$slice" "$fwdir/Info.plist"
    fi
    echo "$fwdir"
}

# Build up -framework args, wrapping each slice's archive in a static framework.
XCFW_ARGS=()
FOUND_ANY=0
for slice in "${SLICES[@]}"; do
    archive="$BUILD_ROOT/$slice/libcryptolib_c_merged.a"
    if [[ -f "$archive" ]]; then
        fw="$(make_static_framework "$slice" "$archive")"
        XCFW_ARGS+=(-framework "$fw")
        FOUND_ANY=1
        log "Including slice: $slice ($(du -h "$archive" | awk '{print $1}') -> ${FW_NAME}.framework)"
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

ok "Built $OUTPUT (static frameworks)"

# Summary
log "Contents:"
ls -la "$OUTPUT"/
for slice_dir in "$OUTPUT"/*/; do
    identifier="$(basename "$slice_dir")"
    printf "    %s%s%s\n" "$BOLD" "$identifier" "$RST"
    find "$slice_dir" -maxdepth 3 -type f | sed 's|^|        |'
done
