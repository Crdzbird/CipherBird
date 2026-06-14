#!/usr/bin/env bash
# One-shot orchestrator: build all deps for all slices, then cryptolib_c per
# slice, then assemble CryptoLib.xcframework.
#
# Usage:
#   ./scripts/ios/build_all.sh                    # all slices
#   ./scripts/ios/build_all.sh iphoneos           # just device
#   ./scripts/ios/build_all.sh iphoneos iphonesimulator
#
# Re-runs are fast: each dep script stamps itself as built and skips.

set -euo pipefail
IOS_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$IOS_SCRIPT_DIR/lib/common.sh"

SLICES=("$@")
if [[ ${#SLICES[@]} -eq 0 ]]; then
    SLICES=(iphoneos iphonesimulator macosx)
fi

# Dependency build order matters: OpenSSL must exist before liboqs.
DEPS=(libsodium blake3 openssl liboqs blst secp256k1)

for slice in "${SLICES[@]}"; do
    printf "\n%s═══ Building dependencies for %s ═══%s\n" "$BOLD$CYN" "$slice" "$RST"
    for dep in "${DEPS[@]}"; do
        "$IOS_SCRIPT_DIR/deps/build_${dep}.sh" "$slice"
    done
done

for slice in "${SLICES[@]}"; do
    printf "\n%s═══ Building cryptolib_c for %s ═══%s\n" "$BOLD$CYN" "$slice" "$RST"
    "$IOS_SCRIPT_DIR/build_cryptolib_slice.sh" "$slice"
done

printf "\n%s═══ Assembling XCFramework ═══%s\n" "$BOLD$CYN" "$RST"
"$IOS_SCRIPT_DIR/assemble_xcframework.sh" "${SLICES[@]}"

printf "\n%s✓ All done — CryptoLib.xcframework ready%s\n" "$BOLD$GRN" "$RST"
