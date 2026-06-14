#!/usr/bin/env bash
# Orchestrator for Android builds.
#   ./build_all.sh                       # arm64-v8a (most common)
#   ./build_all.sh arm64-v8a x86_64      # multiple ABIs
#   ./build_all.sh all                   # all four ABIs
set -euo pipefail
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/lib/common.sh"

ABIS=("$@")
if [[ ${#ABIS[@]} -eq 0 ]]; then
    ABIS=(arm64-v8a)
elif [[ "${ABIS[0]}" == "all" ]]; then
    ABIS=(arm64-v8a armeabi-v7a x86_64 x86)
fi

DEPS=(libsodium blake3 openssl liboqs blst secp256k1)

for abi in "${ABIS[@]}"; do
    printf "\n%s═══ Android deps for %s ═══%s\n" "$BOLD$CYN" "$abi" "$RST"
    for dep in "${DEPS[@]}"; do
        "$_SDIR/deps/build_${dep}.sh" "$abi"
    done
done

for abi in "${ABIS[@]}"; do
    printf "\n%s═══ cryptolib_c.so for %s ═══%s\n" "$BOLD$CYN" "$abi" "$RST"
    "$_SDIR/build_cryptolib_so.sh" "$abi"
done

printf "\n%s✓ Android build done%s\n" "$BOLD$GRN" "$RST"
for abi in "${ABIS[@]}"; do
    echo "  $BUILD_ROOT/$abi/libcryptolib_c.so"
done
