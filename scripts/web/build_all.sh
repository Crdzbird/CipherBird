#!/usr/bin/env bash
# Build every dependency for wasm32 with Emscripten, then the engine.
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/lib/common.sh"
# WebAssembly SIMD for every dependency and the engine: measured 2026-10-24
# in Chrome, Argon2id 83.8 -> 52.3 ms and ML-KEM-768 191 -> 170 us for five
# percent more engine; the portable hashes and ciphers do not change. Set
# CIPHERBIRD_WASM_SIMD=0 for a scalar build.
if [ "${CIPHERBIRD_WASM_SIMD:-1}" != "0" ]; then
    # autoconf builds take CFLAGS as the whole set, so the optimisation level
    # goes here too or libsodium compiles unoptimised.
    export CFLAGS="${CFLAGS:--O3} -msimd128"
    export CXXFLAGS="${CXXFLAGS:--O3} -msimd128"
    export CIPHERBIRD_WASM_FLAGS="${CIPHERBIRD_WASM_FLAGS:-} -msimd128"
fi
for dep in libsodium blake3 secp256k1 blst openssl liboqs; do
    "$_SDIR/deps/build_$dep.sh"
done
"$_SDIR/build_engine.sh"
