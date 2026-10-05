#!/usr/bin/env bash
# Build every dependency for wasm32 with Emscripten, then the engine.
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/lib/common.sh"
for dep in libsodium blake3 secp256k1 blst openssl liboqs; do
    "$_SDIR/deps/build_$dep.sh"
done
"$_SDIR/build_engine.sh"
