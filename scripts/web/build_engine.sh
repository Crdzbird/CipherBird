#!/usr/bin/env bash
# Compile the C ABI engine and its flat wrappers to cipherbird.js + cipherbird.wasm.
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/lib/common.sh"
for dep in libsodium libblake3 liboqs libcrypto libblst libsecp256k1; do
    [[ -f "$PREFIX/lib/${dep}.a" ]] || die "missing $PREFIX/lib/${dep}.a; run scripts/web/build_all.sh"
done
GEN="$BUILD_ROOT/gen"
OUT="$BUILD_ROOT/dist"
mkdir -p "$GEN" "$OUT"
log "Generating the flat boundary"
python3 "$_SDIR/gen_wrappers.py" "$REPO_ROOT/bridge/cryptolib_c.h" "$GEN"
DEFS="-DCRYPTOLIB_BUILD_SHARED -DCRYPTOLIB_HAS_BLAKE3=1 -DCRYPTOLIB_HAS_PQ=1 -DCRYPTOLIB_HAS_BLS=1 -DCRYPTOLIB_HAS_OPENSSL=1 -DCRYPTOLIB_HAS_SECP256K1=1"
log "Compiling the engine"
em++ -std=c++20 -O3 -fwasm-exceptions $DEFS -I "$REPO_ROOT/include" -I "$PREFIX/include" \
    -c "$REPO_ROOT/bridge/cryptolib_c.cpp" -o "$BUILD_ROOT/cryptolib_c.o" > "$BUILD_ROOT/engine.log" 2>&1 \
    || { tail -40 "$BUILD_ROOT/engine.log"; die "engine compile failed"; }
emcc -O3 -I "$REPO_ROOT/bridge" -c "$GEN/cipherbird_wrappers.c" -o "$BUILD_ROOT/wrappers.o" > "$BUILD_ROOT/wrappers.log" 2>&1 \
    || { tail -40 "$BUILD_ROOT/wrappers.log"; die "wrapper compile failed"; }
log "Linking cipherbird.wasm"
em++ -O3 -fwasm-exceptions "$BUILD_ROOT/cryptolib_c.o" "$BUILD_ROOT/wrappers.o" \
    "$PREFIX/lib/libsodium.a" "$PREFIX/lib/libblake3.a" "$PREFIX/lib/liboqs.a" \
    "$PREFIX/lib/libcrypto.a" "$PREFIX/lib/libblst.a" "$PREFIX/lib/libsecp256k1.a" \
    --no-entry \
    -sMODULARIZE=1 -sEXPORT_NAME=createCipherBird \
    -sEXPORTED_FUNCTIONS=@"$GEN/exports.json" \
    -sEXPORTED_RUNTIME_METHODS=HEAPU8,HEAPU32,HEAPF64 \
    -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=32MB -sMAXIMUM_MEMORY=4GB -sSTACK_SIZE=8MB \
    -sENVIRONMENT=web,worker,node -sTEXTDECODER=2 -sASSERTIONS=0 \
    -o "$OUT/cipherbird.js" > "$BUILD_ROOT/link.log" 2>&1 \
    || { tail -60 "$BUILD_ROOT/link.log"; die "link failed"; }
log "Recording wasm32 struct layouts"
emcc -O1 -I "$REPO_ROOT/bridge" "$GEN/layouts.c" -o "$GEN/layouts.js" > "$GEN/layouts.log" 2>&1 \
    || { tail -20 "$GEN/layouts.log"; die "layouts compile failed"; }
node "$GEN/layouts.js" > "$GEN/layouts.json"
ok "Built $OUT/cipherbird.wasm ($(du -h "$OUT/cipherbird.wasm" | cut -f1)) and cipherbird.js ($(du -h "$OUT/cipherbird.js" | cut -f1))"
