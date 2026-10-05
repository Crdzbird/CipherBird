#!/usr/bin/env bash
_SDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$_SDIR/../lib/common.sh"
if is_built liboqs; then ok "liboqs already built"; exit 0; fi
log "Building liboqs $LIBOQS_VERSION for wasm32 (portable, internal hashes)"
ARCHIVE="$(fetch_tarball "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "liboqs-${LIBOQS_VERSION}.tar.gz")"
WORK="$BUILD_ROOT/deps/liboqs"
extract_fresh "$ARCHIVE" "$WORK/src"
ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;KEM_ntruprime_sntrup761;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
for hash in sha2 shake; do
    for lvl in 128s 128f 192s 192f 256s 256f; do
        ALGS+=";SIG_slh_dsa_pure_${hash}_${lvl}"
    done
done
emcmake cmake -S "$WORK/src" -B "$WORK/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    -DOQS_MINIMAL_BUILD="$ALGS" -DCMAKE_INSTALL_PREFIX="$PREFIX" > "$WORK/cmake.log" 2>&1 \
    || { tail -60 "$WORK/cmake.log"; die "cmake failed"; }
cmake --build "$WORK/build" --target install -j"$JOBS" > "$WORK/build.log" 2>&1 \
    || { tail -60 "$WORK/build.log"; die "build failed"; }
flatten_lib64
mark_built liboqs
ok "liboqs installed to $PREFIX"
