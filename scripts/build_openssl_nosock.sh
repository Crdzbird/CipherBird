#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_openssl_nosock.sh — build a socket-free, dlopen-free OpenSSL libcrypto.a
# for the fully-sealed static archive.
#
# Stock OpenSSL's libcrypto carries socket-capable BIO code and a dynamic-loader
# (dlopen) subsystem. When statically linked those come along as latent, unused
# capability. Configuring OpenSSL with `no-sock no-dso` removes them AT SOURCE —
# the only clean way (the references are #ifdef'd out of the core), which object
# surgery on a prebuilt archive cannot replicate.
#
# OpenSSL 3.x has a stable ABI across the series, so this libcrypto links with
# the prebuilt liboqs.a (which uses OpenSSL EVP for AES/SHA). Version + hash are
# pinned for supply-chain integrity; override with OPENSSL_VER / OPENSSL_SHA256.
#
# Output: build/host-deps/openssl-nosock/lib/libcrypto.a
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="${OPENSSL_VER:-3.6.3}"
SHA256="${OPENSSL_SHA256:-243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1}"
DEPS="$ROOT/build/host-deps"
OUT="$DEPS/openssl-nosock"
mkdir -p "$DEPS"

if [ -f "$OUT/lib/libcrypto.a" ]; then
    echo "→ already built: ${OUT#$ROOT/}/lib/libcrypto.a"
    exit 0
fi

TARBALL="$DEPS/openssl-$VER.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz"
[ -f "$TARBALL" ] || { echo "== fetching openssl-$VER =="; curl -fSLm 300 -o "$TARBALL" "$URL"; }
echo "== verifying source checksum =="
echo "$SHA256  $TARBALL" | shasum -a 256 -c - \
    || { echo "checksum mismatch for openssl-$VER — refusing to build" >&2; exit 1; }

SRC="$DEPS/openssl-$VER"
rm -rf "$SRC"
tar xzf "$TARBALL" -C "$DEPS"

echo "== configuring (no-sock no-dso, static libcrypto only) =="
( cd "$SRC"
  ./Configure no-shared no-sock no-dso no-tests no-apps no-docs no-quic \
      --prefix="$OUT" --openssldir="$OUT/ssl" >/dev/null
  echo "== building libcrypto.a (build_libs: generates headers first) =="
  # build_libs is the canonical target for just the libraries; it runs the
  # generated-header step (opensslv.h/opensslconf.h) that a bare `libcrypto.a`
  # target skips. no-shared makes these static archives.
  make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" build_libs >/dev/null
  mkdir -p "$OUT/lib"
  cp libcrypto.a "$OUT/lib/libcrypto.a" )

echo "== verifying no socket / dlopen symbols remain =="
NET=$(nm "$OUT/lib/libcrypto.a" 2>/dev/null | grep -cE 'U _(socket|connect|bind|listen|accept|sendto|recvfrom|sendmsg|recvmsg|getaddrinfo|getnameinfo|gethostbyname)$' || true)
DL=$(nm "$OUT/lib/libcrypto.a" 2>/dev/null | grep -cE 'U _(dlopen|dlsym)$' || true)
echo "   network refs: $NET   dlopen refs: $DL"
[ "$NET" = "0" ] && [ "$DL" = "0" ] || { echo "   WARNING: expected 0/0 — inspect the build" >&2; }
echo "→ ${OUT#$ROOT/}/lib/libcrypto.a (no-sock no-dso)"
