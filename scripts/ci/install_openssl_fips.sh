#!/usr/bin/env bash
# Build OpenSSL 3.1.2 with its FIPS provider from the hash-pinned tarball and
# install it under <prefix>, then run fipsinstall so fipsmodule.cnf carries the
# module's integrity MAC. 3.1.2 is the exact source the CMVP validated as the
# OpenSSL FIPS Provider, certificate #4985 (FIPS 140-3); any other release of
# libcrypto may load that provider, but the provider itself must be this one.
#
# Usage: scripts/ci/install_openssl_fips.sh [prefix]   (default: $HOME/openssl-fips)
# Afterwards:
#   CRYPTOLIB_FIPS_MODULE_DIR=<prefix>/lib/ossl-modules
#   CRYPTOLIB_FIPS_CONFIG=<prefix>/ssl/openssl-fips.cnf
set -euo pipefail

VERSION="3.1.2"
TARBALL="openssl-${VERSION}.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/${TARBALL}"
PREFIX="${1:-$HOME/openssl-fips}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PINS="$ROOT/scripts/lib/sources.sha256"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -sSfL "$URL" -o "$WORK/$TARBALL"
EXPECTED="$(grep " ${TARBALL}\$" "$PINS" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
    echo "no pin for $TARBALL in $PINS" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    GOT="$(sha256sum "$WORK/$TARBALL" | awk '{print $1}')"
else
    GOT="$(shasum -a 256 "$WORK/$TARBALL" | awk '{print $1}')"
fi
if [ "$GOT" != "$EXPECTED" ]; then
    echo "$TARBALL sha256 $GOT, expected $EXPECTED" >&2
    exit 1
fi

tar -xzf "$WORK/$TARBALL" -C "$WORK"
cd "$WORK/openssl-${VERSION}"
./Configure enable-fips no-tests --prefix="$PREFIX" --openssldir="$PREFIX/ssl" >/dev/null
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" >/dev/null
make install_sw install_ssldirs install_fips >/dev/null

cat > "$PREFIX/ssl/openssl-fips.cnf" <<CNF
config_diagnostics = 1
openssl_conf = openssl_init
.include $PREFIX/ssl/fipsmodule.cnf
[openssl_init]
providers = provider_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
CNF

OPENSSL_CONF="$PREFIX/ssl/openssl-fips.cnf" OPENSSL_MODULES="$PREFIX/lib/ossl-modules" \
    "$PREFIX/bin/openssl" list -providers | grep -q "OpenSSL FIPS Provider"
echo "OpenSSL $VERSION with the FIPS provider installed to $PREFIX"
