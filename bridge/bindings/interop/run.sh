#!/usr/bin/env bash
#
# Go <-> Flutter/Dart cryptographic interop demo.
#
# Proves that a value encrypted by one binding is decrypted by the other, in
# BOTH directions, using authenticated public-key encryption (Box / X25519).
# Both "parties" call the same native libcryptolib_c, so the ciphertext format
# is identical — the Dart party uses the exact binding the Flutter plugin ships.
#
# Usage:  bridge/bindings/interop/run.sh
# Requires: a built build/release/libcryptolib_c.{dylib,so}, Go toolchain, Dart SDK.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
GO_DIR="$ROOT/bridge/bindings/go"
DART_DIR="$ROOT/bridge/bindings/dart"
LIBDIR="$ROOT/build/release"

DYLIB="$LIBDIR/libcryptolib_c.dylib"
[ -f "$DYLIB" ] || DYLIB="$LIBDIR/libcryptolib_c.so"
[ -f "$DYLIB" ] || { echo "Native library not found in $LIBDIR. Build it first:"; \
  echo "  cmake -B build/release -DCMAKE_BUILD_TYPE=Release && cmake --build build/release --target cryptolib_c"; exit 1; }

export DYLD_LIBRARY_PATH="$LIBDIR" LD_LIBRARY_PATH="$LIBDIR"

# Compile the Go party once (fast repeated calls); resolve Dart deps quietly.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
GOBIN="$TMP/go-party"
( cd "$GO_DIR" && go build -o "$GOBIN" ./interop )
( cd "$DART_DIR" && dart pub get >/dev/null 2>&1 || true )

go_party()   { "$GOBIN" "$@"; }
dart_party() { ( cd "$DART_DIR" && dart run bin/interop_party.dart "$DYLIB" "$@" ); }

pass=0; fail=0
check() { # <label> <expected> <got>
  if [ "$2" = "$3" ]; then echo "  ✓ $1"; pass=$((pass+1));
  else echo "  ✗ $1"; echo "      expected: $2"; echo "      got:      $3"; fail=$((fail+1)); fi
}

echo "── Identities (each side generates its own X25519 keypair) ──"
read -r PUB_GO   SEC_GO   < <(go_party keygen)
read -r PUB_DART SEC_DART < <(dart_party keygen)
echo "  Go   public key:   ${PUB_GO:0:32}…"
echo "  Dart public key:   ${PUB_DART:0:32}…"
echo "  (public keys are exchanged; secret keys never leave their side)"

echo
echo "── 1) Go ──▶ Flutter  (Go encrypts, Flutter/Dart decrypts) ──"
MSG1="Hello Flutter, this is Go. 🛰️"
CT1="$(go_party enc "$PUB_DART" "$SEC_GO" "$MSG1")"
echo "  Go ciphertext: ${CT1:0:40}…  ($(( ${#CT1} / 2 )) bytes)"
OUT1="$(dart_party dec "$PUB_GO" "$SEC_DART" "$CT1")"
check "Flutter decrypted Go's message" "$MSG1" "$OUT1"

echo
echo "── 2) Flutter ──▶ Go  (Flutter/Dart encrypts, Go decrypts) ──"
MSG2="Hi Go, Flutter here. 📱"
CT2="$(dart_party enc "$PUB_GO" "$SEC_DART" "$MSG2")"
echo "  Dart ciphertext: ${CT2:0:40}…  ($(( ${#CT2} / 2 )) bytes)"
OUT2="$(go_party dec "$PUB_DART" "$SEC_GO" "$CT2")"
check "Go decrypted Flutter's message" "$MSG2" "$OUT2"

echo
echo "── 3) Flutter ◀──▶ Go  (a two-way authenticated conversation) ──"
PING="ping: are you receiving? #42"
CT_PING="$(go_party enc "$PUB_DART" "$SEC_GO" "$PING")"
GOT_PING="$(dart_party dec "$PUB_GO" "$SEC_DART" "$CT_PING")"
check "Flutter received Go's ping" "$PING" "$GOT_PING"
PONG="pong: loud and clear, Go. #42"
CT_PONG="$(dart_party enc "$PUB_GO" "$SEC_DART" "$PONG")"
GOT_PONG="$(go_party dec "$PUB_DART" "$SEC_GO" "$CT_PONG")"
check "Go received Flutter's pong" "$PONG" "$GOT_PONG"

echo
echo "── Negative control: tampering is detected (AEAD) ──"
# Flip the last byte of a valid ciphertext; decryption must fail.
TAMPERED="${CT1:0:$(( ${#CT1} - 2 ))}$(printf '%02x' $(( (0x${CT1: -2} ^ 0xff) )) )"
if dart_party dec "$PUB_GO" "$SEC_DART" "$TAMPERED" >/dev/null 2>&1; then
  echo "  ✗ tampered ciphertext was accepted (unexpected!)"; fail=$((fail+1))
else
  echo "  ✓ tampered ciphertext rejected by Flutter (authentication held)"; pass=$((pass+1))
fi

echo
echo "════════════════════════════════════════════════════"
echo "  INTEROP RESULT: $pass passed, $fail failed"
echo "════════════════════════════════════════════════════"
[ "$fail" -eq 0 ]
