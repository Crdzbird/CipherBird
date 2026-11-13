#!/usr/bin/env bash
# Cross-language SecretStream interop between the Dart and the Go binding:
# each writes a chunked stream to a file with its incremental encryptor and
# each reads the other's (and its own) with its incremental decryptor. A
# reader must report the writer's digest, chunk count and the final tag; a
# stream cut before its last chunk must be reported as not final; a stream
# with one flipped byte must be rejected.
#
#   scripts/verify_stream_interop.sh [chunks]     default 256 (about 16 MiB)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DY="$ROOT/build/release/libcryptolib_c.dylib"
CHUNKS="${1:-256}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0

run() { # $1 = language, then write <file> <chunks> | read <file>
  local lang="$1"; shift
  case "$lang" in
    dart) (cd bridge/bindings/cipherbird_dart && dart run bin/stream_interop.dart "$@" "$DY") ;;
    go)   (cd bridge/bindings/go && DYLD_LIBRARY_PATH="$ROOT/build/release" LD_LIBRARY_PATH="$ROOT/build/release" go run ./streaminterop "$@") ;;
  esac
}
ok()  { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad() { echo "  ✗ $1"; [ -n "${2:-}" ] && echo "      $2"; FAIL=$((FAIL+1)); }

echo "═══ SecretStream cross-language interop ($CHUNKS chunks) ═══"
for w in dart go; do
  file="$WORK/$w.stream"
  wrote="$(run "$w" write "$file" "$CHUNKS" 2>&1 | grep -E '^(digest|FAIL) ' | tail -1)"
  case "$wrote" in digest*final\ true) ;; *) bad "$w failed to write" "$wrote"; continue ;; esac
  size=$(wc -c < "$file" | tr -d ' ')
  for r in dart go; do
    got="$(run "$r" read "$file" 2>&1 | grep -E '^(digest|FAIL) ' | tail -1)"
    if [ "$got" = "$wrote" ]; then ok "$w → $r  ($size bytes, $CHUNKS chunks, final tag seen)"; else bad "$w → $r" "wrote: $wrote | read: $got"; fi
  done
  last=$(( 4 + 32768 + 17 ))
  head -c $(( size - last )) "$file" > "$WORK/$w.cut"
  for r in dart go; do
    got="$(run "$r" read "$WORK/$w.cut" 2>&1 | grep -E '^(digest|FAIL) ' | tail -1)"
    case "$got" in *"chunks $(( CHUNKS - 1 )) final false") ok "$w → $r  truncated stream reported as not final" ;; *) bad "$w → $r truncation" "$got" ;; esac
  done
  python3 - "$file" "$WORK/$w.bad" <<'PY'
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
data[len(data) // 2] ^= 0x01
open(sys.argv[2], 'wb').write(data)
PY
  for r in dart go; do
    got="$(run "$r" read "$WORK/$w.bad" 2>&1 | grep -E '^(digest|FAIL) ' | tail -1)"
    case "$got" in FAIL*rejected*) ok "$w → $r  tampered stream rejected" ;; *) bad "$w → $r tamper" "$got" ;; esac
  done
done
echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
