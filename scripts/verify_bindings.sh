#!/usr/bin/env bash
# Run every host-language binding demo and assert it produced CORRECT data
# (not just that it compiled): SHA-256("abc") must match the known answer, the
# keyring device+passphrase slots must recover the SAME master key, and each
# demo must reach its success line. Exits non-zero if any binding fails.
#
# Usage: scripts/verify_bindings.sh   (run from anywhere; it cd's to repo root)

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SHA="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
KR='device==passphrase'   # demos print "device==passphrase[ master]: true"
DY="$ROOT/build/release/libcryptolib_c.dylib"
PASS=0; FAIL=0; SKIP=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
no(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); echo "${2:-}" | tail -6; }
sk(){ echo "  ⏭  $1 (toolchain missing)"; SKIP=$((SKIP+1)); }
# pass if output has the sha256 KAT and a successful keyring round-trip
chk(){ echo "$2" | grep -qF "$SHA" && echo "$2" | grep -qE "$KR.*true"; }

echo "═══ Building C library (Release) ═══"
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCRYPTOLIB_BUILD_TESTS=OFF >/dev/null
cmake --build build/release --target cryptolib_c >/dev/null
[ -f "$DY" ] || { echo "FATAL: $DY not built"; exit 2; }

echo "═══ C ABI (incl. keyring) ═══"
cc bridge/bindings/c/demo.c -Ibridge -L build/release -lcryptolib_c -Wl,-rpath,"$ROOT/build/release" -o build/c_demo 2>/dev/null \
  && o="$(build/c_demo 2>&1)" && echo "$o" | grep -qF "$SHA" && echo "$o" | grep -qF "device==passphrase master: yes" && ok "c-abi" || no "c-abi" "$o"

echo "═══ C++ examples ═══"
o="$(./build/release/cryptolib_poc 2>&1)"; echo "$o" | grep -qiF "All tests passed" && ok "cpp/poc" || no "cpp/poc" "$o"

echo "═══ Go ═══"
if command -v go >/dev/null 2>&1; then
  o="$(cd bridge/bindings/go && DYLD_LIBRARY_PATH="$ROOT/build/release" go run ./example 2>&1)"
  # The Go example hashes its own message (not "abc"); assert completion + keyring.
  echo "$o" | grep -qF "Done." && echo "$o" | grep -qE "$KR.*true" && ok "go" || no "go" "$o"
else sk go; fi

echo "═══ Swift ═══"
if command -v swiftc >/dev/null 2>&1; then
  swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/main.swift -L build/release -lcryptolib_c -Xlinker -rpath -Xlinker "$ROOT/build/release" -o build/swift_demo 2>/dev/null \
    && o="$(build/swift_demo 2>&1)" && chk swift "$o" && ok "swift" || no "swift" "$o"
else sk swift; fi

echo "═══ Java ═══"
if command -v javac >/dev/null 2>&1; then
  o="$(cd bridge/bindings/java && javac CryptoLibDemo.java 2>/dev/null && java --enable-native-access=ALL-UNNAMED CryptoLibDemo "$DY" 2>&1)"
  chk java "$o" && ok "java" || no "java" "$o"
else sk java; fi

echo "═══ Kotlin ═══"
if command -v kotlinc >/dev/null 2>&1; then
  o="$(cd bridge/bindings/kotlin && kotlinc CryptoLibDemo.kt -include-runtime -d demo.jar 2>/dev/null && java --enable-native-access=ALL-UNNAMED -jar demo.jar "$DY" 2>&1)"
  chk kotlin "$o" && ok "kotlin" || no "kotlin" "$o"
else sk kotlin; fi

echo "═══ Dart ═══"
if command -v dart >/dev/null 2>&1; then
  o="$(cd bridge/bindings/dart && (dart pub get --offline >/dev/null 2>&1 || dart pub get >/dev/null 2>&1); dart run bin/demo.dart "$DY" 2>&1)"
  chk dart "$o" && ok "dart" || no "dart" "$o"
else sk dart; fi

echo "═══ Node ═══"
if command -v node >/dev/null 2>&1; then
  o="$(cd bridge/bindings/node && { [ -d node_modules/koffi ] || npm install >/dev/null 2>&1; }; node demo.js "$DY" 2>&1)"
  chk node "$o" && ok "node" || no "node" "$o"
else sk node; fi

echo "═══ React (Node+koffi server) ═══"
if command -v node >/dev/null 2>&1; then
  (cd bridge/bindings/react && [ -d node_modules ] || npm install >/dev/null 2>&1)
  lsof -ti tcp:8787 2>/dev/null | xargs kill -9 2>/dev/null; sleep 0.3
  CRYPTOLIB_DYLIB="$DY" node bridge/bindings/react/server.mjs >/tmp/cl_srv.log 2>&1 &
  sleep 1.5
  s="$(curl -s -XPOST -H 'Content-Type: application/json' -d '{"text":"abc"}' localhost:8787/api/sha256 2>/dev/null)"
  k="$(curl -s -XPOST localhost:8787/api/keyring 2>/dev/null)"
  lsof -ti tcp:8787 2>/dev/null | xargs kill -9 2>/dev/null
  echo "$s" | grep -qF "$SHA" && echo "$k" | grep -qF '"sameMaster":true' && ok "react/server" || no "react/server" "$s $k"
else sk react; fi

echo "═══ Flutter (flutter test — real FFI) ═══"
if command -v flutter >/dev/null 2>&1; then
  o="$(cd bridge/bindings/flutter && flutter pub get >/dev/null 2>&1; flutter test test/ffi_test.dart 2>&1)"
  echo "$o" | grep -qF "All tests passed" && ok "flutter/ffi_test" || no "flutter/ffi_test" "$o"
else sk flutter; fi

echo ""
echo "═══════════════════════════════════════════"
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════════"
[ $FAIL -eq 0 ]
