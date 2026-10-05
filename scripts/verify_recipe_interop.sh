#!/usr/bin/env bash
# Cross-language CryptoRecipe interop: every binding seals a fixed set of
# configurations, and every OTHER binding must open them. This is what makes the
# envelope a library format rather than four look-alike implementations.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DY="$ROOT/build/release/libcryptolib_c.dylib"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0

seal() { # $1 = language, $2 = dir
  case "$1" in
    dart)  (cd bridge/bindings/cipherbird_dart && dart run bin/recipe_interop.dart seal "$2" "$DY") ;;
    go)    (cd bridge/bindings/go && DYLD_LIBRARY_PATH="$ROOT/build/release" go run ./recipeinterop seal "$2") ;;
    node)  (cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB="$DY" node recipe_interop.js seal "$2") ;;
    swift) DYLD_LIBRARY_PATH="$ROOT/build/release" ./build/swift_security seal "$2" ;;
    java)  (cd bridge/bindings/cryptolib-jvm && java --enable-native-access=ALL-UNNAMED -cp out cryptolib.RecipeVerify seal "$2") ;;
    python) (cd bridge/bindings/cryptolib-python && CRYPTOLIB_DYLIB="$DY" python3 tests/test_recipe.py seal "$2") ;;
    ruby)  (cd bridge/bindings/cryptolib-ruby && CRYPTOLIB_DYLIB="$DY" ruby -Ilib test/recipe.rb seal "$2") ;;
    rust)  (cd bridge/bindings/cryptolib-rust && DYLD_LIBRARY_PATH="$ROOT/build/release" cargo run --quiet --example recipe seal "$2") ;;
    dotnet) (cd bridge/bindings/cryptolib-dotnet && dotnet run --no-build -v q -- seal "$2") ;;
  esac
}
open_() {
  case "$1" in
    dart)  (cd bridge/bindings/cipherbird_dart && dart run bin/recipe_interop.dart open "$2" "$DY") ;;
    go)    (cd bridge/bindings/go && DYLD_LIBRARY_PATH="$ROOT/build/release" go run ./recipeinterop open "$2") ;;
    node)  (cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB="$DY" node recipe_interop.js open "$2") ;;
    swift) DYLD_LIBRARY_PATH="$ROOT/build/release" ./build/swift_security open "$2" ;;
    java)  (cd bridge/bindings/cryptolib-jvm && java --enable-native-access=ALL-UNNAMED -cp out cryptolib.RecipeVerify open "$2") ;;
    python) (cd bridge/bindings/cryptolib-python && CRYPTOLIB_DYLIB="$DY" python3 tests/test_recipe.py open "$2") ;;
    ruby)  (cd bridge/bindings/cryptolib-ruby && CRYPTOLIB_DYLIB="$DY" ruby -Ilib test/recipe.rb open "$2") ;;
    rust)  (cd bridge/bindings/cryptolib-rust && DYLD_LIBRARY_PATH="$ROOT/build/release" cargo run --quiet --example recipe open "$2") ;;
    dotnet) (cd bridge/bindings/cryptolib-dotnet && dotnet run --no-build -v q -- open "$2") ;;
  esac
}

LANGS=(dart go node swift java python ruby rust dotnet)
echo "═══ CryptoRecipe cross-language interop ═══"
for s in "${LANGS[@]}"; do
  dir="$WORK/$s"; mkdir -p "$dir"
  if ! seal "$s" "$dir" >/dev/null 2>&1; then
    echo "  ✗ $s failed to seal"; FAIL=$((FAIL+1)); continue
  fi
  for o in "${LANGS[@]}"; do
    [ "$o" = "$s" ] && continue
    out="$(open_ "$o" "$dir" 2>&1)"
    if echo "$out" | grep -q "FAIL"; then
      echo "  ✗ $s → $o"; echo "$out" | grep FAIL | sed 's/^/      /'; FAIL=$((FAIL+1))
    else
      n="$(echo "$out" | grep -c '  ok  ')"
      echo "  ✓ $s → $o  ($n/5 envelopes)"; PASS=$((PASS+1))
    fi
  done
done
echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
