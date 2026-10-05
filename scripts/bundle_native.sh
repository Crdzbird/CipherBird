#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# bundle_native.sh — refresh every binding's BUNDLED native library from a single
# self-contained build, so each package ships a current, self-contained
# libcryptolib_c and installs from its registry with NO C++ source tree and no
# build step.
#
# HOST platform only (this machine's OS/arch). The cross-platform matrix
# (Linux/Windows/Android/iOS device) is produced in CI and by `make ios` /
# `make android` — see PUBLISHING.md. Re-run this after any C ABI change.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
B=bridge/bindings
HDR=bridge/cryptolib_c.h

echo "== building self-contained dylib + merged static archive =="
bash scripts/build_selfcontained.sh  >/dev/null
bash scripts/build_static_archive.sh >/dev/null
DYLIB=build/selfcontained/libcryptolib_c.dylib
STATIC=build/static/libcryptolib_c.a

# Host platform → the folder names each ecosystem expects.
case "$(uname -s)" in Darwin) OS=darwin; EXT=dylib;; Linux) OS=linux; EXT=so;; *) OS=unknown; EXT=so;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64;; x86_64) ARCH=x64;; *) ARCH="$(uname -m)";; esac
RID="osx-$ARCH"; [ "$OS" = linux ] && RID="linux-$ARCH"

copy() { mkdir -p "$(dirname "$1")"; cp "$2" "$1"; echo "   → ${1#"$ROOT"/}"; }

echo "== refreshing bundled dylibs ($OS-$ARCH) =="
copy "$B/cryptolib-node/prebuilds/$OS-$ARCH/libcryptolib_c.$EXT"          "$DYLIB"
copy "$B/cryptolib-python/cryptolib/_native/$OS-$ARCH/libcryptolib_c.$EXT" "$DYLIB"
copy "$B/cryptolib-ruby/lib/cryptolib/native/$OS-$ARCH/libcryptolib_c.$EXT" "$DYLIB"
copy "$B/cryptolib-rust/native/$OS-$ARCH/libcryptolib_c.$EXT"             "$DYLIB"
copy "$B/cryptolib-jvm/native/$OS-$ARCH/libcryptolib_c.$EXT"              "$DYLIB"
copy "$B/cryptolib-dotnet/runtimes/$RID/native/libcryptolib_c.$EXT"       "$DYLIB"
copy "$B/cipherbird_dart/native/$OS-$ARCH/libcryptolib_c.$EXT"                       "$DYLIB"  # standalone Dart

echo "== vendoring Go static archive + header (self-contained go get) =="
copy "$B/go/cryptolib/native/libcryptolib_c.a" "$STATIC"
copy "$B/go/cryptolib/native/cryptolib_c.h"    "$HDR"

# Refresh the macOS slice of any xcframework (Swift SPM / Flutter macOS). iOS and
# Android slices are rebuilt by `make ios` / `make android` (need those SDKs).
if [ "$OS" = darwin ]; then
  echo "== refreshing xcframework macos-$ARCH slices =="
  while IFS= read -r merged; do
    [ -e "$merged" ] || continue
    cp "$STATIC" "$merged"
    find "$(dirname "$merged")" -name cryptolib_c.h -exec cp "$HDR" {} \;
    echo "   → ${merged#"$ROOT"/}"
  done < <(find "$B" -path '*node_modules*' -prune -o -path "*macos-$ARCH/*libcryptolib_c_merged.a" -print 2>/dev/null)
fi

# The JVM package is a JAR (a snapshot), so rebuild it to embed the refreshed
# native/ — otherwise `make bundle` updates the dylib but the JAR stays stale.
if command -v javac >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
  echo "== rebuilding JVM jar (embeds refreshed native/) =="
  ( cd "$B/cryptolib-jvm"
    rm -rf out/jar && mkdir -p out/jar
    javac -d out/jar src/cryptolib/*.java
    cp -R native out/jar/native
    ( cd out/jar && jar --create --file ../../cryptolib-jvm.jar . )
    echo "   → ${B#"$ROOT"/}/cryptolib-jvm.jar" )
fi

echo "== done. Verify a bundle: (cd $B/cryptolib-node && node -e 'require(\"./index.js\").init()')"
echo "   Cross-platform slots are filled by CI / make ios / make android — see PUBLISHING.md."
