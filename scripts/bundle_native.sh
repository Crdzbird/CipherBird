#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# bundle_native.sh — refresh every binding's BUNDLED native library from a single
# self-contained build, so each package ships a current, self-contained
# libcipherbird_c and installs from its registry with NO C++ source tree and no
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
HDR=bridge/cipherbird_c.h

echo "== building the pinned desktop dylib + merged static archive =="
bash scripts/macos/build_dylib.sh >/dev/null
bash scripts/build_static_archive.sh >/dev/null
DYLIB=build/desktop/libcipherbird_c.dylib
STATIC=build/static/libcipherbird_c.a

# Host platform → the folder names each ecosystem expects.
case "$(uname -s)" in Darwin) OS=darwin; EXT=dylib;; Linux) OS=linux; EXT=so;; *) OS=unknown; EXT=so;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64;; x86_64) ARCH=x64;; *) ARCH="$(uname -m)";; esac
RID="osx-$ARCH"; [ "$OS" = linux ] && RID="linux-$ARCH"

copy() { mkdir -p "$(dirname "$1")"; cp "$2" "$1"; echo "   → ${1#"$ROOT"/}"; }

echo "== refreshing bundled dylibs ($OS-$ARCH) =="
copy "$B/cipherbird-node/prebuilds/$OS-$ARCH/libcipherbird.$EXT"            "$DYLIB"
copy "$B/cipherbird-python/cipherbird/_native/$OS-$ARCH/libcipherbird.$EXT" "$DYLIB"
copy "$B/cipherbird-ruby/lib/cipherbird/native/$OS-$ARCH/libcipherbird.$EXT" "$DYLIB"
copy "$B/cipherbird-rust/native/$OS-$ARCH/libcipherbird.$EXT"             "$DYLIB"
copy "$B/cipherbird-jvm/native/$OS-$ARCH/libcipherbird.$EXT"              "$DYLIB"
copy "$B/cipherbird-dotnet/runtimes/$RID/native/libcipherbird.$EXT"       "$DYLIB"
copy "$B/cipherbird_dart/native/$OS-$ARCH/libcipherbird.$EXT"                       "$DYLIB"  # standalone Dart

# Rust links the bundled library by name at build time, so the copy must carry
# its own file name as its install name (macOS) or soname (Linux).
RUST_LIB="$B/cipherbird-rust/native/$OS-$ARCH/libcipherbird.$EXT"
if [ "$OS" = darwin ]; then
  install_name_tool -id "@rpath/libcipherbird.dylib" "$RUST_LIB"
  codesign --force --sign - "$RUST_LIB" >/dev/null 2>&1
elif command -v patchelf >/dev/null 2>&1; then
  patchelf --set-soname libcipherbird.so "$RUST_LIB"
else
  echo "   patchelf not found: $RUST_LIB keeps the soname libcipherbird_c.so" >&2
fi

echo "== vendoring Go static archive + header (self-contained go get) =="
copy "$B/go/cipherbird/native/libcipherbird.a" "$STATIC"
copy "$B/go/cipherbird/native/cipherbird_c.h"    "$HDR"

# Refresh the macOS slice of any xcframework (Swift SPM / Flutter macOS). iOS and
# Android slices are rebuilt by `make ios` / `make android` (need those SDKs).
if [ "$OS" = darwin ]; then
  echo "== refreshing xcframework macos-$ARCH slices =="
  while IFS= read -r merged; do
    [ -e "$merged" ] || continue
    cp "$STATIC" "$merged"
    find "$(dirname "$merged")" -name cipherbird_c.h -exec cp "$HDR" {} \;
    echo "   → ${merged#"$ROOT"/}"
  done < <(find "$B" -path '*node_modules*' -prune -o -path "*macos-$ARCH/*libcipherbird_c_merged.a" -print 2>/dev/null)
fi

# The JVM package is a JAR (a snapshot), so rebuild it to embed the refreshed
# native/ — otherwise `make bundle` updates the dylib but the JAR stays stale.
if command -v javac >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
  echo "== rebuilding JVM jar (embeds refreshed native/) =="
  ( cd "$B/cipherbird-jvm"
    rm -rf out/jar && mkdir -p out/jar
    javac -d out/jar src/cipherbird/*.java
    cp -R native out/jar/native
    ( cd out/jar && jar --create --file ../../cipherbird-jvm.jar . )
    echo "   → ${B#"$ROOT"/}/cipherbird-jvm.jar" )
fi

echo "== done. Verify a bundle: (cd $B/cipherbird-node && node -e 'require(\"./index.js\").init()')"
echo "   Cross-platform slots are filled by CI / make ios / make android — see PUBLISHING.md."
