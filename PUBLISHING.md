# Publishing CryptoLib bindings

This document is the checklist for releasing CryptoLib's language bindings so
that **consumers get the native library bundled and loaded automatically** — no
manual path, no manual library placement.

Each ecosystem's package and its auto-integration mechanism are below, followed
by the cross-cutting prerequisites and the per-registry publish steps you must
run with your own accounts/credentials.

---

## Status

| Ecosystem | Package | How it auto-loads | Local verification |
|---|---|---|---|
| **Flutter** | `bridge/bindings/cryptolib_flutter` | xcframework via podspec (iOS/macOS), `.so` in `jniLibs` (Android); loader picks `process()`/soname | ✅ Pixel 7 + iOS sim |
| **Node** | `bridge/bindings/cryptolib-node` | binary in `prebuilds/<plat>-<arch>/`, resolved relative to package | ✅ `npm test` |
| **JVM** (Java/Kotlin) | `bridge/bindings/cryptolib-jvm` | binary in JAR under `/native/<os>-<arch>/`, extracted to temp + `SymbolLookup` | ✅ `java -jar` |
| **Swift** (SPM) | `bridge/bindings/swift` | `binaryTarget` xcframework (SPM embeds automatically) | ✅ macOS slice links + runs |
| **.NET** | `bridge/bindings/cryptolib-dotnet` | binary under `runtimes/<rid>/native/` (NuGet auto-probes) + `DllImportResolver` | ✅ `dotnet run` |
| **Go** | `bridge/bindings/go` | cgo links at consumer build time — see Go note below | dev build ✅; portable module pending |

All five bundled-binary ecosystems were verified to load the native library and
round-trip the post-quantum hybrid KEM with **no path supplied**.

---

## Cross-cutting prerequisites (do these before any publish)

### 0. Refresh every binding's bundled binary — `make bundle`
The native libraries bundled in each binding are **git-ignored** (binaries don't
belong in git); they are produced on demand and packed by each registry from the
working tree. **Always run this first** so every package ships the *current* C ABI:

```
make bundle        # → scripts/bundle_native.sh
```

It builds one self-contained dylib + one merged static archive and distributes
them to every binding's host slot: npm `prebuilds/`, Python `_native/`, Ruby
`native/`, Rust `native/`, .NET `runtimes/<rid>/native/`, JVM `native/`, the
standalone Dart `native/`, the Go vendored `cryptolib/native/` (archive + header),
and the macOS slice of the Flutter/Swift xcframeworks. Each binding then loads its
**own** bundled library by default — no C++ source tree, no build step:

- **npm** — `package.json` `files` includes `prebuilds/`; the loader resolves
  `prebuilds/<platform>-<arch>/` (CRYPTOLIB_DYLIB overrides for dev).
- **standalone Dart** — a `.pubignore` keeps `native/` in the package; `CryptoLib.load()`
  resolves `native/<os>-<arch>/` automatically.
- **Go** — build with `-tags cryptolib_vendored` to link the module-internal
  `cryptolib/native/libcryptolib_c.a` (+ header). Because `go get` reads the git
  tree, the per-platform archives must be **committed on the release tag** (they
  are ignored on `main`); run `make bundle` then force-add them when tagging.

`make bundle` is host-arch only; CI / `make ios` / `make android` fill the
cross-platform matrix (§2).

### 1. Self-contained binaries
The bundled binary must statically link every dependency (libsodium, liboqs,
blst, OpenSSL, BLAKE3) so it runs on a machine without them installed.

- iOS / macOS xcframework and Android `.so` are self-contained (merged static
  archive / merged `.so`).
- **macOS desktop: done.** `scripts/build_selfcontained.sh` static-links every
  dep (building `libblake3.a` from the vendored source) into a dylib whose only
  dependencies are `/usr/lib/libc++` and `/usr/lib/libSystem`:
  ```
  bash scripts/build_selfcontained.sh
  otool -L build/selfcontained/libcryptolib_c.dylib   # → only /usr/lib/*
  ```
  This is the binary the npm / JVM / .NET bundles now ship (verified: all three
  package smokes pass against it, and `SHA256SUMS` shows they are byte-identical).
- **Linux/Windows desktop:** apply the same static-link approach on those
  runners (CI) — tracked in §2 of the prerequisites below.

### 2. Cross-arch / cross-OS prebuilt matrix (needs CI)
Each package currently ships only the host slice (`darwin-arm64`). Publishing
requires building every target on CI runners:
`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win-x64`
(and `armeabi-v7a` for Android if 32-bit devices are targeted).

### 3. iOS universal simulator slice
The xcframework ships an **arm64-only** iOS-simulator slice. Real arm64
sims/devices work; a generic `flutter build ios --simulator` (which also wants
x86_64) needs either a universal sim slice (arm64+x86_64 lipo) or a consumer
`post_install` `EXCLUDED_ARCHS[sdk=iphonesimulator*] = x86_64` (see the plugin
README).

---

## Per-registry publish steps (require YOUR accounts)

> These are deliberately left for you to run — publishing is irreversible and
> needs registry credentials this repo does not (and should not) hold.

- **pub.dev (Flutter):** set `homepage`/`repository` + a real `LICENSE`, then
  `cd bridge/bindings/cryptolib_flutter && flutter pub publish`. Requires a
  pub.dev account linked to your Google identity.
- **npm:** `cd bridge/bindings/cryptolib-node && npm publish --access public`.
  Requires `npm login`. Consider scoping as `@yourorg/cryptolib`.
- **Maven Central (JVM):** wrap `cryptolib-jvm` in a Gradle/Maven build, then
  publish to Sonatype Central with GPG-signed artifacts (`./gradlew publish`).
  Requires a Sonatype namespace + signing key.
- **Swift Package Manager:** SPM consumes from git — tag a release
  (`git tag 3.0.0 && git push --tags`). For a standalone distribution, host the
  xcframework as a release asset and switch the manifest to
  `.binaryTarget(url:checksum:)` (compute with `swift package compute-checksum`).
- **NuGet (.NET):** `cd bridge/bindings/cryptolib-dotnet && dotnet pack -c Release`
  then `dotnet nuget push bin/Release/CryptoLib.3.0.0.nupkg -k <API_KEY> -s https://api.nuget.org/v3/index.json`.
- **Go:** tag the module (`git tag bridge/bindings/go/v3.0.0`). See note below —
  Go needs the native code available at the consumer's build time.

## Supply-chain integrity (signing, SBOM, provenance)

`.github/workflows/release.yml` runs on a `v*` tag and:
1. builds the self-contained artifacts (`scripts/build_selfcontained.sh`),
2. writes `SHA256SUMS` (`scripts/release/checksums.sh` — runnable locally too),
3. generates an SPDX SBOM (syft / `anchore/sbom-action`),
4. **keyless-signs** the checksums with cosign (Sigstore OIDC → `SHA256SUMS.sig` + `.pem`),
5. emits **SLSA build provenance** (`slsa-github-generator`) for the artifacts.

Consumers verify with:
```
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
slsa-verifier verify-artifact <artifact> --provenance-path <prov> --source-uri github.com/<org>/cryptolib
```
Requires the repo on GitHub with `id-token: write` (keyless signing + provenance).
Reproducible builds: pin the toolchain and set `SOURCE_DATE_EPOCH`; note macOS
Mach-O carries a per-link UUID, so bit-identical reproducibility is easier on the
Linux artifacts.

---

## Go note

Go's cgo links the native code at the **consumer's** `go build`, so a published
module must carry what the build needs. Two options:

1. **Vendor a self-contained static archive + header per platform** and select
   it with cgo build tags:
   ```go
   /*
   #cgo CFLAGS: -I${SRCDIR}/include
   #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/lib/darwin_arm64/libcryptolib_c_merged.a -lc++ -framework Security
   #cgo linux,amd64  LDFLAGS: ${SRCDIR}/lib/linux_amd64/libcryptolib_c.a
   #include "cryptolib_c.h"
   */
   import "C"
   ```
   The merged static archives already produced for iOS/macOS
   (`CryptoLib.xcframework/macos-arm64/libcryptolib_c_merged.a`) are exactly the
   self-contained inputs this needs; the same must be produced per Go target on CI.
2. **Require a system install** of `libcryptolib_c` + headers (Homebrew/apt) and
   link via `pkg-config`. Simpler module, heavier consumer setup.

The current `bridge/bindings/go` binding uses a local build path (option for
development); switch it to vendored static archives (option 1) before tagging a
public module.
