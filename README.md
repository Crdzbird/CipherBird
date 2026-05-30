# CryptoLib

> A C++20 cryptography library covering classical, post-quantum, and hybrid
> primitives behind a single C ABI — usable from Flutter, Node, JVM, Swift,
> .NET, and Go via auto-loading language packages.

Single include on the C++ side. Five language packages bundle the native
binary and load it automatically — no manual path, no manual setup. Built on
vetted upstreams (libsodium, liboqs, blst, OpenSSL libcrypto, BLAKE3) and
wrapped in misuse-resistant high-level constructions (Vault, Keyring, hybrid
KEM/signatures, committing AEAD, Noise XX).

```cpp
#include <cryptolib/cryptolib.hpp>
```

---

## Capabilities

| Layer | What it does | Primitives |
|---|---|---|
| **Hash / KDF** | Hashes, password hashing, HKDF, HMAC | BLAKE2b, BLAKE3, SHA-256/512, HMAC-256/512, HKDF-256, Argon2id |
| **AEAD** | Authenticated encryption | XChaCha20-Poly1305, AES-256-GCM, SecretStream |
| **AEAD (hardened)** | Key/context **committing** AEAD (closes Invisible-Salamanders / partitioning-oracle), **nonce-misuse-resistant** AEAD | UtC CommittingAead (HKDF + XChaCha20-Poly1305), AES-256-GCM-SIV (RFC 8452) |
| **Asymmetric** | Key exchange, signing, sealed/hybrid boxes | X25519, Ed25519, Box, SealedBox, HybridBox |
| **Post-quantum** | NIST FIPS 203/204/205 | ML-KEM (512/768/1024), ML-DSA (44/65/87), SLH-DSA (128/192/256, SHA2 + SHAKE) |
| **Hybrid PQC** | Classical + post-quantum, secure if EITHER survives | X25519 + ML-KEM-768 (KEM), Ed25519 + ML-DSA-65 (signatures) |
| **Secure channel** | Mutual auth + forward secrecy | Noise XX (`Noise_XX_25519_ChaChaPoly_SHA256`) — vector-validated byte-exact vs `noise-c` |
| **BLS12-381** | Sign / verify / aggregate | via blst |
| **High-level** | Vault (KDF → integrity → AEAD → signature), Keyring (envelope encryption with device + passphrase slots, rotation, anti-downgrade), Shamir M-of-N secret sharing |  |
| **Defense-in-depth** | Steganography (DCT/QIM, phase coding) and LavaRand-style media entropy — framed as novelty / defense-in-depth, not as confidentiality primitives | PPM / BMP / PNG / GIF / JPEG / WAV / FLAC / MP3 / MP4 / AVI / CRVF |

---

## Production posture

| Discipline | Status |
|---|---|
| Test suite | **289 / 289 passing** (custom zero-dependency runner) |
| Memory safety | **AddressSanitizer + UBSan clean**, all suites |
| Concurrency | **ThreadSanitizer clean** (multithreaded stress test) |
| Differential fuzzing | libFuzzer harness in CI; wrapper ⟷ raw libsodium byte-equality |
| Constant-time | `ctgrind`/Valgrind probe over `secure_equal`, AEAD, KEM decaps, keyring unlock (Linux CI) |
| Known-answer tests | RFC/FIPS vectors for the underlying primitives; **byte-exact KAT for Noise XX vs the official `noise-c` vector** |
| Secrets in memory | `SecureBuffer` with `sodium_mlock`/`sodium_munlock`; zeroization audited (see threat model §8) |
| C-ABI boundary | Exception isolation, indistinguishable error returns (no oracle), bounds-checked length math |
| Language coverage | 10 bindings verified end-to-end by running, not just compiling |
| Self-contained binary | macOS desktop dylib depends only on `/usr/lib/libSystem` + `libc++` — bundled in the npm / JVM / .NET packages |
| Release pipeline | SBOM (syft) + keyless cosign signing + SLSA provenance (CI on `v*` tag) |

The full threat model — assets, AI-assisted adversary, security arguments for
the original compositions (Vault, Keyring, hybrid KEM combiner, committing
AEAD), zeroization audit — lives in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**Pending before regulated production:** an external audit of the original
compositions, and FIPS 140-3 validation if your deployment requires it. The
primitives themselves come from vetted upstreams.

> **Standard warranty disclaimer applies.** The software is provided **as is**,
> without warranty of any kind. Cryptography is high-stakes; deployments are
> the operator's responsibility. See the LICENSE for the full disclaimer.

---

## License — MIT

This project is licensed under the [MIT License](LICENSE).

You're free to **use, modify, distribute, and build commercial products on top
of it**. The only requirement is to **preserve the copyright notice** and
credit the author. That's it.

The standard MIT warranty disclaimer applies — provided "as is", no warranty.
Cryptography is high-stakes; deployments are the operator's responsibility.

---

## Multi-language usage — step by step

The C++ library is exposed through a single C ABI (`bridge/cryptolib_c.h`),
and every supported language ships an auto-loading package that bundles the
native binary. Consumers add the dependency and call the API — no path
configuration, no manual `.so`/`.dylib` placement.

Each example below shows the **minimum to round-trip the post-quantum hybrid
KEM** (X25519 + ML-KEM-768), which exercises FFI marshaling, struct returns,
and out-error handling end-to-end.

> Replace `<org>` with the actual package coordinate when published. Until
> publication, use the local paths shown for in-repo evaluation.

### Flutter (Dart + native FFI)

1. **Add the plugin.** In your app's `pubspec.yaml`:
   ```yaml
   dependencies:
     cryptolib_flutter:
       # After publication on pub.dev: cryptolib_flutter: ^3.0.0
       # During evaluation, depend on the path:
       path: ../path/to/bridge/bindings/cryptolib_flutter
   ```
2. **Get dependencies.** `flutter pub get`.
3. **Import + call.** The loader picks `DynamicLibrary.process()` on iOS, the
   bundled `.so` on Android, and the system `.dylib` on macOS automatically.
   ```dart
   import 'package:cryptolib_flutter/cryptolib_flutter.dart';

   void main() {
     final lib = CryptoLib.load();
     lib.init();
     final kp  = lib.hybridKemKeygen();
     final (ct, ss) = lib.hybridKemEncapsulate(kp.publicKey);
     final ss2 = lib.hybridKemDecapsulate(ct, kp.secretKey);
     assert(ss.length == 32);
     // ss and ss2 are equal — both parties hold the same shared secret.
   }
   ```
4. **Build for your platform.** `flutter build apk` / `flutter build ios --simulator`.

### Node.js (npm)

1. **Install.** Once published: `npm install cryptolib`. From source:
   `cd bridge/bindings/cryptolib-node && npm install`.
2. **Use.** The loader resolves the bundled binary from
   `prebuilds/<platform>-<arch>/` automatically.
   ```js
   const crypto = require('cryptolib');
   crypto.init();
   console.log('version:', crypto.version());                              // 3.0.0
   const kp = crypto.hybridKemKeygen();
   const { ciphertext, sharedSecret } = crypto.hybridKemEncapsulate(kp.publicKey);
   const ssDec = crypto.hybridKemDecapsulate(ciphertext, kp.secretKey);
   console.log('match:', sharedSecret.equals(ssDec), 'ss bytes:', sharedSecret.length);
   ```
3. **Run.** `node your_script.js`. No `LD_LIBRARY_PATH`, no `--dlopen`.

### JVM (Java / Kotlin)

JDK 22+ (uses the Foreign Function & Memory API). The JAR embeds the native
library and extracts it at startup.

1. **Build the JAR** (from source, until Maven Central publication):
   ```bash
   cd bridge/bindings/cryptolib-jvm
   javac -d out src/cryptolib/*.java
   mkdir -p out/native && cp -R native/* out/native/
   jar cfe cryptolib-jvm.jar cryptolib.Main -C out .
   ```
2. **Add it to your project** and call:
   ```java
   try (var c = new cryptolib.CryptoLib()) {
       c.init();
       System.out.println(c.version());                                    // 3.0.0
       var kp  = c.hybridKemKeygen();
       var enc = c.hybridKemEncapsulate(kp.publicKey());
       byte[] dec = c.hybridKemDecapsulate(enc.ciphertext(), kp.secretKey());
       assert java.util.Arrays.equals(enc.sharedSecret(), dec);
   }
   ```
3. **Run.** `java --enable-native-access=ALL-UNNAMED -jar cryptolib-jvm.jar`.

### Swift (Swift Package Manager)

1. **Add the package.** In your app's `Package.swift`:
   ```swift
   dependencies: [
     .package(path: "../path/to/bridge/bindings/swift"),
     // After tagging a release with a hosted xcframework:
     // .package(url: "https://github.com/<org>/cryptolib", from: "3.0.0"),
   ],
   targets: [
     .target(name: "YourApp", dependencies: [
       .product(name: "CryptoLibC", package: "CryptoLib"),
     ]),
   ]
   ```
2. **Build.** SPM embeds the `binaryTarget` xcframework automatically — no
   `pod install`, no manual Xcode steps.
3. **Use.**
   ```swift
   import CryptoLibC
   guard cryptolib_init() == 0 else { exit(1) }
   let v = String(cString: cryptolib_version())                            // "3.0.0"
   let kp = cryptolib_hybrid_kem_keygen()
   var err: UnsafeMutablePointer<CChar>? = nil
   let enc = cryptolib_hybrid_kem_encapsulate(kp.public_key.data, kp.public_key.len, &err)
   // ... decapsulate, compare
   ```

### .NET (NuGet)

1. **Add the package** (once published on NuGet): `dotnet add package CryptoLib`.
   From source: `cd bridge/bindings/cryptolib-dotnet && dotnet pack -c Release`,
   then add the produced `.nupkg`.
2. **Use.** The runtime auto-resolves the native binary from
   `runtimes/<rid>/native/`.
   ```csharp
   using CryptoLibNet;
   CryptoLib.Init();
   Console.WriteLine(CryptoLib.Version());                                 // 3.0.0
   var (pub, sec) = CryptoLib.HybridKemKeygen();
   var (ct, ss)   = CryptoLib.HybridKemEncapsulate(pub);
   var ssDec      = CryptoLib.HybridKemDecapsulate(ct, sec);
   ```
3. **Run.** `dotnet run -c Release`.

### Go (cgo)

Go links the native code at the consumer's build time. The current binding
links against a locally-built dylib; for portable distribution, use the
vendored merged static archive (see `PUBLISHING.md`).

1. **Build the native library** (one-time): `make lib` (produces
   `build/release/libcryptolib_c.dylib`).
2. **Run the example:**
   ```bash
   cd bridge/bindings/go
   DYLD_LIBRARY_PATH=$PWD/../../../build/release go run ./showcase
   ```
3. **Use from your code:**
   ```go
   import "cryptolib_bridge/cryptolib"

   func main() {
       if err := cryptolib.Init(); err != nil { panic(err) }
       kp := cryptolib.HybridKemKeygen()
       enc, _ := cryptolib.HybridKemEncapsulate(kp.Public)
       dec, _ := cryptolib.HybridKemDecapsulate(enc.Ciphertext, kp.Secret)
       _ = enc.SharedSecret  // == dec
   }
   ```

---

## Building from source (C++ + C ABI)

```bash
# Native dependencies (macOS)
brew install cmake ninja libsodium liboqs blake3 openssl@3

# Build + run the C++ test suite (289 cases, ASan-clean)
cmake -S . -B build/test -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCRYPTOLIB_BUILD_TESTS=ON -DCRYPTOLIB_BUILD_BRIDGE=OFF
cmake --build build/test --target cryptolib_tests
./build/test/cryptolib_tests

# Build the shared C library used by every binding
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cryptolib_c

# Or, for a self-contained desktop binary (no Homebrew deps at runtime)
bash scripts/build_selfcontained.sh
```

See [`PUBLISHING.md`](PUBLISHING.md) for cross-platform packaging notes (npm,
JVM, Swift, .NET, Go), the supply-chain pipeline (cosign / SBOM / SLSA), and
the publish checklist.

---

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversary model, security
  arguments for original constructions, zeroization audit, assurance posture
- [`PUBLISHING.md`](PUBLISHING.md) — per-ecosystem packaging + release pipeline
- `bridge/cryptolib_c.h` — the C ABI surface every binding marshals over

---

## Contributing

Issues and pull requests welcome. **Do not file vulnerabilities as public
issues** — email the security contact in `SECURITY.md` (or open a private
report via GitHub Security Advisories). Before submitting code, please ensure
the test suite still runs clean (`./build/test/cryptolib_tests`) and that
`scripts/verify_bindings.sh` stays green across all 10 bindings.
