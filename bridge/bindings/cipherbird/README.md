# cipherbird

Native cryptography for Flutter. CipherBird binds its native C++ engine
through `dart:ffi` and ships the compiled library inside the package, so an
app gets hashing, authenticated encryption, public-key cryptography,
post-quantum algorithms, hybrid key agreement, sealed messaging, a secure
channel, password hashing, vaults, a keyring, anonymous credentials,
threshold signatures and steganography from one dependency, with no platform
channels and no setup. The Dart API carries the package name: `CipherBird`, `CipherBirdRecipe`, `CipherBirdRunner`.

| Area | What runs | Notes |
|---|---|---|
| Hashing | SHA-256, SHA-512, BLAKE2b, BLAKE3, Keccak-256 | HMAC, HKDF, incremental BLAKE3 |
| Passwords | Argon2id | PHC strings, derive keys, three cost profiles |
| Symmetric | XChaCha20-Poly1305, AES-256-GCM, key-committing AEAD, SecretStream | the committing mode is the default in easy mode |
| Public key | X25519, Ed25519, boxes, sealed boxes, secp256k1 | EVM addresses and recovery |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, sntrup761 | FIPS 203, 204 and 205 through liboqs |
| Hybrid | X25519 plus ML-KEM-768, Ed25519 plus ML-DSA-65, X25519 plus sntrup761 | secure if either half holds |
| Protocols | sealed messaging, Noise XX, HPKE, OPAQUE, OPRF, BBS, FROST, ECVRF, BLS, session ratchet | composition of the primitives above |
| Storage | vaults, MolecularVault, keyring with device and passphrase slots | |
| Media | media entropy, DRBG, Fortuna, steganography, forward error correction | |

Supported platforms: Android, iOS and macOS. The same code is published for
plain Dart as [cipherbird_dart](https://pub.dev/packages/cipherbird_dart) for
servers, command-line tools and desktop programs; both packages are generated
from one source tree and expose the same API.

## Flutter or Dart?

`cipherbird` is the Flutter package. Use it in a Flutter app: it carries the
compiled engine for every mobile and desktop target the app can run on and
plugs it into Flutter's build through Swift Package Manager and `jniLibs`.
It is optional everywhere else. A server, a command-line tool or a plain Dart
desktop program should depend on
[cipherbird_dart](https://pub.dev/packages/cipherbird_dart) instead, which
has no Flutter dependency. The two expose the same classes and methods and
run the same test suite; they differ only in how the engine reaches the
program.

| | cipherbird | cipherbird_dart |
|---|---|---|
| Depends on | Flutter SDK, `ffi` | `ffi` only |
| Engine binaries | bundled per platform: Android arm64-v8a and x86_64, iOS device and simulator, macOS | bundled for the host under `native/<os>-<arch>/`, macOS on Apple silicon in this release |
| How the engine is found | the process image on iOS and macOS, `libcipherbird.so` from `jniLibs` on Android | the package's `native/` directory, located through the program's package configuration |
| Startup | `await CipherBird.preload()` before `runApp`, or lazy on first use | lazy on first use, `preload` optional |
| Build integration | Flutter's plugin tooling, nothing to configure | none needed; `dart run`, `dart test` and `dart compile exe` (pass the library path) |
| Download size | about 28 MB | about 5 MB |
| API, wire formats, tests | identical | identical |

## Install

```bash
flutter pub add cipherbird
```

Nothing else is required. The native library is vendored per platform: a
dynamic `CipherBird` framework through Swift Package Manager on iOS and
macOS, and `libcipherbird.so` under `jniLibs` on Android. libsodium,
liboqs, OpenSSL libcrypto, blst, secp256k1 and BLAKE3 are linked into it
statically, so no system library is needed.

| Platform | Minimum |
|---|---|
| Android | API 24, arm64-v8a and x86_64 |
| iOS | 15.0, arm64 device and arm64 simulator |
| macOS | 12.0, Apple silicon, Swift Package Manager |

Call `CipherBird.preload()` once at startup. It loads and initialises the
library on a background isolate; every later call is synchronous:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CipherBird.preload();
  runApp(const MyApp());
}
```

Skipping `preload` is allowed: the first use of `CipherBird.instance` does the
same work synchronously.

## Quick start

```dart
import 'package:cipherbird/cipherbird.dart';

final key = SymmetricKey.generate();
final box = key.encryptText('meet at dawn');
final back = key.decryptText(box);

final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
final signature = signer.signText('release 1.0.0');
final valid = signer.verifyKey.verifyText('release 1.0.0', signature);

final me = KemKeyPair.generate();
final blob = KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
final plain = me.decryptText(blob);
```

The easy-mode classes make the safe choice for you: the key-committing AEAD,
Argon2id for passphrases, HKDF for sub-keys and the post-quantum hybrid
signature. To stretch a passphrase into a key:

```dart
final salt = CipherBird.instance.easy.randomBytes(16);
final key = SymmetricKey.fromPassphrase('correct horse battery staple', salt: salt);
final databaseKey = key.derive('database');
```

Store the salt next to the data; it is not secret. The same passphrase and
salt always give the same key.

## Easy mode

Every class exposes its raw bytes and can be rebuilt from them, so moving
between the easy classes and the full API costs nothing.

| Class | Create | Use | Underneath |
|---|---|---|---|
| `SymmetricKey` | `generate()`, `fromBytes`, `fromHex`, `fromBase64`, `fromPassphrase(salt:)` | `encrypt`, `decrypt`, `encryptText`, `decryptText`, `derive(purpose)`, `asKeySource`, `destroy()` | key-committing AEAD, HKDF-SHA256, Argon2id |
| `SigningKey` | `generate(algorithm:)`, `fromBytes` | `sign`, `signText`, `verifyKey`, `scheme` | Ed25519, or Ed25519 plus ML-DSA-65 |
| `VerifyKey` | `fromBytes`, `fromHex` | `verify`, `verifyText`, `scheme` | |
| `KemKeyPair` | `generate()`, `fromBytes` | `encapsulate`, `decapsulate`, `encryptFor`, `decrypt`, `encryptTextFor`, `decryptText` | X25519 plus ML-KEM-768, HKDF, committing AEAD |
| `Identity` | `lib.easy.identity(tier)` | `sealText`, `openText`, `seal`, `open`, streaming sealers and openers | Flagship or Fortress sealed messaging |

`lib.easy` holds the factories plus the small utilities every app needs:

| Utility | Returns |
|---|---|
| `hashPassword(password)` | an Argon2id PHC string to store |
| `verifyPassword(password, phc)` | whether the password matches |
| `randomBytes(n)`, `randomHex(n)` | bytes from the OS CSPRNG |
| `token()` | a URL-safe random token with 32 bytes of entropy |
| `sha256Hex(text)` | the digest as hex |
| `symmetricKeyFromPassphraseAsync`, `hashPasswordAsync`, `verifyPasswordAsync` | the Argon2id operations on a worker |

Strings and bytes convert in place:

| Expression | Result |
|---|---|
| `'text'.bytes` | UTF-8 bytes |
| `'ab12'.hexBytes`, `'aGk='.base64Bytes` | decoded bytes |
| `bytes.hex`, `bytes.base64`, `bytes.base64Url`, `bytes.text` | encoded strings |
| `bytes.constantTimeEquals(other)` | comparison that does not leak the first mismatch |
| `bytes.concat(other)`, `bytes.wipe()`, `list.u8` | join, zero, convert |

## Full API

All 265 native operations are reachable on `CipherBird`, flat or through
grouped views that keep autocomplete usable. Every operation takes and
returns `Uint8List`, throws on failure and never returns partial data.

```dart
final lib = CipherBird.instance;
final digest = lib.hash.sha256('abc'.bytes);
final pair = lib.pq.hybridKem.keygen();
final (ciphertext, shared) = lib.pq.hybridKem.encapsulate(pair.publicKey);
final opened = lib.pq.hybridKem.decapsulate(ciphertext, pair.secretKey);
```

| Group | Operations |
|---|---|
| `lib.hash` | SHA-256, SHA-512, BLAKE2b, BLAKE3 hash, keyed, derive key and incremental hasher, HMAC with constant-time verify, HKDF extract, expand and derive, Argon2id hash, verify and derive |
| `lib.aead` | XChaCha20-Poly1305, AES-256-GCM, committing AEAD, SecretStream, key generation |
| `lib.asym` | Ed25519 keys, sign, verify; X25519; boxes and sealed boxes |
| `lib.pq` | `mlKem`, `mlDsa`, `slhDsa`, `hybridKem`, `hybridSig`, `sntrup` |
| `lib.sealed` | identities, seal, open, streaming, envelope inspection, recipient matching |
| `lib.channel` | Noise XX handshake and transport with re-entrant decryption by counter |
| `lib.session` | post-quantum forward-secret session ratchet |
| `lib.hpke` | HPKE in all four modes, single-shot and context forms |
| `lib.opaque`, `lib.oprf` | OPAQUE password login and the OPRF it builds on |
| `lib.bbs` | BBS signatures, selective disclosure, pseudonyms, blind issuance |
| `lib.frost`, `lib.ecvrf`, `lib.bls` | threshold Ed25519, verifiable random function, BLS12-381 |
| `lib.vault`, `lib.keyring` | symmetric and asymmetric vaults, MolecularVault, keyrings |
| `lib.suite`, `lib.composed` | one-call combinations: post-quantum messages, threshold vaults, file-as-key vaults, physical-media seals, HPKE into a carrier |
| `lib.entropy`, `lib.stego`, `lib.rng` | media entropy and health, DRBG, Fortuna, steganography, forward error correction |
| `lib.chain` | Keccak-256, secp256k1 sign and recover, EVM addresses |

## Profiles and recipes

`SecurityProfile` moves every parameter together so a maximal KEM is never
paired with an interactive KDF.

| Profile | KEM | Signature | Sealed tier | AEAD cascade | Argon2id |
|---|---|---|---|---|---|
| `balanced` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305 | 2 passes, 64 MiB |
| `high` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305, AES-256-GCM | 3 passes, 256 MiB |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | Fortress | XChaCha20-Poly1305, AES-256-GCM, key-committing | 4 passes, 512 MiB |

`CipherBirdRecipe` composes a key source, the cascade, an optional signature,
optional forward error correction and an optional steganographic carrier into
one self-describing envelope:

```dart
final recipe = lib
    .maximumSecurity()
    .withPassphrase('correct horse battery staple')
    .signedBy(identity.secretKey, algorithm: SignatureAlgorithm.hybrid)
    .verifiedBy(identity.publicKey);
final envelope = recipe.seal(secret);
final back = recipe.open(envelope);
```

| Method | Effect |
|---|---|
| `withKey`, `withPassphrase`, `withKeyFile`, `withKeySource` | where the 32-byte root key comes from |
| `withLayers`, `addLayer` | the AEAD cascade, innermost first |
| `signedBy`, `verifiedBy`, `signedWith`, `verifiedWith` | sign the plaintext before encryption |
| `withFec` | repetition or Hamming error correction on the envelope |
| `argon2Cost` | override the passphrase stretching cost |
| `seal`, `open`, `sealIntoCarrier`, `openFromCarrier`, `describe` | run it, or print the configuration for review |

Whatever the configuration, each layer gets its own HKDF-derived key, the
header is authenticated by every layer, the order sign, encrypt, correct,
conceal is fixed, and any failure throws before data is returned.

## Bring your own parts

Three bases can be subclassed, and the built-ins subclass the same ones.

| Base | Built-ins | Register |
|---|---|---|
| `ProtectionLayer` | `xchacha20Poly1305`, `aes256Gcm`, `committing`, `molecular` | `ProtectionLayer.register(layer)` on both sides |
| `CascadeLayer` | | subclass it to mix several layers, built-in or custom, into one; cascades nest |
| `KeySource` | `RawKeySource`, `PassphraseKeySource`, `KeyFileSource` | `recipe.withKeySource(source)` |
| `SignatureScheme` | `Ed25519Signature`, `HybridSignature` | `recipe.signedWith(scheme)`, `recipe.verifiedWith(scheme)` |

```dart
final class BeltAndBraces extends CascadeLayer {
  const BeltAndBraces()
      : super(id: 201, wireName: 'belt-and-braces', layers: const [
          ProtectionLayer.xchacha20Poly1305,
          ProtectionLayer.aes256Gcm,
          ProtectionLayer.committing,
        ]);
}
```

Ids 0 to 127 are reserved and enforced, a key source must return exactly 32
bytes, a layer never chooses its own key, and the wire name feeds the key
derivation, so a mismatched implementation fails the authentication tag
instead of producing garbage.

## Off-thread work

Argon2id at 64 MiB takes a noticeable fraction of a second. The asynchronous
twins run it through a `CipherBirdRunner`, `CipherBirdIsolateRunner` by
default and `CipherBirdInlineRunner` in tests:

```dart
final key = await lib.easy.symmetricKeyFromPassphraseAsync('pw', salt: salt);
final phc = await lib.easy.hashPasswordAsync('hunter2');
```

Everything else is fast enough to call on the UI isolate; the figures below
say how fast.

## How it compares

The pub.dev packages below each cover part of the same job. The first table
is about scope; the second is measured.

| | cipherbird | pointycastle 3.9 | cryptography 2.7 | crypto 3.0 | sodium 3.x |
|---|---|---|---|---|---|
| Implementation | C++ engine over `dart:ffi` | pure Dart | pure Dart, native through a companion package on some platforms | pure Dart | libsodium over `dart:ffi` |
| Hashing | SHA-2, BLAKE2b, BLAKE3, Keccak, HMAC, HKDF | SHA-2, SHA-3, BLAKE2b, HMAC, HKDF | SHA-2, BLAKE2, HMAC, HKDF | SHA-2, HMAC | SHA-2, BLAKE2b |
| AEAD | XChaCha20-Poly1305, AES-256-GCM, key-committing, streaming | ChaCha20-Poly1305, AES-GCM | ChaCha20-Poly1305, AES-GCM | none | XChaCha20-Poly1305, AES-GCM, streaming |
| Password hashing | Argon2id | Argon2 | Argon2id | none | Argon2id |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, sntrup761, hybrids | none | none | none | none |
| Signatures | Ed25519, hybrid, BLS, secp256k1 | ECDSA, RSA | Ed25519, ECDSA | none | Ed25519 |
| Protocols | sealed messaging, Noise XX, HPKE, OPAQUE, OPRF, BBS, FROST, VRF, ratchet | none | none | none | sealed boxes |
| Vaults, keyring, steganography, media entropy | yes | no | no | no | no |
| Safe-default layer | easy mode, profiles, recipes | no | partial | no | partial |
| Same wire format in other languages | ten bindings, verified | no | no | no | libsodium compatible |
| Web | no | yes | yes | yes | yes |
| License | MIT | MIT | MIT | BSD-3-Clause | LGPL-3.0 |

Choose a pure-Dart package for the web or when a few kilobytes of download
matter more than throughput. Choose cipherbird when speed, post-quantum
readiness, higher-level protocols or cross-language compatibility matter.

### Measured

The harness in `cipherbird_dart/benchmark/bench.dart` runs each operation
for two seconds after one warm-up call and reports the mean. Apple M3 Max,
macOS 26.6, Dart 3.13.5, pointycastle 3.9.1, cryptography 2.7.0, crypto
3.0.6. Throughput rows are in MB/s on 1 MiB inputs; the rest are operations
per second. Factors are relative to cipherbird.

| Operation | cipherbird (native) | pointycastle | cryptography | crypto |
|---|---|---|---|---|
| SHA-256, 1 MiB | 275 MB/s | 76 MB/s (3.6x slower) | 90 MB/s (3.1x slower) | 90 MB/s (3.0x slower) |
| BLAKE2b-512, 1 MiB | 624 MB/s | 29 MB/s (21.3x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 1278 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 273 MB/s | 46 MB/s (5.9x slower) | 26 MB/s (10.5x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 647 MB/s | 1 MB/s (584.4x slower) | 14 MB/s (47.7x slower) | n/a |
| Ed25519 sign, 1 KiB | 42771 ops/s | n/a | 415 ops/s (103.2x slower) | n/a |
| Ed25519 verify, 1 KiB | 20353 ops/s | n/a | 403 ops/s (50.5x slower) | n/a |
| X25519 shared secret | 24581 ops/s | n/a | 1494 ops/s (16.5x slower) | n/a |
| Argon2id, 64 MiB, 2 passes | 15.2 ops/s | 1.8 ops/s (8.3x slower) | 2.4 ops/s (6.3x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 11847 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 3826 ops/s | n/a | n/a | n/a |

Reading the numbers fairly:

- Every cipherbird call copies its input into native memory and the result
  back. The throughput rows include that cost; the public-key rows are pure
  compute and show the larger gap.
- The cryptography package runs pure Dart on the Dart VM here. Its companion
  `cryptography_flutter` reaches platform APIs on some targets, which this
  harness does not measure.
- pointycastle's AES-GCM is a pure-Dart table implementation with no
  hardware acceleration, which is where its figure comes from.
- There is no pure-Dart ML-KEM in these packages, so the post-quantum rows
  show what the native engine delivers on its own.

Release bundle size, measured as the whole app against an empty Flutter app
built the same way:

| Build | Empty Flutter app | With cipherbird | Added |
|---|---|---|---|
| macOS release `.app`, Apple silicon | 37 MB | 46 MB | 9 MB (the `CipherBird` framework is 8 MB) |
| Android release APK, arm64 only | 14.8 MB | 30.1 MB | 15.3 MB |

The added size is the native library: libsodium, liboqs with every parameter
set the package exposes, OpenSSL libcrypto, blst, secp256k1 and BLAKE3
linked into one binary per platform.

## Interoperability

Every binding of the same engine (Go, Node, Swift, Java, Kotlin, Python, Ruby, Rust,
.NET and the two Dart packages) wraps the same C ABI and uses the library's
own wire formats. Vaults, sealed envelopes, recipes and keyrings move between
languages unchanged. The repository seals five recipe configurations in each
language and opens them in every other one, 72 pairs, on every change.

## Example and playground

The [example](example) checks the library on a device: it loads the engine,
verifies a SHA-256 known answer and round-trips a hybrid key agreement, a
hybrid signature, a sealed message and a MolecularVault.

The [playground](playground) is the app to play with: buttons to encrypt,
corrupt and decrypt text with the committing AEAD, sign and verify with the
hybrid signature, encrypt to a hybrid KEM public key and hash a passphrase
with Argon2id on a worker.

## Package structure

`lib/src` follows one declaration per file with a limit of 100 lines, no
`else` branches, no inline comments, `final` classes and `const factory`
redirects; `test/conventions_test.dart` enforces it. Large extensions are
split into named chunks such as `CipherBirdHybridKem` or
`CipherBirdRecipeSealing`, all re-exported by the barrel. The pure-Dart package
is generated from this one with `scripts/sync_dart_package.sh`.

## Maintaining the binaries

The prebuilt binaries are committed and published with the package. They go
stale after any C ABI change because the Dart side resolves every symbol, so
a stale binary fails at load. Rebuild from the repository root:

```bash
bash scripts/android/build_all.sh arm64-v8a x86_64
cp build/android/arm64-v8a/libcipherbird.so android/src/main/jniLibs/arm64-v8a/
cp build/android/x86_64/libcipherbird.so android/src/main/jniLibs/x86_64/
make ios
rm -rf ios/cipherbird/CipherBird.xcframework macos/cipherbird/CipherBird.xcframework
cp -R CipherBird.xcframework ios/cipherbird/CipherBird.xcframework
cp -R CipherBird.xcframework macos/cipherbird/CipherBird.xcframework
```

Then check the symbol count against the header, and run the consumer proof,
which installs the exact archive as a hosted package in a fresh app and runs
this package's tests on a device:

```bash
grep -c '^CRYPTO_API' bridge/cryptolib_c.h
nm -gU ios/cipherbird/CipherBird.xcframework/ios-arm64/CipherBird.framework/CipherBird | grep -c ' T _cryptolib_'
make flutter-consumer DEVICE=macos
```

The iOS simulator slice is arm64 only. A generic
`flutter build ios --simulator` also tries x86_64 and fails; exclude that
architecture for the simulator in the consuming app or add a universal slice.

## Engine

The engine is a header-only C++20 core with a
pure C ABI of 265 functions, bindings for ten languages, a custom test runner
with known-answer tests from the official sources, and a cross-language
conformance harness. Its repository holds the build, the tests, the
benchmark and the design notes. Everything is MIT licensed; the vendored
dependencies are BSD, MIT, Apache or public domain. The license requires that
the copyright notice, which credits the author Crdzbird, is kept in every
copy or substantial portion of this software.
