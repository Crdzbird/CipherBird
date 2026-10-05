# cipherbird

Native cryptography for Flutter on Android, iOS, macOS and the web.
CipherBird binds its native C++ engine through `dart:ffi`, or through a
WebAssembly build of the same engine in the browser, and ships the compiled
library for every platform inside the package, so an app gets hashing, authenticated encryption, public-key cryptography,
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

Supported platforms: Android, iOS, macOS and the web, with the same API and
byte-compatible output on all four. The same code is published for plain
Dart as [cipherbird_dart](https://pub.dev/packages/cipherbird_dart) for
servers, command-line tools, desktop programs and browser apps built with
`dart compile`; both packages are generated from one source tree and expose
the same API.

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
| Engine binaries | bundled per platform: Android arm64-v8a and x86_64, iOS device and simulator, macOS, and WebAssembly for the web | bundled for the host under `native/<os>-<arch>/`, macOS on Apple silicon in this release, and WebAssembly for the web |
| How the engine is found | the process image on iOS and macOS, `libcipherbird.so` from `jniLibs` on Android, the package asset on the web | the package's `native/` directory, located through the program's package configuration; the package asset on the web |
| Startup | `await CipherBird.preload()` before `runApp`, or lazy on first use; required on the web | lazy on first use, `preload` optional; required on the web |
| Build integration | Flutter's plugin tooling, nothing to configure | none needed; `dart run`, `dart test` and `dart compile exe` (pass the library path) |
| Download size | about 32 MB | about 9 MB |
| API, wire formats, tests | identical | identical |

## Install

```bash
flutter pub add cipherbird
```

Nothing else is required. The engine is vendored per platform: a dynamic
`CipherBird` framework through Swift Package Manager on iOS and macOS,
`libcipherbird.so` under `jniLibs` on Android, and a WebAssembly build
under `assets/` for the web. libsodium, liboqs, OpenSSL libcrypto, blst,
secp256k1 and BLAKE3 are linked into it statically, so no system library is
needed.

| Platform | Minimum |
|---|---|
| Android | API 24, arm64-v8a and x86_64 |
| iOS | 15.0, arm64 device and arm64 simulator |
| macOS | 12.0, Apple silicon, Swift Package Manager |
| Web | any browser with WebAssembly; `flutter build web` and `flutter build web --wasm`; see [Web](#web) |

Call `CipherBird.preload()` once at startup. It loads and initialises the
library on a background isolate, and on the web it fetches and instantiates
the WebAssembly engine; every later call is synchronous:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CipherBird.preload();
  runApp(const MyApp());
}
```

Skipping `preload` is allowed natively: the first use of
`CipherBird.instance` does the same work synchronously. On the web it is
required, because the engine can only be fetched asynchronously.

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
twins hand the work to a `CipherBirdRunner` as a `CipherBirdJob`, a plain
data description of the call. `CipherBirdIsolateRunner`, the default, runs
the job on a background isolate natively and in a dedicated web worker in
the browser, where a second copy of the engine answers jobs by message so the
page never blocks. `CipherBirdInlineRunner` runs jobs on the calling thread
for tests:

```dart
final key = await lib.easy.symmetricKeyFromPassphraseAsync('pw', salt: salt);
final phc = await lib.easy.hashPasswordAsync('hunter2');
final ok = await lib.easy.verifyPasswordAsync('hunter2', phc);
```

Jobs below the runner's cost threshold (2048 by default) stay inline. Your
own heavy call can become a job too: extend `CipherBirdJob`, implement
`execute` with the synchronous API, and pass it to `runner.run`. Natively
that is all; in the browser the worker script also needs a handler for the
job's `op` name, so custom jobs are isolate-only there.

Everything else is fast enough to call on the UI isolate; the figures below
say how fast.

## Web

The same package runs in the browser. The engine is compiled to WebAssembly
with Emscripten and ships inside the package as `assets/cipherbird.js` and
`assets/cipherbird.wasm`, about 4 MB, fetched once when the app starts. The
Dart API is identical; the only change is that the engine must be loaded
before the first use, because fetching and instantiating WebAssembly is
asynchronous:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CipherBird.preload();
  runApp(const MyApp());
}
```

`preload` finds the engine at the package asset path. Pass
`library: 'https://cdn.example.com/engine/cipherbird.js'` to serve it from
somewhere else (the `.wasm` file is fetched from the same directory), or set
the `CIPHERBIRD_LIBRARY` compile-time define. Both `flutter build web` and
`flutter build web --wasm` are supported; the test suite runs under both.

What differs in the browser:

- Envelopes, signatures and keys are byte-compatible with every other
  platform. A message sealed in the browser opens on a phone or a server and
  the other way round.
- There are no isolates, so `CipherBirdIsolateRunner` uses a web worker
  instead: `assets/cipherbird_worker.js` loads a second copy of the engine
  and runs the Argon2id jobs behind the asynchronous helpers off the main
  thread. The worker is spawned through a blob during `preload`, which a
  strict Content Security Policy must allow (`worker-src blob:`).
- APIs that take a file path (media entropy from a file, key files, suite
  calls with a file, steganography carriers on disk) are unavailable; the
  browser has no filesystem. The in-memory variants of the same operations
  work.
- AES-256-GCM uses OpenSSL's portable implementation because WebAssembly has
  no AES instructions. Output is byte-identical to the hardware path.
- 64-bit integer parameters are exact up to 2^53.

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
| SHA-256, 1 MiB | 282 MB/s | 80 MB/s (3.5x slower) | 96 MB/s (2.9x slower) | 98 MB/s (2.9x slower) |
| BLAKE2b-512, 1 MiB | 671 MB/s | 31 MB/s (21.7x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 1347 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 299 MB/s | 46 MB/s (6.5x slower) | 26 MB/s (11.5x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 736 MB/s | 1 MB/s (659.2x slower) | 14 MB/s (53.2x slower) | n/a |
| Ed25519 sign, 1 KiB | 42531 ops/s | n/a | 377 ops/s (112.7x slower) | n/a |
| Ed25519 verify, 1 KiB | 18697 ops/s | n/a | 375 ops/s (49.8x slower) | n/a |
| X25519 shared secret | 22822 ops/s | n/a | 1387 ops/s (16.5x slower) | n/a |
| Argon2id, 64 MiB, 2 passes | 13.7 ops/s | 1.7 ops/s (8.0x slower) | 2.4 ops/s (5.8x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 12061 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 3839 ops/s | n/a | n/a | n/a |

The same suite in Chrome 155, compiled with dart2js, against the
WebAssembly engine (`dart test -p chrome` in `benchmark/`). Two columns
need reading with care. `cryptography` hands SHA-256, AES-GCM and the
Ed25519 and X25519 operations to the browser's own Web Crypto API, which is
native code with hardware AES and SHA, so it beats any WebAssembly
implementation on those rows; `pointycastle` and `crypto` stay pure Dart,
and `pointycastle`'s ChaCha20 implementation does not run under dart2js. On
everything Web Crypto does not offer, the engine remains the fast option in
the browser: BLAKE2b, BLAKE3, XChaCha20-Poly1305, Argon2id and the
post-quantum algorithms.

| Operation | cipherbird (WebAssembly) | pointycastle | cryptography | crypto |
|---|---|---|---|---|
| SHA-256, 1 MiB | 102 MB/s | 2 MB/s (51.0x slower) | 1498 MB/s (14.7x faster) | 121 MB/s (1.2x faster) |
| BLAKE2b-512, 1 MiB | 133 MB/s | 2 MB/s (66.5x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 131 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 103 MB/s | error: PlatformException | 34 MB/s (3.0x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 51 MB/s | 1 MB/s (51.0x slower) | 1806 MB/s (35.4x faster) | n/a |
| Ed25519 sign, 1 KiB | 18192 ops/s | n/a | 13072 ops/s (1.4x slower) | n/a |
| Ed25519 verify, 1 KiB | 8528 ops/s | n/a | 16640 ops/s (2.0x faster) | n/a |
| X25519 shared secret | 10283 ops/s | n/a | 10520 ops/s (1.0x faster) | n/a |
| Argon2id, 64 MiB, 2 passes | 11.8 ops/s | 0.1 ops/s (118.0x slower) | 0.3 ops/s (39.3x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 5865 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 1858 ops/s | n/a | n/a | n/a |

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

`lib/src/platform/native` holds dart:ffi, the library loader and the isolate
runner; `lib/src/platform/web` holds the same surface over the WebAssembly
engine (pointers, allocation, struct views and the symbol registry, the last
two generated from the C header by `scripts/web/gen_dart.py`). The root
library picks one with a conditional import, so the API layer is written
once.

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

The WebAssembly engine is rebuilt with Emscripten from the same sources and
bundled into both packages:

```bash
make web-engine
make web-bundle
make flutter-web-test
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
