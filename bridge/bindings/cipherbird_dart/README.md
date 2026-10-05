# cipherbird_dart

Native cryptography for Dart on the server, in command-line tools and in
desktop programs. CipherBird binds its native C++ engine through
`dart:ffi` and ships the compiled library inside the package for the host
platform, so a program gets hashing, authenticated encryption, public-key
cryptography, post-quantum algorithms, hybrid key agreement, sealed
messaging, a secure channel, password hashing, vaults, a keyring, anonymous
credentials, threshold signatures and steganography from one dependency. It
is the plain-Dart twin of the [cipherbird](https://pub.dev/packages/cipherbird)
Flutter plugin: both are generated from one source tree and expose the same
API, with `CipherBird` as the entry point.

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

## Dart or Flutter?

`cipherbird_dart` is the plain-Dart package: no Flutter dependency, the
engine bundled for the host machine, found through the program's package
configuration. For a Flutter app use
[cipherbird](https://pub.dev/packages/cipherbird) instead; it carries the
engine for Android, iOS and macOS and plugs it into Flutter's build. The two
expose the same classes and methods and run the same test suite.

| | cipherbird_dart | cipherbird |
|---|---|---|
| Depends on | `ffi` only | Flutter SDK, `ffi` |
| Engine binaries | host slot under `native/<os>-<arch>/`, macOS on Apple silicon in this release | Android arm64-v8a and x86_64, iOS device and simulator, macOS |
| How the engine is found | the package's `native/` directory via `.dart_tool/package_config.json`, the current directory or the script location | the process image on iOS and macOS, `jniLibs` on Android |
| Download size | about 5 MB | about 28 MB |
| API, wire formats, tests | identical | identical |

## Install

```bash
dart pub add cipherbird_dart
```

| Platform | Status |
|---|---|
| macOS, Apple silicon | library bundled under `native/darwin-arm64` |
| Linux x64, Windows x64, Intel macOS | not bundled in this release; build the library from the repository and point `CIPHERBIRD_LIBRARY` at it |

No setup call is needed. `CipherBird.load()` resolves the library in this
order: an explicit path, the `CIPHERBIRD_LIBRARY` environment variable, the
bundled copy found through the program's `.dart_tool/package_config.json`,
the current directory or the directory above the running script, then the
loader path. A compiled executable (`dart compile exe`) has no package
configuration next to it, so pass the path or set the variable and ship the
library file with the binary.

`CipherBird.preload()` warms the library on a worker isolate and is optional;
the first use of `CipherBird.instance` does the same work synchronously.

## Quick start

```dart
import 'package:cipherbird_dart/cipherbird_dart.dart';

void main() {
  final key = SymmetricKey.generate();
  final box = key.encryptText('meet at dawn');
  print(key.decryptText(box));

  final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
  final signature = signer.signText('release 1.0.0');
  print(signer.verifyKey.verifyText('release 1.0.0', signature));

  final me = KemKeyPair.generate();
  final blob = KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
  print(me.decryptText(blob));
}
```

The easy-mode classes make the safe choice: the key-committing AEAD,
Argon2id for passphrases, HKDF for sub-keys and the post-quantum hybrid
signature.

```dart
final salt = CipherBird.instance.easy.randomBytes(16);
final key = SymmetricKey.fromPassphrase('correct horse battery staple', salt: salt);
final databaseKey = key.derive('database');
```

## Easy mode

| Class | Create | Use | Underneath |
|---|---|---|---|
| `SymmetricKey` | `generate()`, `fromBytes`, `fromHex`, `fromBase64`, `fromPassphrase(salt:)` | `encrypt`, `decrypt`, `encryptText`, `decryptText`, `derive(purpose)`, `asKeySource`, `destroy()` | key-committing AEAD, HKDF-SHA256, Argon2id |
| `SigningKey` | `generate(algorithm:)`, `fromBytes` | `sign`, `signText`, `verifyKey`, `scheme` | Ed25519, or Ed25519 plus ML-DSA-65 |
| `VerifyKey` | `fromBytes`, `fromHex` | `verify`, `verifyText`, `scheme` | |
| `KemKeyPair` | `generate()`, `fromBytes` | `encapsulate`, `decapsulate`, `encryptFor`, `decrypt`, `encryptTextFor`, `decryptText` | X25519 plus ML-KEM-768, HKDF, committing AEAD |
| `Identity` | `lib.easy.identity(tier)` | `sealText`, `openText`, `seal`, `open`, streaming sealers and openers | Flagship or Fortress sealed messaging |

| Utility on `lib.easy` | Returns |
|---|---|
| `hashPassword(password)`, `verifyPassword(password, phc)` | an Argon2id PHC string to store, and whether a password matches |
| `randomBytes(n)`, `randomHex(n)`, `token()` | OS randomness, as bytes, hex or a URL-safe token |
| `sha256Hex(text)` | the digest as hex |
| `symmetricKeyFromPassphraseAsync`, `hashPasswordAsync`, `verifyPasswordAsync` | the Argon2id operations on a worker isolate through `CipherBirdRunner` |

| Expression | Result |
|---|---|
| `'text'.bytes`, `'ab12'.hexBytes`, `'aGk='.base64Bytes` | bytes |
| `bytes.hex`, `bytes.base64`, `bytes.base64Url`, `bytes.text` | strings |
| `bytes.constantTimeEquals(other)`, `bytes.concat(other)`, `bytes.wipe()`, `list.u8` | compare without leaking, join, zero, convert |

## Full API

All 265 native operations are reachable on `CipherBird`, flat or through
grouped views. Every operation takes and returns `Uint8List`, throws on
failure and never returns partial data.

| Group | Operations |
|---|---|
| `lib.hash` | SHA-256, SHA-512, BLAKE2b, BLAKE3, HMAC, HKDF, Argon2id |
| `lib.aead` | XChaCha20-Poly1305, AES-256-GCM, committing AEAD, SecretStream |
| `lib.asym` | Ed25519, X25519, boxes, sealed boxes |
| `lib.pq` | `mlKem`, `mlDsa`, `slhDsa`, `hybridKem`, `hybridSig`, `sntrup` |
| `lib.sealed`, `lib.channel`, `lib.session` | sealed messaging, Noise XX, forward-secret ratchet |
| `lib.hpke`, `lib.opaque`, `lib.oprf` | HPKE, OPAQUE login, OPRF |
| `lib.bbs`, `lib.frost`, `lib.ecvrf`, `lib.bls` | anonymous credentials, threshold Ed25519, VRF, BLS12-381 |
| `lib.vault`, `lib.keyring`, `lib.suite`, `lib.composed` | vaults, keyrings, one-call combinations |
| `lib.entropy`, `lib.stego`, `lib.rng`, `lib.chain` | media entropy, steganography, DRBG and Fortuna, Keccak and secp256k1 |

## Profiles and recipes

| Profile | KEM | Signature | Sealed tier | AEAD cascade | Argon2id |
|---|---|---|---|---|---|
| `balanced` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305 | 2 passes, 64 MiB |
| `high` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305, AES-256-GCM | 3 passes, 256 MiB |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | Fortress | XChaCha20-Poly1305, AES-256-GCM, key-committing | 4 passes, 512 MiB |

```dart
final recipe = lib
    .maximumSecurity()
    .withPassphrase('correct horse battery staple')
    .signedBy(identity.secretKey, algorithm: SignatureAlgorithm.hybrid)
    .verifiedBy(identity.publicKey);
final envelope = recipe.seal(secret);
final back = recipe.open(envelope);
```

Each layer gets its own HKDF-derived key, the header is authenticated by
every layer, the order sign, encrypt, correct, conceal is fixed, and any
failure throws before data is returned. `ProtectionLayer`, `CascadeLayer`,
`KeySource` and `SignatureScheme` can be subclassed to add your own parts;
ids 0 to 127 are reserved and the wire name feeds the key derivation, so a
mismatched implementation fails the authentication tag.

## How it compares

| | cipherbird_dart | pointycastle 3.9 | cryptography 2.7 | crypto 3.0 |
|---|---|---|---|---|
| Implementation | C++ engine over `dart:ffi` | pure Dart | pure Dart | pure Dart |
| Hashing | SHA-2, BLAKE2b, BLAKE3, Keccak, HMAC, HKDF | SHA-2, SHA-3, BLAKE2b, HMAC, HKDF | SHA-2, BLAKE2, HMAC, HKDF | SHA-2, HMAC |
| AEAD | XChaCha20-Poly1305, AES-256-GCM, key-committing, streaming | ChaCha20-Poly1305, AES-GCM | ChaCha20-Poly1305, AES-GCM | none |
| Password hashing | Argon2id | Argon2 | Argon2id | none |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, sntrup761, hybrids | none | none | none |
| Signatures | Ed25519, hybrid, BLS, secp256k1 | ECDSA, RSA | Ed25519, ECDSA | none |
| Protocols | sealed messaging, Noise XX, HPKE, OPAQUE, OPRF, BBS, FROST, VRF, ratchet | none | none | none |
| Safe-default layer | easy mode, profiles, recipes | no | partial | no |
| Same wire format in other languages | ten bindings, verified | no | no | no |
| Web | no | yes | yes | yes |

### Measured

`benchmark/bench.dart` runs each operation for two seconds after one warm-up
call and reports the mean. Apple M3 Max, macOS 26.6, Dart 3.13.5,
pointycastle 3.9.1, cryptography 2.7.0, crypto 3.0.6. Throughput rows are in
MB/s on 1 MiB inputs; the rest are operations per second. Factors are
relative to cipherbird.

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

Every cipherbird call copies its input into native memory and the result
back, so the throughput rows include that cost. pointycastle's AES-GCM is a
pure-Dart table implementation with no hardware acceleration. There is no
pure-Dart ML-KEM in these packages. Run the harness yourself:

```bash
cd benchmark && dart pub get && dart run bench.dart
```

## Verifying

`dart test` runs the same 104 tests as the Flutter plugin against the bundled
library, including the structure rules the code follows (one declaration per
file, 100 lines, no `else`, no inline comments). The `bin/` scripts are the
verification harnesses the repository's Makefile drives, including the
cross-language recipe interop.

## Engine

The engine is a header-only C++20 core with a
pure C ABI of 265 functions, bindings for ten languages, known-answer tests
from the official sources, and a cross-language conformance harness. Its
repository holds the build, the tests, the benchmark and the design notes.
Everything is MIT licensed; the vendored dependencies are BSD, MIT, Apache
or public domain. The license requires that the copyright notice, which
credits the author Crdzbird, is kept in every copy or substantial portion of
this software.
