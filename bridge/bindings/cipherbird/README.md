# cipherbird

CipherBird is the Flutter package for CryptoLib: one dependency that gives an
app hashing, authenticated encryption, public-key cryptography, post-quantum
algorithms, hybrid key agreement, sealed messaging, a secure channel, password
hashing, vaults, a keyring, anonymous credentials, threshold signatures and
steganography, all from a single native library that ships inside the package.

The same code is published for plain Dart as `cipherbird_dart`, for servers,
command-line tools and desktop programs. Both packages are generated from one
source tree and expose exactly the same API.

| Package | Use it for | Native library |
|---|---|---|
| `cipherbird` | Flutter apps on Android, iOS and macOS | bundled per platform inside the plugin |
| `cipherbird_dart` | Dart on the server, CLIs, desktop | bundled under `native/<os>-<arch>/` for the host |

## Contents

1. [Why this library](#why-this-library)
2. [Install and set up](#install-and-set-up)
3. [Easy mode](#easy-mode)
4. [The full API, by group](#the-full-api-by-group)
5. [Security profiles and recipes](#security-profiles-and-recipes)
6. [Extending the recipe with your own parts](#extending-the-recipe-with-your-own-parts)
7. [Off-thread work](#off-thread-work)
8. [Comparison with other Dart packages](#comparison-with-other-dart-packages)
9. [Benchmarks](#benchmarks)
10. [Interoperability with other languages](#interoperability-with-other-languages)
11. [Platform support](#platform-support)
12. [Package structure and conventions](#package-structure-and-conventions)
13. [Maintaining the bundled binaries](#maintaining-the-bundled-binaries)
14. [License and attribution](#license-and-attribution)

## Why this library

- Native speed. Every operation runs in the C++ core through `dart:ffi`. A
  1 MiB SHA-256 or AES-GCM runs at memory bandwidth instead of at the speed
  of a Dart loop. The benchmarks below show the difference.
- Vetted primitives, composed. The core wraps libsodium, liboqs, OpenSSL
  libcrypto, blst, secp256k1 and BLAKE3. The library adds composition and
  plumbing, never new cryptography.
- Post-quantum today. ML-KEM, ML-DSA and SLH-DSA from FIPS 203, 204 and 205,
  the sntrup761 KEM, and hybrid constructions that stay secure if either the
  classical or the post-quantum half holds.
- Safe defaults that are hard to misuse. The easy-mode classes pick the
  key-committing AEAD, Argon2id for passphrases, HKDF for sub-keys and the
  hybrid signature. Recipes fix the order of operations and fail closed.
- Higher-level protocols, not just primitives. Sealed messaging with two
  assurance tiers, Noise XX channels, HPKE, OPAQUE password login, OPRF, BBS
  anonymous credentials with selective disclosure, FROST threshold
  signatures, ECVRF, BLS aggregation, a forward-secret session ratchet, media
  entropy and steganography.
- One wire format across ten languages. An envelope sealed in Dart opens in
  Go, Node, Swift, Java, Kotlin, Python, Ruby, Rust and .NET, and the
  repository proves it with 72 cross-language seal and open pairs.
- No setup. The native library is inside the package and loads itself.

## Install and set up

```yaml
dependencies:
  cipherbird: ^1.0.0
```

Warm the library before the first frame and keep every later call
synchronous:

```dart
import 'package:cipherbird/cipherbird.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoLib.preload();
  runApp(const MyApp());
}
```

`preload` runs the one-time load and initialisation on a background isolate.
It is optional: the first use of `CryptoLib.instance` does the same work
synchronously. There is no `await` anywhere else in the API; every operation
is a plain synchronous call.

## Easy mode

The safe choices are already made. Text in, text out, no byte plumbing.

```dart
final key = SymmetricKey.generate();
final box = key.encryptText('meet at dawn');
final back = key.decryptText(box);

final salt = CryptoLib.instance.easy.randomBytes(16);
final fromPassphrase = SymmetricKey.fromPassphrase(
  'correct horse battery staple',
  salt: salt,
);
final databaseKey = key.derive('database');

final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
final signature = signer.signText('release 1.0.0');
final verifier = VerifyKey.fromHex(
  signer.publicKey.hex,
  algorithm: SignatureAlgorithm.hybrid,
);
final valid = verifier.verifyText('release 1.0.0', signature);

final me = KemKeyPair.generate();
final blob = KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
final plain = me.decryptText(blob);

final lib = CryptoLib.instance;
final phc = lib.easy.hashPassword('hunter2');
final good = lib.easy.verifyPassword('hunter2', phc);
final sessionId = lib.easy.token();
final digest = lib.sha256('abc'.bytes).hex;
```

| Class | What it does | Underneath |
|---|---|---|
| `SymmetricKey` | `encrypt`, `decrypt`, `encryptText`, `decryptText`, `derive(purpose)`, `fromPassphrase(salt:)`, hex and base64 round-trips, `asKeySource`, `destroy()` | key-committing AEAD, HKDF-SHA256, Argon2id at the profile cost |
| `SigningKey`, `VerifyKey` | `sign`, `verify`, text variants, `scheme` for recipes | Ed25519, or Ed25519 plus ML-DSA-65 with `algorithm: SignatureAlgorithm.hybrid` |
| `KemKeyPair` | `encapsulate` and `decapsulate` to a `SymmetricKey`, one-call `encryptFor` and `decrypt` | X25519 plus ML-KEM-768, HKDF, key-committing AEAD |
| `Identity` | `sealText`, `openText`, streaming sealers and openers | Flagship or Fortress sealed messaging |
| `lib.easy` | factories for the above, `hashPassword`, `verifyPassword`, `randomBytes`, `randomHex`, `token`, `sha256Hex` | Argon2id PHC strings, the OS CSPRNG |

Bytes and strings convert with `'text'.bytes`, `'ab12'.hexBytes`,
`'...'.base64Bytes`, `bytes.hex`, `bytes.base64`, `bytes.base64Url`,
`bytes.text`, `bytes.constantTimeEquals(other)`, `bytes.concat(other)`,
`bytes.wipe()` and `List<int>.u8`.

Every class exposes its raw bytes and plugs into the recipes, so the full
API is always one step away.

## The full API, by group

All 265 native operations are available on `CryptoLib`, both as flat methods
and through grouped views that keep autocomplete usable.

```dart
final lib = CryptoLib.instance;
final digest = lib.hash.sha256('abc'.bytes);
final pair = lib.pq.hybridKem.keygen();
final (ciphertext, shared) = lib.pq.hybridKem.encapsulate(pair.publicKey);
final opened = lib.pq.hybridKem.decapsulate(ciphertext, pair.secretKey);
```

| Group | Operations |
|---|---|
| `lib.hash` | SHA-256, SHA-512, BLAKE2b, BLAKE3 (hash, keyed, derive key, incremental hasher), HMAC-SHA256 and SHA512 with constant-time verify, HKDF extract, expand and derive, Argon2id hash, verify and derive |
| `lib.aead` | XChaCha20-Poly1305, AES-256-GCM, key-committing AEAD, SecretStream streaming encryption, symmetric key generation |
| `lib.asym` | Ed25519 keys, sign and verify, X25519 key agreement, authenticated boxes and sealed boxes |
| `lib.pq` | ML-KEM 512, 768, 1024; ML-DSA 44, 65, 87; SLH-DSA in all SHA2 and SHAKE parameter sets; hybrid X25519 plus ML-KEM-768 KEM; hybrid Ed25519 plus ML-DSA-65 signature; X25519 plus sntrup761 KEM |
| `lib.sealed` | Flagship and Fortress sealed messaging: identities, one-shot seal and open, streaming, envelope inspection, recipient matching |
| `lib.channel` | Noise XX secure channel with mutual authentication, forward secrecy and re-entrant decryption by counter |
| `lib.session` | post-quantum forward-secret session ratchet |
| `lib.hpke` | HPKE (RFC 9180) in all four modes, single-shot and context forms |
| `lib.opaque`, `lib.oprf` | OPAQUE password-authenticated login and the ristretto255 OPRF it builds on |
| `lib.bbs` | BBS signatures with zero-knowledge selective disclosure, per-verifier pseudonyms and blind issuance |
| `lib.frost` | FROST threshold Ed25519 signatures (RFC 9591) |
| `lib.ecvrf`, `lib.bls` | verifiable random function (RFC 9381), BLS12-381 signatures and aggregation |
| `lib.vault`, `lib.keyring` | symmetric and asymmetric vaults, MolecularVault, keyrings with device and passphrase slots |
| `lib.suite`, `lib.composed` | one-call combinations: post-quantum messages, signed post-quantum messages, threshold vaults, file-as-key vaults, physical-media seals, HPKE into a steganographic carrier |
| `lib.entropy`, `lib.stego` | media entropy with health assessment, DRBG and Fortuna generators, steganography across image, audio and video formats, forward error correction |
| `lib.chain` | Keccak-256, secp256k1 sign and recover, EVM addresses |
| `lib.rng` | OS randomness, DRBG, Fortuna |

Every operation takes and returns `Uint8List`, throws on failure, and never
returns partially decrypted data.

## Security profiles and recipes

`SecurityProfile` moves every algorithm parameter together so a maximal KEM
is never paired with an interactive KDF.

| Profile | KEM | Signature | Sealed tier | Cascade | Argon2id |
|---|---|---|---|---|---|
| `balanced` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305 | 2 passes, 64 MiB |
| `high` | ML-KEM-768 | ML-DSA-65 | Flagship | XChaCha20-Poly1305 then AES-256-GCM | 3 passes, 256 MiB |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | Fortress | XChaCha20-Poly1305, AES-256-GCM, then key-committing | 4 passes, 512 MiB |

`CryptoRecipe` composes a key source, an AEAD cascade, an optional signature,
optional forward error correction and an optional steganographic carrier into
one envelope:

```dart
final recipe = lib
    .maximumSecurity()
    .withPassphrase('correct horse battery staple')
    .signedBy(identity.secretKey, algorithm: SignatureAlgorithm.hybrid)
    .verifiedBy(identity.publicKey);
final envelope = recipe.seal(secret);
final back = recipe.open(envelope);
print(recipe.describe());
```

What the recipe guarantees regardless of configuration: each layer gets its
own HKDF-derived key, the header describing the recipe is authenticated by
every layer, the order sign, encrypt, correct, conceal is fixed, and any
failure throws before data is returned.

## Extending the recipe with your own parts

Three abstract classes can be subclassed; the library's own implementations
subclass the same ones.

| Base | Built-ins | Your subclass |
|---|---|---|
| `ProtectionLayer` | XChaCha20-Poly1305, AES-256-GCM, key-committing, MolecularVault | implement `id`, `wireName`, `seal`, `open`, then `ProtectionLayer.register()` it |
| `CascadeLayer` | | mixes several layers, built-in or custom, into one layer; cascades nest |
| `KeySource` | raw key, passphrase, media file | a hardware token, a KMS, a keyring unlock, via `withKeySource()` |
| `SignatureScheme` | Ed25519, hybrid | another algorithm, via `signedWith()` and `verifiedWith()` |

```dart
final class BeltAndBraces extends CascadeLayer {
  const BeltAndBraces()
      : super(id: 201, wireName: 'belt-and-braces', layers: const [
          ProtectionLayer.xchacha20Poly1305,
          ProtectionLayer.aes256Gcm,
          ProtectionLayer.committing,
        ]);
}

ProtectionLayer.register(const BeltAndBraces());
final envelope = lib.recipe().withKey(key).withLayers([const BeltAndBraces()]).seal(secret);
```

Ids 0 to 127 are reserved and enforced, a key source must return exactly 32
bytes, a layer never chooses its key, and the wire name feeds the key
derivation, so a mismatched implementation fails the authentication tag
instead of producing garbage.

## Off-thread work

Argon2id at 64 MiB takes a noticeable fraction of a second. The asynchronous
twins run it on a worker through a `CryptoLibRunner`:

```dart
final key = await lib.easy.symmetricKeyFromPassphraseAsync('pw', salt: salt);
final phc = await lib.easy.hashPasswordAsync('hunter2');
final ok = await lib.easy.verifyPasswordAsync('hunter2', phc);
```

`CryptoLibIsolateRunner` is the default. Pass `CryptoLibInlineRunner` in
tests to keep them deterministic. The seam has the same shape as an
injectable isolate runner, so an app can wrap its own.

## Comparison with other Dart packages

| | cipherbird | pointycastle | cryptography | crypto | libsodium bindings |
|---|---|---|---|---|---|
| Implementation | native C++ core through FFI | pure Dart | pure Dart, native on some platforms through a companion package | pure Dart | native |
| Hashing | SHA-2, BLAKE2b, BLAKE3, Keccak, HMAC, HKDF | SHA-2, SHA-3, BLAKE2b, HMAC, HKDF | SHA-2, BLAKE2, HMAC, HKDF | SHA-2, HMAC | SHA-2, BLAKE2b |
| AEAD | XChaCha20-Poly1305, AES-256-GCM, key-committing, streaming | ChaCha20-Poly1305, AES-GCM | ChaCha20-Poly1305, AES-GCM | none | XChaCha20-Poly1305, AES-GCM, streaming |
| Password hashing | Argon2id | Argon2 | Argon2id | none | Argon2id |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, sntrup761, hybrids | none | none | none | none |
| Signatures | Ed25519, hybrid Ed25519 plus ML-DSA, BLS, secp256k1 | ECDSA, RSA | Ed25519, ECDSA | none | Ed25519 |
| Protocols | sealed messaging, Noise XX, HPKE, OPAQUE, OPRF, BBS, FROST, VRF, session ratchet | none | none | none | sealed boxes |
| Vaults, keyring, steganography, media entropy | yes | none | none | none | none |
| Cross-language wire formats | ten languages, verified | n/a | n/a | n/a | compatible with libsodium |
| Safe-default layer | easy mode, profiles, recipes | no | partial | no | no |
| Size cost | about 28 MB download, 7 MB per platform in the app | small | small | small | native library size |
| Web | no | yes | yes | yes | depends |

Choose a pure-Dart package when the target is the web or when a few
kilobytes of download matter more than throughput. Choose cipherbird when
speed, post-quantum readiness, higher-level protocols or cross-language
compatibility matter.

## Benchmarks

Measured with `cipherbird_dart/benchmark/bench.dart` on an Apple M3 Max,
macOS 26.6, Dart 3.13.5, pointycastle 3.9, cryptography 2.7, crypto 3.0.
Each cell is the mean over a two-second window after one warm-up run.
Throughput rows are in MB/s on 1 MiB inputs; the rest are operations per
second. Factors are relative to cipherbird. Run the harness on your own
machine before relying on any number here.

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

Every cipherbird call copies its input into native memory and the result back,
so the throughput rows include that cost; the gap on long inputs is the
difference between the C implementations and Dart loops, and the gap on
public-key operations is larger still.

There is no pure-Dart ML-KEM to compare against in these packages. The
post-quantum rows show what the native core delivers on its own.

## Interoperability with other languages

Every CryptoLib binding (Go, Node, Swift, Java, Kotlin, Python, Ruby, Rust,
.NET and the two Dart packages) wraps the same C ABI and uses the library's
own wire formats, so vaults, sealed envelopes, recipes and keyrings move
between languages unchanged. `make recipe-interop` in the repository seals
five recipe configurations in each language and opens them in every other
one, 72 pairs in total.

## Platform support

| Platform | Status |
|---|---|
| Android (arm64-v8a, x86_64) | bundled, verified on device |
| iOS 15 and later (arm64 device and arm64 simulator) | bundled, verified on simulator |
| macOS 12 and later (Apple silicon) | bundled, verified build |
| Linux, Windows, web | not in this release |
| Android armeabi-v7a and x86, Intel macOS | not in this release |

The iOS simulator slice is arm64 only. A generic
`flutter build ios --simulator` also tries x86_64 and fails. Either add a
universal simulator slice before publishing or exclude x86_64 in the consuming
app:

```ruby
post_install do |installer|
  installer.pods_project.targets.each do |t|
    t.build_configurations.each do |c|
      c.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
    end
  end
end
```

## Package structure and conventions

`lib/src` follows one declaration per file with a limit of 100 lines, no
`else` branches, no inline comments, `final` classes and `const factory`
redirects. `test/conventions_test.dart` enforces it. Large extensions are
split into named chunks such as `CryptoLibHybridKem` or
`CryptoRecipeSealing`; all are re-exported by the barrel, so every method is
reachable from a single import.

`playground/` is a small Flutter app that exercises the package the way an
app would, with buttons to encrypt, corrupt and decrypt, sign and verify,
encrypt to a public key and hash a passphrase on a worker.

The pure-Dart package is generated from this one with
`scripts/sync_dart_package.sh`; never edit its `lib/src` by hand.

## Maintaining the bundled binaries

The prebuilt binaries are committed and published with the package. They go
stale after any C ABI change because the Dart side resolves every symbol, so
a stale binary fails at load. Rebuild from the repository root:

```bash
bash scripts/android/build_all.sh arm64-v8a x86_64
cp build/android/arm64-v8a/libcryptolib_c.so android/src/main/jniLibs/arm64-v8a/
cp build/android/x86_64/libcryptolib_c.so android/src/main/jniLibs/x86_64/
make ios
rm -rf ios/cipherbird/CryptoLibC.xcframework macos/cipherbird/CryptoLibC.xcframework
cp -R CryptoLib.xcframework ios/cipherbird/CryptoLibC.xcframework
cp -R CryptoLib.xcframework macos/cipherbird/CryptoLibC.xcframework
```

Then check that the symbol count matches the header:

```bash
grep -c '^CRYPTO_API' bridge/cryptolib_c.h
nm -gU ios/cipherbird/CryptoLibC.xcframework/ios-arm64/CryptoLibC.framework/CryptoLibC | grep -c ' T _cryptolib_'
strings android/src/main/jniLibs/arm64-v8a/libcryptolib_c.so | grep -c '^cryptolib_'
```

Before publishing, run the consumer proof from the repository root. It
installs the exact archive as a hosted package in a fresh app and runs this
package's test suite on a device:

```bash
make flutter-consumer DEVICE=macos
```

## License and attribution

MIT, see [LICENSE](LICENSE). The license requires that the copyright notice,
which credits the author Crdzbird, is kept in every copy or substantial
portion of this software, including apps and libraries that bundle it.
