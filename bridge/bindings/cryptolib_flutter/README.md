# cryptolib_flutter

CryptoLib for Flutter: hashing, authenticated encryption, public-key
cryptography, vaults, post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA), a
hybrid X25519 plus ML-KEM-768 key agreement, BLS, Noise, sealed messaging and a
keyring, exposed through `dart:ffi`.

The native library ships inside the package and loads automatically. iOS and
macOS vendor the prebuilt `CryptoLibC.xcframework`, a self-contained dynamic
framework with libsodium, liboqs, blst, OpenSSL libcrypto, secp256k1 and BLAKE3
linked in. Android ships `libcryptolib_c.so` in `jniLibs`. That is why the
package is about 28 MB compressed.

## Setup

Warm the library before the first frame and keep every later call synchronous:

```dart
import 'package:cryptolib_flutter/cryptolib_flutter.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoLib.preload();
  runApp(const MyApp());
}
```

`preload` runs the one-time load and initialisation on a background isolate
through a `CryptoLibRunner`. The default is `CryptoLibIsolateRunner`; pass
`CryptoLibInlineRunner` in tests. Skipping `preload` is allowed: the first use
of `CryptoLib.instance` performs the same work synchronously.

## Quick start

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
final signature = signer.signText('release 4.3.0');
final verifier = VerifyKey.fromHex(
  signer.publicKey.hex,
  algorithm: SignatureAlgorithm.hybrid,
);
final valid = verifier.verifyText('release 4.3.0', signature);

final me = KemKeyPair.generate();
final blob = KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
final plain = me.decryptText(blob);

final lib = CryptoLib.instance;
final phc = lib.easy.hashPassword('hunter2');
final good = lib.easy.verifyPassword('hunter2', phc);
final sessionId = lib.easy.token();
final digest = lib.sha256('abc'.bytes).hex;
```

What each piece gives you:

- `SymmetricKey` encrypts with the key-committing AEAD, stretches passphrases
  with Argon2id, derives independent sub-keys with HKDF, and serialises to hex
  or base64.
- `SigningKey` and `VerifyKey` use Ed25519 or the Ed25519 plus ML-DSA-65
  hybrid behind one `algorithm` argument.
- `KemKeyPair` agrees on a `SymmetricKey` with hybrid X25519 plus ML-KEM-768
  and offers one-call public-key encryption with `encryptFor` and `decrypt`.
- `lib.easy` holds the factories, password hashing, random bytes and tokens.
- Slow operations have asynchronous twins that run on a worker:
  `symmetricKeyFromPassphraseAsync`, `hashPasswordAsync`,
  `verifyPasswordAsync`.
- Strings and bytes convert with `'text'.bytes`, `'ab12'.hexBytes`,
  `bytes.hex`, `bytes.base64`, `bytes.text` and
  `bytes.constantTimeEquals(other)`.

Every class exposes its raw bytes and plugs into the composable recipes
through `key.asKeySource` and `signer.scheme`, so the full API stays one step
away.

## Playground app

`playground/` is a small Flutter app that consumes the package the way an app
would: self-test rows at the top, then buttons to encrypt, corrupt and decrypt
text with the committing AEAD, sign and verify with the hybrid signature,
encrypt to a hybrid KEM public key, and hash a passphrase with Argon2id on a
worker. Run it with `flutter run` from that directory.

## Full API

All 265 native operations are available on `CryptoLib`, flat and grouped:

```dart
final lib = CryptoLib.instance;
final digest = lib.hash.sha256('abc'.bytes);
final pair = lib.pq.hybridKem.keygen();
final (ciphertext, shared) = lib.pq.hybridKem.encapsulate(pair.publicKey);
final opened = lib.pq.hybridKem.decapsulate(ciphertext, pair.secretKey);
```

Groups: `hash`, `aead`, `asym`, `bls`, `vault`, `keyring`, `entropy`, `stego`,
`composed`, `chain`, `suite`, `sealed`, `session`, `frost`, `hpke`, `ecvrf`,
`bbs`, `oprf`, `opaque`, `rng`, `pq` and `channel` (Noise XX).

`SecurityProfile` (balanced, high, maximum) moves every algorithm parameter
together, and `CryptoRecipe` composes a key source, an AEAD cascade, a
signature, forward error correction and a steganographic carrier into one
envelope whose wire format is identical in every CryptoLib binding. Custom
layers, key sources and signature schemes subclass `ProtectionLayer`,
`KeySource` and `SignatureScheme`; `CascadeLayer` mixes several ciphers into
one layer.

## Package structure

`lib/src` follows one declaration per file with a limit of 100 lines, no
`else` branches and no inline comments. `test/conventions_test.dart` enforces
it. Large extensions are split into named chunks (for example
`CryptoLibBbsProofGen`), all re-exported by the package barrel, so every method
stays reachable from a single import.

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

## Updating the bundled binaries

The prebuilt binaries are committed and published with the package. They go
stale after any C ABI change because the Dart side resolves every symbol, so a
stale binary fails at load. Rebuild from the repository root:

```bash
bash scripts/android/build_all.sh arm64-v8a x86_64
cp build/android/arm64-v8a/libcryptolib_c.so android/src/main/jniLibs/arm64-v8a/
cp build/android/x86_64/libcryptolib_c.so android/src/main/jniLibs/x86_64/
make ios
rm -rf ios/cryptolib_flutter/CryptoLibC.xcframework macos/cryptolib_flutter/CryptoLibC.xcframework
cp -R CryptoLib.xcframework ios/cryptolib_flutter/CryptoLibC.xcframework
cp -R CryptoLib.xcframework macos/cryptolib_flutter/CryptoLibC.xcframework
```

Then check that the symbol count matches the header:

```bash
grep -c '^CRYPTO_API' bridge/cryptolib_c.h
nm -gU ios/cryptolib_flutter/CryptoLibC.xcframework/ios-arm64/CryptoLibC.framework/CryptoLibC | grep -c ' T _cryptolib_'
strings android/src/main/jniLibs/arm64-v8a/libcryptolib_c.so | grep -c '^cryptolib_'
```

Before publishing, run the consumer proof from the repository root. It installs
the exact archive as a hosted package in a fresh app and runs this package's
test suite on a device:

```bash
make flutter-consumer DEVICE=macos
```

## License and attribution

MIT, see [LICENSE](LICENSE). The license requires that the copyright notice,
which credits the author Crdzbird, is kept in every copy or substantial
portion of this software, including apps and libraries that bundle it.
