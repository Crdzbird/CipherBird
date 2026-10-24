# cipherbird_dart

Native cryptography for Dart on the server, in command-line tools, in
desktop programs and in the browser. CipherBird binds its native C++ engine
through `dart:ffi`, or through a WebAssembly build of the same engine on the
web, and ships the compiled library inside the package for the host platform
and for the browser, so a program gets hashing, authenticated encryption, public-key
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
| Media | media entropy with a live stream source, DRBG, Fortuna, steganography, forward error correction | |

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
| Engine binaries | host slot under `native/<os>-<arch>/`, macOS on Apple silicon in this release, and WebAssembly for the web | Android arm64-v8a and x86_64, iOS device and simulator, macOS, and WebAssembly for the web |
| How the engine is found | the package's `native/` directory via `.dart_tool/package_config.json`, the current directory or the script location; the package asset on the web | the process image on iOS and macOS, `jniLibs` on Android, the package asset on the web |
| Download size | about 7 MB | about 17 MB |
| API, wire formats, tests | identical | identical |

## Install

```bash
dart pub add cipherbird_dart
```

| Platform | Status |
|---|---|
| macOS, Apple silicon | library bundled under `native/darwin-arm64` |
| Web (dart2js and dart2wasm) | WebAssembly engine bundled under `lib/assets` |
| Linux x64, Windows x64, Intel macOS | not bundled in this release; build the library from the repository and point `CIPHERBIRD_LIBRARY` at it |

No setup call is needed. `CipherBird.load()` resolves the library in this
order: an explicit path, the `CIPHERBIRD_LIBRARY` environment variable, the
bundled copy found through the program's `.dart_tool/package_config.json`,
the current directory or the directory above the running script, then the
loader path. A release build (`dart compile exe`, or any build with
`dart.vm.product`) skips the environment variable, the package
configuration and the current directory: it opens only an explicit path or
`native/<os>-<arch>/` beside the executable's directory, so ship the library
file with the binary or pass its path.

`CipherBird.preload()` returns immediately on native platforms; the first
use of `CipherBird.instance` opens the library synchronously. In the browser
it is the one await that fetches and compiles the engine, unless the page
boots the engine itself and the build opts in to adopting it, see Web.

## Hardware slots

The keyring's hardware slots (`keyringBeginHardwareSlot`,
`keyringSetHardwareBlob`, `keyringSlotType`, `keyringHardwareSlot`,
`keyringUnlockWithHardwareFactor`) are available here for programs that
bring their own key module; the Secure Enclave and Android Keystore
integration (`HardwareKey`) ships only in the Flutter plugin.

## Web

The package also runs in the browser, compiled with either `dart compile js`
or `dart compile wasm`. The engine ships inside the package as
`lib/assets/cipherbird.js` and `lib/assets/cipherbird.wasm` (about 4 MB),
served by `webdev` and `dart test -p chrome` under
`packages/cipherbird_dart/assets/`. Browsers compile a module of that size
asynchronously, so await `CipherBird.preload()` once before the first use
(`CipherBird.ready` is the same future for code that runs later):

```dart
Future<void> main() async {
  await CipherBird.preload();
  final digest = CipherBird.instance.sha256('abc'.bytes).hex;
}
```

`dart run cipherbird_dart:web_setup` inserts the engine tag into
`web/index.html` with the Subresource Integrity digest of the bundled file,
so the download starts early and the browser refuses changed bytes; rerun
it after upgrading the package. To add it by hand, take the digest from
`lib/src/engine_integrity.dart`. The loader and the worker check the same
digests on everything they fetch.

To drop the await, run `web_setup --boot` (adds `cipherbird_boot.js`, which
instantiates the engine as soon as it arrives) and compile with
`-DCIPHERBIRD_PAGE_ENGINE=true`; the package then adopts the page's engine
synchronously. This is off by default because it trusts the
`self.cipherbirdEngine` global, that is, every script on the page. Keep the
await where the first use may run before the boot script finishes; it
returns at once when the engine is already there.

The browser build is not approved for long-lived keys or card data, and
`CipherBird.requireApprovedFor` fails closed for them on the web: the
engine's linear memory is readable by every script on the page, so keys
that outlive one operation belong on the native platforms, where the
package wipes its native copies on free and `SecretBytes` gives key
material a definite end of life.

For a deployment that does not serve `packages/`, copy the two files next to
the app and pass their location: `CipherBird.preload(library:
'/engine/cipherbird.js')`. In the browser there are no isolates, so
`CipherBirdIsolateRunner` runs every job, the Argon2id ones and any
`EngineCallJob` behind the asynchronous methods, in a web worker
(`cipherbird_worker.js`, spawned when the engine loads) that holds its own
engine; the file-path methods have byte-based twins that work in the
browser through the engine's in-memory file system, and AES-256-GCM uses
OpenSSL's portable implementation with byte-identical output. Everything else,
including every envelope and key format, matches the native build.

`dart run cipherbird_dart:web_setup --check` reads the page and reports what it has
and lacks: the two tags and whether their digests are current, a preload
link, and a Content Security Policy that lets the worker spawn, plus the
host settings it cannot see.

### Serving the engine

The engine is fetched with its subresource integrity digest and
instantiated from the verified bytes, so the host can serve it as any
static file. Three settings make it fast:

- Compress with Brotli (or gzip): the 2.99 MB engine is about 0.9 MB on
  the wire under Brotli.
- Send `Cache-Control: public, max-age=31536000, immutable` for
  `cipherbird.wasm` and `cipherbird.js`; a new package version ships new
  digests, so a cached engine is never used with the wrong digest.
- Add `<link rel="preload" href=".../cipherbird.wasm" as="fetch" crossorigin>`
  next to the two boot tags so the download starts with the page.

A Content Security Policy without `unsafe-eval` is enough: the engine is
instantiated from bytes, not evaluated. The cross-origin isolation
headers (`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`) are not needed by this
engine; they will select a threaded engine when one ships.

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

All 320 native operations are reachable on `CipherBird`, flat or through
grouped views. Every operation takes and returns `Uint8List`, throws on
failure and never returns partial data.

| Group | Operations |
|---|---|
| `lib.hash` | SHA-256, SHA-512, BLAKE2b, BLAKE3, HMAC, HKDF, Argon2id |
| `lib.aead` | XChaCha20-Poly1305, AES-256-GCM, committing AEAD, SecretStream |
| `lib.asym` | Ed25519, X25519, boxes, sealed boxes |
| `lib.pq` | `mlKem`, `mlDsa`, `slhDsa`, `hybridKem`, `hybridSig`, `sntrup`, X-Wing |
| `lib.sealed`, `lib.channel`, `lib.session` | sealed messaging, Noise XX, forward-secret ratchet |
| `lib.hpke`, `lib.opaque`, `lib.oprf` | HPKE, OPAQUE login, OPRF |
| `lib.bbs`, `lib.frost`, `lib.ecvrf`, `lib.bls` | anonymous credentials, threshold Ed25519, VRF, BLS12-381 |
| `lib.vault`, `lib.keyring`, `lib.suite`, `lib.composed` | vaults, keyrings, one-call combinations |
| `lib.entropy`, `lib.stego`, `lib.rng`, `lib.chain` | media entropy, steganography, DRBG and Fortuna, Keccak and secp256k1 |

## Post-quantum envelopes

The standards-track surface a regulated deployment uses, all over X-Wing
(ML-KEM-768 + X25519) with the Ed25519 + ML-DSA-65 hybrid signature:

```dart
final bob = lib.xwingKeygen();
final alice = lib.hybridSigKeygen();
final env = lib.suite2Seal(message, bob.publicKey, alice.secretKey, aad: ctx);
final plain = lib.suite2Open(env, bob.secretKey, bob.publicKey, alice.publicKey, aad: ctx);
```

The Suite v2 signature covers the recipient key, the KEM ciphertext and the
associated data, so an envelope cannot be re-addressed. Session v2 is the
forward-secret ratchet behind an authenticated handshake: the responder
publishes a prekey bundle signed by its identity (`generateSession2Prekey`),
the initiator verifies it and signs the handshake (`initiateSession2`), and
the responder accepts only the identity it expects (`acceptSession2`), which
the application pins through a directory, a certificate or a prior session.
HPKE takes a KEM of your choice through `HpkeKem` and the `*Kem` setup
calls, and every `SecurityProfile` selects X-Wing.

`ProtectedDataClass` with `approvedFor` and `requireApprovedFor` state what a
build is approved to protect: native builds everything, the web build
ephemeral data only.

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

The harness in `cipherbird_dart/benchmark/bench.dart` runs each operation
for two seconds after one warm-up call and reports the mean. Apple M3 Max,
macOS 26.6, Dart 3.13.5, pointycastle 3.9.1, cryptography 2.9.0, crypto
3.0.7, measured on 2026-10-22. Throughput rows are in MB/s on 1 MiB
inputs; the rest are operations per second. Every cell also gives the mean
time of one operation, and every comparison cell the factor and the time
difference against cipherbird for that one operation (a positive
difference is time the other package needs on top). The "vs 1.1.0 engine"
column is the change against the 1.1.0 engine measured in the same session
on the same machine state (`bench.dart --emit-json` on the old library,
then `--previous`), so it reflects the engine rather than the machine.
Another process was using about three cores during this session, which is
why the absolute figures are lower than the 1.1.0 table for every column,
the pure-Dart packages included; the differences within a table are fair.

| Operation | cipherbird (native) | vs 1.1.0 engine | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 217 MB/s, 4.60 ms | -7% | 74 MB/s, 13.5 ms (2.9x slower, +8.87 ms) | 90 MB/s, 11.1 ms (2.4x slower, +6.49 ms) | 91 MB/s, 11.0 ms (2.4x slower, +6.40 ms) |
| BLAKE2b-512, 1 MiB | 514 MB/s, 1.94 ms | +23% | 31 MB/s, 32.1 ms (16.5x slower, +30.2 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 820 MB/s, 1.22 ms | +3% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 296 MB/s, 3.38 ms | +14% | 46 MB/s, 21.6 ms (6.4x slower, +18.2 ms) | 26 MB/s, 38.5 ms (11.4x slower, +35.1 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 651 MB/s, 1.54 ms | +17% | 1 MB/s, 901.5 ms (586.7x slower, +900.0 ms) | 14 MB/s, 71.9 ms (46.8x slower, +70.3 ms) | n/a |
| Ed25519 sign, 1 KiB | 49597 ops/s, 20.2 us | +20% | n/a | 424 ops/s, 2.36 ms (116.9x slower, +2.34 ms) | n/a |
| Ed25519 verify, 1 KiB | 21576 ops/s, 46.3 us | +8% | n/a | 421 ops/s, 2.37 ms (51.2x slower, +2.33 ms) | n/a |
| X25519 shared secret | 25549 ops/s, 39.1 us | +6% | n/a | 1501 ops/s, 666.1 us (17.0x slower, +627.0 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 14.1 ops/s, 70.7 ms | -3% | 1.8 ops/s, 563.8 ms (8.0x slower, +493.2 ms) | 2.6 ops/s, 386.4 ms (5.5x slower, +315.7 ms) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 14079 ops/s, 71.0 us | +9% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 4272 ops/s, 234.1 us | +10% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2308 ops/s, 433.2 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 9407 ops/s, 106.3 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1614 ops/s, 619.5 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 4425 ops/s, 226.0 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 4309 ops/s, 232.1 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 1129 ops/s, 885.6 us | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 573 ops/s, 1.75 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 11485 ops/s, 87.1 us | new | n/a | n/a | n/a |

The same measurements as time only, against the fastest alternative for
each operation:

| Operation | cipherbird (native) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 4.60 ms | crypto | 11.0 ms | +6.40 ms |
| BLAKE2b-512, 1 MiB | 1.94 ms | pointycastle | 32.1 ms | +30.2 ms |
| BLAKE3, 1 MiB | 1.22 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 3.38 ms | pointycastle | 21.6 ms | +18.2 ms |
| AES-256-GCM encrypt, 1 MiB | 1.54 ms | cryptography | 71.9 ms | +70.3 ms |
| Ed25519 sign, 1 KiB | 20.2 us | cryptography | 2.36 ms | +2.34 ms |
| Ed25519 verify, 1 KiB | 46.3 us | cryptography | 2.37 ms | +2.33 ms |
| X25519 shared secret | 39.1 us | cryptography | 666.1 us | +627.0 us |
| Argon2id, 64 MiB, 2 passes | 70.7 ms | cryptography | 386.4 ms | +315.7 ms |
| ML-KEM-768 keygen + encapsulate + decapsulate | 71.0 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 234.1 us | none | | |
| ML-DSA-65 sign, 1 KiB | 433.2 us | none | | |
| ML-DSA-65 verify, 1 KiB | 106.3 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 619.5 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 226.0 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 232.1 us | none | | |
| Suite v2 seal + open, 1 KiB | 885.6 us | none | | |
| Session v2 handshake (prekey, initiate, accept) | 1.75 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 87.1 us | none | | |

The same suite in Chrome 155, compiled with dart2js, against the
WebAssembly engine (`dart test -p chrome` in `benchmark/`). Two columns
need reading with care. `cryptography` hands SHA-256, AES-GCM and the
Ed25519 and X25519 operations to the browser's own Web Crypto API, which is
native code with hardware AES and SHA, so it beats any WebAssembly
implementation on those rows; `pointycastle` and `crypto` stay pure Dart,
and `pointycastle`'s ChaCha20 implementation does not run under dart2js. On
everything Web Crypto does not offer, the engine remains the fast option in
the browser: BLAKE2b, BLAKE3, XChaCha20-Poly1305, Argon2id and the
post-quantum algorithms. The browser cannot swap engines in one session, so
its change column compares against the figures published for 1.1.0, taken
on an idle machine, and overstates the slowdown by the load noted above.

| Operation | cipherbird (WebAssembly) | vs 1.1.0 published | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 63 MB/s, 15.8 ms | -38% | 2 MB/s, 605.0 ms (38.3x slower, +589.2 ms) | 1452 MB/s, 688.7 us (23.0x faster, -15.1 ms) | 118 MB/s, 8.45 ms (1.9x faster, -7.36 ms) |
| BLAKE2b-512, 1 MiB | 73 MB/s, 13.7 ms | -45% | 2 MB/s, 408.5 ms (29.8x slower, +394.8 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 72 MB/s, 13.9 ms | -45% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 63 MB/s, 15.8 ms | -39% | error: PlatformException | 36 MB/s, 27.6 ms (1.7x slower, +11.7 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 39 MB/s, 25.8 ms | -24% | 1 MB/s, 1.56 s (60.6x slower, +1.54 s) | 1708 MB/s, 585.5 us (44.0x faster, -25.2 ms) | n/a |
| Ed25519 sign, 1 KiB | 15914 ops/s, 62.8 us | -13% | n/a | 13137 ops/s, 76.1 us (1.2x slower, +13.3 us) | n/a |
| Ed25519 verify, 1 KiB | 7993 ops/s, 125.1 us | -6% | n/a | 16631 ops/s, 60.1 us (2.1x faster, -65.0 us) | n/a |
| X25519 shared secret | 10129 ops/s, 98.7 us | -1% | n/a | 10532 ops/s, 95.0 us (1.0x faster, -3.77 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 11.9 ops/s, 84.3 ms | +1% | 0.1 ops/s, 18.83 s (223.4x slower, +18.75 s) | 0.3 ops/s, 3.56 s (42.2x slower, +3.47 s) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 4913 ops/s, 203.6 us | -16% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 1946 ops/s, 513.9 us | +5% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2116 ops/s, 472.7 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 5104 ops/s, 195.9 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1293 ops/s, 773.5 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 2150 ops/s, 465.1 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 1993 ops/s, 501.8 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 807 ops/s, 1.24 ms | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 391 ops/s, 2.56 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 7651 ops/s, 130.7 us | new | n/a | n/a | n/a |

As time only, against the fastest alternative in the browser:

| Operation | cipherbird (WebAssembly) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 15.8 ms | cryptography | 688.7 us | -15.1 ms |
| BLAKE2b-512, 1 MiB | 13.7 ms | pointycastle | 408.5 ms | +394.8 ms |
| BLAKE3, 1 MiB | 13.9 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 15.8 ms | cryptography | 27.6 ms | +11.7 ms |
| AES-256-GCM encrypt, 1 MiB | 25.8 ms | cryptography | 585.5 us | -25.2 ms |
| Ed25519 sign, 1 KiB | 62.8 us | cryptography | 76.1 us | +13.3 us |
| Ed25519 verify, 1 KiB | 125.1 us | cryptography | 60.1 us | -65.0 us |
| X25519 shared secret | 98.7 us | cryptography | 95.0 us | -3.77 us |
| Argon2id, 64 MiB, 2 passes | 84.3 ms | cryptography | 3.56 s | +3.47 s |
| ML-KEM-768 keygen + encapsulate + decapsulate | 203.6 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 513.9 us | none | | |
| ML-DSA-65 sign, 1 KiB | 472.7 us | none | | |
| ML-DSA-65 verify, 1 KiB | 195.9 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 773.5 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 465.1 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 501.8 us | none | | |
| Suite v2 seal + open, 1 KiB | 1.24 ms | none | | |
| Session v2 handshake (prekey, initiate, accept) | 2.56 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 130.7 us | none | | |

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
pure C ABI of 320 functions, bindings for ten languages, known-answer tests
from the official sources, and a cross-language conformance harness. Its
repository holds the build, the tests, the benchmark and the design notes.
Everything is MIT licensed; the vendored dependencies are BSD, MIT, Apache
or public domain. The license requires that the copyright notice, which
credits the author Crdzbird, is kept in every copy or substantial portion of
this software.

## Media entropy: the health report and a live source

`assessFileHealth(path)` returns every number behind the verdict: the two
SP 800-90B estimates (`mcvBitsPerByte`, `markovBitsPerByte`) and their
minimum, the sample size, the longest run of one byte with the
`rctCutoff` it is judged against, the peak window count with `aptCutoff`,
both verdicts, and `summary`, the engine's own explanation one line per
signal. The cutoffs are calibrated against `floorBitsPerByte` (1.0 by
default, the same floor the harvests require), so a real photo with a
short run of padding passes and a blank image fails; a refusal from
`entropyFromFile` or `entropyFromFileWithPolicy` names the figure, the
cutoff and the setting that would relax it.

`liveEntropy()` (also `lib.rng.live()`) is the continuous form. Feed it
camera frames, audio buffers or any bytes as they arrive:

```dart
final live = lib.liveEntropy(minBitsPerByte: 1.0, requireRct: true);
final report = live.feed(frame.planes.first.bytes, sourceId: 1);
if (!report.accepted) print(report.reason);
if (report.ready) final key = live.generate(32);
final status = live.status();
live.close();
```

Each chunk is assessed under the policy, credited `minEntropyPerByte *
length` bits when it passes and mixed in without credit when it does not,
with the repetition-count run carried across chunks. `generate` draws from
an HMAC-DRBG seeded once 256 credited bits have arrived (`minCreditedBits`)
and reseeded every time that much arrives again; it throws until then.
Chunks below 1024 bytes are mixed but never credited.

## Media on bytes, on every platform

Every file-taking media entry point has a byte-based twin, so a carrier or
a key photo picked in a browser, or held in memory, works the same on the
web as on a phone: `stegoEmbedBytes`, `stegoExtractBytes`,
`stegoCapacityOf`, `stegoInspectBytes`, `stegoDetectHiddenBytes`,
`stegoContentDigestOf`, the keyed and encrypted forms,
`physicalSealBytes` and `physicalOpenBytes`, `hpkeStegoSealBytes` and
`hpkeStegoOpenBytes`, `imageFactorSealBytes` and `imageFactorOpenBytes`,
`entropyFromBytes`, `assessHealthOf`, `keyFromBytes`, `sealWithBytes`,
`openWithBytes`, and `KeyBytesSource` for a recipe. Each takes the
carrier's `MediaFormat`, since the engine dispatches on the container.

```dart
final carrier = lib.stegoEmbedEncryptedBytes(photo, MediaFormat.pngImage, secret, key);
final back = lib.stegoExtractDecryptBytes(carrier, MediaFormat.pngImage, key);
```

In the browser the bytes pass through the engine's in-memory file system
and are removed afterwards; natively they pass through a private temporary
directory and are overwritten before removal. The path-taking methods
stay as they were.

## Off the main thread

The runner seam moves heavy work to a background isolate natively and to
the engine worker in the browser, where the worker holds its own copy of
the engine. `EngineCallJob` describes one engine entry point by symbol,
with its arguments as plain data (bytes, strings, integers, a scratch file
or an output file) and how it returns, so any entry point can run on a
worker; the asynchronous methods are built on it: `mlDsaKeygenAsync`,
`mlDsaSignAsync`, `slhDsaKeygenAsync`, `slhDsaSignAsync`,
`hybridSigSignAsync`, `suite2SealAsync`, `suite2OpenAsync`,
`stegoEmbedBytesAsync`, `stegoExtractBytesAsync`,
`stegoEmbedEncryptedBytesAsync`, `stegoExtractDecryptBytesAsync`,
`keyFromBytesAsync`, next to the Argon2id ones.

```dart
final sig = await lib.slhDsaSignAsync(message, sk, SlhDsaLevel.fast128, SlhDsaHash.shake);
final carrier = await lib.stegoEmbedEncryptedBytesAsync(photo, MediaFormat.pngImage, secret, key);
```

Each takes a `runner`; the default is `CipherBirdIsolateRunner`, and
`CipherBirdInlineRunner` keeps tests deterministic. Handles such as
sessions and live sources belong to the engine that made them and stay on
the calling thread.
