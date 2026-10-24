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
| Media | media entropy with a live stream source, DRBG, Fortuna, steganography, forward error correction | |

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
| Startup | none; lazy on first use, and on the web the engine starts loading at plugin registration, gate the first use on `CipherBird.ready` | none; lazy on first use, on the web await `CipherBird.ready` once |
| Build integration | Flutter's plugin tooling, nothing to configure | none needed; `dart run`, `dart test` and `dart compile exe` (pass the library path) |
| Download size | about 17 MB | about 7 MB |
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

One await at startup, the same on every platform:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CipherBird.preload();
  runApp(const MyApp());
}
```

On Android, iOS and macOS the call returns immediately: the library opens
synchronously on first use, so skipping it is also fine there. In the
browser the plugin registration starts downloading the WebAssembly engine
before `main` runs, and `preload` joins that download, so the await covers
only whatever transfer time is left. Code that runs later and only needs to
wait can await `CipherBird.ready`, the same future.

On the web, run this once from the app root (idempotent; `--remove` takes
the tag out again):

```bash
dart run cipherbird:web_setup
```

It adds the engine script to `web/index.html` with the Subresource
Integrity digest of the bundled file (`integrity="sha384-..."
crossorigin="anonymous"`), so the download starts in parallel with
Flutter's bootstrap and the browser refuses an engine whose bytes differ
from the ones the package was built with. The Dart loader and its worker
apply the same digests to everything they fetch. Rerun the command after
upgrading the package to refresh the digest; to add the tag by hand, take
the digest from `lib/src/engine_integrity.dart`.

The await itself can be dropped on the web as well, as an opt-in:

```bash
dart run cipherbird:web_setup --boot
flutter build web --dart-define=CIPHERBIRD_PAGE_ENGINE=true
```

`--boot` adds `cipherbird_boot.js`, which instantiates the engine as soon
as it arrives, and the define makes the package adopt that engine
synchronously: `CipherBird.instance` works from the first line of `main`
and `await CipherBird.preload()` returns at once if you keep it. This is
off by default because adopting the engine means trusting the
`self.cipherbirdEngine` global, that is, every script running on the page;
turn it on only for pages whose scripts you control. Without the define,
`preload` always loads the engine itself through the digest-checked path,
and a direct `CipherBird.instance` before it completes throws a
`StateError` that says to await it.

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

All 320 native operations are reachable on `CipherBird`, flat or through
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
| `lib.pq` | `mlKem`, `mlDsa`, `slhDsa`, `hybridKem`, `hybridSig`, `sntrup`, X-Wing |
| `lib.sealed` | identities, seal, open, streaming, envelope inspection, recipient matching |
| `lib.channel` | Noise XX handshake and transport with re-entrant decryption by counter |
| `lib.session` | post-quantum forward-secret session ratchet, version 1 and the authenticated Session v2 |
| Suite v2, `fips*` | recipient-bound signed envelopes; the engine's FIPS Provider layer |
| `lib.hpke` | HPKE in all four modes, single-shot and context forms, with DHKEM(X25519), ML-KEM-768 or X-Wing |
| `lib.opaque`, `lib.oprf` | OPAQUE password login and the OPRF it builds on |
| `lib.bbs` | BBS signatures, selective disclosure, pseudonyms, blind issuance |
| `lib.frost`, `lib.ecvrf`, `lib.bls` | threshold Ed25519, verifiable random function, BLS12-381 |
| `lib.vault`, `lib.keyring` | symmetric and asymmetric vaults, MolecularVault, keyrings |
| `lib.suite`, `lib.composed` | one-call combinations: post-quantum messages, threshold vaults, file-as-key vaults, physical-media seals, HPKE into a carrier |
| `lib.entropy`, `lib.stego`, `lib.rng` | media entropy and health, DRBG, Fortuna, steganography, forward error correction |
| `lib.chain` | Keccak-256, secp256k1 sign and recover, EVM addresses |

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

## Hardware-backed keys

`package:cipherbird/cipherbird_hardware.dart` puts the possession factor
in the platform key module: the Secure Enclave on iOS and macOS, and the
Android Keystore, in StrongBox when the device has one and otherwise in the
trusted execution environment (the fallback is reported in `backing`, never
silent). The key never leaves the module. It wraps a keyring slot, so the
keyring master is recoverable only through the module, and a key created
with `biometric: true` unwraps only after the user passes the system
biometric prompt (`LAContext` on Apple, `BiometricPrompt` with a
`CryptoObject` on Android).

```dart
import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';

final key = await HardwareKey.create('bank-possession', biometric: true);
final lib = CipherBird.instance;
final kr = lib.keyringCreate();
await lib.keyringAddHardwareSlot(kr, key);
final envelope = lib.keyringSerialise(kr);

final loaded = lib.keyringDeserialise(envelope);
final master = await lib.keyringUnlockWithHardware(loaded, key, reason: 'Open your vault');
master.wipe();
```

Attestation is for your server: `key.attest(challenge)` returns an App
Attest attestation object (Apple) computed over
`SHA-256(challenge || enclave public key)`, or the Android key attestation
certificate chain of a companion EC key generated with the challenge at the
same security level. The documents are returned to the app and are not
stored in the keyring envelope. Envelopes with a hardware slot carry
version 2, which earlier package versions refuse to parse.

Not every environment has a module: the iOS simulator uses a software key
and reports `HardwareBacking.software`, App Attest is unavailable there,
emulators land in the TEE, and the browser and the pure Dart package have
no key module at all (`HardwareKeyException` with code `unsupported`).
Requires Android 9 (API 28) for hardware keys and biometric gating.
On macOS the Secure Enclave key lives in the data protection keychain,
which requires the host app to be signed with a Team ID (an ad-hoc or
"sign to run locally" build fails with `errSecMissingEntitlement`,
status -34018).

## Validated modules

`package:cipherbird/cipherbird_fips.dart` performs the approved operations
(SHA-2, HMAC, HKDF, PBKDF2, DRBG, AES-256-GCM, P-256 ECDH and ECDSA) inside
the module the platform already validated, so a regulated app keeps them in a
CMVP boundary on every platform it ships to: Apple corecrypto behind
CryptoKit on iOS and macOS, the Android platform providers on Android, and
the OpenSSL FIPS Provider (certificate #4985) when the engine was built as
the fips profile.

```dart
final fips = DeviceFips.platform();
final info = await fips.module();
final tag = await fips.hmac(FipsHash.sha256, key, message);
```

`module()` reports what served the calls so the app can refuse a device
whose provider is not the expected one. On Android the HKDF and PBKDF2
loops run in the app around the provider's HMAC and are reported as
composed. In the browser the same facade runs on WebCrypto, the
platform's own crypto, with the same wire formats, and `module()` states
that it is not a validated module as exposed to pages. Flutter only. The
same operations are on the engine as the `fips*` family when the engine was
built with `CRYPTOLIB_PROFILE=fips`; on the bundled engine `fipsAvailable`
is false.

## Web

The same package runs in the browser. The engine is compiled to WebAssembly
with Emscripten and ships inside the package as `assets/cipherbird.js` and
`assets/cipherbird.wasm`, about 4 MB, fetched once when the app starts. The
Dart API is identical. Browsers only compile a module of that size
asynchronously, so there are two ways to run:

- **By default** the plugin registration starts the download before
  `main`, every file is checked against its integrity digest, and
  `await CipherBird.preload()` in `main` waits for the compilation; the
  await is required in this setup.
- **With `web_setup --boot` and `--dart-define=CIPHERBIRD_PAGE_ENGINE=true`**
  the page instantiates the engine while Flutter bootstraps and the package
  adopts it synchronously, so no await is needed; see Install for what that
  trusts.

The browser build is not approved for long-lived keys or card data, and
`CipherBird.requireApprovedFor` fails closed for them on the web. The
engine's linear memory is readable by every script on the page, so a key
that outlives one operation, or cardholder data at rest, belongs on the
native platforms (where the package wipes its native copies on free and
`SecretBytes` gives key material a definite end of life). Use the web
build for session-scoped operations.

The engine is found at the package asset path. To serve it from somewhere
else, call `CipherBird.preload(library:
'https://cdn.example.com/engine/cipherbird.js')` (the `.wasm` file is fetched
from the same directory) or set the `CIPHERBIRD_LIBRARY` compile-time
define. Both `flutter build web` and `flutter build web --wasm` are
supported; the test suite runs under both.

What differs in the browser:

- Envelopes, signatures and keys are byte-compatible with every other
  platform. A message sealed in the browser opens on a phone or a server and
  the other way round.
- There are no isolates, so `CipherBirdIsolateRunner` uses a web worker
  instead: `assets/cipherbird_worker.js` loads a second copy of the engine
  and runs every job off the main thread, the Argon2id ones and any
  `EngineCallJob` behind the asynchronous methods. The worker is spawned
  through a blob when the engine loads, which a strict Content Security
  Policy must allow (`worker-src blob:`).
- The browser has no filesystem, so the methods that take a file path
  (media entropy from a file, key files, suite calls with a file,
  steganography carriers on disk) have byte-based twins that work there
  through the engine's in-memory file system; see "Media on bytes" below.
- `DeviceFips` runs on WebCrypto, the browser's own crypto; `module()`
  states that it is not a validated module as exposed to pages.
- AES-256-GCM uses OpenSSL's portable implementation because WebAssembly has
  no AES instructions. Output is byte-identical to the hardware path.
- 64-bit integer parameters are exact up to 2^53.

`dart run cipherbird:web_setup --check` reads the page and reports what it has
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

The [example](example) is a showcase with one screen per capability
(overview and approvals, primitives, post-quantum, envelopes, hardware keys,
the validated module), each row a live check, plus a Play tab of
interactive playgrounds: hashes and MACs, symmetric encryption with a bit
flip, signatures, HPKE with a chosen KEM, Suite v2 with Bob and Carol, a
Session v2 chat with Mallory, hardware keys and the validated module. Its
integration tests run every section and press every button on a device.

The [playground](playground) is the earlier single-screen app: encrypt,
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
cp build/android/arm64-v8a/libcryptolib_c.so android/src/main/jniLibs/arm64-v8a/libcipherbird.so
cp build/android/x86_64/libcryptolib_c.so android/src/main/jniLibs/x86_64/libcipherbird.so
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
pure C ABI of 320 functions, bindings for ten languages, a custom test runner
with known-answer tests from the official sources, and a cross-language
conformance harness. Its repository holds the build, the tests, the
benchmark and the design notes. Everything is MIT licensed; the vendored
dependencies are BSD, MIT, Apache or public domain. The license requires that
the copyright notice, which credits the author Crdzbird, is kept in every
copy or substantial portion of this software.

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
