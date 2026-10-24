## Unreleased

- `web_setup --check` reports what a page has and lacks for the engine;
  the READMEs gain hosting guidance (Brotli, an immutable cache header, a
  preload link, the Content Security Policy the worker needs), and a Pages
  workflow publishes the showcase for the browser.
- The WebAssembly engine is 37% smaller (4.78 MB to 2.99 MB): OpenSSL is
  trimmed as in the native builds and secp256k1 uses the small
  precomputed tables, at the same speed.
- The WebAssembly engine and its dependencies are built with SIMD:
  Argon2id takes 38% less time and ML-KEM-768 11% less in Chrome, the
  hashes and ciphers are unchanged, the engine is 5% larger.
- `DeviceFips` in the browser runs on WebCrypto, the platform's own
  crypto: SHA-2, HMAC, HKDF, PBKDF2, random bytes, AES-256-GCM in the
  engine's wire layout, and P-256 ECDH and ECDSA with DER signatures, with
  known-answer and engine-interoperability tests in Chrome. `module()`
  states that it is the browser platform crypto and not a validated module
  as exposed to pages.
- Heavy work off the main thread on every platform: `EngineCallJob`
  describes one engine entry point by symbol as plain data, the web worker
  runs any such call on its own engine, and the asynchronous methods
  (`mlDsaSignAsync`, `slhDsaSignAsync`, `hybridSigSignAsync`,
  `suite2SealAsync`, `stegoEmbedBytesAsync` and the rest) use it through
  the runner seam, a background isolate natively.
- Steganography, media entropy and the composed seals on bytes, on every
  platform including the browser: `stegoEmbedBytes` and the rest of the
  byte-based twins of the file-taking methods, `entropyFromBytes`,
  `assessHealthOf`, `keyFromBytes`, `sealWithBytes`, `openWithBytes` and
  `KeyBytesSource`, each taking the carrier's `MediaFormat`. The engine
  carries an in-memory file system for the web; natively a private
  temporary directory is used and wiped. The Chrome suites of both
  packages now run in CI.
- The health report says everything behind its verdict: both SP 800-90B
  estimates, the sample size, the longest run with the repetition-count
  cutoff, the peak window count with the adaptive-proportion cutoff, the
  floor the cutoffs were calibrated for, and a `summary` the engine writes
  one line per signal. The cutoffs now follow the floor the policy claims
  (31 identical bytes at the default one bit per byte) instead of the
  entropy measured, so a real photograph with a short run of padding in
  its header passes while a blank image still fails; a refusal names the
  figure, the cutoff and the setting that would relax it.
  `assessFileHealth` takes `floorBitsPerByte`.
- `liveEntropy()` and `lib.rng.live()`: a continuous entropy source for a
  stream. Feed camera frames, audio buffers or any bytes as they arrive;
  each chunk is assessed under the policy, credited when it passes and
  mixed in without credit when it does not, with the reason reported and
  the repetition-count run carried across chunks. `generate` draws from an
  HMAC-DRBG seeded after 256 credited bits and reseeded as credit keeps
  arriving; it throws until the first seed. `status()` reports the credit,
  the counters and the last verdict.
- Media entropy assesses every source before trusting it: two SP 800-90B
  estimators (the Most-Common-Value bound over the whole file and the
  Markov bound over the bit expansion of the first MiB) with the
  repetition-count and adaptive-proportion tests. The plain harvests now
  refuse a file below one bit of min-entropy per byte or one that fails the
  repetition-count test; `entropyFromFileWithPolicy` takes the floor and
  the test requirement explicitly, and 0 with `requireRct: false` accepts
  any file. The engine's `entropyInfo` estimate is now that min-entropy
  lower bound rather than the earlier Shannon figure, so it reads lower for
  the same file.
- The media readers are fuzzed from a seed corpus of every format in CI
  and every night with a persisted corpus. The campaigns found and fixed
  five ways a crafted file could exhaust memory or divide by zero before
  any payload check: a GIF that declares more pixels than its data could
  encode, GIF or oversized bytes reaching the PNG decoder, a PNG chunk
  length beyond the end of the file, a progressive JPEG with no size
  check before decode, and a WAV with zero channels (in both the WAV and
  the FLAC reader). Every image carrier now caps at 67 million pixels and
  the PNG and JPEG readers validate the declared size before decoding.
- The example app's Play tab gains two playgrounds. Steganography generates
  a photo or a sound, or takes any image, sound or video picked from the
  device, hides a secret seven ways (plain, keyed placement,
  encrypted, physical seal, HPKE, image factor, or a recipe whose profile,
  layers, error correction, signature and key source are each a pick),
  shows the carrier before and after, reveals with the right and the wrong
  key, inspects, runs detection and damages the file. LavaRand reads a
  source's health report, harvests it under the policy the developer sets,
  derives keys, seeds a DRBG and Fortuna, and seals with the file directly
  or through a recipe keyed by it. Both take any file the system picker
  offers, and the health line is the engine's own summary. A Live entropy
  playground feeds camera frames or any picked file into the live source,
  shows every chunk and the credit arriving on a meter, and draws a key
  and re-encrypts a message on every credited chunk, so the ciphertext
  follows the stream; on every reseed or by hand are the other modes. The
  three media playgrounds run in the browser too, with the camera through
  getUserMedia.

## 1.2.0

The bank-readiness release: the standards-track post-quantum surface, the
validated-module routing, the explicit approval boundary, and the
supply-chain and loader hardening from the assessment. Existing APIs and
wire formats are unchanged; the new envelopes carry new ids and versions.

- Standards-track post-quantum surface from the bank-readiness assessment
  (findings M4, M5, M6): X-Wing (draft-connolly-cfrg-xwing-kem-11) with
  `xwingKeygen`, `xwingKeypairFromSeed`, `xwingEncapsulate` and
  `xwingDecapsulate`; HPKE with a chosen KEM through `HpkeKem`
  (DHKEM(X25519), ML-KEM-768, X-Wing), `hpkeKeygenKem`,
  `hpkeDeriveKeypairKem`, `hpkeSetupSKem` and `hpkeSetupRKem`; Suite v2
  envelopes (`suite2Seal`, `suite2Open`, `suite2SuiteOf`, `Suite2Id`), whose
  signature binds the recipient key, the KEM ciphertext and the associated
  data so an envelope cannot be re-addressed; and Session v2 (`Session2`,
  `generateSession2Prekey`, `verifySession2Prekey`, `initiateSession2`,
  `claimedSession2Initiator`, `acceptSession2`), a forward-secret ratchet
  over X-Wing behind a handshake that authenticates both identities. Every
  `SecurityProfile` selects X-Wing (`hpkeKem`, `suite2`). The version 1
  Suite and Session stay available and unchanged.
- The engine's FIPS layer for engines built with `CRYPTOLIB_PROFILE=fips`
  (OpenSSL FIPS Provider, CMVP certificate #4985): `fipsAvailable`,
  `fipsInit`, `fipsStatus` and the `fips*` family (digest, HMAC, HKDF,
  PBKDF2, DRBG, AES-256-GCM, P-256, a key envelope, HPKE P-256). On the
  bundled full-profile engine `fipsAvailable` is false and every call
  throws.
- The approval boundary is explicit (finding M3): `ProtectedDataClass`,
  `CipherBird.approvedFor`, `requireApprovedFor` and `isWebBuild`. The web
  build is approved for ephemeral data only and `requireApprovedFor` fails
  closed for long-lived keys and card data.
- Engines carry the 320-function C ABI, every slice built and attested on
  CI from hash-pinned sources. Engine fixes: a WAV file without a valid
  format chunk is rejected by the FLAC steganographer (found by the now
  blocking fuzz job), and authentication verdicts are declassified for the
  blocking constant-time job.
- `DeviceFips` (`package:cipherbird/cipherbird_fips.dart`) performs the
  approved operations (SHA-2, HMAC, HKDF, PBKDF2, DRBG, AES-256-GCM, P-256
  ECDH and ECDSA) inside the module the platform already validated: Apple
  corecrypto behind CryptoKit and CommonCrypto on iOS and macOS, the
  Android platform providers (Conscrypt, BoringCrypto) on Android, or the
  OpenSSL FIPS Provider when the engine is the fips profile.
  `DeviceFips.module()` reports what served the calls; on Android the
  HKDF and PBKDF2 loops run in the app around the provider's HMAC and are
  reported as composed. Flutter only; the browser has no validated module.
- The example app is a showcase with one screen per capability and a
  Play tab of interactive playgrounds (hashes, symmetric encryption,
  signatures, HPKE with a chosen KEM, Suite v2, a Session v2 chat,
  hardware keys, the validated module), with integration tests that run
  every section and press every button on a device.

- Hardware-backed keys (`package:cipherbird/cipherbird_hardware.dart`):
  `HardwareKey` lives in the Secure Enclave on iOS and macOS or the Android
  Keystore (StrongBox, with a reported fallback to the TEE), optionally
  behind the system biometric prompt, and wraps a new keyring slot type.
  `keyringAddHardwareSlot` and `keyringUnlockWithHardware` drive it;
  `attest` returns App Attest or Android key attestation documents for a
  server. Envelopes holding a hardware slot are version 2 and are refused
  by earlier versions. The Android side registers a plugin class for the
  method channel; the plugin stays an FFI plugin otherwise. On macOS
  the host app must be signed with a Team ID for the enclave keychain.
- Secrets are wiped at the FFI edge. Every native block the package
  allocates, natively and in the browser, is overwritten with zeros before
  it is freed, and so is every scratch block in the web worker; passphrases
  are marshalled through that path. New byte forms take a passphrase as
  `Uint8List` the caller can wipe: `argon2idDeriveBytes`,
  `argon2idHashStrBytes`, `argon2idVerifyStrBytes`, `molecularSealBytes`,
  `molecularOpenBytes`, `keyringAddPassphraseSlotBytes`,
  `keyringUnlockWithPassphraseBytes`, `SymmetricKey.fromPassphraseBytes`
  and the matching `easy` and facade entries. `SecretBytes` is a handle
  for key material with a definite end of life; `SymmetricKey` now holds
  one, `SymmetricKey.bytes` throws after `destroy`, `KemKeyPair.destroy`
  wipes the secret key, and KEM shared secrets are wiped once the session
  key is derived.
- The browser build is not approved for long-lived keys or card data: the
  engine's linear memory is readable by every script on the page, so a key
  that must outlive one operation belongs on the native platforms. The
  web README says so.
- Engine fixes from the assessment: HMAC-SHA512 now uses every key byte
  (RFC 2104) instead of the first 32; `cryptolib_init` reports failure;
  an envelope header can no longer demand an Argon2id cost above the
  policy ceiling (64 passes, 4 GiB) before it is authenticated; the
  MolecularVault mode byte is checked; HPKE, Noise, the DRBG, Fortuna and
  the PQ backend wipe their scratch secrets; Noise `into_session` is one
  shot and the transport nonce is read only; a Shamir share record with a
  length near 2^32 is rejected on 32-bit targets; AES-GCM inputs above
  2 GiB are refused instead of truncated.
- Every web engine file is loaded with a Subresource Integrity digest.
  `web_setup` writes `integrity` and `crossorigin` attributes on the two
  page tags and refreshes them on rerun; the Dart loader injects
  `cipherbird.js` with the same digest, fetches `cipherbird.wasm` with
  `integrity` and hands the verified bytes to the engine; the worker is
  built from the verified bytes of `cipherbird.js` and
  `cipherbird_worker.js` and receives the verified `.wasm` in its first
  message, so it imports nothing by URL and nothing is interpolated into
  its source. The digests live in `lib/src/engine_integrity.dart`,
  generated from the bundled files.
- A `createCipherBird` global that was on the page before the verified
  script ran is removed rather than called.
- Adopting an engine the page booted through `cipherbird_boot.js` is now
  an opt-in: `dart run cipherbird:web_setup --boot` writes the boot tag and
  `CIPHERBIRD_PAGE_ENGINE=true` (a dart-define) makes the loader adopt the
  page's engine. By default `web_setup` writes only the engine tag and the
  loader always loads through the digest-checked path, so the await in
  `main` is required on the web; pages set up with 1.1.1 or 1.1.2 keep
  working but need the define to keep the no-await startup.
- Release builds (`dart.vm.product`) no longer honour the
  `CIPHERBIRD_LIBRARY` and `CRYPTOLIB_DYLIB` environment variables, the
  package configuration or the current directory when opening the native
  engine; only an explicit path, the library beside the executable or the
  process image is used.
- Engine binaries: the desktop library for macOS is now linked against the
  same pinned static dependency set as the iOS and Android slices
  (libsodium 1.0.22, OpenSSL 3.5.9, liboqs 0.15.0, blst v0.3.17) instead of
  Homebrew packages, and every bundled engine is built from sha256-pinned
  sources with a pinned blst commit, NDK and Emscripten. `cryptolib_init`
  reports failure with a non-zero result.

## 1.1.2

Faster public hashing; no API or wire-format change.

- The engine's unkeyed digests (SHA-256, SHA-512, BLAKE2b and BLAKE3
  without a key, one shot and streaming) no longer allocate page-locked,
  wiped buffers for their output. A digest of public data is public, so the
  lock protected nothing and cost two system calls per hash. Measured on an
  Apple M3 Max, 100,000 calls, best of five: `sha256` on 32 bytes 2.44 us to
  0.30 us, `blake3` 2.15 us to 0.25 us; on 1 KiB 6.09 us to 3.88 us and
  4.26 us to 1.89 us.
- Keyed BLAKE2b and BLAKE3, `deriveKey`, HMAC, HKDF and Argon2id keep their
  locked, wiped buffers; a keyed BLAKE3 stream cannot take the plain path.
  Output bytes are unchanged, so every known answer test keeps passing.
- Public outputs across the engine (ciphertexts, signatures, public keys,
  envelopes, Keccak-256 and RIPEMD-160) now use plain buffers like the
  digests, removing two system calls from every such call; keys, shared
  secrets, decrypted plaintext, MACs and KDF outputs keep their locked, wiped
  buffers. In the browser, randomness now comes from one
  `crypto.getRandomValues` call per buffer instead of one per byte: 32
  random bytes went from 39 us to 1.3 us and a 32-byte XChaCha20 encrypt
  from 28 us to 4.9 us in Chrome.
- Every shipped engine is rebuilt: Android, iOS, macOS and WebAssembly.

## 1.1.1

Engine hardening and smaller binaries; no API or wire-format change.

- Vault packets whose signature is not 64 bytes are rejected before
  verification, in packet parsing and in the symmetric and asymmetric vault
  open paths; a short signature previously reached the verifier and could
  crash the process. The asymmetric vault also checks the sender, recipient
  and secret key lengths on seal and open.
- Length arithmetic in the suite, session and Flagship parsers is done in
  `size_t`, so a signature or ciphertext length near 2^32 can no longer wrap
  a bounds check. The suite requires the exact hybrid signature size.
  Regression tests cover both findings and the related short-input cases.
- Every shipped binary is rebuilt with libsodium 1.0.22 and OpenSSL 3.5.9
  (3.5 LTS). OpenSSL is trimmed to the EVP ciphers the engine uses, liboqs
  carries only the algorithms the API exposes, and the secp256k1 table is
  smaller. Android arm64 goes from 7.5 MB to 4.9 MB, x86_64 from 8.3 MB to
  6.3 MB, iOS from 7.6 MB to 5.0 MB, macOS from 7.8 MB to 5.2 MB; the
  WebAssembly engine is 4.4 MB.
- The C ABI is unchanged at 265 functions and the generated web shim is
  identical to 1.1.0.
- `await CipherBird.preload()` is now cheap everywhere. Natively it returns
  immediately instead of warming the library on an isolate; the library
  opens synchronously on first use. In the browser Flutter's plugin
  registration starts fetching and compiling the engine before `main` runs,
  so `preload` only joins a download already in flight. With the
  `cipherbird.js` and new `cipherbird_boot.js` script tags in `index.html`
  the page instantiates the engine during Flutter's bootstrap and the
  package adopts it synchronously, so the await can be dropped on the web as
  well; `dart run cipherbird:web_setup` adds the tags to `web/index.html`.
  Concurrent loads are shared. `CipherBird.ready` is the same future for code
  that runs after `main`.

## 1.1.0

Web support. The engine is compiled to WebAssembly with Emscripten and
bundled as `assets/cipherbird.js` and `assets/cipherbird.wasm`; the same
Dart API runs in the browser under both `flutter build web` and
`flutter build web --wasm`, with byte-compatible envelopes, signatures and
keys. `CipherBird.preload()` loads the engine and is required on the web; it
takes an optional `library` location (a file path natively, the URL of
`cipherbird.js` on the web). File-path APIs are unavailable in the browser.
AES-256-GCM gained a portable OpenSSL path for CPUs without AES
instructions, byte-identical to the hardware path.

Off-thread work is now described by `CipherBirdJob`, plain data a runner can
copy into an isolate or post to a worker. `CipherBirdRunner.run` takes a job
instead of a function and a message, and the three Argon2id jobs behind the
asynchronous easy-mode helpers are public (`Argon2DeriveJob`,
`Argon2HashJob`, `Argon2VerifyJob`). In the browser
`CipherBirdIsolateRunner` runs jobs in a web worker shipped as
`assets/cipherbird_worker.js`, so password hashing no longer blocks the
page.

## 1.0.0

First release under the name `cipherbird`. The package was previously
`cryptolib_flutter` (last version 4.3.0); the API, the bundled binaries and
the wire formats are unchanged. The Dart entry point stays `CipherBird`, the
name of the native library this package binds.

## 4.3.0

Package structure and conventions.

### Changed

* `lib/src` now follows one declaration per file with a 100-line limit, no
  `else` branches and no inline comments; `test/conventions_test.dart`
  enforces it. Native lookups live in per-domain holders resolved lazily; the
  large extensions are split into named chunks (`CipherBirdBbsProofGen`,
  `CipherBirdRecipeSealing`, ...) that the barrel re-exports, so every method is
  still reachable from one import.
* `CipherBird.preload()` runs through a `CipherBirdRunner`
  (`CipherBirdIsolateRunner` by default, `CipherBirdInlineRunner` for tests).
  Await it in `main` before `runApp`.
* Data classes use `const factory` redirects and `final class`.
* Documentation and strings use plain ASCII; `CipherBirdRecipe.describe()` joins
  layers with `->`.

### Added

* `lib.easy.symmetricKeyFromPassphraseAsync`, `hashPasswordAsync` and
  `verifyPasswordAsync` run Argon2id on a worker through a `CipherBirdRunner`.

## 4.2.0

Easy mode: developer-friendly sugar on top of the full API.

### Added

* Bytes/text extensions: `'text'.bytes`, `'ab12'.hexBytes`, `'…'.base64Bytes`,
  `bytes.hex` / `.base64` / `.base64Url` / `.text`, `bytes.constantTimeEquals()`,
  `bytes.concat()`, `bytes.wipe()`, `List<int>.u8`, `KeyPairResult.publicHex`.
* `SymmetricKey` — 32-byte key with key-committing AEAD encryption,
  `encryptText`/`decryptText`, Argon2id `fromPassphrase(salt:)`, HKDF
  `derive(purpose)`, hex/base64 (de)serialisation, `asKeySource` for recipes,
  `destroy()`.
* `SigningKey` / `VerifyKey` — Ed25519 or the Ed25519+ML-DSA-65 hybrid behind
  one `algorithm:` argument; `signText`/`verifyText`; `scheme` for recipes.
* `KemKeyPair` — hybrid X25519+ML-KEM-768 `encapsulate`/`decapsulate` to a
  `SymmetricKey`, and one-call public-key encryption `encryptFor`/`decrypt`
  (`encryptTextFor`/`decryptText`).
* `Identity.sealText` / `openText` for the Flagship/Fortress sealed messaging.
* `lib.easy` — factories for the above plus `hashPassword`/`verifyPassword`
  (Argon2id PHC strings), `randomBytes`/`randomHex`/`token`, `sha256Hex`.

Every easy-mode class takes an optional `CipherBird` and defaults to
`CipherBird.instance`. Composition only — no new cryptography.

## 4.1.0

Extensible recipes: mix your own encryption into a `CipherBirdRecipe`.

### Added

* `ProtectionLayer` is now an abstract class you can subclass (`id`, `wireName`,
  `seal`, `open`) and register with `ProtectionLayer.register()`. The four
  built-ins (`xchacha20Poly1305`, `aes256Gcm`, `committing`, `molecular`) are
  instances of the same base.
* `CascadeLayer` — a layer that is itself a mixture of layers, so several
  ciphers (built-in or custom) become ONE custom layer; cascades nest.
* `KeySource` (abstract) with `RawKeySource`, `PassphraseKeySource`,
  `KeyFileSource`; `CipherBirdRecipe.withKeySource()` accepts your own (token, KMS,
  keyring unlock).
* `SignatureScheme` (abstract) with `Ed25519Signature`, `HybridSignature`;
  `CipherBirdRecipe.signedWith()` / `verifiedWith()` accept your own.
* Guardrails: ids 0–127 are reserved for the library (custom parts must use
  128–255, enforced); a key source must return exactly 32 bytes; a layer's
  `wireName` feeds its HKDF sub-key; the envelope pins the key-source id and
  the signature-scheme id.

### Packaging

* First pub.dev-ready release: the prebuilt native binaries (Android
  arm64-v8a + x86_64 `.so`, iOS device + simulator and macOS `CipherBird`
  frameworks) are committed and included in the published archive, rebuilt
  against the current 265-function C ABI. Real `LICENSE` (MIT, credit to the
  author required), repository links, declared platforms (Android, iOS 15+,
  macOS 12+ on Apple silicon).

### Changed

* `verifiedBy(pk)` no longer takes an `algorithm` argument — the envelope
  records which built-in scheme signed it. A custom scheme must be supplied
  with `verifiedWith()`.
* The wire format is unchanged: envelopes sealed by 4.0.0 open unchanged, and
  cross-language interop stays byte-identical.

## 4.0.0

Full parity with the native C ABI, type-safe algorithm selectors, and a grouped
API for navigating the surface.

### Breaking

* Algorithm selectors are now enums instead of bare `int` wire values. Every
  affected call site must be updated:

  | Before | After |
  |---|---|
  | `mlKemKeygen(1)` | `mlKemKeygen(MlKemLevel.level768)` |
  | `mlDsaKeygen(1)` | `mlDsaKeygen(MlDsaLevel.level65)` |
  | `slhDsaKeygen(3, 1)` | `slhDsaKeygen(SlhDsaLevel.fast192, SlhDsaHash.shake)` |
  | `hpkeSetupS(1, 3, 0, …)` | `hpkeSetupS(HpkeKdf.sha256, HpkeAead.chaCha20Poly1305, HpkeMode.base, …)` |

  `HpkeKdf`, `HpkeAead` and `HpkeMode` were classes of `static const int`; they
  are now real enums, so the constants keep their names but change type.
* `SealedInfo.suite` is a `SealedTier` rather than an `int` (`1`/`2`). Compare
  against `SealedTier.flagship` / `SealedTier.fortress`. `SealedTier` now
  carries an explicit wire value instead of relying on declaration order.
* Argon2id cost is a `KdfPreset` rather than `0`/`1`, on `vaultCreate`,
  `vaultFromEntropy` and `keyringAddPassphraseSlot`.

### Added — features that had no Dart binding

The plugin bound 218 of the 250 C ABI functions; it now binds all 244 that are
callable (the remaining 6 are struct-level `*_free` calls, deliberately unbound
because the buffer helpers already free those allocations).

* **Stateful RNGs** — `Drbg` (HMAC-DRBG, SP 800-90A) and `Fortuna`, via
  `lib.rng.drbg(...)` / `lib.rng.fortuna()`. Both hold native handles; call
  `close()` when done.
* **Keyed and encrypted steganography** — `stegoEmbedKeyed`,
  `stegoExtractKeyed`, `stegoEmbedEncrypted`, `stegoExtractDecrypt`.
* **Carrier diagnostics** — `stegoInspect` (→ `StegoFileInspection`),
  `stegoDetectHidden` (→ `StegoHiddenDataReport`), `stegoContentDigest`.
* **Entropy-source health** — `assessFileHealth` (→ `HealthReport`), the
  SP 800-90B style checks.
* **Composed carriers** — `physicalSeal`/`physicalOpen`,
  `imageFactorSeal`/`imageFactorOpen`, `hpkeStegoSeal`/`hpkeStegoOpen`.
* **Forward error correction** — `fecEncode`/`fecDecode` with `FecScheme`.

### Added — maximal security and composition

* **`SecurityProfile`** (`balanced` / `high` / `maximum`) sets every algorithm
  parameter together — ML-KEM/ML-DSA/SLH-DSA parameter sets, sealed tier, HPKE
  suite, Argon2id cost and the AEAD cascade. `maximum` takes the strongest
  option at every choice, so a maximal KEM can no longer be paired with an
  interactive-cost KDF by accident.

* **`CipherBirdRecipe`** composes the library's protections instead of exposing them
  one call at a time:

  ```dart
  final recipe = lib.maximumSecurity()
      .withPassphrase('correct horse battery staple')
      .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
      .verifiedBy(id.publicKey)
      .withFec(FecScheme.repetition3);

  final envelope = recipe.seal(secret);
  recipe.sealIntoCarrier(secret, coverPath: cover, outputPath: out);
  ```

  Key sources: a passphrase (Argon2id), a raw 32-byte key, or a media file
  (reproducible). Layers: XChaCha20-Poly1305, AES-256-GCM, key-committing AEAD,
  or a whole MolecularVault as one layer. Then optional signing, forward error
  correction, and concealment in a carrier.

  Composition only — every step is an existing vetted operation. What the recipe
  adds is the plumbing that is easy to get wrong by hand: each layer gets its
  own HKDF-separated key, the recipe descriptor is authenticated as AAD by every
  layer, the order is fixed rather than caller-selectable, and everything fails
  closed. `describe()` prints the configuration for review. The envelope is a
  library-native format, not a standard.

### Added — organisation

* **Grouped API.** Each domain is reachable through a named group, so
  autocomplete narrows to one area instead of listing ~200 members:

  ```dart
  lib.pq.mlKem.keygen(MlKemLevel.level768);
  lib.stego.detectHidden(path);
  lib.rng.drbg(entropy);
  lib.hash.sha256(bytes);
  ```

  Groups: `hash`, `aead`, `asym`, `pq` (with `mlKem`, `mlDsa`, `slhDsa`,
  `hybridKem`, `hybridSig`, `sntrup`), `bls`, `vault`, `keyring`, `entropy`,
  `stego`, `composed`, `chain`, `suite`, `sealed`, `session`, `frost`, `hpke`,
  `ecvrf`, `bbs`, `oprf`, `opaque`, `rng`.

  These are zero-cost `extension type` views over the same instance. The
  existing flat methods are unchanged and remain fully supported — neither
  style is deprecated.
* **New result types** — `StegoFileInspection`, `StegoHiddenDataReport`,
  `HealthReport`, plus the `MediaFormat` and `FecScheme` enums.
* `MlKemLevel` / `MlDsaLevel` / `SlhDsaLevel` expose `bits`, `nistCategory` and
  `fastVariant` so a parameter set can be inspected, not just passed along.

## 3.0.0

* Initial release: hashing, AEAD, asymmetric, vaults, post-quantum
  (ML-KEM/ML-DSA/SLH-DSA), hybrid KEM, BLS, keyring, sealed messaging, FROST,
  HPKE, ECVRF, BBS, OPRF and OPAQUE over `dart:ffi`.
