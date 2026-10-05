## 1.0.0

First release under the name `cipherbird`. The package was previously
`cryptolib_flutter` (last version 4.3.0); the API, the bundled binaries and
the wire formats are unchanged. The Dart entry point stays `CryptoLib`, the
name of the native library this package binds.

## 4.3.0

Package structure and conventions.

### Changed

* `lib/src` now follows one declaration per file with a 100-line limit, no
  `else` branches and no inline comments; `test/conventions_test.dart`
  enforces it. Native lookups live in per-domain holders resolved lazily; the
  large extensions are split into named chunks (`CryptoLibBbsProofGen`,
  `CryptoRecipeSealing`, ...) that the barrel re-exports, so every method is
  still reachable from one import.
* `CryptoLib.preload()` runs through a `CryptoLibRunner`
  (`CryptoLibIsolateRunner` by default, `CryptoLibInlineRunner` for tests).
  Await it in `main` before `runApp`.
* Data classes use `const factory` redirects and `final class`.
* Documentation and strings use plain ASCII; `CryptoRecipe.describe()` joins
  layers with `->`.

### Added

* `lib.easy.symmetricKeyFromPassphraseAsync`, `hashPasswordAsync` and
  `verifyPasswordAsync` run Argon2id on a worker through a `CryptoLibRunner`.

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

Every easy-mode class takes an optional `CryptoLib` and defaults to
`CryptoLib.instance`. Composition only — no new cryptography.

## 4.1.0

Extensible recipes: mix your own encryption into a `CryptoRecipe`.

### Added

* `ProtectionLayer` is now an abstract class you can subclass (`id`, `wireName`,
  `seal`, `open`) and register with `ProtectionLayer.register()`. The four
  built-ins (`xchacha20Poly1305`, `aes256Gcm`, `committing`, `molecular`) are
  instances of the same base.
* `CascadeLayer` — a layer that is itself a mixture of layers, so several
  ciphers (built-in or custom) become ONE custom layer; cascades nest.
* `KeySource` (abstract) with `RawKeySource`, `PassphraseKeySource`,
  `KeyFileSource`; `CryptoRecipe.withKeySource()` accepts your own (token, KMS,
  keyring unlock).
* `SignatureScheme` (abstract) with `Ed25519Signature`, `HybridSignature`;
  `CryptoRecipe.signedWith()` / `verifiedWith()` accept your own.
* Guardrails: ids 0–127 are reserved for the library (custom parts must use
  128–255, enforced); a key source must return exactly 32 bytes; a layer's
  `wireName` feeds its HKDF sub-key; the envelope pins the key-source id and
  the signature-scheme id.

### Packaging

* First pub.dev-ready release: the prebuilt native binaries (Android
  arm64-v8a + x86_64 `.so`, iOS device + simulator and macOS `CryptoLibC`
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

* **`CryptoRecipe`** composes the library's protections instead of exposing them
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
