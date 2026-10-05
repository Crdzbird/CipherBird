## 0.4.0

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
* `CryptoLib.instance` — process-wide lazily loaded instance, matching the
  Flutter plugin, so the easy-mode classes work without passing a library.

Every easy-mode class takes an optional `CryptoLib` and defaults to
`CryptoLib.instance`. Composition only — no new cryptography.

## 0.3.0

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

### Changed

* `verifiedBy(pk)` no longer takes an `algorithm` argument — the envelope
  records which built-in scheme signed it. A custom scheme must be supplied
  with `verifiedWith()`.
* The wire format is unchanged: envelopes sealed by 0.2.0 open unchanged, and
  cross-language interop stays byte-identical.

## 0.2.0

Brought in line with the Flutter plugin.

### Breaking

* Algorithm selectors are enums instead of bare `int` wire values:
  `mlKemKeygen(MlKemLevel.level768)`, `slhDsaKeygen(SlhDsaLevel.fast192,
  SlhDsaHash.shake)`, `hpkeSetupS(HpkeKdf.sha256, HpkeAead.chaCha20Poly1305,
  HpkeMode.base, …)`, `fecEncode(data, FecScheme.repetition3)`,
  `keyringAddPassphraseSlot(kr, pass, KdfPreset.interactive)`.
  `HpkeKdf`/`HpkeAead`/`HpkeMode` were classes of `static const int` and are now
  real enums. `StegoFileInspection.format` is a `MediaFormat`.
* `SealedTier` carries an explicit wire value rather than relying on
  declaration order, and gains `fromSuiteId`.
* Minimum SDK is now 3.3.0 (the grouped API uses extension types).

### Added

* **Grouped API** — `lib.pq.mlKem.keygen(...)`, `lib.stego.detectHidden(...)`,
  `lib.rng.drbg(...)`. 20 domain groups over the same instance, built as
  zero-cost extension types. The flat methods are unchanged.
* **`SecurityProfile`** — `balanced` / `high` / `maximum`, setting every
  algorithm parameter consistently so a maximal KEM can't be paired with an
  interactive-cost KDF by accident.
* **`CryptoRecipe`** — a composable pipeline: choose a key source (passphrase,
  raw key or a media file), stack AEAD layers, sign, add forward error
  correction, and optionally hide the result in a carrier. Each layer gets its
  own HKDF-separated key, the recipe descriptor is authenticated as AAD by every
  layer, and the order (sign → encrypt → correct → conceal) is fixed.

## 0.1.0

* Initial standalone dart:ffi bindings.
