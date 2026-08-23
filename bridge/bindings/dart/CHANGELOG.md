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
