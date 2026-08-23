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
  against `SealedTier.flagship` / `SealedTier.fortress`.

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
