# Changelog

## 1.3.0

The first npm release, at parity with the cipherbird Dart packages and the
full C ABI of the CryptoLib engine (327 entry points).

- The package is `cipherbird`; the engine is bundled for macOS on Apple
  silicon under `prebuilds/darwin-arm64/libcipherbird.dylib`, self-contained
  (libsodium, liboqs, blst, OpenSSL and BLAKE3 linked statically) and the
  same binary the v1.3.0 GitHub release and the Dart packages ship.
  `CIPHERBIRD_LIBRARY` points at another build; `CRYPTOLIB_DYLIB` still
  works.
- New groups: X-Wing (ML-KEM-768 + X25519), HPKE with a selectable KEM
  (X25519, ML-KEM-768 or X-Wing), Suite v2 signed sealed envelopes,
  Session v2 (the X-Wing ratchet behind an authenticated handshake), the
  live entropy source for streams, the calibrated SP 800-90B health report
  with its summary, the explicit entropy policy, keyring hardware slots,
  the FIPS profile surface (digests, HMAC, HKDF, PBKDF2, AES-256-GCM, P-256,
  HPKE and the key envelope), box and sealed box, ML-DSA, and chunked
  SecretStream helpers.
- The media methods on bytes: steganography, the composed seals and media
  entropy over in-memory carriers through a wiped scratch directory, plus
  `KeyBytesSource` for recipes.
- The domain namespaces of the Dart packages: `hash`, `aead`, `asym`, `bls`,
  `vault`, `keyring`, `entropy`, `stego`, `composed`, `chain`, `suite`,
  `sealed`, `session`, `frost`, `hpke`, `ecvrf`, `bbs`, `oprf`, `opaque`,
  `rng`, `pq`, `channel` and `fips`.
- Easy mode: `SymmetricKey`, `SigningKey`, `VerifyKey`, `KemKeyPair` and
  the `easy` helpers, with the byte layouts and HKDF labels of the Dart
  packages, so a blob made here opens there.
- `async`: any data-in, data-out method runs on one worker thread
  (`cipherbird.async.suite2Seal(...)`), the way the Dart packages move
  heavy work to a background isolate; the Dart `*Async` names are exported
  too.
- TypeScript declarations for the whole surface.
- Fixed: every error slot was declared as `char**`, which koffi decodes
  into a string and loses the pointer; an engine failure through those
  paths threw a type error instead of the engine's message and leaked the
  string. The slots are `void**` now and the message is decoded and freed.
- Errors are prefixed `cipherbird:`; the detect-hidden report field is
  `cipherbirdPayload`.
