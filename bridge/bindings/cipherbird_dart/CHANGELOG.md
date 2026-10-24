## Unreleased

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
- The Flutter plugin's example app gains steganography and LavaRand
  playgrounds; this package has no app.

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

- Keyring hardware slots in the C ABI and here: `keyringBeginHardwareSlot`,
  `keyringSetHardwareBlob`, `keyringSlotType`, `keyringHardwareSlot` and
  `keyringUnlockWithHardwareFactor`, for programs with their own key
  module. Envelopes holding a hardware slot are version 2 and are refused
  by earlier versions. The Secure Enclave and Keystore integration ships in
  the Flutter plugin only.
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
  an opt-in: `dart run cipherbird_dart:web_setup --boot` writes the boot tag and
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
- The bundled macOS library and the WebAssembly engine are rebuilt.

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
- Both bundled engines are rebuilt. The WebAssembly engine (4.4 MB) uses
  libsodium 1.0.22 and OpenSSL 3.5.9 (3.5 LTS) with OpenSSL trimmed to the
  EVP ciphers the engine uses. The macOS library comes from the host
  toolchain with libsodium 1.0.22, liboqs 0.16.0 and the sealed OpenSSL
  3.6.3 build.
- `await CipherBird.preload()` is now cheap everywhere: immediate on native
  platforms, the one engine load in the browser, where the `cipherbird.js`
  and new `cipherbird_boot.js` script tags let the page boot the engine
  first so the package adopts it synchronously and no await is needed;
  `dart run cipherbird_dart:web_setup` inserts them into `web/index.html`.
  Concurrent loads are shared. `CipherBird.ready` is the same future for code
  that runs after `main`.
- The C ABI is unchanged at 265 functions and the generated web shim is
  identical to 1.1.0.

## 1.1.0

Web support. The engine is compiled to WebAssembly and bundled under
`lib/assets/`; the same API runs in the browser with `dart compile js` or
`dart compile wasm`, with byte-compatible envelopes, signatures and keys.
`CipherBird.preload()` loads the engine and is required on the web; it takes
an optional `library` location. File-path APIs are unavailable in the
browser. AES-256-GCM gained a portable OpenSSL path for CPUs without AES
instructions.

Off-thread work is now described by `CipherBirdJob`, plain data a runner can
copy into an isolate or post to a worker. `CipherBirdRunner.run` takes a job
instead of a function and a message, and the three Argon2id jobs behind the
asynchronous easy-mode helpers are public. In the browser
`CipherBirdIsolateRunner` runs jobs in a web worker shipped under
`lib/assets/`, so password hashing no longer blocks the page.

## 1.0.0

First release. `cipherbird_dart` is the plain-Dart twin of the `cipherbird`
Flutter plugin: the same generated source tree and API, with the native
native engine bundled under `native/<os>-<arch>/` for the host platform
and resolved automatically through the package configuration. Every public identifier carries the package name: `CipherBird`, `CipherBirdRecipe`,
`CipherBirdRunner`, `CipherBirdIsolateRunner`, `CipherBirdInlineRunner` and the
`CipherBird*` extension groups. Error messages start with `cipherbird:` and the
library path override is `CIPHERBIRD_LIBRARY` (`CRYPTOLIB_DYLIB` still works). It replaces
the repository's earlier internal `cryptolib_dart` verification package.
