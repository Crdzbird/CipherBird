# External audit scope

This document fixes what an external reviewer is asked to look at, what is
deliberately outside the engagement, and how to rebuild and re-run every
check named here. It answers finding H8 of the bank-readiness assessment r2
(`docs/assessments/bank-readiness-r2.html`).

## 1. Frozen commit

The audit target is the commit that introduces this file on `main`:

```bash
git log --diff-filter=A --format='%H %ad' --date=iso -- docs/AUDIT_SCOPE.md
```

Later commits are out of scope unless a new revision of this document names
them. Every reviewer builds from a clean checkout of that commit; the
committed engine binaries are not part of the review (they are rebuilt and
attested by CI, see section 6).

## 2. What is in scope: the bank profile

Build with `-DCRYPTOLIB_PROFILE=bank`. The reviewer evaluates only what that
profile compiles. Headers under `include/cryptolib/`:

| Area | Headers | Standard or construction |
|---|---|---|
| Core types and secrets | `types.hpp`, `shamir.hpp` | SecureBuffer, Result, Shamir over GF(256) |
| Hashing and KDFs | `hash.hpp`, `keccak.hpp`, `ripemd160.hpp` | SHA-2, BLAKE2b, HMAC, HKDF, Argon2id (cost capped), Keccak |
| Symmetric | `symmetric.hpp`, `committing.hpp`, `aead_siv.hpp` | XChaCha20-Poly1305, AES-256-GCM, UtC committing AEAD, AES-GCM-SIV |
| Classical asymmetric | `asymmetric.hpp` | X25519, Ed25519, Box, SealedBox |
| Post-quantum | `pq.hpp`, `xwing.hpp`, `hybrid_sig.hpp` | ML-KEM, ML-DSA, SLH-DSA (liboqs); X-Wing (draft-connolly-cfrg-xwing-kem-11); Ed25519 + ML-DSA-65 |
| Envelopes | `vault.hpp`, `keyring.hpp`, `suite_v2.hpp` | 4-layer vaults, key-slot envelopes, Suite v2 recipient-bound signed envelopes |
| Channels | `ratchet.hpp`, `session_v2.hpp`, `noise.hpp`, `hpke.hpp` | KEM ratchet, Session v2 authenticated handshake, Noise XX, HPKE (RFC 9180) with DHKEM(X25519), ML-KEM-768 and X-Wing |
| Protocols | `frost.hpp`, `ecvrf.hpp`, `bbs.hpp`, `oprf.hpp`, `opaque.hpp`, `bls.hpp` | FROST (RFC 9591), ECVRF (RFC 9381), BBS, OPRF (RFC 9497), OPAQUE, BLS12-381 |
| Entropy | `entropy_drbg.hpp`, `entropy_fortuna.hpp` | HMAC-DRBG, Fortuna |
| C ABI | `bridge/cryptolib_c.h`, `bridge/cryptolib_c.cpp` | the trust boundary, 320 functions in the full build, 270 in the bank build |

Priority for the reviewer, highest first:

1. The original compositions: Suite v2 (`suite_v2.hpp`), Session v2 and the
   ratchet (`session_v2.hpp`, `ratchet.hpp`), the vault pipelines
   (`vault.hpp`), the keyring (`keyring.hpp`), the committing AEAD
   (`committing.hpp`), and the Argon2id policy cap in `hash.hpp`.
2. The C ABI: exception isolation, ownership, bounds checks, oracle-free
   errors, secret wiping before free.
3. The standards implementations that are not taken from a vetted upstream:
   X-Wing (`xwing.hpp`, against the draft's Appendix C vectors), the HPKE
   KEM dispatch (`hpke.hpp`), ECVRF, FROST, OPRF, OPAQUE, BBS.
4. The Dart edge (`bridge/bindings/cipherbird/lib/src/platform`,
   `lib/src/hardware`): the zeroing allocator, the engine integrity check,
   the hardware keyring slots on iOS and Android.

## 3. What is out of scope

- Steganography, media entropy and every library-native combiner
  (MolecularVault, the triple hybrids, sntrup761 + X25519, the legacy Suite
  and Session, Flagship and Fortress). The bank profile compiles none of
  them; they remain in the full profile for other users.
- The vetted upstreams themselves: libsodium 1.0.22, liboqs 0.15.0, OpenSSL
  libcrypto, blst v0.3.17, BLAKE3, libsecp256k1. Their pins are in
  `scripts/lib/sources.sha256` and `scripts/lib/toolchain_pins.sh`.
- The `fips` profile's cryptography: it is performed by the OpenSSL FIPS
  Provider (CMVP certificate #4985, FIPS 140-3, OpenSSL 3.1.2) and, through
  `DeviceFips`, by the platform modules on devices: Apple corecrypto
  (certificates #5184 user space and #5387 kernel for iOS 18; #5216 and
  #5263 for iOS 17) and Google BoringCrypto (#5296) inside Conscrypt on
  Android. The reviewer may check that the profile fetches every algorithm
  with `fips=yes` and compiles nothing else (`tests/test_fips_provider.cpp`,
  the `fips_profile` CI job) and that `DeviceFips` calls only platform APIs
  (`FipsCrypto.swift`, `CipherbirdFipsChannel.kt`), not the modules. On
  Android the HMAC primitive runs in the provider while the HKDF and PBKDF2
  loops around it run in the app, which `DeviceFips.module()` reports as
  `hkdfComposed` and `pbkdf2Composed`; Android's own PBKDF2 is served by
  the software BouncyCastle provider and is therefore not used.
- Bindings other than Dart (Go, JVM, Node, Python, Ruby, Rust, .NET, Swift)
  beyond their secret-wiping edge, which Phase 2 of the remediation covered.
- Physical side channels, a privileged attacker on the same host, and
  endpoint malware (threat model, section 3).

## 4. Threat model

`docs/THREAT_MODEL.md` is the reference: assets, the AI-assisted adversary,
the trust boundary, the security arguments for each original construction,
the zeroization audit, and section 9 for mobile banking deployments (hostile
device, memory dumps, hooking).

## 5. Known findings and their status

The bank-readiness assessment r2 lists 32 findings. Their state at the
frozen commit:

| Finding | State | Where |
|---|---|---|
| C1 attested engines | FIXED | `scripts/release/import_engines.sh`, Engines workflow; every committed binary carries an attestation |
| C3 validated cryptography | FIXED | `fips` profile against certificate #4985 on servers; `DeviceFips` routes the approved operations through Apple corecrypto (CryptoKit) on iOS and macOS and the Android platform providers on Android, with the serving module reported per call; device integration tests in `bridge/bindings/cipherbird/example/integration_test/fips_test.dart` |
| N1-N5 release hygiene | FIXED | Phases 1 and 2 |
| H3 secret wiping at every edge | FIXED | Phase 2, all bindings |
| H4 hardware-backed keys | FIXED | Secure Enclave verified on macOS with the Team ID signed example; StrongBox on Android |
| H5, H7, H9 | FIXED | Phase 1 |
| H8 second reviewer, signed commits, audit readiness | FIXED (controls) | branch protection with required checks; every commit and tag from this revision on is SSH-signed (`git log --show-signature`); `.github/CODEOWNERS` and the pull request template require a code-owner review; this document scopes the external engagement and the DORA exit plan is section 7. The audit itself is performed by the external reviewer, not by this repository |
| M1, M2, M7, M10, M11 | FIXED | Phases 1 and 2 |
| M3 web secrets in JavaScript-readable memory | FIXED | byte passphrases, zeroing allocator and worker wipe (Phase 2) plus the enforced approval boundary: the web build is approved for ephemeral data only and `requireApprovedFor` fails closed (threat model 9.5) |
| M4 standards-track defaults | FIXED | X-Wing and HPKE with ML-KEM-768 and X-Wing; `SecurityProfile.hpkeKem` |
| M5 Suite recipient binding | FIXED | Suite v2, suite ids 0x11 and 0x12, `tests/test_suite_v2.cpp` |
| M6 Session initiator authentication | FIXED | Session v2, wire "RTC2", `tests/test_session_v2.cpp` |
| M8 bank profile build | FIXED | `-DCRYPTOLIB_PROFILE=bank`, `bank_profile` CI job |
| M9 mobile threat model | FIXED | `docs/THREAT_MODEL.md` section 9 |
| M12 CI gaps | FIXED | release gated on CI, fuzz crashes fail the job, Linux ctgrind job blocks on any secret-dependent branch (verdicts declassified in `detail/ct.hpp`, one libsodium verdict branch in `tests/ct/ct_probe.supp`), Dart, Flutter and Go binding jobs, examples built in the test job |
| L1-L7 | FIXED | Phase 2 |

## 6. Build and test

Every command runs from the repository root on macOS 14 or later with
Homebrew; Linux instructions match the `ctgrind` CI job.

```bash
brew install cmake ninja libsodium liboqs blake3 openssl@3 secp256k1
bash scripts/ci/install_blst.sh /opt/homebrew
```

Bank profile, the audit target:

```bash
cmake -S . -B build/bank -G Ninja -DCMAKE_BUILD_TYPE=Release -DCRYPTOLIB_PROFILE=bank -DCRYPTOLIB_BUILD_TESTS=ON -DCRYPTOLIB_BUILD_BRIDGE=ON
cmake --build build/bank
./build/bank/cryptolib_tests
```

Expected: 274 tests, 0 failed. The library exports 270 C functions and none
of the excluded families (the `bank_profile` CI job asserts this).

Full profile with sanitizers (the reviewer's fuzzing and memory baseline):

```bash
cmake -S . -B build/asan -G Ninja -DCRYPTOLIB_SANITIZE=ON -DCRYPTOLIB_BUILD_TESTS=ON
cmake --build build/asan && ./build/asan/cryptolib_tests
```

Expected: 526 tests, 0 failed, no sanitizer report. The Linux constant-time
probe (`ctgrind` CI job) must report zero errors.

FIPS profile:

```bash
bash scripts/ci/install_openssl_fips.sh "$HOME/openssl-fips"
PKG_CONFIG_PATH="$HOME/openssl-fips/lib/pkgconfig" cmake -S . -B build/fips -G Ninja -DCRYPTOLIB_PROFILE=fips -DCRYPTOLIB_BUILD_TESTS=ON -DCRYPTOLIB_BUILD_BRIDGE=ON
cmake --build build/fips
CRYPTOLIB_FIPS_MODULE_DIR="$HOME/openssl-fips/lib/ossl-modules" CRYPTOLIB_FIPS_CONFIG="$HOME/openssl-fips/ssl/openssl-fips.cnf" ./build/fips/cryptolib_tests
```

Expected: 25 tests, 0 failed; the library references only
`sodium_init`, `sodium_memzero`, `sodium_mlock`, `sodium_munlock` and
`sodium_memcmp` from libsodium.

Dart packages (the plugin and its twin), natively and in Chrome:

```bash
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCRYPTOLIB_BUILD_TESTS=OFF && cmake --build build/release --target cryptolib_c
cd bridge/bindings/cipherbird && CIPHERBIRD_LIBRARY="$PWD/../../../build/release/libcryptolib_c.dylib" flutter test
cd ../cipherbird_dart && CIPHERBIRD_LIBRARY="$PWD/../../../build/release/libcryptolib_c.dylib" dart test && dart test -p chrome
cd ../../.. && make flutter-web-test
```

All bindings end to end:

```bash
bash scripts/verify_bindings.sh
```

Walk-throughs for the reviewer: `cryptolib_showcase_bank` (full and bank
profiles) exercises X-Wing, HPKE with ML-KEM-768 and X-Wing, Suite v2 and
Session v2; `cryptolib_showcase_fips` (fips profile) exercises every
approved operation against its known answer; the Flutter showcase in
`bridge/bindings/cipherbird/example` runs the same surface plus the
hardware keys and the device validated module on iOS, Android, macOS and
the web.

Fuzzers and the constant-time probe are described in `CMakeLists.txt`
(`CRYPTOLIB_FUZZ`, `CRYPTOLIB_CT_VALGRIND`) and in the `fuzz` and `ctgrind`
CI jobs.

## 7. DORA exit plan

For a deployment under the EU Digital Operational Resilience Act, the
library is an ICT third-party component. The exit plan the operator needs:

- Every wire format is documented in the header that produces it (magic,
  version, suite id). Data sealed with Suite v2, the vaults, the keyring and
  HPKE can be decrypted by any implementation of the named standards given
  the keys; nothing depends on this library's process.
- Keys are exportable: X-Wing seeds, ML-KEM and ML-DSA keys in their FIPS
  203 and 204 encodings, X25519 and Ed25519 raw keys, P-256 in SEC 1
  encodings in the fips profile.
- The source is MIT licensed, builds from hash-pinned upstreams with no
  network access after the fetch, and every engine is reproducible from
  the Engines workflow. An operator can fork and keep building without the
  maintainer.
- The migration path off the library-native constructions is the bank
  profile itself: an application that uses only the bank profile already
  uses only standards-track formats.
