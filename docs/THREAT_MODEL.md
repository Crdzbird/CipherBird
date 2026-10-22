# CryptoLib — Threat Model

Status: living document. Covers what CryptoLib defends against, what it does not,
and the security arguments for its **original** constructions (the parts not
inherited from vetted upstreams).

## 1. What CryptoLib is

A C++20 library that **wraps vetted primitives** — libsodium (XChaCha20-Poly1305,
AES-256-GCM, Ed25519, X25519, BLAKE2b, Argon2id, HKDF, HMAC), liboqs (ML-KEM,
ML-DSA, SLH-DSA), blst (BLS12-381), BLAKE3, OpenSSL libcrypto — behind a clean
C ABI, plus a small set of **original compositions**: SecureVault, Keyring,
the X25519+ML-KEM-768 hybrid KEM combiner, the committing-AEAD wrapper, and the
steganography / media-entropy subsystems.

Security of the *primitives* rests on their upstreams. This document focuses on
the **original compositions and the boundary**, because that is where review
effort and an adversary's effort are best spent.

## 2. Assets

- **Long-term secrets:** vault master keys, keyring master key, private signing /
  KEM keys, passphrases, device-factor keys.
- **Session secrets:** derived keys, KEM shared secrets, AEAD keys/nonces.
- **Plaintext** confidentiality and integrity.
- **Authentication / non-repudiation** of signed or sender-authenticated data.

## 3. Adversary model

We assume a **Dolev–Yao network adversary** (full read/modify/replay/inject on
ciphertexts and envelopes) **plus** the following, explicitly including an
**AI-assisted attacker**:

- **Implementation-flaw scanning at scale.** The adversary uses automated /
  AI-assisted tooling to find memory-safety bugs, secret-dependent branches or
  memory accesses (timing/cache side channels), API-misuse footguns, parsing
  bugs on untrusted input, and weak/!unique nonces. *This is the primary threat
  this model prioritizes — sound primitives are not the weak point; their
  framing and composition are.*
- **Chosen-ciphertext / oracle attacks**, including **partitioning oracles** and
  **key/context non-commitment** attacks (Invisible Salamanders class).
- **Multi-key / multi-target** attacks.
- **Local same-host attacker** for timing and memory-disclosure (but not a
  privileged kernel/hypervisor attacker — see out of scope).
- **Harvest-now-decrypt-later** quantum adversary against key agreement.

### Out of scope
- Physical side channels (power, EM, fault injection) — software library.
- A privileged attacker on the same host (root / kernel / debugger / cold-boot).
- Endpoint compromise / malware on the user's device.
- Traffic analysis / metadata (size, timing of messages).
- Steganographic *undetectability* against steganalysis (see §6).
- Supply-chain integrity of the *consumer's* build (we provide signed releases;
  the consumer must verify them — see `PUBLISHING.md`).

## 4. Trust boundary

The **C ABI** (`bridge/cryptolib_c.h`) is the boundary. Contract:
- No C++ exception crosses it (function-try-blocks + `CL_FAIL_*`).
- Ownership is explicit: every returned buffer/handle has a matching `*_free`.
- Error returns must **not** be a decryption oracle: failures are
  indistinguishable ("auth failed") regardless of *why*.
- All length math on caller-supplied input is bounds-checked before allocation.

Everything beyond the boundary (the Flutter/Node/JVM/Swift/.NET/Go bindings) is
the *caller's* trust domain; the library makes no assumptions about it.

## 5. Security arguments for original constructions

### 5.1 SecureVault (4-layer symmetric pipeline)
KDF → integrity → AEAD → signature. AAD binds context; the signature binds the
ciphertext (encrypt-then-sign, with the documented signer-stripping caveat for
`HybridBox` — mitigated by out-of-band verification of the signer key).
**Assumption:** AEAD is IND-CCA2; signature is EUF-CMA; KDF is a secure PRF.

### 5.2 Keyring (envelope encryption with key-slots)
One random master key, wrapped per "unlock factor" (device = HKDF, passphrase =
Argon2id). Each slot AEAD-binds its `type ‖ salt ‖ KDF-params` into the AAD →
**anti-downgrade**: a tampered envelope cannot weaken Argon2id params or swap a
strong slot for a weak one without failing authentication. Revocation = drop a
slot + re-serialise. **Assumption:** AEAD is IND-CCA2 + key-committing for the
master-key wrap (see 5.4); Argon2id/HKDF are secure KDFs.

### 5.3 Hybrid KEM combiner (X25519 + ML-KEM-768)
`ss = HKDF-Expand(HKDF-Extract(LABEL, ss_mlkem ‖ ss_x25519), ct_mlkem ‖ ct_x25519 ‖ pk_x25519)`.
Robust if **either** component is unbroken: ML-KEM-768 carries IND-CCA2; binding
`ct_x25519/pk_x25519` lifts raw X25519 DH. **Assumption:** HKDF-SHA256 modeled
as a random oracle (standard for hybrid-KEM combiners). **Not** wire-compatible
with TLS X25519MLKEM768 / X-Wing — interop is a non-goal.

### 5.4 Committing AEAD (UtC)
`(K_enc, K_com) = HKDF(K, info=AAD); wire = K_com ‖ AEAD(K_enc, P, AAD)`; decrypt
constant-time-compares `K_com`. Commits to (key, AAD), closing the
partitioning-oracle / non-committal AEAD gap. **Assumption:** HKDF is
collision/preimage-resistant; comparison is constant-time. **Review status:**
new composition — pending external review; KAT- and differential-fuzz-covered.

### 5.5 NoiseXX secure channel
`Noise_XX_25519_ChaChaPoly_SHA256` from the Noise spec: mutual static
authentication + forward secrecy (per-session ephemerals). Built from X25519 +
ChaCha20-Poly1305(IETF) + SHA-256/HKDF. Apps must **pin/verify `remote_static()`**
to stop MITM (XX is trust-on-first-use otherwise). **Review status:** round-trip
and security-property tested AND **validated byte-exact against the official
noise-c test vector** (`rweather/noise-c`) — handshake messages, handshake hash,
and transport ciphertexts all match, so it is wire-interoperable. `MixHash(prologue)`
applied per spec.

### 5.6 Shamir secret sharing (GF(256))
Information-theoretic K-of-N split (any K-1 shares reveal nothing). Constant-time
GF(2^8) multiply/inverse (no secret-dependent table lookups). For key
backup/escrow (e.g. splitting a Keyring master across guardians).

### 5.7 Keyring rotation
`rewrap` re-wraps the SAME master under new factors (change credentials, data
stays decryptable); `rekey` rotates to a NEW master and returns the old one for
re-encryption. Both require the keyring unlocked, re-derive slot keys from the
supplied factors (never stored), use a fresh envelope id, and roll back atomically
on failure.

## 6. Steganography & media-entropy — explicit caveat

Stego is **security through obscurity**, not confidentiality: it hides *that* a
message exists, not its contents, and naive LSB/DCT carriers are readily broken
by (AI-assisted) steganalysis. Always encrypt *before* embedding; treat stego as
defense-in-depth only. `StegoEngine::embed_encrypted()` / `extract_decrypt()`
enforce this — one master key drives a domain-separated XChaCha20-Poly1305 seal,
whitening (no surviving `CSTG` signature), and a key-seeded block permutation, so
the always-encrypt path cannot place cleartext in a carrier. Keyed
whitening covers every carrier format; the key-seeded block permutation
applies to the DCT image path.

"LavaRand" media-entropy is a novelty entropy *source* — keys must still come
from the OS CSPRNG. Every harvest assesses the source with two SP 800-90B
estimators (the Most-Common-Value bound over the whole file and the Markov
bound over the bit expansion of the first MiB) plus the Repetition-Count and
Adaptive-Proportion tests, and refuses by default a file below one bit of
min-entropy per byte or one that fails the repetition-count test
(`SourcePolicy`; `permissive()` keeps the assessment but never refuses).
The two local tests are calibrated against the floor the policy claims,
not against the entropy measured: the repetition-count cutoff is
1 + ceil(30 / floor), 31 bytes at the default floor, so a short run of
padding in a container header passes while a blank region or an empty file
still fails. Every report carries the estimates, the sample size, the
longest run and both cutoffs, `explain()` prints them one per line, and a
refusal names the number, the cutoff and the setting that would relax it.
`info().entropy_bits_claimed` caps the claim at the 512-bit conditioner
output. Two estimators are not the full 90B non-IID suite, and a file an
attacker also holds has no entropy against that attacker whatever the
estimate says: the deterministic mode is a password made of a file. `MediaEntropy::make_drbg()` exposes an SP 800-90A HMAC-DRBG
beacon seeded from the conditioned entropy (deterministic mode reproducible,
mixed mode folds in system entropy).

`LiveEntropy` (`entropy_live.hpp`) is the continuous form for a stream:
camera frames, audio buffers or packets are fed as they arrive, each chunk
is assessed under the same policy with the repetition-count run carried
across chunk boundaries, a passing chunk is credited
`min_entropy_per_byte * size` bits and a failing one is mixed in but
credited nothing, with the reason reported. The output is an SP 800-90A
HMAC-DRBG instantiated once 256 credited bits (configurable) have been
earned, with an operating-system nonce so the output is never weaker than
the system generator, and reseeded every time that much credit arrives
again; `generate` fails closed before the first seed. The credit is an
estimate from two 90B estimators over the stream's own bytes, so a static
scene or a highly compressible feed earns little, and the status says so.

## 7. Assurance posture (current → target)

| Control | Now | Target |
|---|---|---|
| KATs (RFC/FIPS vectors) | ✅ | maintain |
| Fuzzing (parsers) | ✅ | + differential fuzz, CI corpus |
| ASan/UBSan | ✅ | + TSan; MSan on pure parsers; in CI |
| Constant-time | by construction | **verified** (Valgrind/ctgrind in CI) |
| Committing AEAD | ✅ (new) | external review |
| External audit / FIPS | ✗ | engage |
| Signed/reproducible releases | ✗ | cosign + SBOM + SLSA |

## 8. Zeroization audit (2026-05)

Reviewed every secret-bearing intermediate in the core constructions:

- **Keys, shared secrets, KDF outputs (PRK/OKM), decrypted plaintext** are held
  in `SecureBuffer` (mlock + `sodium_munlock`-on-destroy, zeroes on every exit
  path incl. errors). Verified for: HKDF (`hash.hpp`), the hybrid-KEM combiner
  IKM, committing-AEAD `okm`, hybrid-sig key concatenation, GCM-SIV plaintext.
- **`std::vector<uint8_t>` intermediates** in `hybrid_kem`/`keyring` hold only
  PUBLIC data (ciphertexts, public keys, envelope magic/version/salt/KDF-params)
  — not secret, no scrub required.
- The one raw-byte buffer over potentially-sensitive input (the media-entropy
  chunk reader) is explicitly `sodium_memzero`'d after hashing.
- OpenSSL `EVP_CIPHER_CTX` round keys are cleared by `EVP_CIPHER_CTX_free`.
- **Public outputs** return `PublicBuffer`, a plain buffer with no page lock
  and no wipe (2026-10). This covers unkeyed digests (SHA-256, SHA-512,
  BLAKE2b and BLAKE3 without a key, one-shot and streaming; `Digest` is an
  alias), AEAD ciphertexts (XChaCha20-Poly1305, AES-256-GCM, the committing
  mode, GCM-SIV), signatures (Ed25519, ML-DSA, SLH-DSA, the hybrid and
  triple schemes, BLS, secp256k1), derived and recovered public keys,
  Keccak-256 and RIPEMD-160, and every sealed envelope (Box, SealedBox,
  Noise transport and handshake messages, Session, HPKE, Flagship,
  MolecularVault, the Suite, the Keyring's wrapped slots). Each of these is
  either a function of data the caller already holds or the bytes that go on
  the wire, so locking them protected nothing and cost two system calls per
  call. The line is drawn by what the output depends on: keys, shared
  secrets, decrypted plaintext, keyed BLAKE2b and BLAKE3, `derive_key`,
  HMAC, HKDF, Argon2id, Shamir shares and every KEM shared secret still
  return `SecureBuffer`; a keyed BLAKE3 stream refuses the plain
  `finalize_digest`; and hasher and cipher state is still wiped in every
  mode.
- **Randomness in WebAssembly** comes from the browser CSPRNG through one
  `crypto.getRandomValues` call per buffer (`cryptolib_init` installs the
  provider). No user-space generator sits between the platform CSPRNG and
  the keys; the change only removed a per-byte round trip through the
  in-memory filesystem.

Finding: no plaintext-secret survives its scope. Re-run this audit when new
secret-handling code lands.

## 9. Mobile banking deployments (assessment r2, M9)

A banking app runs the library on a device the bank does not control. This
section names the attacks that matter there, says which the library resists,
which it only narrows, and which belong to the application or the platform.
The adversary model of section 3 still applies; everything here is in
addition to it.

### 9.1 Hostile device

The phone may be rooted or jailbroken, run a repackaged copy of the app, or
carry a malicious accessibility service or overlay.

| Attack | Library control | What the application must add |
|---|---|---|
| Key material read from the app sandbox at rest | `Keyring` hardware slots wrap the master secret under a Secure Enclave or StrongBox key (`HardwareKey` in cipherbird); the stored blob is useless without that device | Pin the hardware slot as the only unlock path on enrolled devices; keep passphrase slots for recovery only |
| Repackaged or modified app binary | iOS App Attest assertion over the hardware key (`HardwareKey.attest`) lets the server tie a key to a genuine app on a genuine device; on Android the Play Integrity verdict plays the same role (not a library feature) | Verify attestations server side before trusting a device key |
| Modified native library | The Flutter plugin verifies the bundled engine's hash before loading it (`engine_integrity.dart`); every release engine is built and attested on CI | Ship the attested engines unchanged; verify the release signature on download |
| Fake server or fake recipient | Suite v2 signatures bind the recipient KEM key, the KEM ciphertext and the AAD, so a sealed message cannot be re-addressed; Session v2 verifies a signed prekey and the initiator identity before any key is derived | Pin the bank's identity keys (certificate or directory); never accept an unpinned identity from the wire |

### 9.2 Memory dumps

An attacker with a debugger, a process dump, or a cold device image reads the
app's memory.

- Secrets live in `SecureBuffer` (locked with `sodium_mlock` where the OS
  allows it, wiped on destruction) and the C ABI wipes every secret buffer
  before freeing it; the Dart edge wipes its copies (`SecretBytes`, byte
  passphrases) as soon as the native call returns. Section 8 is the audit.
- What the library cannot do: keep a secret out of memory while it is in use.
  A debugger attached during a transaction sees the session key. Hardware
  keyring slots and hardware-backed signing keys reduce the exposure to the
  one derived secret in use, never the long-term key.
- `String` passphrases in Dart are immutable and garbage collected; the
  byte-passphrase APIs exist so the application can wipe them. Use them.

### 9.3 Hooking and instrumentation

Frida, Xposed, substrate hooks, or a patched runtime intercept calls at the
Dart, FFI, or native layer.

- The library has no anti-hooking defence and does not claim one; a hook on
  `cryptolib_vault_open` sees the plaintext. Detection and response belong to
  the application's runtime protection and to the platform attestation above.
- The controls that survive a hooked client are the ones that move trust
  off the device: hardware-attested keys (the hook cannot export the key),
  server-side verification of attestations and signatures, and short-lived
  session keys (Session v2 forward secrecy limits what one captured key
  reveals).
- A hooked client that lies about `HardwareBacking` is caught by the server
  only through attestation, never by a client-side flag. Treat
  `HardwareBacking.software` and any unattested device as untrusted.

### 9.4 Profile guidance

- Build the `bank` profile (`-DCRYPTOLIB_PROFILE=bank`): no steganography,
  no media entropy, no library-native combiners; X-Wing and HPKE with ML-KEM
  are the defaults and Suite v2 and Session v2 the envelopes.
- Where the regulator requires validated cryptography, the `fips` profile
  routes every operation through the OpenSSL FIPS Provider on servers, and
  `DeviceFips` (package `cipherbird_fips.dart`) routes the same operations
  through the platform module on devices: Apple corecrypto behind CryptoKit
  on iOS and macOS, the Android platform providers (Conscrypt, BoringCrypto)
  on Android. `DeviceFips.module()` reports what served each call, so an app
  can refuse a device whose provider is not the validated one (see
  `docs/AUDIT_SCOPE.md` for the certificate numbers and the exact boundary).
- Regardless of profile: Argon2id cost is capped by the library, so a hostile
  envelope cannot force the app to allocate gigabytes; headers are parsed
  with explicit bounds; and every failure is reported as a single
  "authentication failed" to deny oracles.

### 9.5 Web approval boundary (assessment r2, M3)

In a browser the engine's linear memory is readable by every script on the
page, the worker cannot wipe JavaScript strings, and there is no platform
key module. The byte-passphrase APIs, the zeroing allocator and the worker
wipe (Phase 2) shrink the exposure; they cannot remove it. The approval
boundary is therefore explicit and enforced:

- The web build is approved for `ProtectedDataClass.ephemeral` only:
  session keys and payloads that live for one exchange.
- `CipherBird.approvedFor(ProtectedDataClass)` answers the question at run
  time and `requireApprovedFor` throws on a web build asked to protect
  `longLivedKeys` or `cardData`. Call it once at startup with the most
  sensitive class the app handles, so a web build of a banking app fails
  closed instead of storing a keyring in a browser.
- Long-lived keys and cardholder data stay on native builds, where
  `HardwareKey` and `DeviceFips` are available.
