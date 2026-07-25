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
the always-encrypt path cannot place cleartext in a carrier. Keyed embedding is
`.ppm`-only for now; other carriers reject a key rather than silently ignoring it.

"LavaRand" media-entropy is a novelty entropy *source* — keys must still come
from the OS CSPRNG. Its trust signal is a real SP 800-90B **Most-Common-Value
min-entropy lower bound** (`MediaEntropy::assess_file_health()`, with SP 800-90B
Repetition-Count + Adaptive-Proportion local tests), not the legacy Shannon
i.i.d. *upper* bound. `MediaEntropy::make_drbg()` exposes an SP 800-90A HMAC-DRBG
beacon seeded from the conditioned entropy (deterministic mode reproducible,
mixed mode folds in system entropy).

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

Finding: no plaintext-secret survives its scope. Re-run this audit when new
secret-handling code lands.
