# Roadmap — candidate primitives & constructions for later iterations

Where the library stands today and what would extend it most, in priority order.
Guiding rule (unchanged): **wrap vetted implementations, never hand-roll**, and
prefer *constructions* composed from existing primitives over new primitives.

## What already exists (so we don't duplicate)

- **KEMs:** ML-KEM 512/768/1024; sntrup761 (NTRU-Prime); hybrids X25519+ML-KEM-768,
  X25519+sntrup761, and the triple X25519+ML-KEM-768+sntrup761.
- **Signatures:** Ed25519; ML-DSA 44/65/87; SLH-DSA (SHA2/SHAKE); hybrids
  Ed25519+ML-DSA-65 and the triple +SLH-DSA; BLS12-381 aggregate.
- **AEAD / symmetric:** XChaCha20-Poly1305, AES-256-GCM, AES-256-GCM-SIV,
  committing AEAD, SecretStream; Argon2id, HKDF, HMAC, BLAKE2b/3, SHA-2, Keccak.
- **Constructions:** Vault, MolecularVault, Flagship/Fortress sealed messaging,
  Keyring, Shamir M-of-N, Noise XX, media entropy / steganography.
- **Chain interop:** secp256k1 (ECDSA + ecrecover), Keccak-256, RIPEMD-160.

## Tier 1 — highest value, natural next steps

- **PQ forward-secret ratchet — ✅ DONE (`crypto::Session`).** Closes the static-
  recipient gap in Flagship/Fortress: a live channel with forward secrecy AND
  post-compromise security, all post-quantum. Hybrid KEM Double Ratchet
  (HybridKem asymmetric ratchet + HKDF root/chain + key-committing AEAD), PQ
  X3DH-lite handshake, transactional decrypt (no desync-DoS). C++ core + 11 tests
  landed; C ABI + bindings are the next step (same flow as Flagship/Fortress).
- **FROST threshold signatures — ✅ DONE (`crypto::Frost`).** t-of-n parties
  jointly produce ONE ordinary Ed25519 signature without ever reconstructing the
  key; the output verifies with standard Ed25519 against the group public key, so
  verifiers need know nothing of the threshold setup — the custody/wallet
  primitive the EVM/BTC direction was missing. FROST(Ed25519, SHA-512) per
  RFC 9591, built on libsodium edwards25519 scalar/point arithmetic (composition
  only, no new crypto). Validated byte-for-byte against the RFC §C.1 vectors
  (commitments, signature shares, aggregate) + end-to-end threshold properties.
  C++ core + 6 tests, C ABI (stateless — no handle), and all five bindings (Go,
  Node, Dart, Flutter, Swift) landed. Follow-up candidate: a secp256k1 variant
  for BTC/EVM on-chain multisig.

## Tier 2 — standards interop & cryptographic diversity

- **HPKE (RFC 9180) — ✅ DONE (`crypto::Hpke`).** *The* standardized hybrid
  public-key encryption (TLS ECH, MLS, Oblivious HTTP) — the wire-interop
  counterpart to the library-native tiers; an envelope sealed here opens in any
  conformant HPKE. KEM = DHKEM(X25519, HKDF-SHA256); KDF = HKDF-SHA256/512;
  AEAD = AES-128/256-GCM / ChaCha20Poly1305 / export-only; all four modes
  (Base/PSK/Auth/AuthPSK). Single-shot + streaming Context (seal/open/export).
  Composition only over vetted primitives; validated byte-for-byte against the
  CFRG RFC 9180 vectors. C++ core + 9 tests, C ABI (opaque context handle), and
  all five bindings landed. Follow-up candidate: HPKE's hybrid/PQ KEM variants
  (X25519MLKEM768) once the draft stabilizes — the KEM slots in cleanly.
- **HQC (code-based KEM) — ⏸ DEFERRED (build-blocked).** NIST's 2025 code-based
  backup to ML-KEM — a genuinely different math family (codes, not lattices). An
  optional X25519+HQC hybrid (or a "quad" KEM) extends diversity beyond the two
  lattice families. **Blocker:** the pinned Homebrew liboqs 0.15.0 is built with
  `OQS_ENABLE_KEM_HQC` OFF (`OQS_KEM_new("HQC-*")` returns NULL), so it can't be
  built or KAT-validated against the current dependency. Revisit once liboqs ships
  HQC enabled (or via a vendored liboqs source build). Caveat: CVE-2024-54137 +
  side-channel history — ship as an opt-in hedge, not a default.

## Tier 3 — targeted capabilities (adopt when a use case calls)

- **ECVRF (RFC 9381) — ✅ DONE (`crypto::Ecvrf`).** Verifiable random function
  (ECVRF-EDWARDS25519-SHA512-TAI) for leader election, verifiable lotteries, and
  on-chain randomness — the chain-interop counterpart to the EVM/BTC primitives.
  prove/proof_to_hash/verify on libsodium edwards25519 + SHA-512; the
  try-and-increment hash-to-curve clears the cofactor with three point additions
  (no custom field arithmetic). Validated byte-for-byte against all three RFC 9381
  Appendix B.3 vectors. C++ core + 4 tests, C ABI (stateless), and all five
  bindings landed. (Pulled forward from Tier 3 when HQC was build-blocked.)
- **BBS signatures / anonymous credentials — ✅ DONE (`crypto::Bbs`).** Multi-message
  signatures with zero-knowledge SELECTIVE DISCLOSURE (W3C Verifiable Credentials,
  mDL-style): sign a vector of messages; the holder derives a proof revealing only
  a chosen subset while proving a valid signature covers all of them.
  draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256, over blst (G1/G2 + pairings) +
  SHA-256; only expand_message_xmd (RFC 9380) is assembled locally. keygen / sign /
  verify / proof_gen / proof_verify. Validated byte-for-byte against the official
  draft fixtures (signatures + a proof reproduced via the fixture-trace mocked
  randomness). C++ core + 3 tests, C ABI (guarded by CRYPTOLIB_HAS_BLS), and all
  five bindings landed.
- **OPRF (RFC 9497) — ✅ DONE (`crypto::Oprf`).** Oblivious pseudorandom function
  (base-mode ristretto255-SHA-512): the client blinds its input, the server
  evaluates under its key without seeing it, the client unblinds to a PRF output.
  Building block for Privacy Pass, private set intersection, password hardening —
  and OPAQUE's core. Validated byte-for-byte against RFC 9497 Appendix A.1.1. C++
  core + 2 tests, C ABI, and all five bindings landed. (A final RFC, cleaner on the
  KAT discipline than the OPAQUE draft; pulled in first as OPAQUE's foundation.)
- **OPAQUE (aPAKE, CFRG) — ✅ DONE (`crypto::Opaque`).** Asymmetric PAKE
  (OPAQUE-3DH, ristretto255-SHA-512, KSF=Identity): client and server agree on a
  session key from a password that never leaves the client and is never stored
  server-side; a server compromise is offline-dictionary-hard and the password is
  hidden even from a malicious server. Registration (request/response/finalize +
  envelope) and a 3DH login (KE1/KE2/KE3 + mutual auth + session key), built on
  `crypto::Oprf` + HKDF-SHA-512 + HMAC-SHA-512. Validated byte-for-byte against
  the draft's official test vector (full registration AND the complete 3DH login,
  both sides' session keys). C++ core + 3 tests, C ABI, and all five bindings.
  Still a draft (not a final RFC).
- **FN-DSA / FALCON (FIPS 206, in progress)** — compact PQ signatures (much smaller
  than ML-DSA) where signature size dominates. **Wait for a vetted constant-time
  implementation:** its floating-point Gaussian sampling is a notorious
  side-channel hazard.

## Tier 4 — niche / on-demand

MLS group messaging (RFC 9420, TreeKEM); threshold ECDSA / threshold BLS; XMSS/LMS
stateful hash-based signatures (RFC 8391/8554 — smaller than SLH-DSA but
catastrophic on state reuse); FF1/FF3-1 format-preserving encryption (tokenization
/ compliance); Sphinx mixnet packet format (metadata privacy).

## Explicitly out of scope (for now)

Fully homomorphic encryption, private information retrieval, ORAM, and searchable
symmetric encryption are research-grade subsystems, not general-library
primitives. Reach for a dedicated, specialized library if a concrete use case
demands them rather than folding them in here.

---

### Suggested near-term sequence

1. ~~**PQ forward-secret ratchet**~~ — ✅ done (`crypto::Session`, all bindings).
2. ~~**FROST threshold signatures**~~ — ✅ done (`crypto::Frost`, all bindings).
3. ~~**HPKE (RFC 9180)**~~ — ✅ done (`crypto::Hpke`, all bindings).
4. ~~**ECVRF (RFC 9381)**~~ — ✅ done (`crypto::Ecvrf`, all bindings); pulled
   forward from Tier 3 after HQC hit a build blocker.
5. **HQC (code-based KEM)** — deferred until liboqs ships with HQC enabled;
   then cryptographic-family diversity beyond lattices as an opt-in hedge.

Everything else is demand-driven: add it when a target application needs it, and
always behind the same discipline — vetted implementation, KATs before ship,
constant-time verified, no new wire format without a versioned, self-describing
envelope.
