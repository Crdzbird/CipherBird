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
- **HQC (code-based KEM).** NIST's 2025 code-based backup to ML-KEM — a genuinely
  different math family (codes, not lattices). An optional X25519+HQC hybrid (or a
  "quad" KEM) extends diversity beyond the two lattice families. liboqs ships it.
  Caveat: CVE-2024-54137 + side-channel history — ship as an opt-in hedge, not a
  default.

## Tier 3 — targeted capabilities (adopt when a use case calls)

- **ECVRF (RFC 9381)** — verifiable random function for leader election,
  verifiable lotteries, on-chain randomness. Fits the existing chain-interop story.
- **BBS+ / anonymous credentials** over BLS12-381 (we already link blst) — selective
  disclosure and zero-knowledge attribute proofs (W3C Verifiable Credentials).
- **OPAQUE (aPAKE, CFRG)** — password-authenticated key exchange so a password
  yields a strong key without ever being sent. Composes with our Argon2id + Noise.
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
4. **HQC (code-based KEM)** — cryptographic-family diversity beyond lattices;
   ship as an opt-in hybrid hedge (Tier 2), next up.

Everything else is demand-driven: add it when a target application needs it, and
always behind the same discipline — vetted implementation, KATs before ship,
constant-time verified, no new wire format without a versioned, self-describing
envelope.
