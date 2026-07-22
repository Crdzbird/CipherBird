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

- **PQ forward-secret ratchet (Double Ratchet + PQXDH-style handshake).** The one
  real gap in Flagship/Fortress: they target a *static* recipient key, so they are
  not forward-secret against recipient-key compromise. A ratchet adds forward
  secrecy **and** post-compromise security for live, back-and-forth messaging.
  This is a *construction* over primitives we already have (X25519/ML-KEM hybrid
  handshake → symmetric ratchet with HKDF + AEAD), so no new dependency — the
  highest-leverage addition for any messaging use case.
- **FROST threshold signatures (Ed25519 + secp256k1).** N-of-M parties jointly
  sign without ever reconstructing the key — the custody/wallet primitive the
  library's EVM/BTC direction is missing. Well-specified (RFC 9591); complements
  the existing Shamir (secret sharing) and BLS (aggregation).

## Tier 2 — standards interop & cryptographic diversity

- **HPKE (RFC 9180), incl. the hybrid/PQ variants.** Flagship is deliberately
  library-native (not a wire standard). HPKE is *the* standardized hybrid
  public-key encryption; adding it gives wire-interoperability with TLS ECH, MLS,
  and other ecosystems — the interop counterpart to the native tiers.
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

1. **PQ forward-secret ratchet** — closes the one honest gap in Flagship/Fortress.
2. **FROST threshold signatures** — unlocks custody/multi-party for the wallet side.
3. **HPKE** — standards-interoperable sealed encryption alongside the native tiers.

Everything else is demand-driven: add it when a target application needs it, and
always behind the same discipline — vetted implementation, KATs before ship,
constant-time verified, no new wire format without a versioned, self-describing
envelope.
