#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLib — C++20 high-grade cryptography                               ║
 * ║                                                                            ║
 * ║  Single-header include. All capabilities available after:                ║
 * ║    #include <cryptolib/cryptolib.hpp>                                    ║
 * ║                                                                            ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐  ║
 * ║  │  LAYERED VAULT PIPELINE                                             │  ║
 * ║  │                                                                     │  ║
 * ║  │  crypto::SecureVault   — 4-layer symmetric pipeline                 │  ║
 * ║  │    vault.seal(plaintext, aad)      → EncryptedPacket                │  ║
 * ║  │    vault.open(packet,   aad)       → SecureBuffer                   │  ║
 * ║  │    vault.seal_into(cover, pt, out, aad)  ← NATIVE STEGO            │  ║
 * ║  │    vault.open_from(stego, aad)           ← NATIVE STEGO            │  ║
 * ║  │                                                                     │  ║
 * ║  │  crypto::AsymmetricVault — 4-layer public-key pipeline              │  ║
 * ║  │    AsymmetricVault::seal(pt, sender, recip_pub, aad)               │  ║
 * ║  │    AsymmetricVault::open(pkt, recip, sender_pub, aad)              │  ║
 * ║  │    AsymmetricVault::seal_into(sender, recip_pub, pt, cover, out)   │  ║
 * ║  │    AsymmetricVault::open_from(recip, sender_pub, stego, aad)       │  ║
 * ║  │                                                                     │  ║
 * ║  │  Both chain 4 layers (fail-fast at each):                          │  ║
 * ║  │    L1 Argon2id/BLAKE2b KDF   → brute force resistance              │  ║
 * ║  │    L2 BLAKE2b integrity tag  → corruption detection                │  ║
 * ║  │    L3 XChaCha20-Poly1305     → confidentiality + AEAD auth         │  ║
 * ║  │    L4 Ed25519 signature      → forgery / impersonation             │  ║
 * ║  └─────────────────────────────────────────────────────────────────────┘  ║
 * ║                                                                            ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐  ║
 * ║  │  MEDIA ENTROPY  (LavaRand-inspired physical entropy harvester)      │  ║
 * ║  │                                                                     │  ║
 * ║  │  crypto::entropy::MediaEntropy::from_file(path)                    │  ║
 * ║  │    me.make_vault()             → SecureVault seeded by pixel noise  │  ║
 * ║  │    me.seal_into(cover, pt, out, aad)   ← NATIVE STEGO             │  ║
 * ║  │    me.open_from(stego, aad)            ← NATIVE STEGO (same me)   │  ║
 * ║  │  crypto::entropy::vault_from_file(path)                            │  ║
 * ║  │  crypto::entropy::key_from_file(path)                              │  ║
 * ║  │                                                                     │  ║
 * ║  │  Pipeline: file bytes → BLAKE2b stream → XOR system entropy        │  ║
 * ║  │            → BLAKE2b re-hash → HKDF domain-separated keys          │  ║
 * ║  └─────────────────────────────────────────────────────────────────────┘  ║
 * ║                                                                            ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐  ║
 * ║  │  STEGANOGRAPHY  (hide payloads inside media — used by vault/entropy)│  ║
 * ║  │                                                                     │  ║
 * ║  │  Low-level / bypass-vault access:                                   │  ║
 * ║  │    crypto::stego::StegoEngine::embed(cover, bytes, out)            │  ║
 * ║  │    crypto::stego::StegoEngine::extract(stego) → bytes              │  ║
 * ║  │    crypto::stego::StegoEngine::embed_packet(cover, pkt, out)       │  ║
 * ║  │    crypto::stego::StegoEngine::extract_packet(stego) → pkt        │  ║
 * ║  │    crypto::stego::StegoEngine::capacity(cover) → StegoCapacity     │  ║
 * ║  │    crypto::stego::StegoEngine::quality(cover, stego) → dB          │  ║
 * ║  │                                                                     │  ║
 * ║  │  Algorithms (auto-dispatched by extension):                        │  ║
 * ║  │    .ppm  → ImageSteganographer  DCT/QIM blue-channel  ~4.7 KB/img  │  ║
 * ║  │    .wav  → AudioSteganographer  phase coding mid-freq ~830 B/10s   │  ║
 * ║  │    .crvf → VideoSteganographer  DCT/QIM per-frame     ~1.2 KB/frame│  ║
 * ║  │                                                                     │  ║
 * ║  │  Carrier generation:                                                │  ║
 * ║  │    crypto::stego::MediaGenerator::generate_ppm(path, w, h)         │  ║
 * ║  │    crypto::stego::MediaGenerator::generate_wav(path, sr, ch, dur)  │  ║
 * ║  │    crypto::stego::MediaGenerator::generate_crvf(path,w,h,fps,n)   │  ║
 * ║  └─────────────────────────────────────────────────────────────────────┘  ║
 * ║                                                                            ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐  ║
 * ║  │  STANDALONE PRIMITIVES                                              │  ║
 * ║  │                                                                     │  ║
 * ║  │  crypto::hash::Blake2b / Blake3† / Sha256 / Sha512 / Argon2id      │  ║
 * ║  │  crypto::hash::HmacSha256 / HmacSha512 / HkdfSha256              │  ║
 * ║  │  crypto::symmetric::XChaCha20Poly1305 / Aes256Gcm / SecretStream   │  ║
 * ║  │  crypto::asymmetric::Box / SealedBox / Ed25519 / X25519 / HybridBox│  ║
 * ║  │  crypto::pq::MlKem (FIPS 203) / MlDsa (FIPS 204) / SlhDsa (205)†  │  ║
 * ║  │  crypto::bls::Bls12381 — aggregate signatures (sign/verify/agg)†  │  ║
 * ║  │    † optional deps: BLAKE3 / liboqs / blst (ON by default)        │  ║
 * ║  └─────────────────────────────────────────────────────────────────────┘  ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 *
 * Quick-start:
 *
 *   crypto::init();   // once at startup
 *
 *   // ── Vault seal + stego in one call ────────────────────────────────────────
 *   auto kp    = crypto::SecureVault::generate_keypair();
 *   auto vault = crypto::SecureVault(master_key, std::move(kp));
 *   vault.seal_into("cover.ppm", "classified", "stego.ppm", "my-context");
 *   auto plain = vault.open_from("stego.ppm", "my-context");
 *
 *   // ── Entropy from a photo → vault → stego ──────────────────────────────────
 *   auto me    = crypto::entropy::MediaEntropy::from_file("photo.ppm").value();
 *   auto vault = me.make_vault().value();
 *   vault.seal_into("cover.wav", "secret", "stego.wav", "ctx");
 *   auto plain = vault.open_from("stego.wav", "ctx");
 *
 *   // ── Alice sends to Bob via stego (asymmetric) ──────────────────────────────
 *   auto alice = crypto::AsymmetricVault::generate_bundle();
 *   auto bob   = crypto::AsymmetricVault::generate_bundle();
 *   crypto::AsymmetricVault::seal_into(alice, bob.box_public.span(),
 *                                      "Bob, meet at midnight", "cover.ppm", "stego.ppm");
 *   auto plain = crypto::AsymmetricVault::open_from(bob, alice.sign_public.span(),
 *                                                   "stego.ppm");
 */

// Include order matters for the circular-dep resolution:
//   vault.hpp   → packet.hpp          (EncryptedPacket, KdfParams)
//              → steganography.hpp    (StegoEngine + sub-headers)
//              → packet.hpp           (already included, idempotent)
//   media_entropy.hpp → steganography.hpp  (idempotent)
// All stego headers are therefore reachable from this single include.
#include "types.hpp"
#include "hash.hpp"
#include "keccak.hpp"            // → Keccak-256 (original padding, Ethereum)
#include "ripemd160.hpp"         // → RIPEMD-160 (Bitcoin HASH160)
#include "secp256k1.hpp"         // → secp256k1 ECDSA (EVM/BTC; guarded by CRYPTOLIB_HAS_SECP256K1)
#include "symmetric.hpp"
#include "committing.hpp"        // → key/context-committing AEAD (UtC)
#include "aead_siv.hpp"          // → AES-256-GCM-SIV nonce-misuse-resistant AEAD (OpenSSL)
#include "asymmetric.hpp"
#include "vault.hpp"              // → packet.hpp + steganography.hpp (all stego)
#include "media_entropy.hpp"      // → steganography.hpp (idempotent via #pragma once)
#include "stego_media_generator.hpp"
#include "pq.hpp"                 // → post-quantum (liboqs, guarded by CRYPTOLIB_HAS_PQ)
#include "hybrid_kem.hpp"         // → X25519 + ML-KEM-768 hybrid KEM (guarded by CRYPTOLIB_HAS_PQ)
#include "sntrup_x25519.hpp"      // → X25519 + sntrup761 hybrid KEM (guarded by CRYPTOLIB_HAS_PQ)
#include "triple_hybrid_kem.hpp"  // → X25519 + ML-KEM-768 + sntrup761 triple hybrid KEM (guarded)
#include "hybrid_sig.hpp"         // → Ed25519 + ML-DSA-65 hybrid signatures (guarded by CRYPTOLIB_HAS_PQ)
#include "triple_sig.hpp"        // → Ed25519 + ML-DSA-65 + SLH-DSA triple signature (guarded)
#include "bls.hpp"                // → BLS12-381 (blst, guarded by CRYPTOLIB_HAS_BLS)
#include "keyring.hpp"            // → envelope encryption with key-slots (device / passphrase)
#include "shamir.hpp"             // → Shamir secret sharing (GF(256), M-of-N)
#include "frost.hpp"          // → FROST(Ed25519,SHA-512) threshold signatures
#include "ecvrf.hpp"          // → ECVRF (RFC 9381) verifiable random function
#include "bbs.hpp"            // → BBS signatures + selective disclosure (BLS12-381)
#include "oprf.hpp"           // → OPRF (RFC 9497) oblivious pseudorandom function
#include "hpke.hpp"           // → HPKE (RFC 9180) hybrid public-key encryption
#include "session.hpp"        // → PQ forward-secret ratchet (needs PQ)
#include "flagship.hpp"        // → Flagship / Fortress sealed-messaging tiers (needs OpenSSL + PQ)
#include "suite.hpp"             // → Suite: one-call advanced combinations (needs OpenSSL + PQ)
#include "molecular_vault.hpp"    // → max-assurance layered vault (cascade + Argon2id + committing)
#include "noise.hpp"              // → Noise_XX secure channel (mutual auth + forward secrecy)

#include <sodium.h>

namespace crypto {

/// Must be called once at program startup before any crypto operation.
inline void init() {
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium initialisation failed");
}

/// Cryptographically secure random bytes.
[[nodiscard]] inline SecureBuffer random_bytes(std::size_t n) {
    SecureBuffer buf(n);
    randombytes_buf(buf.data(), n);
    return buf;
}

/// Constant-time equality comparison (safe against timing attacks).
[[nodiscard]] inline bool secure_equal(std::span<const uint8_t> a,
                                       std::span<const uint8_t> b) noexcept {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace crypto
