#pragma once

/**
 * crypto::asymmetric — Standalone bidirectional asymmetric-key operations
 *
 *   Box        — X25519 + XChaCha20-Poly1305 (authenticated encryption)
 *   SealedBox  — anonymous sender encryption
 *   Ed25519    — digital signatures (detached, deterministic)
 *   X25519     — raw ECDH key agreement (use with a KDF before keying a cipher)
 *   HybridBox  — sign-then-encrypt convenience wrapper
 */

#include "types.hpp"
#include <sodium.h>

namespace crypto::asymmetric {

struct EncryptionKeyPair {
    SecureBuffer public_key;  // 32 bytes (X25519)
    SecureBuffer secret_key;  // 32 bytes
};

struct SigningKeyPair {
    SecureBuffer public_key;  // 32 bytes (Ed25519)
    SecureBuffer secret_key;  // 64 bytes (seed + public)
};

// ─────────────────────────────────────────────────────────────────────────────
// Box — authenticated public-key encryption (NaCl crypto_box)
// Both sender and receiver are identified.
// Output: [ nonce(24) | MAC(16) | ciphertext ]
// ─────────────────────────────────────────────────────────────────────────────
class Box {
public:
    static constexpr std::size_t PUBLIC_KEY_BYTES = crypto_box_PUBLICKEYBYTES;  // 32
    static constexpr std::size_t SECRET_KEY_BYTES = crypto_box_SECRETKEYBYTES;  // 32
    static constexpr std::size_t NONCE_BYTES      = crypto_box_NONCEBYTES;      // 24
    static constexpr std::size_t MAC_BYTES        = crypto_box_MACBYTES;        // 16

    [[nodiscard]] static EncryptionKeyPair generate_keypair() {
        EncryptionKeyPair kp;
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        kp.secret_key.resize(SECRET_KEY_BYTES);
        crypto_box_keypair(kp.public_key.data(), kp.secret_key.data());
        return kp;
    }

    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> recipient_pub,
            std::span<const uint8_t> sender_sec) {
        if (recipient_pub.size() != PUBLIC_KEY_BYTES || sender_sec.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("Box: invalid key length");
        SecureBuffer out(NONCE_BYTES + MAC_BYTES + plaintext.size());
        randombytes_buf(out.data(), NONCE_BYTES);
        if (crypto_box_easy(out.data() + NONCE_BYTES,
                            plaintext.data(), plaintext.size(),
                            out.data(),
                            recipient_pub.data(), sender_sec.data()) != 0)
            return Result<SecureBuffer>::err("Box: encryption failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> ct_with_nonce,
            std::span<const uint8_t> sender_pub,
            std::span<const uint8_t> recipient_sec) {
        if (sender_pub.size() != PUBLIC_KEY_BYTES || recipient_sec.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("Box: invalid key length");
        if (ct_with_nonce.size() <= NONCE_BYTES + MAC_BYTES)
            return Result<SecureBuffer>::err("Box: ciphertext too short");
        const uint8_t* nonce = ct_with_nonce.data();
        const uint8_t* ct    = ct_with_nonce.data() + NONCE_BYTES;
        std::size_t    ct_len = ct_with_nonce.size() - NONCE_BYTES;
        SecureBuffer out(ct_len - MAC_BYTES);
        if (crypto_box_open_easy(out.data(), ct, ct_len, nonce,
                                 sender_pub.data(), recipient_sec.data()) != 0)
            return Result<SecureBuffer>::err("Box: decryption failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SealedBox — anonymous sender; recipient can decrypt but not identify sender
// Output: [ ephemeral_pk(32) | MAC(16) | ciphertext ]
// ─────────────────────────────────────────────────────────────────────────────
class SealedBox {
public:
    static constexpr std::size_t PUBLIC_KEY_BYTES = crypto_box_PUBLICKEYBYTES;
    static constexpr std::size_t SECRET_KEY_BYTES = crypto_box_SECRETKEYBYTES;
    static constexpr std::size_t OVERHEAD         = crypto_box_SEALBYTES;

    [[nodiscard]] static EncryptionKeyPair generate_keypair() {
        return Box::generate_keypair();
    }

    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> recipient_pub) {
        if (recipient_pub.size() != PUBLIC_KEY_BYTES)
            return Result<SecureBuffer>::err("SealedBox: invalid public key");
        SecureBuffer out(OVERHEAD + plaintext.size());
        if (crypto_box_seal(out.data(), plaintext.data(), plaintext.size(), recipient_pub.data()) != 0)
            return Result<SecureBuffer>::err("SealedBox: encryption failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> ciphertext,
            std::span<const uint8_t> recipient_pub,
            std::span<const uint8_t> recipient_sec) {
        if (recipient_pub.size() != PUBLIC_KEY_BYTES || recipient_sec.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("SealedBox: invalid key");
        if (ciphertext.size() <= OVERHEAD)
            return Result<SecureBuffer>::err("SealedBox: ciphertext too short");
        SecureBuffer out(ciphertext.size() - OVERHEAD);
        if (crypto_box_seal_open(out.data(), ciphertext.data(), ciphertext.size(),
                                 recipient_pub.data(), recipient_sec.data()) != 0)
            return Result<SecureBuffer>::err("SealedBox: decryption failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 — digital signatures (detached)
// ─────────────────────────────────────────────────────────────────────────────
class Ed25519 {
public:
    static constexpr std::size_t PUBLIC_KEY_BYTES = crypto_sign_PUBLICKEYBYTES;  // 32
    static constexpr std::size_t SECRET_KEY_BYTES = crypto_sign_SECRETKEYBYTES;  // 64
    static constexpr std::size_t SIG_BYTES        = crypto_sign_BYTES;           // 64

    [[nodiscard]] static SigningKeyPair generate_keypair() {
        SigningKeyPair kp;
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        kp.secret_key.resize(SECRET_KEY_BYTES);
        crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
        return kp;
    }

    [[nodiscard]] static Result<SigningKeyPair>
    keypair_from_seed(std::span<const uint8_t> seed) {
        if (seed.size() != crypto_sign_SEEDBYTES)
            return Result<SigningKeyPair>::err("Ed25519: seed must be 32 bytes");
        SigningKeyPair kp;
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        kp.secret_key.resize(SECRET_KEY_BYTES);
        crypto_sign_seed_keypair(kp.public_key.data(), kp.secret_key.data(), seed.data());
        return Result<SigningKeyPair>::ok(std::move(kp));
    }

    /// Returns detached signature (64 bytes)
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message, std::span<const uint8_t> secret_key) {
        if (secret_key.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("Ed25519: invalid secret key");
        SecureBuffer sig(SIG_BYTES);
        unsigned long long len = 0;
        crypto_sign_detached(sig.data(), &len, message.data(), message.size(), secret_key.data());
        sig.resize(static_cast<std::size_t>(len));
        return Result<SecureBuffer>::ok(std::move(sig));
    }

    [[nodiscard]] static bool
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key) {
        if (public_key.size() != PUBLIC_KEY_BYTES || signature.size() != SIG_BYTES)
            return false;
        return crypto_sign_verify_detached(signature.data(),
                                           message.data(), message.size(),
                                           public_key.data()) == 0;
    }

    /// Convert Ed25519 → X25519 (for hybrid schemes using a single key pair)
    [[nodiscard]] static Result<SecureBuffer>
    to_x25519_public(std::span<const uint8_t> ed_pub) {
        if (ed_pub.size() != PUBLIC_KEY_BYTES)
            return Result<SecureBuffer>::err("Ed25519->X25519: bad key");
        SecureBuffer out(Box::PUBLIC_KEY_BYTES);
        if (crypto_sign_ed25519_pk_to_curve25519(out.data(), ed_pub.data()) != 0)
            return Result<SecureBuffer>::err("Ed25519->X25519: conversion failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    to_x25519_secret(std::span<const uint8_t> ed_sec) {
        if (ed_sec.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("Ed25519->X25519: bad key");
        SecureBuffer out(Box::SECRET_KEY_BYTES);
        if (crypto_sign_ed25519_sk_to_curve25519(out.data(), ed_sec.data()) != 0)
            return Result<SecureBuffer>::err("Ed25519->X25519: conversion failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// X25519 — raw ECDH key agreement
// WARNING: The raw shared secret must be processed through a KDF before
//          being used as a cipher key. Use Box instead for most cases.
// ─────────────────────────────────────────────────────────────────────────────
class X25519 {
public:
    static constexpr std::size_t PUBLIC_KEY_BYTES = crypto_scalarmult_BYTES;       // 32
    static constexpr std::size_t SECRET_KEY_BYTES = crypto_scalarmult_SCALARBYTES; // 32
    static constexpr std::size_t SHARED_KEY_BYTES = crypto_scalarmult_BYTES;       // 32

    [[nodiscard]] static EncryptionKeyPair generate_keypair() {
        EncryptionKeyPair kp;
        kp.secret_key.resize(SECRET_KEY_BYTES);
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        randombytes_buf(kp.secret_key.data(), SECRET_KEY_BYTES);
        crypto_scalarmult_base(kp.public_key.data(), kp.secret_key.data());
        return kp;
    }

    [[nodiscard]] static Result<SecureBuffer>
    shared_secret(std::span<const uint8_t> our_sec, std::span<const uint8_t> their_pub) {
        if (our_sec.size() != SECRET_KEY_BYTES || their_pub.size() != PUBLIC_KEY_BYTES)
            return Result<SecureBuffer>::err("X25519: invalid key lengths");
        SecureBuffer out(SHARED_KEY_BYTES);
        if (crypto_scalarmult(out.data(), our_sec.data(), their_pub.data()) != 0)
            return Result<SecureBuffer>::err("X25519: key agreement failed (low-order point?)");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HybridBox — encrypt-then-sign convenience wrapper
// Provides: confidentiality + integrity + sender authentication
//
// ⚠ SIGNER-STRIPPING CAVEAT: This class uses Encrypt-then-Sign — the
//   signature covers the ciphertext, NOT the plaintext.  An active attacker
//   who possesses the recipient's public key can:
//     1. Intercept the HybridCiphertext
//     2. Strip the original signature
//     3. Re-sign the (unchanged) ciphertext with their own signing key
//   The recipient will successfully decrypt and see a valid signature, but
//   will attribute the message to the attacker instead of the real sender.
//
//   MITIGATION: Always verify the sender's signing public key through an
//   independent authenticated channel (e.g. TOFU, PKI, or out-of-band
//   fingerprint comparison).  For applications requiring non-repudiation,
//   use the full vault pipeline (SecureVault / AsymmetricVault) which binds
//   the signature to the encryption context.
// ─────────────────────────────────────────────────────────────────────────────
class HybridBox {
public:
    struct HybridCiphertext {
        SecureBuffer ciphertext;   // Box-encrypted payload
        SecureBuffer signature;    // Ed25519 signature over ciphertext
    };

    [[nodiscard]] static Result<HybridCiphertext>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> recipient_box_pub,
            std::span<const uint8_t> sender_box_sec,
            std::span<const uint8_t> sender_sign_sec) {
        auto ct  = Box::encrypt(plaintext, recipient_box_pub, sender_box_sec);
        if (ct.is_err()) return Result<HybridCiphertext>::err(ct.error().message);
        auto sig = Ed25519::sign(ct.value().span(), sender_sign_sec);
        if (sig.is_err()) return Result<HybridCiphertext>::err(sig.error().message);
        return Result<HybridCiphertext>::ok(
            HybridCiphertext{ std::move(ct.value()), std::move(sig.value()) });
    }

    [[nodiscard]] static Result<SecureBuffer>
    decrypt(const HybridCiphertext&  hybrid,
            std::span<const uint8_t> sender_box_pub,
            std::span<const uint8_t> recipient_box_sec,
            std::span<const uint8_t> sender_sign_pub) {
        if (!Ed25519::verify(hybrid.ciphertext.span(),
                             hybrid.signature.span(),
                             sender_sign_pub))
            return Result<SecureBuffer>::err("HybridBox: signature verification failed");
        return Box::decrypt(hybrid.ciphertext.span(), sender_box_pub, recipient_box_sec);
    }
};

} // namespace crypto::asymmetric
