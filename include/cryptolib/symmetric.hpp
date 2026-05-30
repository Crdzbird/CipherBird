#pragma once

/**
 * crypto::symmetric — Standalone bidirectional symmetric-key encryption
 *
 *   XChaCha20Poly1305 — recommended default AEAD (192-bit nonce)
 *   Aes256Gcm         — hardware-accelerated AEAD (AES-NI / ARMv8)
 *   SecretStream      — streaming AEAD for large data (ratcheting keys)
 *
 * All ciphers prepend the nonce to the ciphertext output automatically.
 * Output layout: [ nonce | ciphertext | MAC ]
 */

#include "types.hpp"
#include <sodium.h>
#include <string_view>

namespace crypto::symmetric {

// ─────────────────────────────────────────────────────────────────────────────
// XChaCha20-Poly1305 — recommended default
//   192-bit nonce — random nonce reuse is safe in practice
//   No hardware requirement — fast on all platforms
// ─────────────────────────────────────────────────────────────────────────────
class XChaCha20Poly1305 {
public:
    static constexpr std::size_t KEY_BYTES   = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
    static constexpr std::size_t NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    static constexpr std::size_t MAC_BYTES   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16

    [[nodiscard]] static SecureBuffer generate_key() {
        SecureBuffer k(KEY_BYTES);
        crypto_aead_xchacha20poly1305_ietf_keygen(k.data());
        return k;
    }

    /// Output: [ nonce(24) | ciphertext | MAC(16) ]
    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("XChaCha20: invalid key");
        SecureBuffer out(NONCE_BYTES + plaintext.size() + MAC_BYTES);
        randombytes_buf(out.data(), NONCE_BYTES);
        unsigned long long ct_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                out.data() + NONCE_BYTES, &ct_len,
                plaintext.data(), plaintext.size(),
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nullptr, out.data(), key.data()) != 0)
            return Result<SecureBuffer>::err("XChaCha20: encryption failed");
        out.resize(NONCE_BYTES + static_cast<std::size_t>(ct_len));
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::string_view plaintext,
            std::span<const uint8_t> key,
            std::string_view aad = {}) {
        return encrypt(
            { reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size() },
            key,
            { reinterpret_cast<const uint8_t*>(aad.data()), aad.size() });
    }

    /// Input: [ nonce(24) | ciphertext | MAC(16) ]
    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> ciphertext_with_nonce,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("XChaCha20: invalid key");
        if (ciphertext_with_nonce.size() < NONCE_BYTES + MAC_BYTES)
            return Result<SecureBuffer>::err("XChaCha20: ciphertext too short");
        const uint8_t* nonce = ciphertext_with_nonce.data();
        const uint8_t* ct    = ciphertext_with_nonce.data() + NONCE_BYTES;
        std::size_t    ct_len = ciphertext_with_nonce.size() - NONCE_BYTES;
        SecureBuffer out(ct_len - MAC_BYTES);
        unsigned long long pt_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                out.data(), &pt_len, nullptr,
                ct, ct_len,
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nonce, key.data()) != 0)
            return Result<SecureBuffer>::err("XChaCha20: decryption failed (tampered?)");
        out.resize(static_cast<std::size_t>(pt_len));
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM — hardware-accelerated on AES-NI / ARMv8 Crypto CPUs
// Always call is_available() before use.
// Output: [ nonce(12) | ciphertext | MAC(16) ]
//
// ⚠ NONCE SAFETY: AES-GCM uses a 96-bit random nonce.  Birthday-bound
//   collision probability exceeds 2^−32 after ~2^32 (~4 billion) encrypt
//   calls under the SAME key.  For high-volume use, prefer XChaCha20Poly1305
//   (192-bit nonce, safe to ~2^80 messages).  If you must use AES-GCM at
//   scale, rotate the key well before 2^32 messages.
// ─────────────────────────────────────────────────────────────────────────────
class Aes256Gcm {
public:
    static constexpr std::size_t KEY_BYTES   = crypto_aead_aes256gcm_KEYBYTES;  // 32
    static constexpr std::size_t NONCE_BYTES = crypto_aead_aes256gcm_NPUBBYTES; // 12
    static constexpr std::size_t MAC_BYTES   = crypto_aead_aes256gcm_ABYTES;    // 16

    [[nodiscard]] static bool is_available() noexcept {
        return crypto_aead_aes256gcm_is_available() != 0;
    }

    [[nodiscard]] static SecureBuffer generate_key() {
        SecureBuffer k(KEY_BYTES);
        crypto_aead_aes256gcm_keygen(k.data());
        return k;
    }

    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (!is_available())
            return Result<SecureBuffer>::err("AES-256-GCM: not available on this CPU");
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM: invalid key");
        SecureBuffer out(NONCE_BYTES + plaintext.size() + MAC_BYTES);
        randombytes_buf(out.data(), NONCE_BYTES);
        unsigned long long ct_len = 0;
        if (crypto_aead_aes256gcm_encrypt(
                out.data() + NONCE_BYTES, &ct_len,
                plaintext.data(), plaintext.size(),
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nullptr, out.data(), key.data()) != 0)
            return Result<SecureBuffer>::err("AES-256-GCM: encryption failed");
        out.resize(NONCE_BYTES + static_cast<std::size_t>(ct_len));
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> ciphertext_with_nonce,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (!is_available())
            return Result<SecureBuffer>::err("AES-256-GCM: not available on this CPU");
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM: invalid key");
        if (ciphertext_with_nonce.size() < NONCE_BYTES + MAC_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM: ciphertext too short");
        const uint8_t* nonce  = ciphertext_with_nonce.data();
        const uint8_t* ct     = ciphertext_with_nonce.data() + NONCE_BYTES;
        std::size_t    ct_len = ciphertext_with_nonce.size() - NONCE_BYTES;
        SecureBuffer out(ct_len - MAC_BYTES);
        unsigned long long pt_len = 0;
        if (crypto_aead_aes256gcm_decrypt(
                out.data(), &pt_len, nullptr,
                ct, ct_len,
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nonce, key.data()) != 0)
            return Result<SecureBuffer>::err("AES-256-GCM: decryption failed (tampered?)");
        out.resize(static_cast<std::size_t>(pt_len));
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SecretStream — streaming AEAD for large files / data
//   Per-chunk authentication + ratcheting key material
// ─────────────────────────────────────────────────────────────────────────────
class SecretStream {
public:
    static constexpr std::size_t KEY_BYTES    = crypto_secretstream_xchacha20poly1305_KEYBYTES;
    static constexpr std::size_t HEADER_BYTES = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    static constexpr std::size_t MAC_BYTES    = crypto_secretstream_xchacha20poly1305_ABYTES;

    static constexpr uint8_t TAG_MESSAGE = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    static constexpr uint8_t TAG_FINAL   = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    static constexpr uint8_t TAG_PUSH    = crypto_secretstream_xchacha20poly1305_TAG_PUSH;
    static constexpr uint8_t TAG_REKEY   = crypto_secretstream_xchacha20poly1305_TAG_REKEY;

    [[nodiscard]] static SecureBuffer generate_key() {
        SecureBuffer k(KEY_BYTES);
        crypto_secretstream_xchacha20poly1305_keygen(k.data());
        return k;
    }

    class Encryptor {
    public:
        explicit Encryptor(std::span<const uint8_t> key) {
            if (key.size() != KEY_BYTES) throw std::invalid_argument("SecretStream: bad key");
            header_.resize(HEADER_BYTES);
            crypto_secretstream_xchacha20poly1305_init_push(&st_, header_.data(), key.data());
        }
        ~Encryptor() { sodium_memzero(&st_, sizeof(st_)); }  // wipe ratchet key material

        // Non-copyable (copying the ratchet state would enable nonce reuse).
        // Move transfers the state and wipes the source.
        Encryptor(const Encryptor&)            = delete;
        Encryptor& operator=(const Encryptor&) = delete;
        Encryptor(Encryptor&& o) noexcept : header_(std::move(o.header_)) {
            std::memcpy(&st_, &o.st_, sizeof(st_));
            sodium_memzero(&o.st_, sizeof(o.st_));
        }
        Encryptor& operator=(Encryptor&&) = delete;
        [[nodiscard]] const SecureBuffer& header() const noexcept { return header_; }
        [[nodiscard]] SecureBuffer
        push(std::span<const uint8_t> plaintext,
             uint8_t tag = TAG_MESSAGE,
             std::span<const uint8_t> aad = {}) {
            SecureBuffer ct(plaintext.size() + MAC_BYTES);
            crypto_secretstream_xchacha20poly1305_push(
                &st_, ct.data(), nullptr,
                plaintext.data(), plaintext.size(),
                aad.empty() ? nullptr : aad.data(), aad.size(), tag);
            return ct;
        }
        [[nodiscard]] SecureBuffer
        push_final(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad = {}) {
            return push(plaintext, TAG_FINAL, aad);
        }
    private:
        crypto_secretstream_xchacha20poly1305_state st_{};
        SecureBuffer header_;
    };

    class Decryptor {
    public:
        Decryptor(std::span<const uint8_t> key, std::span<const uint8_t> header) {
            if (key.size() != KEY_BYTES)     throw std::invalid_argument("SecretStream: bad key");
            if (header.size() != HEADER_BYTES) throw std::invalid_argument("SecretStream: bad header");
            if (crypto_secretstream_xchacha20poly1305_init_pull(&st_, header.data(), key.data()) != 0)
                throw std::runtime_error("SecretStream: pull init failed");
        }
        ~Decryptor() { sodium_memzero(&st_, sizeof(st_)); }  // wipe ratchet key material

        Decryptor(const Decryptor&)            = delete;
        Decryptor& operator=(const Decryptor&) = delete;
        Decryptor(Decryptor&& o) noexcept {
            std::memcpy(&st_, &o.st_, sizeof(st_));
            sodium_memzero(&o.st_, sizeof(o.st_));
        }
        Decryptor& operator=(Decryptor&&) = delete;
        struct PullResult { SecureBuffer plaintext; uint8_t tag; };
        [[nodiscard]] Result<PullResult>
        pull(std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad = {}) {
            if (ciphertext.size() < MAC_BYTES)
                return Result<PullResult>::err("SecretStream: chunk too small");
            SecureBuffer pt(ciphertext.size() - MAC_BYTES);
            uint8_t tag = 0;
            unsigned long long pt_len = 0;
            if (crypto_secretstream_xchacha20poly1305_pull(
                    &st_, pt.data(), &pt_len, &tag,
                    ciphertext.data(), ciphertext.size(),
                    aad.empty() ? nullptr : aad.data(), aad.size()) != 0)
                return Result<PullResult>::err("SecretStream: authentication failed");
            pt.resize(static_cast<std::size_t>(pt_len));
            return Result<PullResult>::ok(PullResult{ std::move(pt), tag });
        }
    private:
        crypto_secretstream_xchacha20poly1305_state st_{};
    };
};

} // namespace crypto::symmetric
