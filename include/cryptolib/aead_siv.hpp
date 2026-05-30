#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::symmetric::Aes256GcmSiv — nonce-misuse-resistant AEAD (RFC 8452)   ║
 * ║                                                                            ║
 * ║  Standard AEADs (AES-GCM, ChaCha20-Poly1305) catastrophically fail under   ║
 * ║  nonce reuse: a single repeat leaks the auth key and XOR of plaintexts.    ║
 * ║  AES-256-GCM-SIV degrades gracefully — a repeated (key, nonce, AAD,         ║
 * ║  plaintext) only reveals that the messages were identical; nothing else.   ║
 * ║  Use it when nonce uniqueness cannot be guaranteed, or when deterministic   ║
 * ║  encryption is desired.                                                     ║
 * ║                                                                            ║
 * ║  Backed by OpenSSL libcrypto's EVP (the library already links it).          ║
 * ║  Wire layout: [ nonce(12) | ciphertext | tag(16) ].                         ║
 * ║                                                                            ║
 * ║  Guarded by CRYPTOLIB_HAS_OPENSSL — builds without OpenSSL (e.g. WASM)      ║
 * ║  simply omit this type.                                                    ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_OPENSSL

#include "types.hpp"

#include <openssl/evp.h>
#include <sodium.h>        // randombytes_buf
#include <memory>
#include <span>

namespace crypto::symmetric {

class Aes256GcmSiv {
public:
    static constexpr std::size_t KEY_BYTES   = 32;
    static constexpr std::size_t NONCE_BYTES = 12;
    static constexpr std::size_t TAG_BYTES   = 16;
    static constexpr const char* ALG         = "AES-256-GCM-SIV";

    /// True if the linked OpenSSL provides AES-256-GCM-SIV.
    [[nodiscard]] static bool is_available() {
        CipherPtr c{EVP_CIPHER_fetch(nullptr, ALG, nullptr)};
        return c != nullptr;
    }

    [[nodiscard]] static SecureBuffer generate_key() {
        SecureBuffer k(KEY_BYTES);
        randombytes_buf(k.data(), KEY_BYTES);
        return k;
    }

    /// Encrypt → [ nonce(12) | ciphertext | tag(16) ].
    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: key must be 32 bytes");
        auto cipher = fetch();
        if (!cipher) return Result<SecureBuffer>::err("AES-256-GCM-SIV: unavailable in this OpenSSL");
        CtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) return Result<SecureBuffer>::err("AES-256-GCM-SIV: ctx alloc failed");

        SecureBuffer out(NONCE_BYTES + plaintext.size() + TAG_BYTES);
        randombytes_buf(out.data(), NONCE_BYTES);
        uint8_t* ct  = out.data() + NONCE_BYTES;
        uint8_t* tag = ct + plaintext.size();

        int len = 0;
        if (EVP_EncryptInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr) != 1 ||
            EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data(), out.data(), nullptr) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: init failed");
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: aad failed");
        if (EVP_EncryptUpdate(ctx.get(), ct, &len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: encrypt failed");
        int fin = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), ct + len, &fin) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: finalize failed");
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, TAG_BYTES, tag) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: get tag failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Decrypt [ nonce(12) | ciphertext | tag(16) ]. Fails closed on tamper.
    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> wire,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: key must be 32 bytes");
        if (wire.size() < NONCE_BYTES + TAG_BYTES)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: ciphertext too short");
        auto cipher = fetch();
        if (!cipher) return Result<SecureBuffer>::err("AES-256-GCM-SIV: unavailable in this OpenSSL");
        CtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) return Result<SecureBuffer>::err("AES-256-GCM-SIV: ctx alloc failed");

        const uint8_t* nonce = wire.data();
        std::size_t    ct_len = wire.size() - NONCE_BYTES - TAG_BYTES;
        const uint8_t* ct  = nonce + NONCE_BYTES;
        const uint8_t* tag = ct + ct_len;

        SecureBuffer out(ct_len);
        int len = 0;
        if (EVP_DecryptInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr) != 1 ||
            EVP_DecryptInit_ex2(ctx.get(), nullptr, key.data(), nonce, nullptr) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: init failed");
        // SIV: the tag is the synthetic IV — must be set before decryption.
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, TAG_BYTES,
                                const_cast<uint8_t*>(tag)) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: set tag failed");
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: aad failed");
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, ct,
                              static_cast<int>(ct_len)) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: decryption failed (tampered?)");
        int fin = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1)
            return Result<SecureBuffer>::err("AES-256-GCM-SIV: authentication failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

private:
    struct CipherDeleter { void operator()(EVP_CIPHER* c) const { if (c) EVP_CIPHER_free(c); } };
    struct CtxDeleter    { void operator()(EVP_CIPHER_CTX* c) const { if (c) EVP_CIPHER_CTX_free(c); } };
    using CipherPtr = std::unique_ptr<EVP_CIPHER, CipherDeleter>;
    using CtxPtr    = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

    [[nodiscard]] static CipherPtr fetch() {
        return CipherPtr{EVP_CIPHER_fetch(nullptr, ALG, nullptr)};
    }
};

} // namespace crypto::symmetric

#endif // CRYPTOLIB_HAS_OPENSSL
