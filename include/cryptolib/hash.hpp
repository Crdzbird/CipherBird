#pragma once

/**
 * crypto::hash — Standalone unidirectional primitives
 *
 * Use these directly when you need raw hashing, password storage,
 * or MACs without going through the vault pipeline.
 *
 *   Blake2b      — fast general-purpose hash (one-shot + streaming + keyed)
 *   Blake3       — BLAKE3 hash (one-shot + streaming + keyed + KDF) [requires libblake3]
 *   Sha256       — NIST SHA-2, 256-bit
 *   Sha512       — NIST SHA-2, 512-bit
 *   Argon2id     — memory-hard password hashing / key derivation (OWASP)
 *   HmacSha512   — keyed message authentication code
 *   HmacSha256   — keyed message authentication code (SHA-256)
 *   HkdfSha256   — HMAC-based key derivation function (RFC 5869)
 */

#include "types.hpp"
#include <sodium.h>
#include <string_view>

namespace crypto::hash {

// ─────────────────────────────────────────────────────────────────────────────
// BLAKE2b-512
// ─────────────────────────────────────────────────────────────────────────────
class Blake2b {
public:
    static constexpr std::size_t DIGEST_BYTES = crypto_generichash_BYTES_MAX; // 64

    [[nodiscard]] static Result<SecureBuffer>
    digest(std::span<const uint8_t> msg, std::span<const uint8_t> key = {}) {
        if (!key.empty() &&
            (key.size() < crypto_generichash_KEYBYTES_MIN ||
             key.size() > crypto_generichash_KEYBYTES_MAX))
            return Result<SecureBuffer>::err("Blake2b: invalid key length");

        SecureBuffer out(DIGEST_BYTES);
        if (crypto_generichash(out.data(), out.size(),
                               msg.data(), msg.size(),
                               key.empty() ? nullptr : key.data(),
                               key.size()) != 0)
            return Result<SecureBuffer>::err("Blake2b: hashing failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    digest(std::string_view msg) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() });
    }

    // Streaming API — feed data in chunks
    class Stream {
    public:
        Stream() {
            if (crypto_generichash_init(&st_, nullptr, 0, DIGEST_BYTES) != 0)
                throw std::runtime_error("Blake2b stream: init failed");
        }
        void update(std::span<const uint8_t> chunk) {
            if (finalized_)
                throw std::runtime_error("Blake2b stream: update after finalize");
            crypto_generichash_update(&st_, chunk.data(), chunk.size());
        }
        [[nodiscard]] SecureBuffer finalize() {
            if (finalized_)
                throw std::runtime_error("Blake2b stream: finalize called twice");
            finalized_ = true;
            SecureBuffer out(DIGEST_BYTES);
            crypto_generichash_final(&st_, out.data(), out.size());
            sodium_memzero(&st_, sizeof(st_));
            return out;
        }
    private:
        crypto_generichash_state st_{};
        bool finalized_ = false;
    };
};

// ─────────────────────────────────────────────────────────────────────────────
// BLAKE3 — fast, parallelizable hash (one-shot + streaming + keyed + KDF)
//   Requires: libblake3 (brew install blake3)
//   Enable:   -DCRYPTOLIB_BLAKE3=ON (default)
// ─────────────────────────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_BLAKE3
#include <blake3.h>

class Blake3 {
public:
    static constexpr std::size_t DIGEST_BYTES = BLAKE3_OUT_LEN;  // 32
    static constexpr std::size_t KEY_BYTES    = BLAKE3_KEY_LEN;  // 32

    /// One-shot unkeyed hash (default 32 bytes, extendable)
    [[nodiscard]] static Result<SecureBuffer>
    digest(std::span<const uint8_t> msg, std::size_t out_len = DIGEST_BYTES) {
        if (out_len == 0)
            return Result<SecureBuffer>::err("Blake3: output length must be > 0");
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, msg.data(), msg.size());
        SecureBuffer out(out_len);
        blake3_hasher_finalize(&h, out.data(), out.size());
        sodium_memzero(&h, sizeof(h));
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    digest(std::string_view msg, std::size_t out_len = DIGEST_BYTES) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() }, out_len);
    }

    /// Keyed hash (MAC) — key must be exactly 32 bytes
    [[nodiscard]] static Result<SecureBuffer>
    keyed(std::span<const uint8_t> msg,
          std::span<const uint8_t> key,
          std::size_t out_len = DIGEST_BYTES) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("Blake3: key must be exactly 32 bytes");
        if (out_len == 0)
            return Result<SecureBuffer>::err("Blake3: output length must be > 0");
        blake3_hasher h;
        blake3_hasher_init_keyed(&h, key.data());
        blake3_hasher_update(&h, msg.data(), msg.size());
        SecureBuffer out(out_len);
        blake3_hasher_finalize(&h, out.data(), out.size());
        sodium_memzero(&h, sizeof(h));
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Key derivation — domain-separated via context string (RFC-style)
    [[nodiscard]] static Result<SecureBuffer>
    derive_key(std::string_view context,
               std::span<const uint8_t> input_keying_material,
               std::size_t out_len = DIGEST_BYTES) {
        if (context.empty())
            return Result<SecureBuffer>::err("Blake3: context must not be empty");
        if (out_len == 0)
            return Result<SecureBuffer>::err("Blake3: output length must be > 0");
        blake3_hasher h;
        blake3_hasher_init_derive_key(&h, context.data());
        blake3_hasher_update(&h, input_keying_material.data(), input_keying_material.size());
        SecureBuffer out(out_len);
        blake3_hasher_finalize(&h, out.data(), out.size());
        sodium_memzero(&h, sizeof(h));
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Streaming API — feed data in chunks, finalize once
    class Stream {
    public:
        Stream() { blake3_hasher_init(&h_); }

        /// Construct keyed stream (MAC mode)
        explicit Stream(std::span<const uint8_t> key) {
            if (key.size() != KEY_BYTES)
                throw std::runtime_error("Blake3 stream: key must be exactly 32 bytes");
            blake3_hasher_init_keyed(&h_, key.data());
        }

        void update(std::span<const uint8_t> chunk) {
            if (finalized_)
                throw std::runtime_error("Blake3 stream: update after finalize");
            blake3_hasher_update(&h_, chunk.data(), chunk.size());
        }

        [[nodiscard]] SecureBuffer finalize(std::size_t out_len = DIGEST_BYTES) {
            if (finalized_)
                throw std::runtime_error("Blake3 stream: finalize called twice");
            finalized_ = true;
            SecureBuffer out(out_len);
            blake3_hasher_finalize(&h_, out.data(), out.size());
            sodium_memzero(&h_, sizeof(h_));
            return out;
        }
    private:
        blake3_hasher h_{};
        bool finalized_ = false;
    };
};

#endif // CRYPTOLIB_HAS_BLAKE3

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256
// ─────────────────────────────────────────────────────────────────────────────
class Sha256 {
public:
    static constexpr std::size_t DIGEST_BYTES = crypto_hash_sha256_BYTES;

    [[nodiscard]] static Result<SecureBuffer>
    digest(std::span<const uint8_t> msg) {
        SecureBuffer out(DIGEST_BYTES);
        if (crypto_hash_sha256(out.data(), msg.data(), msg.size()) != 0)
            return Result<SecureBuffer>::err("SHA256: failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
    [[nodiscard]] static Result<SecureBuffer>
    digest(std::string_view msg) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() });
    }

    class Stream {
    public:
        Stream() { crypto_hash_sha256_init(&st_); }
        void update(std::span<const uint8_t> chunk) {
            if (finalized_)
                throw std::runtime_error("SHA256 stream: update after finalize");
            crypto_hash_sha256_update(&st_, chunk.data(), chunk.size());
        }
        [[nodiscard]] SecureBuffer finalize() {
            if (finalized_)
                throw std::runtime_error("SHA256 stream: finalize called twice");
            finalized_ = true;
            SecureBuffer out(DIGEST_BYTES);
            crypto_hash_sha256_final(&st_, out.data());
            sodium_memzero(&st_, sizeof(st_));
            return out;
        }
    private:
        crypto_hash_sha256_state st_{};
        bool finalized_ = false;
    };
};

// ─────────────────────────────────────────────────────────────────────────────
// SHA-512
// ─────────────────────────────────────────────────────────────────────────────
class Sha512 {
public:
    static constexpr std::size_t DIGEST_BYTES = crypto_hash_sha512_BYTES;

    [[nodiscard]] static Result<SecureBuffer>
    digest(std::span<const uint8_t> msg) {
        SecureBuffer out(DIGEST_BYTES);
        if (crypto_hash_sha512(out.data(), msg.data(), msg.size()) != 0)
            return Result<SecureBuffer>::err("SHA512: failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
    [[nodiscard]] static Result<SecureBuffer>
    digest(std::string_view msg) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() });
    }

    class Stream {
    public:
        Stream() { crypto_hash_sha512_init(&st_); }
        void update(std::span<const uint8_t> chunk) {
            if (finalized_)
                throw std::runtime_error("SHA512 stream: update after finalize");
            crypto_hash_sha512_update(&st_, chunk.data(), chunk.size());
        }
        [[nodiscard]] SecureBuffer finalize() {
            if (finalized_)
                throw std::runtime_error("SHA512 stream: finalize called twice");
            finalized_ = true;
            SecureBuffer out(DIGEST_BYTES);
            crypto_hash_sha512_final(&st_, out.data());
            sodium_memzero(&st_, sizeof(st_));
            return out;
        }
    private:
        crypto_hash_sha512_state st_{};
        bool finalized_ = false;
    };
};

// ─────────────────────────────────────────────────────────────────────────────
// Argon2id — memory-hard password hashing / key derivation (OWASP 2023)
// ─────────────────────────────────────────────────────────────────────────────
class Argon2id {
public:
    static constexpr std::size_t SALT_BYTES = crypto_pwhash_SALTBYTES;
    static constexpr std::size_t HASH_BYTES = 32;

    struct HashResult { SecureBuffer hash; SecureBuffer salt; };

    /// Hash password — salt is generated internally
    [[nodiscard]] static Result<HashResult>
    hash_password(std::string_view password,
                  std::size_t       hash_len = HASH_BYTES,
                  unsigned long long ops     = crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  std::size_t        mem     = crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        SecureBuffer salt(SALT_BYTES);
        randombytes_buf(salt.data(), SALT_BYTES);
        SecureBuffer hash(hash_len);
        if (crypto_pwhash(hash.data(), hash.size(),
                          password.data(), password.size(), salt.data(),
                          ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0)
            return Result<HashResult>::err("Argon2id: OOM or bad params");
        return Result<HashResult>::ok(HashResult{ std::move(hash), std::move(salt) });
    }

    /// Derive key from password + existing salt
    [[nodiscard]] static Result<SecureBuffer>
    derive_key(std::string_view         password,
               std::span<const uint8_t> salt,
               std::size_t              key_len = HASH_BYTES,
               unsigned long long       ops     = crypto_pwhash_OPSLIMIT_INTERACTIVE,
               std::size_t              mem     = crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        if (salt.size() != SALT_BYTES)
            return Result<SecureBuffer>::err("Argon2id: salt must be 16 bytes");
        SecureBuffer key(key_len);
        if (crypto_pwhash(key.data(), key.size(),
                          password.data(), password.size(), salt.data(),
                          ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0)
            return Result<SecureBuffer>::err("Argon2id: derivation failed");
        return Result<SecureBuffer>::ok(std::move(key));
    }

    /// Constant-time verification
    [[nodiscard]] static bool
    verify(std::string_view         password,
           std::span<const uint8_t> stored_hash,
           std::span<const uint8_t> salt,
           unsigned long long       ops = crypto_pwhash_OPSLIMIT_INTERACTIVE,
           std::size_t              mem = crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        auto r = derive_key(password, salt, stored_hash.size(), ops, mem);
        if (r.is_err()) return false;
        return sodium_memcmp(r.value().data(), stored_hash.data(), stored_hash.size()) == 0;
    }

    /// PHC string — self-contained (embeds params + salt)
    [[nodiscard]] static Result<std::string>
    hash_password_str(std::string_view   password,
                      unsigned long long ops = crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      std::size_t        mem = crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        std::string out(crypto_pwhash_STRBYTES, '\0');
        if (crypto_pwhash_str(out.data(), password.data(), password.size(), ops, mem) != 0)
            return Result<std::string>::err("Argon2id: PHC hash failed");
        out.resize(std::strlen(out.c_str()));
        return Result<std::string>::ok(std::move(out));
    }

    [[nodiscard]] static bool
    verify_str(std::string_view password, std::string_view phc_str) {
        return crypto_pwhash_str_verify(phc_str.data(),
                                        password.data(), password.size()) == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA512 — keyed authentication code
// ─────────────────────────────────────────────────────────────────────────────
class HmacSha512 {
public:
    static constexpr std::size_t MAC_BYTES = crypto_auth_hmacsha512_BYTES;
    static constexpr std::size_t KEY_BYTES = crypto_auth_hmacsha512_KEYBYTES;

    [[nodiscard]] static Result<SecureBuffer>
    compute(std::span<const uint8_t> msg, std::span<const uint8_t> key) {
        if (key.size() < KEY_BYTES)
            return Result<SecureBuffer>::err("HMAC-SHA512: key too short");
        SecureBuffer mac(MAC_BYTES);
        crypto_auth_hmacsha512(mac.data(), msg.data(), msg.size(), key.data());
        return Result<SecureBuffer>::ok(std::move(mac));
    }

    [[nodiscard]] static bool
    verify(std::span<const uint8_t> msg,
           std::span<const uint8_t> mac,
           std::span<const uint8_t> key) {
        if (mac.size() != MAC_BYTES || key.size() < KEY_BYTES) return false;
        return crypto_auth_hmacsha512_verify(mac.data(), msg.data(), msg.size(), key.data()) == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 — keyed authentication code (SHA-256)
// ─────────────────────────────────────────────────────────────────────────────
class HmacSha256 {
public:
    static constexpr std::size_t MAC_BYTES = crypto_auth_hmacsha256_BYTES;   // 32
    static constexpr std::size_t KEY_BYTES = crypto_auth_hmacsha256_KEYBYTES; // 32

    [[nodiscard]] static Result<SecureBuffer>
    compute(std::span<const uint8_t> msg, std::span<const uint8_t> key) {
        if (key.size() < KEY_BYTES)
            return Result<SecureBuffer>::err("HMAC-SHA256: key too short");
        SecureBuffer mac(MAC_BYTES);
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, key.data(), key.size());
        crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
        crypto_auth_hmacsha256_final(&st, mac.data());
        sodium_memzero(&st, sizeof(st));
        return Result<SecureBuffer>::ok(std::move(mac));
    }

    [[nodiscard]] static bool
    verify(std::span<const uint8_t> msg,
           std::span<const uint8_t> mac,
           std::span<const uint8_t> key) {
        if (mac.size() != MAC_BYTES || key.size() < KEY_BYTES) return false;
        auto r = compute(msg, key);
        if (r.is_err()) return false;
        return sodium_memcmp(r.value().data(), mac.data(), MAC_BYTES) == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HKDF-SHA256 — HMAC-based Extract-and-Expand Key Derivation (RFC 5869)
//
// Built on top of libsodium's HMAC-SHA256 — no additional dependencies.
//
// Usage:
//   auto prk = HkdfSha256::extract(salt, ikm).value();
//   auto okm = HkdfSha256::expand(prk.span(), info, 64).value();
//
// Or one-shot:
//   auto key = HkdfSha256::derive(ikm, salt, info, 32).value();
// ─────────────────────────────────────────────────────────────────────────────
class HkdfSha256 {
public:
    static constexpr std::size_t PRK_BYTES  = crypto_auth_hmacsha256_BYTES; // 32
    static constexpr std::size_t HASH_BYTES = crypto_auth_hmacsha256_BYTES; // 32

    /// Extract: PRK = HMAC-SHA256(salt, IKM)
    /// If salt is empty, a zero-filled salt of HASH_BYTES is used (per RFC 5869 §2.2).
    [[nodiscard]] static Result<SecureBuffer>
    extract(std::span<const uint8_t> salt,
            std::span<const uint8_t> ikm) {
        // Salt defaults to a string of HASH_BYTES zeros
        uint8_t zero_salt[HASH_BYTES] = {};
        auto effective_salt = salt.empty()
            ? std::span<const uint8_t>{zero_salt, HASH_BYTES}
            : salt;

        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, effective_salt.data(), effective_salt.size());
        crypto_auth_hmacsha256_update(&st, ikm.data(), ikm.size());
        SecureBuffer prk(PRK_BYTES);
        crypto_auth_hmacsha256_final(&st, prk.data());
        sodium_memzero(&st, sizeof(st));
        return Result<SecureBuffer>::ok(std::move(prk));
    }

    /// Expand: OKM = T(1) ‖ T(2) ‖ ... ‖ T(N), truncated to out_len
    ///   T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)   (1-based counter byte)
    [[nodiscard]] static Result<SecureBuffer>
    expand(std::span<const uint8_t> prk,
           std::span<const uint8_t> info,
           std::size_t              out_len) {
        if (prk.size() < PRK_BYTES)
            return Result<SecureBuffer>::err("HKDF-SHA256: PRK too short");
        if (out_len == 0)
            return Result<SecureBuffer>::err("HKDF-SHA256: output length must be > 0");
        if (out_len > 255 * HASH_BYTES)
            return Result<SecureBuffer>::err("HKDF-SHA256: output length too large (max 8160)");

        SecureBuffer okm(out_len);
        uint8_t prev[HASH_BYTES] = {};  // T(i-1), empty for first iteration
        std::size_t prev_len = 0;
        std::size_t offset   = 0;
        uint8_t counter      = 1;

        while (offset < out_len) {
            crypto_auth_hmacsha256_state st;
            crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
            if (prev_len > 0)
                crypto_auth_hmacsha256_update(&st, prev, prev_len);
            if (!info.empty())
                crypto_auth_hmacsha256_update(&st, info.data(), info.size());
            crypto_auth_hmacsha256_update(&st, &counter, 1);
            crypto_auth_hmacsha256_final(&st, prev);
            sodium_memzero(&st, sizeof(st));

            prev_len = HASH_BYTES;
            std::size_t to_copy = std::min<std::size_t>(HASH_BYTES, out_len - offset);
            std::memcpy(okm.data() + offset, prev, to_copy);
            offset += to_copy;
            ++counter;
        }

        sodium_memzero(prev, HASH_BYTES);
        return Result<SecureBuffer>::ok(std::move(okm));
    }

    /// Convenience: extract + expand
    [[nodiscard]] static Result<SecureBuffer>
    expand(std::span<const uint8_t> prk,
           std::string_view         info,
           std::size_t              out_len) {
        return expand(prk,
            { reinterpret_cast<const uint8_t*>(info.data()), info.size() },
            out_len);
    }

    /// One-shot: extract → expand
    [[nodiscard]] static Result<SecureBuffer>
    derive(std::span<const uint8_t> ikm,
           std::span<const uint8_t> salt,
           std::span<const uint8_t> info,
           std::size_t              out_len) {
        auto prk = extract(salt, ikm);
        if (prk.is_err()) return Result<SecureBuffer>::err(prk.error().message);
        return expand(prk.value().span(), info, out_len);
    }

    [[nodiscard]] static Result<SecureBuffer>
    derive(std::span<const uint8_t> ikm,
           std::span<const uint8_t> salt,
           std::string_view         info,
           std::size_t              out_len) {
        return derive(ikm, salt,
            { reinterpret_cast<const uint8_t*>(info.data()), info.size() },
            out_len);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HKDF-SHA512 — HMAC-based Extract-and-Expand Key Derivation (RFC 5869)
//
// Built on libsodium's HMAC-SHA512 — no additional dependencies. Same contract
// as HkdfSha256 with a 64-byte hash (used by HPKE's HKDF-SHA512 KDF option).
// ─────────────────────────────────────────────────────────────────────────────
class HkdfSha512 {
public:
    static constexpr std::size_t PRK_BYTES  = crypto_auth_hmacsha512_BYTES; // 64
    static constexpr std::size_t HASH_BYTES = crypto_auth_hmacsha512_BYTES; // 64

    /// Extract: PRK = HMAC-SHA512(salt, IKM). Empty salt → HASH_BYTES zeros.
    [[nodiscard]] static Result<SecureBuffer>
    extract(std::span<const uint8_t> salt, std::span<const uint8_t> ikm) {
        uint8_t zero_salt[HASH_BYTES] = {};
        auto effective_salt = salt.empty()
            ? std::span<const uint8_t>{zero_salt, HASH_BYTES}
            : salt;
        crypto_auth_hmacsha512_state st;
        crypto_auth_hmacsha512_init(&st, effective_salt.data(), effective_salt.size());
        crypto_auth_hmacsha512_update(&st, ikm.data(), ikm.size());
        SecureBuffer prk(PRK_BYTES);
        crypto_auth_hmacsha512_final(&st, prk.data());
        sodium_memzero(&st, sizeof(st));
        return Result<SecureBuffer>::ok(std::move(prk));
    }

    /// Expand: OKM = T(1) ‖ T(2) ‖ … truncated to out_len (RFC 5869 §2.3).
    [[nodiscard]] static Result<SecureBuffer>
    expand(std::span<const uint8_t> prk, std::span<const uint8_t> info, std::size_t out_len) {
        if (prk.size() < PRK_BYTES)
            return Result<SecureBuffer>::err("HKDF-SHA512: PRK too short");
        if (out_len == 0)
            return Result<SecureBuffer>::err("HKDF-SHA512: output length must be > 0");
        if (out_len > 255 * HASH_BYTES)
            return Result<SecureBuffer>::err("HKDF-SHA512: output length too large");

        SecureBuffer okm(out_len);
        uint8_t prev[HASH_BYTES] = {};
        std::size_t prev_len = 0, offset = 0;
        uint8_t counter = 1;
        while (offset < out_len) {
            crypto_auth_hmacsha512_state st;
            crypto_auth_hmacsha512_init(&st, prk.data(), prk.size());
            if (prev_len > 0) crypto_auth_hmacsha512_update(&st, prev, prev_len);
            if (!info.empty()) crypto_auth_hmacsha512_update(&st, info.data(), info.size());
            crypto_auth_hmacsha512_update(&st, &counter, 1);
            crypto_auth_hmacsha512_final(&st, prev);
            sodium_memzero(&st, sizeof(st));
            prev_len = HASH_BYTES;
            std::size_t to_copy = std::min<std::size_t>(HASH_BYTES, out_len - offset);
            std::memcpy(okm.data() + offset, prev, to_copy);
            offset += to_copy;
            ++counter;
        }
        sodium_memzero(prev, HASH_BYTES);
        return Result<SecureBuffer>::ok(std::move(okm));
    }
};

} // namespace crypto::hash
