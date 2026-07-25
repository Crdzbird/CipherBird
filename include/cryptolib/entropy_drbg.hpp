#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::entropy::HmacDrbg — HMAC-DRBG (NIST SP 800-90A), HMAC-SHA-512        ║
 * ║                                                                            ║
 * ║  A deterministic random-bit generator: seed it once from a high-entropy      ║
 * ║  source, then pull an arbitrarily long, forward-secure keystream. Turns a     ║
 * ║  one-shot entropy pull (e.g. MediaEntropy's conditioned 64 bytes) into a      ║
 * ║  reproducible-or-fresh *beacon* — the real LavaRand shape.                    ║
 * ║                                                                            ║
 * ║  Faithful to SP 800-90A §10.1.2 (Update / Instantiate / Generate / Reseed).  ║
 * ║  Built on libsodium HMAC-SHA-512 — composition only, no new cryptography.     ║
 * ║  Validated byte-for-byte against a NIST CAVP HMAC_DRBG SHA-512 vector.        ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace crypto::entropy {

class HmacDrbg {
public:
    static constexpr std::size_t OUTLEN = 64;                 // SHA-512 output
    static constexpr std::size_t MIN_ENTROPY_BYTES = 32;      // 256-bit strength
    static constexpr std::size_t MAX_BYTES_PER_REQUEST = 1u << 16; // 65536
    static constexpr uint64_t    RESEED_INTERVAL = (1ull << 48);

    /// Instantiate from an entropy input (>= 32 bytes), an optional nonce, and
    /// an optional personalization string (SP 800-90A §10.1.2.3).
    [[nodiscard]] static Result<HmacDrbg>
    instantiate(std::span<const uint8_t> entropy, std::span<const uint8_t> nonce = {},
                std::span<const uint8_t> personalization = {}) {
        if (entropy.size() < MIN_ENTROPY_BYTES)
            return Result<HmacDrbg>::err("HMAC-DRBG: entropy input must be >= 32 bytes");
        HmacDrbg d;
        std::memset(d.K_.data(), 0x00, OUTLEN);
        std::memset(d.V_.data(), 0x01, OUTLEN);
        std::vector<uint8_t> seed;
        seed.insert(seed.end(), entropy.begin(), entropy.end());
        seed.insert(seed.end(), nonce.begin(), nonce.end());
        seed.insert(seed.end(), personalization.begin(), personalization.end());
        d.update({ seed.data(), seed.size() });
        sodium_memzero(seed.data(), seed.size());
        d.reseed_counter_ = 1;
        return Result<HmacDrbg>::ok(std::move(d));
    }

    /// Generate `num_bytes` pseudo-random bytes (SP 800-90A §10.1.2.5).
    [[nodiscard]] Result<SecureBuffer>
    generate(std::size_t num_bytes, std::span<const uint8_t> additional = {}) {
        if (num_bytes > MAX_BYTES_PER_REQUEST)
            return Result<SecureBuffer>::err("HMAC-DRBG: at most 65536 bytes per request");
        if (reseed_counter_ > RESEED_INTERVAL)
            return Result<SecureBuffer>::err("HMAC-DRBG: reseed required");
        if (!additional.empty()) update(additional);

        SecureBuffer out(num_bytes);
        std::size_t off = 0;
        while (off < num_bytes) {
            hmac(K_, { V_.data(), OUTLEN }, V_.data());  // V = HMAC(K, V)
            std::size_t n = std::min(OUTLEN, num_bytes - off);
            std::memcpy(out.data() + off, V_.data(), n);
            off += n;
        }
        update(additional);  // final update (additional may be empty)
        ++reseed_counter_;
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Reseed with fresh entropy (SP 800-90A §10.1.2.4).
    void reseed(std::span<const uint8_t> entropy, std::span<const uint8_t> additional = {}) {
        std::vector<uint8_t> seed(entropy.begin(), entropy.end());
        seed.insert(seed.end(), additional.begin(), additional.end());
        update({ seed.data(), seed.size() });
        sodium_memzero(seed.data(), seed.size());
        reseed_counter_ = 1;
    }

    // Internal-state accessors (for known-answer validation).
    [[nodiscard]] std::span<const uint8_t> key_state() const { return { K_.data(), OUTLEN }; }
    [[nodiscard]] std::span<const uint8_t> v_state() const { return { V_.data(), OUTLEN }; }

private:
    std::array<uint8_t, OUTLEN> K_{}, V_{};
    uint64_t reseed_counter_ = 0;

    static void hmac(const std::array<uint8_t, OUTLEN>& key, std::span<const uint8_t> msg, uint8_t* out) {
        crypto_auth_hmacsha512_state st;
        crypto_auth_hmacsha512_init(&st, key.data(), key.size());
        crypto_auth_hmacsha512_update(&st, msg.data(), msg.size());
        crypto_auth_hmacsha512_final(&st, out);
        sodium_memzero(&st, sizeof st);
    }

    // Update (SP 800-90A §10.1.2.2):
    //   K = HMAC(K, V || 0x00 || provided);  V = HMAC(K, V)
    //   if provided != "":  K = HMAC(K, V || 0x01 || provided);  V = HMAC(K, V)
    void update(std::span<const uint8_t> provided) {
        auto round = [&](uint8_t tag) {
            crypto_auth_hmacsha512_state st;
            crypto_auth_hmacsha512_init(&st, K_.data(), OUTLEN);
            crypto_auth_hmacsha512_update(&st, V_.data(), OUTLEN);
            crypto_auth_hmacsha512_update(&st, &tag, 1);
            if (!provided.empty())
                crypto_auth_hmacsha512_update(&st, provided.data(), provided.size());
            crypto_auth_hmacsha512_final(&st, K_.data());  // K = HMAC(K, V || tag || provided)
            sodium_memzero(&st, sizeof st);
            hmac(K_, { V_.data(), OUTLEN }, V_.data());     // V = HMAC(K, V)
        };
        round(0x00);
        if (!provided.empty()) round(0x01);
    }
};

} // namespace crypto::entropy
