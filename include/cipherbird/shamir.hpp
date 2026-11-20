#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Shamir — Shamir Secret Sharing over GF(256)                        ║
 * ║                                                                            ║
 * ║  Split a secret into N shares such that any K reconstruct it and any K-1    ║
 * ║  reveal NOTHING (information-theoretic). Use for key backup / escrow /      ║
 * ║  M-of-N recovery (e.g. split a Keyring master across guardians).           ║
 * ║                                                                            ║
 * ║  Per-byte degree-(K-1) polynomials over GF(2^8) (AES field, 0x11b).         ║
 * ║  GF multiply/inverse are CONSTANT-TIME (branchless) — no secret-dependent   ║
 * ║  table lookups.                                                            ║
 * ║                                                                            ║
 * ║  Share wire layout: index(1) ‖ y-bytes(len = secret length).               ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>   // randombytes_buf
#include <cstdint>
#include <span>
#include <vector>

namespace crypto {

class Shamir {
public:
    struct Share {
        uint8_t      index;   // x-coordinate, 1..255 (never 0)
        SecureBuffer y;       // one y per secret byte
    };

    /// Split `secret` into `n` shares, any `k` of which reconstruct it.
    [[nodiscard]] static Result<std::vector<Share>>
    split(std::span<const uint8_t> secret, uint8_t n, uint8_t k) {
        if (k == 0 || n == 0 || k > n)
            return Result<std::vector<Share>>::err("Shamir: require 1 <= k <= n");
        if (secret.empty())
            return Result<std::vector<Share>>::err("Shamir: empty secret");
        // n <= 255 because indices are distinct non-zero bytes.
        // (uint8_t n already bounds this to <= 255.)

        std::vector<Share> shares;
        shares.reserve(n);
        for (uint8_t i = 0; i < n; ++i)
            shares.push_back(Share{static_cast<uint8_t>(i + 1), SecureBuffer(secret.size())});

        SecureBuffer coeffs(k);  // reused per byte: coeffs[0]=secret byte, rest random
        for (std::size_t b = 0; b < secret.size(); ++b) {
            coeffs.data()[0] = secret[b];
            if (k > 1) randombytes_buf(coeffs.data() + 1, k - 1);
            for (auto& sh : shares)
                sh.y.data()[b] = eval(coeffs.span(), sh.index);
        }
        return Result<std::vector<Share>>::ok(std::move(shares));
    }

    /// Reconstruct from shares. With >= k correct shares → the secret; with
    /// fewer (or wrong) shares → an unrelated value (no error: that secrecy is
    /// the whole point). Requires distinct indices and equal y-lengths.
    [[nodiscard]] static Result<SecureBuffer>
    combine(std::span<const Share> shares) {
        if (shares.empty())
            return Result<SecureBuffer>::err("Shamir: no shares");
        const std::size_t len = shares[0].y.size();
        for (const auto& s : shares) {
            if (s.index == 0)
                return Result<SecureBuffer>::err("Shamir: invalid share index 0");
            if (s.y.size() != len)
                return Result<SecureBuffer>::err("Shamir: inconsistent share length");
        }
        for (std::size_t i = 0; i < shares.size(); ++i)
            for (std::size_t j = i + 1; j < shares.size(); ++j)
                if (shares[i].index == shares[j].index)
                    return Result<SecureBuffer>::err("Shamir: duplicate share index");

        SecureBuffer out(len);
        // Lagrange basis at x=0: b_j = Π_{m≠j} x_m * inv(x_j ⊕ x_m).
        for (std::size_t j = 0; j < shares.size(); ++j) {
            uint8_t basis = 1;
            for (std::size_t m = 0; m < shares.size(); ++m) {
                if (m == j) continue;
                basis = gf_mul(basis, gf_mul(shares[m].index,
                                             gf_inv(shares[j].index ^ shares[m].index)));
            }
            for (std::size_t b = 0; b < len; ++b)
                out.data()[b] ^= gf_mul(shares[j].y.data()[b], basis);
        }
        return Result<SecureBuffer>::ok(std::move(out));
    }

private:
    // Evaluate polynomial (coeffs low→high) at x, Horner's method, GF(256).
    [[nodiscard]] static uint8_t eval(std::span<const uint8_t> coeffs, uint8_t x) {
        uint8_t acc = 0;
        for (std::size_t i = coeffs.size(); i-- > 0;)
            acc = gf_mul(acc, x) ^ coeffs[i];
        return acc;
    }

    // Constant-time GF(2^8) multiply (Russian-peasant, AES poly 0x11b).
    [[nodiscard]] static uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; ++i) {
            p ^= static_cast<uint8_t>(-(b & 1)) & a;
            uint8_t hi = static_cast<uint8_t>(-(a >> 7)) & 0x1b;
            a = static_cast<uint8_t>(a << 1) ^ hi;
            b = static_cast<uint8_t>(b >> 1);
        }
        return p;
    }

    // Inverse via Fermat: a^(254) = a^-1 in GF(2^8). Fixed exponent ⇒ const-time.
    [[nodiscard]] static uint8_t gf_inv(uint8_t a) {
        uint8_t r = 1, base = a;
        // 254 = 0b11111110
        for (int bit = 1; bit < 8; ++bit) {           // exponent bits 1..7 are set
            base = gf_mul(base, base);                 // base = a^(2^bit)
            r = gf_mul(r, base);
        }
        return r;  // a^(2+4+...+128) = a^254
    }
};

} // namespace crypto
