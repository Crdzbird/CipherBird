// ─────────────────────────────────────────────────────────────────────────────
// Keccak-256 — ORIGINAL Keccak padding (0x01), as used by Ethereum.
//
// This is NOT NIST SHA3-256. The only difference is the domain/padding byte:
//   • original Keccak (this file, Ethereum): first pad byte 0x01
//   • NIST FIPS-202 SHA3-256:                first pad byte 0x06
// They produce DIFFERENT digests for the same input. Ethereum (tx hashing,
// contract-address derivation, ABI selectors, event topics, EIP-55) uses the
// original Keccak — hence this dedicated implementation.
//
// The Keccak-f[1600] permutation below is the public-domain compact reference
// (tiny_sha3, Markku-Juhani O. Saarinen). Absorb/squeeze use shift-based byte
// access so the code is endianness-independent. Keccak operates only on public
// data (messages, public keys) — there is no secret-dependent control flow, so
// constant-timeness is not a requirement here.
//
// KAT-REQUIRED (validated in tests/test_evm_btc.cpp):
//   keccak256("")    = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//   keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>

#include "types.hpp"

namespace crypto::hash {

class Keccak256 {
public:
    static constexpr std::size_t DIGEST_BYTES = 32;
    static constexpr std::size_t RATE_BYTES   = 136;  // (1600 - 2*256) / 8

    [[nodiscard]] static Result<SecureBuffer> digest(std::span<const uint8_t> msg) {
        SecureBuffer out(DIGEST_BYTES);
        keccak(msg.data(), msg.size(), out.data());
        return Result<SecureBuffer>::ok(std::move(out));
    }
    [[nodiscard]] static Result<SecureBuffer> digest(std::string_view msg) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() });
    }

private:
    static constexpr uint64_t rotl64(uint64_t x, unsigned n) {
        return (x << n) | (x >> (64 - n));
    }

    static void keccakf(uint64_t st[25]) {
        static const uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
        };
        static const int rho[24]  = { 1, 3, 6,10,15,21,28,36,45,55, 2,14,27,41,56, 8,25,43,62,18,39,61,20,44 };
        static const int pi_[24]  = {10, 7,11,17,18, 3, 5,16, 8,21,24, 4,15,23,19,13,12, 2,20,14,22, 9, 6, 1 };

        uint64_t t, bc[5];
        for (int round = 0; round < 24; ++round) {
            // θ (theta)
            for (int i = 0; i < 5; ++i)
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            for (int i = 0; i < 5; ++i) {
                t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
            }
            // ρ (rho) and π (pi)
            t = st[1];
            for (int i = 0; i < 24; ++i) {
                int j = pi_[i];
                bc[0] = st[j];
                st[j] = rotl64(t, rho[i]);
                t = bc[0];
            }
            // χ (chi)
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; ++i) bc[i] = st[j + i];
                for (int i = 0; i < 5; ++i) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
            // ι (iota)
            st[0] ^= RC[round];
        }
    }

    // Endianness-independent absorb/squeeze (byte access via shifts on the lanes).
    static void keccak(const uint8_t* in, std::size_t inlen, uint8_t* out) {
        uint64_t st[25] = {0};
        const std::size_t rate = RATE_BYTES;

        auto absorb_byte = [&](std::size_t pos, uint8_t b) {
            st[pos >> 3] ^= static_cast<uint64_t>(b) << (8 * (pos & 7));
        };

        // Absorb full rate-sized blocks.
        while (inlen >= rate) {
            for (std::size_t i = 0; i < rate; ++i) absorb_byte(i, in[i]);
            keccakf(st);
            in += rate;
            inlen -= rate;
        }
        // Final block: remaining bytes + pad10*1 with original-Keccak 0x01 first byte.
        for (std::size_t i = 0; i < inlen; ++i) absorb_byte(i, in[i]);
        absorb_byte(inlen, 0x01);        // ORIGINAL Keccak (Ethereum). SHA3 would be 0x06.
        absorb_byte(rate - 1, 0x80);     // final padding bit
        keccakf(st);

        // Squeeze 32 bytes (rate > 32, so a single permutation suffices).
        for (std::size_t i = 0; i < DIGEST_BYTES; ++i)
            out[i] = static_cast<uint8_t>(st[i >> 3] >> (8 * (i & 7)));
    }
};

} // namespace crypto::hash
