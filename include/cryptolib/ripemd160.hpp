// ─────────────────────────────────────────────────────────────────────────────
// RIPEMD-160 — 160-bit hash (Bosselaers/Dobbertin/Preneel, 1996).
//
// Used by Bitcoin: HASH160(x) = ripemd160(sha256(x)) for P2PKH / P2WPKH address
// derivation. Composes with the existing cryptolib_sha256.
//
// Standalone reference implementation (two parallel 80-step lines, little-endian
// message schedule, MD-style padding). RIPEMD-160 operates only on public data;
// there is no secret-dependent control flow, so constant-timeness is not a
// requirement here.
//
// KAT-REQUIRED (validated in tests/test_evm_btc.cpp):
//   ripemd160("")    = 9c1185a5c5e9fc54612808977ee8f548b2258d31
//   ripemd160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <span>
#include <string_view>

#include "types.hpp"

namespace crypto::hash {

class Ripemd160 {
public:
    static constexpr std::size_t DIGEST_BYTES = 20;

    [[nodiscard]] static Result<SecureBuffer> digest(std::span<const uint8_t> msg) {
        SecureBuffer out(DIGEST_BYTES);
        hash(msg.data(), msg.size(), out.data());
        return Result<SecureBuffer>::ok(std::move(out));
    }
    [[nodiscard]] static Result<SecureBuffer> digest(std::string_view msg) {
        return digest({ reinterpret_cast<const uint8_t*>(msg.data()), msg.size() });
    }

private:
    static constexpr uint32_t rol(uint32_t x, unsigned n) {
        return (x << n) | (x >> (32 - n));
    }
    // Round functions f1..f5.
    static constexpr uint32_t f(int round, uint32_t x, uint32_t y, uint32_t z) {
        switch (round) {
            case 0: return x ^ y ^ z;
            case 1: return (x & y) | (~x & z);
            case 2: return (x | ~y) ^ z;
            case 3: return (x & z) | (y & ~z);
            default: return x ^ (y | ~z);
        }
    }

    static void compress(uint32_t h[5], const uint8_t block[64]) {
        // Message-word selection (left / right lines).
        static const int rL[80] = {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
            1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
        static const int rR[80] = {
            5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
            6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
            8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
        // Rotation amounts (left / right lines).
        static const int sL[80] = {
            11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
            7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
            11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
        static const int sR[80] = {
            8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
            9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
            15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };
        // Per-round added constants (left / right lines), one per 16-step group.
        static const uint32_t kL[5] = { 0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu };
        static const uint32_t kR[5] = { 0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u };

        uint32_t X[16];
        for (int i = 0; i < 16; ++i) {
            X[i] = static_cast<uint32_t>(block[i*4])
                 | (static_cast<uint32_t>(block[i*4+1]) << 8)
                 | (static_cast<uint32_t>(block[i*4+2]) << 16)
                 | (static_cast<uint32_t>(block[i*4+3]) << 24);
        }

        uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
        uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

        for (int j = 0; j < 80; ++j) {
            int g = j / 16;                 // 0..4
            int gr = 4 - g;                 // right line uses functions in reverse order
            uint32_t t;
            t = rol(al + f(g,  bl, cl, dl) + X[rL[j]] + kL[g],  sL[j]) + el;
            al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
            t = rol(ar + f(gr, br, cr, dr) + X[rR[j]] + kR[g],  sR[j]) + er;
            ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
        }

        uint32_t t = h[1] + cl + dr;
        h[1] = h[2] + dl + er;
        h[2] = h[3] + el + ar;
        h[3] = h[4] + al + br;
        h[4] = h[0] + bl + cr;
        h[0] = t;
    }

    static void hash(const uint8_t* msg, std::size_t len, uint8_t* out) {
        uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };

        std::size_t full = len / 64;
        for (std::size_t i = 0; i < full; ++i) compress(h, msg + i * 64);

        // Padding: 0x80, zero-fill, then 64-bit little-endian bit length.
        uint8_t block[128] = {0};
        std::size_t rem = len - full * 64;
        if (rem) std::memcpy(block, msg + full * 64, rem);
        block[rem] = 0x80;
        std::size_t pad_blocks = (rem >= 56) ? 2 : 1;
        std::size_t total = pad_blocks * 64;
        uint64_t bits = static_cast<uint64_t>(len) * 8;
        for (int i = 0; i < 8; ++i)
            block[total - 8 + i] = static_cast<uint8_t>(bits >> (8 * i));

        compress(h, block);
        if (pad_blocks == 2) compress(h, block + 64);

        for (int i = 0; i < 5; ++i) {
            out[i*4]   = static_cast<uint8_t>(h[i]);
            out[i*4+1] = static_cast<uint8_t>(h[i] >> 8);
            out[i*4+2] = static_cast<uint8_t>(h[i] >> 16);
            out[i*4+3] = static_cast<uint8_t>(h[i] >> 24);
        }
    }
};

} // namespace crypto::hash
