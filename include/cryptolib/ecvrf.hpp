#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Ecvrf — Verifiable Random Function (RFC 9381)                        ║
 * ║  ECVRF-EDWARDS25519-SHA512-TAI  (ciphersuite 0x03)                          ║
 * ║                                                                            ║
 * ║  A VRF is a public-key pseudo-random function: the holder of a secret key    ║
 * ║  turns an input into a pseudo-random output PLUS a proof that anyone with    ║
 * ║  the public key can verify — without learning the key or being able to       ║
 * ║  forge a different output. The output is unique per (key, input) and         ║
 * ║  unpredictable to everyone but the key holder.                              ║
 * ║                                                                            ║
 * ║  Uses: verifiable lotteries, leader election (proof-of-stake), on-chain      ║
 * ║  randomness beacons, verifiable DNS (the chain-interop counterpart to the    ║
 * ║  EVM/BTC primitives).                                                       ║
 * ║                                                                            ║
 * ║  Built on libsodium edwards25519 scalar/point arithmetic + SHA-512. The      ║
 * ║  try-and-increment hash-to-curve decodes a hash as a curve point and clears  ║
 * ║  the cofactor (×8 via three point additions). No new cryptography — a        ║
 * ║  faithful RFC 9381 implementation, validated against its Appendix B vectors. ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace crypto {

class Ecvrf {
public:
    static constexpr uint8_t  SUITE   = 0x03; // ECVRF-EDWARDS25519-SHA512-TAI
    static constexpr std::size_t PT_BYTES     = 32; // point / public key
    static constexpr std::size_t SK_BYTES     = 32; // secret seed
    static constexpr std::size_t SCALAR_BYTES = 32;
    static constexpr std::size_t C_BYTES      = 16; // cLen
    static constexpr std::size_t PROOF_BYTES  = 80; // Gamma(32) + c(16) + s(32)
    static constexpr std::size_t HASH_BYTES   = 64; // beta (SHA-512)

    struct KeyPair {
        SecureBuffer public_key;  // 32-byte Y = x·B
        SecureBuffer secret_key;  // 32-byte seed (RFC 8032 SK)
    };

    // ── Key generation ────────────────────────────────────────────────────────
    [[nodiscard]] static KeyPair generate_keypair() {
        KeyPair kp;
        kp.secret_key = SecureBuffer(SK_BYTES);
        randombytes_buf(kp.secret_key.data(), SK_BYTES);
        kp.public_key = derive_public_key(kp.secret_key.span());
        return kp;
    }

    /// Y = x·B for the RFC 8032 secret seed `sk`.
    [[nodiscard]] static SecureBuffer derive_public_key(std::span<const uint8_t> sk) {
        auto [x, trunc] = expand_sk(sk);
        (void)trunc;
        SecureBuffer y(PT_BYTES);
        crypto_scalarmult_ed25519_base_noclamp(y.data(), x.data());
        return y;
    }

    // ── Prove: pi = ECVRF_prove(SK, alpha) ────────────────────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    prove(std::span<const uint8_t> sk, std::span<const uint8_t> alpha) {
        if (sk.size() != SK_BYTES) return Result<SecureBuffer>::err("ECVRF: secret key must be 32 bytes");
        auto [x, trunc] = expand_sk(sk);
        SecureBuffer Y(PT_BYTES);
        crypto_scalarmult_ed25519_base_noclamp(Y.data(), x.data());

        auto H = encode_to_curve(Y.span(), alpha);
        if (H.is_err()) return Result<SecureBuffer>::err(H.error().message);
        const auto& h = H.value();

        SecureBuffer Gamma(PT_BYTES);
        if (crypto_scalarmult_ed25519_noclamp(Gamma.data(), x.data(), h.data()) != 0)
            return Result<SecureBuffer>::err("ECVRF: gamma computation failed");

        // Nonce k = SHA512(trunc || h) reduced mod q.
        SecureBuffer k = reduce64(sha512(trunc.span(), h.span()).span());
        SecureBuffer kB(PT_BYTES), kH(PT_BYTES);
        if (crypto_scalarmult_ed25519_base_noclamp(kB.data(), k.data()) != 0 ||
            crypto_scalarmult_ed25519_noclamp(kH.data(), k.data(), h.data()) != 0)
            return Result<SecureBuffer>::err("ECVRF: nonce commitment failed");

        auto c = challenge(Y.span(), h.span(), Gamma.span(), kB.span(), kH.span()); // 16 bytes
        SecureBuffer c32 = pad_scalar(c.span());
        SecureBuffer s(SCALAR_BYTES);
        crypto_core_ed25519_scalar_mul(s.data(), c32.data(), x.data()); // c·x
        crypto_core_ed25519_scalar_add(s.data(), k.data(), s.data());   // k + c·x

        SecureBuffer pi(PROOF_BYTES);
        std::memcpy(pi.data(), Gamma.data(), PT_BYTES);
        std::memcpy(pi.data() + PT_BYTES, c.data(), C_BYTES);
        std::memcpy(pi.data() + PT_BYTES + C_BYTES, s.data(), SCALAR_BYTES);
        return Result<SecureBuffer>::ok(std::move(pi));
    }

    // ── proof_to_hash: beta = ECVRF_proof_to_hash(pi) ─────────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    proof_to_hash(std::span<const uint8_t> pi) {
        if (pi.size() != PROOF_BYTES) return Result<SecureBuffer>::err("ECVRF: proof must be 80 bytes");
        std::span<const uint8_t> Gamma = pi.subspan(0, PT_BYTES);
        SecureBuffer cofG(PT_BYTES);
        if (!cofactor_mul(Gamma, cofG))
            return Result<SecureBuffer>::err("ECVRF: invalid gamma in proof");
        // beta = Hash(suite || 0x03 || point_to_string(8·Gamma) || 0x00)
        std::array<uint8_t, 1> front{ 0x03 }, back{ 0x00 }, suite{ SUITE };
        return Result<SecureBuffer>::ok(
            sha512(suite, front, cofG.span(), back));
    }

    // ── Verify: beta or INVALID = ECVRF_verify(Y, alpha, pi) ───────────────────
    [[nodiscard]] static Result<SecureBuffer>
    verify(std::span<const uint8_t> pk, std::span<const uint8_t> alpha, std::span<const uint8_t> pi) {
        if (pk.size() != PT_BYTES) return Result<SecureBuffer>::err("ECVRF: public key must be 32 bytes");
        if (pi.size() != PROOF_BYTES) return Result<SecureBuffer>::err("ECVRF: proof must be 80 bytes");
        if (crypto_core_ed25519_is_valid_point(pk.data()) != 1)
            return Result<SecureBuffer>::err("ECVRF: invalid public key");

        std::span<const uint8_t> Gamma = pi.subspan(0, PT_BYTES);
        std::span<const uint8_t> c     = pi.subspan(PT_BYTES, C_BYTES);
        std::span<const uint8_t> s     = pi.subspan(PT_BYTES + C_BYTES, SCALAR_BYTES);
        if (!scalar_is_canonical(s)) return Result<SecureBuffer>::err("ECVRF: s out of range");

        auto H = encode_to_curve(pk, alpha);
        if (H.is_err()) return Result<SecureBuffer>::err(H.error().message);
        const auto& h = H.value();

        SecureBuffer c32 = pad_scalar(c);
        // U = s·B - c·Y
        SecureBuffer sB(PT_BYTES), cY(PT_BYTES), U(PT_BYTES);
        if (crypto_scalarmult_ed25519_base_noclamp(sB.data(), s.data()) != 0 ||
            crypto_scalarmult_ed25519_noclamp(cY.data(), c32.data(), pk.data()) != 0 ||
            crypto_core_ed25519_sub(U.data(), sB.data(), cY.data()) != 0)
            return Result<SecureBuffer>::err("ECVRF: verification math failed (U)");
        // V = s·H - c·Gamma
        SecureBuffer sH(PT_BYTES), cG(PT_BYTES), V(PT_BYTES);
        if (crypto_scalarmult_ed25519_noclamp(sH.data(), s.data(), h.data()) != 0 ||
            crypto_scalarmult_ed25519_noclamp(cG.data(), c32.data(), Gamma.data()) != 0 ||
            crypto_core_ed25519_sub(V.data(), sH.data(), cG.data()) != 0)
            return Result<SecureBuffer>::err("ECVRF: verification math failed (V)");

        auto c_prime = challenge(pk, h.span(), Gamma, U.span(), V.span());
        if (sodium_memcmp(c_prime.data(), c.data(), C_BYTES) != 0)
            return Result<SecureBuffer>::err("ECVRF: proof invalid");
        return proof_to_hash(pi);
    }

private:
    // ── SHA-512 over a concatenation of spans ─────────────────────────────────
    template <typename... Spans>
    static SecureBuffer sha512(Spans... parts) {
        std::vector<uint8_t> in;
        (in.insert(in.end(), std::span<const uint8_t>(parts).begin(),
                              std::span<const uint8_t>(parts).end()), ...);
        SecureBuffer out(HASH_BYTES);
        crypto_hash_sha512(out.data(), in.data(), in.size());
        return out;
    }

    static SecureBuffer reduce64(std::span<const uint8_t> h64) {
        SecureBuffer out(SCALAR_BYTES);
        crypto_core_ed25519_scalar_reduce(out.data(), h64.data());
        return out;
    }

    // Zero-extend a <32-byte little-endian integer to a 32-byte scalar.
    static SecureBuffer pad_scalar(std::span<const uint8_t> v) {
        SecureBuffer out(SCALAR_BYTES); // zero-initialised
        std::memcpy(out.data(), v.data(), v.size());
        return out;
    }

    // s must be a canonical scalar in [0, L). Check reduce(s) == s.
    static bool scalar_is_canonical(std::span<const uint8_t> s) {
        std::array<uint8_t, 64> s64{};
        std::memcpy(s64.data(), s.data(), SCALAR_BYTES);
        uint8_t reduced[SCALAR_BYTES];
        crypto_core_ed25519_scalar_reduce(reduced, s64.data());
        return std::memcmp(reduced, s.data(), SCALAR_BYTES) == 0;
    }

    // x = clamp(SHA512(sk)[0:32]) reduced mod q; trunc = SHA512(sk)[32:64].
    static std::pair<SecureBuffer, SecureBuffer> expand_sk(std::span<const uint8_t> sk) {
        uint8_t h[HASH_BYTES];
        crypto_hash_sha512(h, sk.data(), sk.size());
        uint8_t clamped[SCALAR_BYTES];
        std::memcpy(clamped, h, SCALAR_BYTES);
        clamped[0]  &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        std::array<uint8_t, 64> padded{};
        std::memcpy(padded.data(), clamped, SCALAR_BYTES);
        SecureBuffer x = reduce64({ padded.data(), padded.size() });
        SecureBuffer trunc(SCALAR_BYTES);
        std::memcpy(trunc.data(), h + SCALAR_BYTES, SCALAR_BYTES);
        sodium_memzero(h, sizeof h);
        sodium_memzero(clamped, sizeof clamped);
        return { std::move(x), std::move(trunc) };
    }

    // H = 8·P where P decodes from the 32-byte string `pt`. Returns false if
    // `pt` is not a valid curve point encoding. Uses three point additions —
    // crypto_core_ed25519_add accepts any on-curve point (not just prime-order).
    static bool cofactor_mul(std::span<const uint8_t> pt, SecureBuffer& out) {
        SecureBuffer p2(PT_BYTES), p4(PT_BYTES);
        if (crypto_core_ed25519_add(p2.data(), pt.data(), pt.data()) != 0) return false; // 2P
        if (crypto_core_ed25519_add(p4.data(), p2.data(), p2.data()) != 0) return false; // 4P
        if (crypto_core_ed25519_add(out.data(), p4.data(), p4.data()) != 0) return false; // 8P
        return true;
    }

    static bool is_identity(std::span<const uint8_t> p) {
        // Neutral element encoding: y = 1, x = 0  →  0x01 0x00 … 0x00
        if (p[0] != 0x01) return false;
        for (std::size_t i = 1; i < PT_BYTES; ++i) if (p[i] != 0) return false;
        return true;
    }

    // ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1).
    static Result<SecureBuffer>
    encode_to_curve(std::span<const uint8_t> pk, std::span<const uint8_t> alpha) {
        std::array<uint8_t, 1> suite{ SUITE }, front{ 0x01 }, back{ 0x00 };
        for (int ctr = 0; ctr <= 0xFF; ++ctr) {
            std::array<uint8_t, 1> ctr_string{ static_cast<uint8_t>(ctr) };
            SecureBuffer hash = sha512(suite, front, pk, alpha, ctr_string, back);
            std::span<const uint8_t> candidate{ hash.data(), PT_BYTES };
            SecureBuffer H(PT_BYTES);
            if (cofactor_mul(candidate, H) && !is_identity(H.span()))
                return Result<SecureBuffer>::ok(std::move(H));
        }
        return Result<SecureBuffer>::err("ECVRF: encode_to_curve exhausted the counter");
    }

    // ECVRF_challenge_generation (RFC 9381 §5.4.3) → 16-byte c.
    static SecureBuffer challenge(std::span<const uint8_t> p1, std::span<const uint8_t> p2,
                                  std::span<const uint8_t> p3, std::span<const uint8_t> p4,
                                  std::span<const uint8_t> p5) {
        std::array<uint8_t, 1> suite{ SUITE }, front{ 0x02 }, back{ 0x00 };
        SecureBuffer full = sha512(suite, front, p1, p2, p3, p4, p5, back);
        SecureBuffer c(C_BYTES);
        std::memcpy(c.data(), full.data(), C_BYTES);
        return c;
    }
};

} // namespace crypto
