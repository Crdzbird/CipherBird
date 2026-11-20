#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Oprf — Oblivious Pseudorandom Function (RFC 9497)                    ║
 * ║  Base-mode OPRF(ristretto255, SHA-512)                                       ║
 * ║                                                                            ║
 * ║  A two-party PRF where the server holds the key and the client holds the     ║
 * ║  input, and NEITHER learns the other's secret: the client blinds its input,  ║
 * ║  the server evaluates under its key without seeing the input, and the client ║
 * ║  unblinds to a PRF output it could not have computed alone. The building      ║
 * ║  block for Privacy Pass, private set intersection, password hardening, and   ║
 * ║  the OPAQUE aPAKE.                                                           ║
 * ║                                                                            ║
 * ║  Built on libsodium ristretto255 (hash-to-group, scalar arithmetic) +        ║
 * ║  SHA-512. Only expand_message_xmd (RFC 9380) is assembled here from SHA-512.  ║
 * ║  No new cryptography — a faithful RFC 9497 base-mode implementation,          ║
 * ║  validated against its Appendix A.1 test vectors.                           ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

class Oprf {
public:
    static constexpr std::size_t ELEMENT_BYTES = 32; // ristretto255 point
    static constexpr std::size_t SCALAR_BYTES  = 32;
    static constexpr std::size_t OUTPUT_BYTES  = 64; // SHA-512
    static constexpr std::size_t UNIFORM_BYTES = 64;

    struct KeyPair { SecureBuffer secret_key; SecureBuffer public_key; };
    struct BlindResult { SecureBuffer blind; SecureBuffer blinded_element; };

    // ── DeriveKeyPair(seed, info) ─────────────────────────────────────────────
    [[nodiscard]] static Result<KeyPair>
    derive_keypair(std::span<const uint8_t> seed, std::span<const uint8_t> info = {}) {
        std::vector<uint8_t> derive_input(seed.begin(), seed.end());
        derive_input.push_back(static_cast<uint8_t>((info.size() >> 8) & 0xff));
        derive_input.push_back(static_cast<uint8_t>(info.size() & 0xff));
        derive_input.insert(derive_input.end(), info.begin(), info.end());
        auto dkp_dst = dst("DeriveKeyPair");

        for (int counter = 0; counter <= 255; ++counter) {
            std::vector<uint8_t> m = derive_input;
            m.push_back(static_cast<uint8_t>(counter));
            SecureBuffer sk = hash_to_scalar(m, dkp_dst);
            if (!is_zero(sk.span())) {
                SecureBuffer pk(ELEMENT_BYTES);
                crypto_scalarmult_ristretto255_base(pk.data(), sk.data());
                return Result<KeyPair>::ok(KeyPair{ std::move(sk), std::move(pk) });
            }
        }
        return Result<KeyPair>::err("OPRF: DeriveKeyPair failed (counter exhausted)");
    }

    // ── Client: Blind(input) ──────────────────────────────────────────────────
    /// Blind an input with a fresh random scalar. Returns the blind (keep it for
    /// Finalize) and the blinded element (send to the server).
    [[nodiscard]] static Result<BlindResult> blind(std::span<const uint8_t> input) {
        SecureBuffer b(SCALAR_BYTES);
        crypto_core_ristretto255_scalar_random(b.data());
        return blind_with_scalar(input, b.span());
    }

    /// Deterministic Blind with a caller-supplied scalar (test vectors).
    [[nodiscard]] static Result<BlindResult>
    blind_with_scalar(std::span<const uint8_t> input, std::span<const uint8_t> blind_scalar) {
        if (blind_scalar.size() != SCALAR_BYTES)
            return Result<BlindResult>::err("OPRF: blind must be 32 bytes");
        auto P = hash_to_group(input);
        SecureBuffer blinded(ELEMENT_BYTES);
        if (crypto_scalarmult_ristretto255(blinded.data(), blind_scalar.data(), P.data()) != 0)
            return Result<BlindResult>::err("OPRF: invalid input (identity element)");
        return Result<BlindResult>::ok(BlindResult{
            SecureBuffer(blind_scalar.data(), blind_scalar.size()), std::move(blinded) });
    }

    // ── Server: BlindEvaluate(skS, blindedElement) ────────────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    blind_evaluate(std::span<const uint8_t> sk, std::span<const uint8_t> blinded_element) {
        if (sk.size() != SCALAR_BYTES || blinded_element.size() != ELEMENT_BYTES)
            return Result<SecureBuffer>::err("OPRF: bad key/element length");
        SecureBuffer ev(ELEMENT_BYTES);
        if (crypto_scalarmult_ristretto255(ev.data(), sk.data(), blinded_element.data()) != 0)
            return Result<SecureBuffer>::err("OPRF: blind evaluate failed");
        return Result<SecureBuffer>::ok(std::move(ev));
    }

    // ── Client: Finalize(input, blind, evaluatedElement) ──────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    finalize(std::span<const uint8_t> input, std::span<const uint8_t> blind_scalar,
             std::span<const uint8_t> evaluated_element) {
        if (blind_scalar.size() != SCALAR_BYTES || evaluated_element.size() != ELEMENT_BYTES)
            return Result<SecureBuffer>::err("OPRF: bad blind/element length");
        SecureBuffer binv(SCALAR_BYTES);
        if (crypto_core_ristretto255_scalar_invert(binv.data(), blind_scalar.data()) != 0)
            return Result<SecureBuffer>::err("OPRF: non-invertible blind");
        SecureBuffer N(ELEMENT_BYTES);
        if (crypto_scalarmult_ristretto255(N.data(), binv.data(), evaluated_element.data()) != 0)
            return Result<SecureBuffer>::err("OPRF: finalize failed");
        return Result<SecureBuffer>::ok(hash_finalize(input, N.span()));
    }

    // ── Server one-shot: Evaluate(skS, input) ─────────────────────────────────
    /// Compute the PRF output directly from the key + cleartext input (server
    /// side; useful to check a client's finalized output).
    [[nodiscard]] static Result<SecureBuffer>
    evaluate(std::span<const uint8_t> sk, std::span<const uint8_t> input) {
        if (sk.size() != SCALAR_BYTES) return Result<SecureBuffer>::err("OPRF: key must be 32 bytes");
        auto P = hash_to_group(input);
        SecureBuffer ev(ELEMENT_BYTES);
        if (crypto_scalarmult_ristretto255(ev.data(), sk.data(), P.data()) != 0)
            return Result<SecureBuffer>::err("OPRF: invalid input (identity element)");
        return Result<SecureBuffer>::ok(hash_finalize(input, ev.span()));
    }

private:
    static void put(std::vector<uint8_t>& v, std::string_view s) {
        v.insert(v.end(), s.begin(), s.end());
    }

    // contextString = "OPRFV1-" || I2OSP(0x00, 1) || "-" || "ristretto255-SHA512"
    static std::vector<uint8_t> context_string() {
        std::vector<uint8_t> c;
        put(c, "OPRFV1-");
        c.push_back(0x00); // mode = base
        put(c, "-");
        put(c, "ristretto255-SHA512");
        return c;
    }
    static std::vector<uint8_t> dst(std::string_view prefix) {
        std::vector<uint8_t> d;
        put(d, prefix);
        auto c = context_string();
        d.insert(d.end(), c.begin(), c.end());
        return d;
    }

    static bool is_zero(std::span<const uint8_t> s) {
        uint8_t acc = 0;
        for (auto b : s) acc |= b;
        return acc == 0;
    }

    // expand_message_xmd (RFC 9380 §5.3.1) over SHA-512.
    static std::vector<uint8_t>
    expand_message_xmd(std::span<const uint8_t> msg, std::span<const uint8_t> dst_, std::size_t len) {
        constexpr std::size_t b_in = 64, s_in = 128;
        std::size_t ell = (len + b_in - 1) / b_in;
        std::vector<uint8_t> dst_prime(dst_.begin(), dst_.end());
        dst_prime.push_back(static_cast<uint8_t>(dst_.size()));

        std::vector<uint8_t> msg_prime(s_in, 0);
        msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
        msg_prime.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
        msg_prime.push_back(static_cast<uint8_t>(len & 0xff));
        msg_prime.push_back(0x00);
        msg_prime.insert(msg_prime.end(), dst_prime.begin(), dst_prime.end());

        uint8_t b0[b_in];
        crypto_hash_sha512(b0, msg_prime.data(), msg_prime.size());
        std::vector<uint8_t> t(b0, b0 + b_in);
        t.push_back(0x01);
        t.insert(t.end(), dst_prime.begin(), dst_prime.end());
        uint8_t prev[b_in];
        crypto_hash_sha512(prev, t.data(), t.size());
        std::vector<uint8_t> out(prev, prev + b_in);
        for (std::size_t i = 2; i <= ell; ++i) {
            uint8_t x[b_in];
            for (std::size_t j = 0; j < b_in; ++j) x[j] = b0[j] ^ prev[j];
            std::vector<uint8_t> ti(x, x + b_in);
            ti.push_back(static_cast<uint8_t>(i));
            ti.insert(ti.end(), dst_prime.begin(), dst_prime.end());
            crypto_hash_sha512(prev, ti.data(), ti.size());
            out.insert(out.end(), prev, prev + b_in);
        }
        out.resize(len);
        return out;
    }

    // HashToGroup: hash_to_ristretto255 = from_hash(expand_message_xmd(input, DST, 64)).
    static SecureBuffer hash_to_group(std::span<const uint8_t> input) {
        auto d = dst("HashToGroup-");
        auto u = expand_message_xmd(input, d, UNIFORM_BYTES);
        SecureBuffer el(ELEMENT_BYTES);
        crypto_core_ristretto255_from_hash(el.data(), u.data());
        return el;
    }

    // HashToScalar: reduce expand_message_xmd(msg, dst, 64) as a 512-bit LE int.
    static SecureBuffer hash_to_scalar(std::span<const uint8_t> msg, std::span<const uint8_t> d) {
        auto u = expand_message_xmd(msg, d, UNIFORM_BYTES);
        SecureBuffer s(SCALAR_BYTES);
        crypto_core_ristretto255_scalar_reduce(s.data(), u.data());
        return s;
    }

    // Hash(I2OSP(len(input),2) || input || I2OSP(32,2) || element || "Finalize").
    static SecureBuffer hash_finalize(std::span<const uint8_t> input, std::span<const uint8_t> element) {
        std::vector<uint8_t> h;
        h.push_back(static_cast<uint8_t>((input.size() >> 8) & 0xff));
        h.push_back(static_cast<uint8_t>(input.size() & 0xff));
        h.insert(h.end(), input.begin(), input.end());
        h.push_back(0x00);
        h.push_back(static_cast<uint8_t>(ELEMENT_BYTES));
        h.insert(h.end(), element.begin(), element.end());
        put(h, "Finalize");
        SecureBuffer out(OUTPUT_BYTES);
        crypto_hash_sha512(out.data(), h.data(), h.size());
        return out;
    }
};

} // namespace crypto
