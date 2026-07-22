#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Frost — FROST(Ed25519, SHA-512) threshold Schnorr signatures        ║
 * ║  (RFC 9591)                                                                  ║
 * ║                                                                            ║
 * ║  t-of-n parties jointly produce ONE ordinary Ed25519 signature without ever  ║
 * ║  reconstructing the signing key — no single party can sign, and any t can.   ║
 * ║  The output verifies with standard Ed25519 verification against the group    ║
 * ║  public key, so verifiers need to know nothing about the threshold setup.    ║
 * ║                                                                            ║
 * ║  Two rounds:                                                                ║
 * ║    1. each signer commits to a pair of nonces (commit)                       ║
 * ║    2. each signer, given the message + everyone's commitments, returns a     ║
 * ║       signature share (sign); a coordinator aggregates them (aggregate)      ║
 * ║                                                                            ║
 * ║  Built on libsodium's edwards25519 scalar/point arithmetic (mod L). No new   ║
 * ║  cryptography — a faithful implementation of RFC 9591, validated against     ║
 * ║  its official FROST(Ed25519, SHA-512) test vectors.                          ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "asymmetric.hpp"   // crypto::asymmetric::Ed25519 (verify)

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

class Frost {
public:
    static constexpr std::size_t SCALAR_BYTES = 32; // crypto_core_ed25519_SCALARBYTES
    static constexpr std::size_t ELEMENT_BYTES = 32; // crypto_core_ed25519_BYTES
    static constexpr std::size_t SIGNATURE_BYTES = 64;

    struct SignerShare {                 // a participant's secret key share
        uint16_t     identifier;         // 1..n (never 0)
        SecureBuffer secret;             // sk_i (32-byte scalar)
    };
    struct Commitment {                  // a participant's public round-1 commitment
        uint16_t     identifier;
        SecureBuffer hiding;             // D_i = hiding_nonce · B   (32-byte point)
        SecureBuffer binding;            // E_i = binding_nonce · B
    };
    struct Nonces {                      // a participant's secret round-1 nonces
        SecureBuffer hiding;             // 32-byte scalar
        SecureBuffer binding;
    };
    struct KeyGen {                      // trusted-dealer output
        SecureBuffer              group_public_key;   // 32-byte point
        std::vector<SignerShare>  shares;             // one per participant
        std::vector<SecureBuffer> public_shares;      // PK_i = sk_i · B (for verify_share)
    };

    // ── Trusted-dealer key generation ─────────────────────────────────────────
    /// Sample a random group key and split it into `n` shares, any `t` of which
    /// can sign. Returns the group public key + per-participant secret shares.
    [[nodiscard]] static Result<KeyGen> keygen(uint16_t n, uint16_t t) {
        if (t < 1 || n < t) return Result<KeyGen>::err("FROST: require 1 <= t <= n");
        // Random degree-(t-1) polynomial; constant term is the group secret.
        std::vector<SecureBuffer> coeffs;
        for (uint16_t k = 0; k < t; ++k) coeffs.push_back(random_scalar());

        KeyGen out;
        out.group_public_key = SecureBuffer(ELEMENT_BYTES);
        if (crypto_scalarmult_ed25519_base_noclamp(out.group_public_key.data(), coeffs[0].data()) != 0)
            return Result<KeyGen>::err("FROST: group public key derivation failed");

        for (uint16_t i = 1; i <= n; ++i) {
            auto sk = poly_eval(coeffs, i);                 // f(i)
            SecureBuffer pk(ELEMENT_BYTES);
            if (crypto_scalarmult_ed25519_base_noclamp(pk.data(), sk.data()) != 0)
                return Result<KeyGen>::err("FROST: public share derivation failed");
            out.shares.push_back(SignerShare{ i, std::move(sk) });
            out.public_shares.push_back(std::move(pk));
        }
        return Result<KeyGen>::ok(std::move(out));
    }

    // ── Round 1: commit ───────────────────────────────────────────────────────
    /// Generate a fresh nonce pair and its public commitment for `share`.
    [[nodiscard]] static Result<std::pair<Nonces, Commitment>>
    commit(const SignerShare& share) {
        return commit_with_nonces(share.identifier,
                                  nonce_generate(share.secret.span()),
                                  nonce_generate(share.secret.span()));
    }

    /// Deterministic variant (test vectors / caller-provided nonces).
    [[nodiscard]] static Result<std::pair<Nonces, Commitment>>
    commit_with_nonces(uint16_t identifier, SecureBuffer hiding, SecureBuffer binding) {
        Commitment c{ identifier, SecureBuffer(ELEMENT_BYTES), SecureBuffer(ELEMENT_BYTES) };
        if (crypto_scalarmult_ed25519_base_noclamp(c.hiding.data(), hiding.data()) != 0 ||
            crypto_scalarmult_ed25519_base_noclamp(c.binding.data(), binding.data()) != 0)
            return Result<std::pair<Nonces, Commitment>>::err("FROST: commitment derivation failed");
        return Result<std::pair<Nonces, Commitment>>::ok(
            { Nonces{ std::move(hiding), std::move(binding) }, std::move(c) });
    }

    // ── Round 2: signature share ──────────────────────────────────────────────
    /// Produce this participant's signature share. `commitments` is the full set
    /// of round-1 commitments from every participating signer (including self).
    [[nodiscard]] static Result<SecureBuffer>
    sign(const SignerShare& share, std::span<const uint8_t> group_public_key,
         const Nonces& nonces, std::span<const uint8_t> message,
         const std::vector<Commitment>& commitments) {
        auto bind = compute_binding_factors(group_public_key, commitments, message);
        auto R = compute_group_commitment(commitments, bind);
        if (R.is_err()) return Result<SecureBuffer>::err(R.error().message);

        std::vector<uint16_t> ids;
        for (const auto& c : commitments) ids.push_back(c.identifier);
        auto lambda = interpolating_value(ids, share.identifier);
        if (lambda.is_err()) return Result<SecureBuffer>::err(lambda.error().message);

        auto rho = binding_factor_for(bind, share.identifier);
        auto c = challenge(R.value().span(), group_public_key, message);

        // z_i = hiding + binding*rho + lambda*sk*c
        SecureBuffer z = scalar_mul(nonces.binding.span(), rho.span());
        z = scalar_add(nonces.hiding.span(), z.span());
        SecureBuffer t = scalar_mul(lambda.value().span(), share.secret.span());
        t = scalar_mul(t.span(), c.span());
        z = scalar_add(z.span(), t.span());
        return Result<SecureBuffer>::ok(std::move(z));
    }

    // ── Aggregate → one Ed25519 signature ─────────────────────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    aggregate(std::span<const uint8_t> group_public_key, std::span<const uint8_t> message,
              const std::vector<Commitment>& commitments,
              const std::vector<SecureBuffer>& sig_shares) {
        auto bind = compute_binding_factors(group_public_key, commitments, message);
        auto R = compute_group_commitment(commitments, bind);
        if (R.is_err()) return Result<SecureBuffer>::err(R.error().message);

        SecureBuffer z(SCALAR_BYTES); // zero
        for (const auto& s : sig_shares) z = scalar_add(z.span(), s.span());

        SecureBuffer sig(SIGNATURE_BYTES);
        std::memcpy(sig.data(), R.value().data(), ELEMENT_BYTES);
        std::memcpy(sig.data() + ELEMENT_BYTES, z.data(), SCALAR_BYTES);
        return Result<SecureBuffer>::ok(std::move(sig));
    }

    /// Verify an aggregated signature with standard Ed25519 verification.
    [[nodiscard]] static bool
    verify(std::span<const uint8_t> message, std::span<const uint8_t> signature,
           std::span<const uint8_t> group_public_key) {
        return asymmetric::Ed25519::verify(message, signature, group_public_key);
    }

    /// Verify a single participant's signature share (for coordinator robustness).
    [[nodiscard]] static Result<bool>
    verify_share(uint16_t identifier, std::span<const uint8_t> public_share,
                 std::span<const uint8_t> sig_share, const Commitment& commitment,
                 std::span<const uint8_t> group_public_key, std::span<const uint8_t> message,
                 const std::vector<Commitment>& commitments) {
        auto bind = compute_binding_factors(group_public_key, commitments, message);
        auto R = compute_group_commitment(commitments, bind);
        if (R.is_err()) return Result<bool>::err(R.error().message);
        auto rho = binding_factor_for(bind, identifier);

        // Commitment share: D_i + rho_i * E_i
        SecureBuffer rhoE(ELEMENT_BYTES);
        if (crypto_scalarmult_ed25519_noclamp(rhoE.data(), rho.data(), commitment.binding.data()) != 0)
            return Result<bool>::err("FROST: bad commitment");
        SecureBuffer comm_share(ELEMENT_BYTES);
        if (crypto_core_ed25519_add(comm_share.data(), commitment.hiding.data(), rhoE.data()) != 0)
            return Result<bool>::err("FROST: bad commitment");

        std::vector<uint16_t> ids;
        for (const auto& c : commitments) ids.push_back(c.identifier);
        auto lambda = interpolating_value(ids, identifier);
        if (lambda.is_err()) return Result<bool>::err(lambda.error().message);
        auto c = challenge(R.value().span(), group_public_key, message);
        SecureBuffer lc = scalar_mul(lambda.value().span(), c.span());

        // Check: z_i * B == comm_share + (lambda_i * c) * PK_i
        SecureBuffer lhs(ELEMENT_BYTES);
        if (crypto_scalarmult_ed25519_base_noclamp(lhs.data(), sig_share.data()) != 0)
            return Result<bool>::err("FROST: bad share");
        SecureBuffer term(ELEMENT_BYTES);
        if (crypto_scalarmult_ed25519_noclamp(term.data(), lc.data(), public_share.data()) != 0)
            return Result<bool>::err("FROST: bad public share");
        SecureBuffer rhs(ELEMENT_BYTES);
        if (crypto_core_ed25519_add(rhs.data(), comm_share.data(), term.data()) != 0)
            return Result<bool>::err("FROST: point add failed");
        return Result<bool>::ok(sodium_memcmp(lhs.data(), rhs.data(), ELEMENT_BYTES) == 0);
    }

private:
    static constexpr std::string_view CTX = "FROST-ED25519-SHA512-v1";

    // ── scalar / point helpers (all mod L) ────────────────────────────────────
    static SecureBuffer random_scalar() {
        SecureBuffer s(SCALAR_BYTES);
        crypto_core_ed25519_scalar_random(s.data());
        return s;
    }
    static SecureBuffer scalar_from_id(uint16_t id) {
        SecureBuffer s(SCALAR_BYTES);
        s.data()[0] = static_cast<uint8_t>(id & 0xff);
        s.data()[1] = static_cast<uint8_t>((id >> 8) & 0xff);
        return s;
    }
    static SecureBuffer scalar_add(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer o(SCALAR_BYTES); crypto_core_ed25519_scalar_add(o.data(), a.data(), b.data()); return o;
    }
    static SecureBuffer scalar_sub(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer o(SCALAR_BYTES); crypto_core_ed25519_scalar_sub(o.data(), a.data(), b.data()); return o;
    }
    static SecureBuffer scalar_mul(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer o(SCALAR_BYTES); crypto_core_ed25519_scalar_mul(o.data(), a.data(), b.data()); return o;
    }
    static SecureBuffer scalar_invert(std::span<const uint8_t> a) {
        SecureBuffer o(SCALAR_BYTES); crypto_core_ed25519_scalar_invert(o.data(), a.data()); return o;
    }
    static SecureBuffer reduce64(std::span<const uint8_t> h64) {
        SecureBuffer o(SCALAR_BYTES); crypto_core_ed25519_scalar_reduce(o.data(), h64.data()); return o;
    }

    // f(x) via Horner over L, coeffs low→high.
    static SecureBuffer poly_eval(const std::vector<SecureBuffer>& coeffs, uint16_t x) {
        SecureBuffer xs = scalar_from_id(x);
        SecureBuffer acc(SCALAR_BYTES); // 0
        for (std::size_t i = coeffs.size(); i-- > 0;) {
            acc = scalar_mul(acc.span(), xs.span());
            acc = scalar_add(acc.span(), coeffs[i].span());
        }
        return acc;
    }

    // ── hashing (RFC 9591 §6.1) ───────────────────────────────────────────────
    static SecureBuffer sha512(std::span<const uint8_t> a, std::span<const uint8_t> b = {},
                               std::span<const uint8_t> c = {}) {
        std::vector<uint8_t> in;
        in.insert(in.end(), a.begin(), a.end());
        in.insert(in.end(), b.begin(), b.end());
        in.insert(in.end(), c.begin(), c.end());
        SecureBuffer out(64);
        crypto_hash_sha512(out.data(), in.data(), in.size());
        return out;
    }
    static std::span<const uint8_t> ctx() {
        return { reinterpret_cast<const uint8_t*>(CTX.data()), CTX.size() };
    }
    static std::span<const uint8_t> lit(const char* s) {
        return { reinterpret_cast<const uint8_t*>(s), std::strlen(s) };
    }
    // H1/H3: SHA512(ctx || label || m) reduced to a scalar.
    static SecureBuffer H_scalar(const char* label, std::span<const uint8_t> m) {
        return reduce64(sha512(ctx(), lit(label), m).span());
    }
    // H2 (challenge): SHA512(m) reduced — no context, for Ed25519 compatibility.
    static SecureBuffer challenge(std::span<const uint8_t> R, std::span<const uint8_t> pk,
                                  std::span<const uint8_t> msg) {
        std::vector<uint8_t> in;
        in.insert(in.end(), R.begin(), R.end());
        in.insert(in.end(), pk.begin(), pk.end());
        in.insert(in.end(), msg.begin(), msg.end());
        return reduce64(sha512(in).span());
    }
    static SecureBuffer nonce_generate(std::span<const uint8_t> secret) {
        std::array<uint8_t, 32> r{};
        randombytes_buf(r.data(), r.size());
        return H_scalar("nonce", concat(r, secret).span());
    }

    static SecureBuffer concat(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer o(a.size() + b.size());
        std::memcpy(o.data(), a.data(), a.size());
        std::memcpy(o.data() + a.size(), b.data(), b.size());
        return o;
    }

    // ── binding factors, group commitment, Lagrange (RFC 9591 §4) ─────────────
    struct BindingFactor { uint16_t identifier; SecureBuffer factor; };

    static std::vector<uint8_t> encode_commitments(const std::vector<Commitment>& cs) {
        std::vector<uint8_t> out;
        for (const auto& c : cs) {
            auto id = scalar_from_id(c.identifier);
            out.insert(out.end(), id.span().begin(), id.span().end());
            out.insert(out.end(), c.hiding.span().begin(), c.hiding.span().end());
            out.insert(out.end(), c.binding.span().begin(), c.binding.span().end());
        }
        return out;
    }
    static std::vector<BindingFactor>
    compute_binding_factors(std::span<const uint8_t> group_public_key,
                            const std::vector<Commitment>& cs, std::span<const uint8_t> msg) {
        SecureBuffer msg_hash = sha512(ctx(), lit("msg"), msg);          // H4
        auto enc = encode_commitments(cs);
        SecureBuffer com_hash = sha512(ctx(), lit("com"), enc);          // H5
        // rho_input_prefix = SerializeElement(group_public_key) || H4(msg) || H5(commitments)
        std::vector<uint8_t> prefix;
        prefix.insert(prefix.end(), group_public_key.begin(), group_public_key.end());
        prefix.insert(prefix.end(), msg_hash.span().begin(), msg_hash.span().end());
        prefix.insert(prefix.end(), com_hash.span().begin(), com_hash.span().end());

        std::vector<BindingFactor> out;
        for (const auto& c : cs) {
            std::vector<uint8_t> rho_input = prefix;
            auto id = scalar_from_id(c.identifier);
            rho_input.insert(rho_input.end(), id.span().begin(), id.span().end());
            out.push_back(BindingFactor{ c.identifier, H_scalar("rho", rho_input) });
        }
        return out;
    }
    static SecureBuffer binding_factor_for(const std::vector<BindingFactor>& bs, uint16_t id) {
        for (const auto& b : bs)
            if (b.identifier == id) return SecureBuffer(b.factor.span().data(), b.factor.span().size());
        return SecureBuffer(SCALAR_BYTES);
    }
    // R = Σ (D_i + rho_i · E_i)
    static Result<SecureBuffer>
    compute_group_commitment(const std::vector<Commitment>& cs, const std::vector<BindingFactor>& bs) {
        bool have = false;
        SecureBuffer R(ELEMENT_BYTES);
        for (const auto& c : cs) {
            auto rho = binding_factor_for(bs, c.identifier);
            SecureBuffer rhoE(ELEMENT_BYTES);
            if (crypto_scalarmult_ed25519_noclamp(rhoE.data(), rho.data(), c.binding.data()) != 0)
                return Result<SecureBuffer>::err("FROST: invalid binding commitment");
            SecureBuffer term(ELEMENT_BYTES);
            if (crypto_core_ed25519_add(term.data(), c.hiding.data(), rhoE.data()) != 0)
                return Result<SecureBuffer>::err("FROST: invalid hiding commitment");
            if (!have) { R = std::move(term); have = true; }
            else if (crypto_core_ed25519_add(R.data(), R.data(), term.data()) != 0)
                return Result<SecureBuffer>::err("FROST: group commitment add failed");
        }
        if (!have) return Result<SecureBuffer>::err("FROST: no commitments");
        return Result<SecureBuffer>::ok(std::move(R));
    }
    // λ_i = Π_{j≠i} x_j / (x_j − x_i)  over L
    static Result<SecureBuffer> interpolating_value(const std::vector<uint16_t>& ids, uint16_t i) {
        SecureBuffer num(SCALAR_BYTES); num.data()[0] = 1;  // 1
        SecureBuffer den(SCALAR_BYTES); den.data()[0] = 1;
        SecureBuffer xi = scalar_from_id(i);
        bool found = false;
        for (uint16_t j : ids) {
            if (j == i) { found = true; continue; }
            SecureBuffer xj = scalar_from_id(j);
            num = scalar_mul(num.span(), xj.span());
            den = scalar_mul(den.span(), scalar_sub(xj.span(), xi.span()).span());
        }
        if (!found) return Result<SecureBuffer>::err("FROST: signer not in the set");
        return Result<SecureBuffer>::ok(scalar_mul(num.span(), scalar_invert(den.span()).span()));
    }
};

} // namespace crypto
