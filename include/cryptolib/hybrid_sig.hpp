#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::pq::HybridSig — Ed25519 + ML-DSA-65 hybrid signatures              ║
 * ║                                                                            ║
 * ║  Signs with BOTH a classical (Ed25519, EUF-CMA) and a post-quantum         ║
 * ║  (ML-DSA-65 / FIPS 204, NIST L3) scheme. A signature verifies only if      ║
 * ║  BOTH components verify — so it stays unforgeable as long as EITHER         ║
 * ║  scheme is unbroken (quantum break of Ed25519 → ML-DSA holds; lattice      ║
 * ║  break of ML-DSA → Ed25519 holds). Companion to the X25519+ML-KEM-768       ║
 * ║  HybridKem; same migration rationale (NIST IR 8547).                        ║
 * ║                                                                            ║
 * ║  Wire layout (deterministic concatenation):                                 ║
 * ║    public_key = ed25519_pub(32) ‖ ml_dsa_pub                                ║
 * ║    secret_key = ed25519_sec(64) ‖ ml_dsa_sec                                ║
 * ║    signature  = ed25519_sig(64) ‖ ml_dsa_sig                                ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "asymmetric.hpp"   // crypto::asymmetric::Ed25519
#include "pq.hpp"           // crypto::pq::MlDsa

#include <cstring>
#include <span>

namespace crypto::pq {

class HybridSig {
public:
    static constexpr std::size_t ED_PUBLIC_BYTES = 32;
    static constexpr std::size_t ED_SECRET_BYTES = 64;
    static constexpr std::size_t ED_SIG_BYTES    = 64;
    static constexpr MlDsa::Level ML_DSA_LEVEL   = MlDsa::Level::DSA_65;

    struct KeyPair {
        SecureBuffer public_key;   // ed_pub ‖ mldsa_pub
        SecureBuffer secret_key;   // ed_sec ‖ mldsa_sec
    };
    struct Sizes { std::size_t public_key, secret_key, signature; };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto m = MlDsa::sizes(ML_DSA_LEVEL);
        if (m.is_err()) return Result<Sizes>::err(m.error().message);
        return Result<Sizes>::ok(Sizes{
            ED_PUBLIC_BYTES + m.value().public_key,
            ED_SECRET_BYTES + m.value().secret_key,
            ED_SIG_BYTES    + m.value().signature });
    }

    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto ed = asymmetric::Ed25519::generate_keypair();
        auto md = MlDsa::generate_keypair(ML_DSA_LEVEL);
        if (md.is_err()) return Result<KeyPair>::err(md.error().message);
        return Result<KeyPair>::ok(KeyPair{
            concat(ed.public_key.span(), md.value().public_key.span()),
            concat(ed.secret_key.span(), md.value().secret_key.span()) });
    }

    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message, std::span<const uint8_t> secret_key) {
        auto ms = MlDsa::sizes(ML_DSA_LEVEL);
        if (ms.is_err()) return Result<SecureBuffer>::err(ms.error().message);
        if (secret_key.size() != ED_SECRET_BYTES + ms.value().secret_key)
            return Result<SecureBuffer>::err("HybridSig: invalid secret key length");

        auto ed_sig = asymmetric::Ed25519::sign(message, secret_key.first(ED_SECRET_BYTES));
        if (ed_sig.is_err()) return Result<SecureBuffer>::err(ed_sig.error().message);
        auto md_sig = MlDsa::sign(message, secret_key.subspan(ED_SECRET_BYTES), ML_DSA_LEVEL);
        if (md_sig.is_err()) return Result<SecureBuffer>::err(md_sig.error().message);

        return Result<SecureBuffer>::ok(concat(ed_sig.value().span(), md_sig.value().span()));
    }

    /// Verify: fails unless BOTH components verify.
    [[nodiscard]] static Result<void>
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key) {
        auto ms = MlDsa::sizes(ML_DSA_LEVEL);
        if (ms.is_err()) return Result<void>::err(ms.error().message);
        if (public_key.size() != ED_PUBLIC_BYTES + ms.value().public_key)
            return Result<void>::err("HybridSig: invalid public key length");
        if (signature.size() <= ED_SIG_BYTES)
            return Result<void>::err("HybridSig: invalid signature length");

        bool ed_ok = asymmetric::Ed25519::verify(
            message, signature.first(ED_SIG_BYTES), public_key.first(ED_PUBLIC_BYTES));
        auto md_ok = MlDsa::verify(
            message, signature.subspan(ED_SIG_BYTES), public_key.subspan(ED_PUBLIC_BYTES),
            ML_DSA_LEVEL);

        if (!ed_ok || md_ok.is_err())
            return Result<void>::err("HybridSig: signature verification failed");
        return Result<void>::ok();
    }

private:
    [[nodiscard]] static SecureBuffer
    concat(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer out(a.size() + b.size());
        std::memcpy(out.data(), a.data(), a.size());
        std::memcpy(out.data() + a.size(), b.data(), b.size());
        return out;
    }
};

} // namespace crypto::pq

#endif // CRYPTOLIB_HAS_PQ
