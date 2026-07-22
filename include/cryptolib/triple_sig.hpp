#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::pq::TripleSig — Ed25519 + ML-DSA-65 + SLH-DSA triple signature     ║
 * ║                                                                            ║
 * ║  Signs with THREE schemes spanning three assumptions:                       ║
 * ║    • Ed25519    — classical EC (EUF-CMA)                                    ║
 * ║    • ML-DSA-65  — structured-lattice signature (FIPS 204, NIST L3)          ║
 * ║    • SLH-DSA    — HASH-BASED signature (FIPS 205); security rests only on   ║
 * ║                   the hash function, no lattice/EC assumption at all        ║
 * ║                                                                            ║
 * ║  A signature verifies only if ALL THREE components verify, so it stays       ║
 * ║  unforgeable as long as ANY ONE remains unbroken. SLH-DSA is the            ║
 * ║  conservative hedge: even a break of BOTH the classical and the lattice     ║
 * ║  signature leaves a hash-based signature standing. The maximum-assurance     ║
 * ║  authenticity leg of the Fortress flagship.                                 ║
 * ║                                                                            ║
 * ║  Trade-off: SLH-DSA-128f signatures are ~17 KB, so a TripleSig signature is  ║
 * ║  large and signing is slower than HybridSig. Use it where the assurance is   ║
 * ║  worth the size (Fortress); use HybridSig (Flagship) otherwise.             ║
 * ║                                                                            ║
 * ║  Wire layout (deterministic concatenation, fixed component sizes):          ║
 * ║    public_key = ed_pub(32) ‖ mldsa_pub(1952) ‖ slhdsa_pub(32)               ║
 * ║    secret_key = ed_sec(64) ‖ mldsa_sec(4032) ‖ slhdsa_sec(64)               ║
 * ║    signature  = ed_sig(64) ‖ mldsa_sig(3309) ‖ slhdsa_sig(17088)            ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "asymmetric.hpp"   // crypto::asymmetric::Ed25519
#include "pq.hpp"           // crypto::pq::MlDsa, crypto::pq::SlhDsa

#include <cstring>
#include <span>

namespace crypto::pq {

class TripleSig {
public:
    static constexpr std::size_t ED_PUBLIC_BYTES = 32;
    static constexpr std::size_t ED_SECRET_BYTES = 64;
    static constexpr std::size_t ED_SIG_BYTES    = 64;
    static constexpr MlDsa::Level ML_DSA_LEVEL   = MlDsa::Level::DSA_65;
    static constexpr SlhDsa::Level      SLH_LEVEL = SlhDsa::Level::L128f;
    static constexpr SlhDsa::HashFamily SLH_HASH  = SlhDsa::HashFamily::SHA2;

    struct KeyPair {
        SecureBuffer public_key;   // ed_pub ‖ mldsa_pub ‖ slhdsa_pub
        SecureBuffer secret_key;   // ed_sec ‖ mldsa_sec ‖ slhdsa_sec
    };
    struct Sizes {
        std::size_t public_key, secret_key, signature;
        std::size_t mldsa_public, mldsa_secret, mldsa_signature;
        std::size_t slh_public, slh_secret, slh_signature;
    };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto m = MlDsa::sizes(ML_DSA_LEVEL);
        if (m.is_err()) return Result<Sizes>::err(m.error().message);
        auto s = SlhDsa::sizes(SLH_LEVEL, SLH_HASH);
        if (s.is_err()) return Result<Sizes>::err(s.error().message);
        const auto& md = m.value();
        const auto& sl = s.value();
        return Result<Sizes>::ok(Sizes{
            ED_PUBLIC_BYTES + md.public_key + sl.public_key,
            ED_SECRET_BYTES + md.secret_key + sl.secret_key,
            ED_SIG_BYTES    + md.signature  + sl.signature,
            md.public_key, md.secret_key, md.signature,
            sl.public_key, sl.secret_key, sl.signature });
    }

    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto ed = asymmetric::Ed25519::generate_keypair();
        auto md = MlDsa::generate_keypair(ML_DSA_LEVEL);
        if (md.is_err()) return Result<KeyPair>::err(md.error().message);
        auto sl = SlhDsa::generate_keypair(SLH_LEVEL, SLH_HASH);
        if (sl.is_err()) return Result<KeyPair>::err(sl.error().message);
        return Result<KeyPair>::ok(KeyPair{
            concat3(ed.public_key.span(), md.value().public_key.span(), sl.value().public_key.span()),
            concat3(ed.secret_key.span(), md.value().secret_key.span(), sl.value().secret_key.span()) });
    }

    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message, std::span<const uint8_t> secret_key) {
        auto sz = sizes();
        if (sz.is_err()) return Result<SecureBuffer>::err(sz.error().message);
        if (secret_key.size() != sz.value().secret_key)
            return Result<SecureBuffer>::err("TripleSig: invalid secret key length");

        auto ed_sec = secret_key.first(ED_SECRET_BYTES);
        auto md_sec = secret_key.subspan(ED_SECRET_BYTES, sz.value().mldsa_secret);
        auto sl_sec = secret_key.subspan(ED_SECRET_BYTES + sz.value().mldsa_secret);

        auto ed_sig = asymmetric::Ed25519::sign(message, ed_sec);
        if (ed_sig.is_err()) return Result<SecureBuffer>::err(ed_sig.error().message);
        auto md_sig = MlDsa::sign(message, md_sec, ML_DSA_LEVEL);
        if (md_sig.is_err()) return Result<SecureBuffer>::err(md_sig.error().message);
        auto sl_sig = SlhDsa::sign(message, sl_sec, SLH_LEVEL, SLH_HASH);
        if (sl_sig.is_err()) return Result<SecureBuffer>::err(sl_sig.error().message);

        return Result<SecureBuffer>::ok(
            concat3(ed_sig.value().span(), md_sig.value().span(), sl_sig.value().span()));
    }

    /// Verify: fails unless ALL THREE components verify.
    [[nodiscard]] static Result<void>
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key) {
        auto sz = sizes();
        if (sz.is_err()) return Result<void>::err(sz.error().message);
        if (public_key.size() != sz.value().public_key)
            return Result<void>::err("TripleSig: invalid public key length");
        if (signature.size() != sz.value().signature)
            return Result<void>::err("TripleSig: invalid signature length");

        auto ed_pub = public_key.first(ED_PUBLIC_BYTES);
        auto md_pub = public_key.subspan(ED_PUBLIC_BYTES, sz.value().mldsa_public);
        auto sl_pub = public_key.subspan(ED_PUBLIC_BYTES + sz.value().mldsa_public);

        auto ed_s = signature.first(ED_SIG_BYTES);
        auto md_s = signature.subspan(ED_SIG_BYTES, sz.value().mldsa_signature);
        auto sl_s = signature.subspan(ED_SIG_BYTES + sz.value().mldsa_signature);

        bool ed_ok = asymmetric::Ed25519::verify(message, ed_s, ed_pub);
        auto md_ok = MlDsa::verify(message, md_s, md_pub, ML_DSA_LEVEL);
        auto sl_ok = SlhDsa::verify(message, sl_s, sl_pub, SLH_LEVEL, SLH_HASH);

        if (!ed_ok || md_ok.is_err() || sl_ok.is_err())
            return Result<void>::err("TripleSig: signature verification failed");
        return Result<void>::ok();
    }

private:
    [[nodiscard]] static SecureBuffer
    concat3(std::span<const uint8_t> a, std::span<const uint8_t> b, std::span<const uint8_t> c) {
        SecureBuffer out(a.size() + b.size() + c.size());
        std::memcpy(out.data(), a.data(), a.size());
        std::memcpy(out.data() + a.size(), b.data(), b.size());
        std::memcpy(out.data() + a.size() + b.size(), c.data(), c.size());
        return out;
    }
};

} // namespace crypto::pq

#endif // CRYPTOLIB_HAS_PQ
