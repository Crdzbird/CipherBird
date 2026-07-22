#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::pq::TripleHybridKem — X25519 + ML-KEM-768 + sntrup761 hybrid KEM   ║
 * ║                                                                            ║
 * ║  The maximum-assurance key agreement: ONE shared secret derived from THREE  ║
 * ║  independent KEMs spanning three hardness assumptions —                    ║
 * ║                                                                            ║
 * ║    • X25519      — classical elliptic-curve Diffie–Hellman (RFC 7748)      ║
 * ║    • ML-KEM-768  — structured-lattice / module-LWE (FIPS 203, NIST L3)     ║
 * ║    • sntrup761   — unstructured NTRU-Prime lattice (OpenSSH's PQ half)     ║
 * ║                                                                            ║
 * ║  The combined secret stays secure as long as AT LEAST ONE remains          ║
 * ║  unbroken. Because ML-KEM and sntrup761 come from DIFFERENT lattice         ║
 * ║  families, a cryptanalytic break confined to one lattice line does not      ║
 * ║  compromise the other — no single point of cryptanalytic failure.          ║
 * ║                                                                            ║
 * ║  ── Combiner ──────────────────────────────────────────────────────────   ║
 * ║  Same robust, transcript-binding construction as HybridKem, extended to     ║
 * ║  three legs, with its OWN domain-separation label so it can never derive    ║
 * ║  the same key as either two-way hybrid from the same inputs. NOT wire-       ║
 * ║  compatible with any standard; CryptoLib-to-CryptoLib only.                 ║
 * ║                                                                            ║
 * ║   PRK = HKDF-Extract(salt = LABEL, IKM = ss_x25519 ‖ ss_mlkem ‖ ss_sntrup) ║
 * ║   ss  = HKDF-Expand (PRK, info = ct_x25519 ‖ ct_mlkem ‖ ct_sntrup          ║
 * ║                                        ‖ pk_x25519, 32)                     ║
 * ║                                                                            ║
 * ║  All three component secrets feed the IKM (any one being secret+random      ║
 * ║  makes the output pseudorandom); the full transcript — all three            ║
 * ║  ciphertexts plus the recipient X25519 public key — is bound into the       ║
 * ║  expand step, lifting the passively-secure raw X25519 DH to contribute CCA  ║
 * ║  security (X-Wing rationale). ML-KEM and sntrup761 each carry IND-CCA2.      ║
 * ║                                                                            ║
 * ║  ── Wire layout (deterministic concatenation) ─────────────────────────    ║
 * ║     public_key = x25519_pub(32) ‖ mlkem_pub(1184) ‖ sntrup_pub(1158)        ║
 * ║     secret_key = x25519_sec(32) ‖ mlkem_sec(2400) ‖ sntrup_sec(1763)        ║
 * ║     ciphertext = x25519_eph(32) ‖ mlkem_ct(1088)  ‖ sntrup_ct(1039)         ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "asymmetric.hpp"     // crypto::asymmetric::X25519
#include "hash.hpp"           // crypto::hash::HkdfSha256
#include "pq.hpp"             // crypto::pq::MlKem
#include "sntrup_x25519.hpp"  // crypto::pq::Sntrup761

#include <sodium.h>           // crypto_scalarmult_base
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::pq {

class TripleHybridKem {
public:
    static constexpr std::size_t X25519_PUBLIC_BYTES = 32;
    static constexpr std::size_t X25519_SECRET_BYTES = 32;
    static constexpr std::size_t SHARED_SECRET_BYTES = 32;
    static constexpr MlKem::Level ML_KEM_LEVEL       = MlKem::Level::KEM_768;

    static constexpr std::string_view COMBINER_LABEL =
        "cryptolib/hybrid-kem/X25519-ML-KEM-768-sntrup761/v1";

    struct KeyPair {
        SecureBuffer public_key;   // x25519_pub ‖ mlkem_pub ‖ sntrup_pub
        SecureBuffer secret_key;   // x25519_sec ‖ mlkem_sec ‖ sntrup_sec
    };
    struct EncapsResult {
        SecureBuffer ciphertext;     // x25519_eph ‖ mlkem_ct ‖ sntrup_ct
        SecureBuffer shared_secret;  // 32 bytes
    };
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t ciphertext;
        std::size_t shared_secret;
        // Per-leg splits (so callers/decap can slice the concatenations).
        std::size_t mlkem_public, mlkem_secret, mlkem_ct;
        std::size_t sntrup_public, sntrup_secret, sntrup_ct;
    };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto m = MlKem::sizes(ML_KEM_LEVEL);
        if (m.is_err()) return Result<Sizes>::err(m.error().message);
        auto s = Sntrup761::sizes();
        if (s.is_err()) return Result<Sizes>::err(s.error().message);
        const auto& mk = m.value();
        const auto& sn = s.value();
        return Result<Sizes>::ok(Sizes{
            X25519_PUBLIC_BYTES + mk.public_key + sn.public_key,
            X25519_SECRET_BYTES + mk.secret_key + sn.secret_key,
            X25519_PUBLIC_BYTES + mk.ciphertext + sn.ciphertext,
            SHARED_SECRET_BYTES,
            mk.public_key, mk.secret_key, mk.ciphertext,
            sn.public_key, sn.secret_key, sn.ciphertext });
    }

    /// Generate one X25519 + one ML-KEM-768 + one sntrup761 keypair.
    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto x = asymmetric::X25519::generate_keypair();
        auto m = MlKem::generate_keypair(ML_KEM_LEVEL);
        if (m.is_err()) return Result<KeyPair>::err(m.error().message);
        auto s = Sntrup761::generate_keypair();
        if (s.is_err()) return Result<KeyPair>::err(s.error().message);

        return Result<KeyPair>::ok(KeyPair{
            concat3(x.public_key.span(), m.value().public_key.span(), s.value().public_key.span()),
            concat3(x.secret_key.span(), m.value().secret_key.span(), s.value().secret_key.span()) });
    }

    /// Encapsulate to a triple public key → (ciphertext, 32-byte shared secret).
    [[nodiscard]] static Result<EncapsResult>
    encapsulate(std::span<const uint8_t> public_key) {
        auto sz = sizes();
        if (sz.is_err()) return Result<EncapsResult>::err(sz.error().message);
        if (public_key.size() != sz.value().public_key)
            return Result<EncapsResult>::err("TripleHybridKem: invalid public key length");

        auto x_pub = public_key.first(X25519_PUBLIC_BYTES);
        auto m_pub = public_key.subspan(X25519_PUBLIC_BYTES, sz.value().mlkem_public);
        auto s_pub = public_key.subspan(X25519_PUBLIC_BYTES + sz.value().mlkem_public);

        auto eph = asymmetric::X25519::generate_keypair();
        auto ss_x = asymmetric::X25519::shared_secret(eph.secret_key.span(), x_pub);
        if (ss_x.is_err()) return Result<EncapsResult>::err(ss_x.error().message);

        auto enc_m = MlKem::encapsulate(m_pub, ML_KEM_LEVEL);
        if (enc_m.is_err()) return Result<EncapsResult>::err(enc_m.error().message);
        auto enc_s = Sntrup761::encapsulate(s_pub);
        if (enc_s.is_err()) return Result<EncapsResult>::err(enc_s.error().message);

        auto ss = combine(ss_x.value().span(), enc_m.value().shared_secret.span(),
                          enc_s.value().shared_secret.span(),
                          eph.public_key.span(), enc_m.value().ciphertext.span(),
                          enc_s.value().ciphertext.span(), x_pub);
        if (ss.is_err()) return Result<EncapsResult>::err(ss.error().message);

        return Result<EncapsResult>::ok(EncapsResult{
            concat3(eph.public_key.span(), enc_m.value().ciphertext.span(),
                    enc_s.value().ciphertext.span()),
            std::move(ss.value()) });
    }

    /// Decapsulate with the triple secret key → 32-byte shared secret.
    [[nodiscard]] static Result<SecureBuffer>
    decapsulate(std::span<const uint8_t> ciphertext,
                std::span<const uint8_t> secret_key) {
        auto sz = sizes();
        if (sz.is_err()) return Result<SecureBuffer>::err(sz.error().message);
        if (ciphertext.size() != sz.value().ciphertext)
            return Result<SecureBuffer>::err("TripleHybridKem: invalid ciphertext length");
        if (secret_key.size() != sz.value().secret_key)
            return Result<SecureBuffer>::err("TripleHybridKem: invalid secret key length");

        auto ct_x = ciphertext.first(X25519_PUBLIC_BYTES);
        auto ct_m = ciphertext.subspan(X25519_PUBLIC_BYTES, sz.value().mlkem_ct);
        auto ct_s = ciphertext.subspan(X25519_PUBLIC_BYTES + sz.value().mlkem_ct);

        auto x_sec = secret_key.first(X25519_SECRET_BYTES);
        auto m_sec = secret_key.subspan(X25519_SECRET_BYTES, sz.value().mlkem_secret);
        auto s_sec = secret_key.subspan(X25519_SECRET_BYTES + sz.value().mlkem_secret);

        auto ss_x = asymmetric::X25519::shared_secret(x_sec, ct_x);
        if (ss_x.is_err()) return Result<SecureBuffer>::err(ss_x.error().message);
        auto ss_m = MlKem::decapsulate(ct_m, m_sec, ML_KEM_LEVEL);
        if (ss_m.is_err()) return Result<SecureBuffer>::err(ss_m.error().message);
        auto ss_s = Sntrup761::decapsulate(ct_s, s_sec);
        if (ss_s.is_err()) return Result<SecureBuffer>::err(ss_s.error().message);

        // Reconstruct the recipient's X25519 public key to bind it into the
        // transcript (the encapsulator had it from the public key).
        std::array<uint8_t, X25519_PUBLIC_BYTES> x_pub{};
        crypto_scalarmult_base(x_pub.data(), x_sec.data());

        return combine(ss_x.value().span(), ss_m.value().span(), ss_s.value().span(),
                       ct_x, ct_m, ct_s, std::span<const uint8_t>{x_pub});
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

    /// The three-leg KEM combiner. See the header banner for construction + model.
    [[nodiscard]] static Result<SecureBuffer>
    combine(std::span<const uint8_t> ss_x25519,
            std::span<const uint8_t> ss_mlkem,
            std::span<const uint8_t> ss_sntrup,
            std::span<const uint8_t> ct_x25519,
            std::span<const uint8_t> ct_mlkem,
            std::span<const uint8_t> ct_sntrup,
            std::span<const uint8_t> pk_x25519) {
        // IKM = ss_x25519 ‖ ss_mlkem ‖ ss_sntrup
        SecureBuffer ikm(ss_x25519.size() + ss_mlkem.size() + ss_sntrup.size());
        std::memcpy(ikm.data(), ss_x25519.data(), ss_x25519.size());
        std::memcpy(ikm.data() + ss_x25519.size(), ss_mlkem.data(), ss_mlkem.size());
        std::memcpy(ikm.data() + ss_x25519.size() + ss_mlkem.size(), ss_sntrup.data(), ss_sntrup.size());

        // info = ct_x25519 ‖ ct_mlkem ‖ ct_sntrup ‖ pk_x25519  (public transcript)
        std::vector<uint8_t> info;
        info.reserve(ct_x25519.size() + ct_mlkem.size() + ct_sntrup.size() + pk_x25519.size());
        info.insert(info.end(), ct_x25519.begin(), ct_x25519.end());
        info.insert(info.end(), ct_mlkem.begin(),  ct_mlkem.end());
        info.insert(info.end(), ct_sntrup.begin(), ct_sntrup.end());
        info.insert(info.end(), pk_x25519.begin(), pk_x25519.end());

        const std::span<const uint8_t> label{
            reinterpret_cast<const uint8_t*>(COMBINER_LABEL.data()), COMBINER_LABEL.size()};

        auto prk = hash::HkdfSha256::extract(label, ikm.span());
        if (prk.is_err()) return Result<SecureBuffer>::err(prk.error().message);
        return hash::HkdfSha256::expand(prk.value().span(), info, SHARED_SECRET_BYTES);
    }
};

} // namespace crypto::pq

#endif // CRYPTOLIB_HAS_PQ
