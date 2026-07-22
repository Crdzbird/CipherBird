#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::pq::SntrupX25519 — X25519 + Streamlined NTRU Prime 761 hybrid KEM  ║
 * ║                                                                            ║
 * ║  A second post-quantum hybrid KEM alongside HybridKem (X25519+ML-KEM-768). ║
 * ║  Where ML-KEM is module-LWE (structured lattice), Streamlined NTRU Prime   ║
 * ║  (sntrup761) is a deliberately unstructured NTRU-family lattice KEM — a     ║
 * ║  DIFFERENT design lineage. Running both gives defense-in-diversity: a       ║
 * ║  cryptanalytic break confined to one lattice family does not take the       ║
 * ║  other down with it. sntrup761 is the PQ half of OpenSSH's default key      ║
 * ║  exchange, so it is heavily deployed and scrutinized.                       ║
 * ║                                                                            ║
 * ║  Security holds as long as AT LEAST ONE of {X25519, sntrup761} is unbroken.║
 * ║                                                                            ║
 * ║  ── Combiner ──────────────────────────────────────────────────────────   ║
 * ║  CryptoLib's OWN domain-separated combiner, structurally identical to       ║
 * ║  HybridKem's (HKDF-SHA256, transcript-binding) but with a distinct label,   ║
 * ║  so the two hybrids can never produce the same key from the same inputs.    ║
 * ║  NOT wire-compatible with OpenSSH's sntrup761x25519-sha512 (which fixes     ║
 * ║  SHA-512 and its own framing); use it for CryptoLib-to-CryptoLib agreement. ║
 * ║                                                                            ║
 * ║     PRK = HKDF-Extract(salt = LABEL, IKM = ss_sntrup ‖ ss_x25519)           ║
 * ║     ss  = HKDF-Expand (PRK, info = ct_sntrup ‖ ct_x25519 ‖ pk_x25519, 32)   ║
 * ║                                                                            ║
 * ║  Both component secrets feed the IKM (either being secret+random makes the  ║
 * ║  output pseudorandom); the full transcript — both ciphertexts plus the      ║
 * ║  recipient's X25519 public key — is bound into the expand step, lifting the ║
 * ║  passively-secure raw X25519 DH to contribute CCA security (X-Wing          ║
 * ║  rationale). sntrup761 carries IND-CCA2 on its own.                         ║
 * ║                                                                            ║
 * ║  ── Wire layout (deterministic concatenation) ─────────────────────────    ║
 * ║     public_key = x25519_pub(32) ‖ sntrup_pub(1158)                          ║
 * ║     secret_key = x25519_sec(32) ‖ sntrup_sec(1763)                          ║
 * ║     ciphertext = x25519_eph_pub(32) ‖ sntrup_ct(1039)                       ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "asymmetric.hpp"   // crypto::asymmetric::X25519
#include "hash.hpp"         // crypto::hash::HkdfSha256

#include <oqs/oqs.h>
#include <sodium.h>         // crypto_scalarmult_base
#include <array>
#include <cstdint>
#include <cstring>          // std::memcpy
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::pq {

// ─────────────────────────────────────────────────────────────────────────────
// Sntrup761 — Streamlined NTRU Prime 761 KEM (liboqs). Not a NIST-standardized
// algorithm and not provided by OpenSSL, so this is always liboqs-backed.
// ─────────────────────────────────────────────────────────────────────────────
class Sntrup761 {
public:
    struct KeyPair {
        SecureBuffer public_key;
        SecureBuffer secret_key;
    };
    struct EncapsResult {
        SecureBuffer ciphertext;
        SecureBuffer shared_secret;
    };
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t ciphertext;
        std::size_t shared_secret;
    };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto kem = make_kem();
        if (!kem) return Result<Sizes>::err("sntrup761: algorithm not available in liboqs build");
        return Result<Sizes>::ok(Sizes{
            kem->length_public_key, kem->length_secret_key,
            kem->length_ciphertext, kem->length_shared_secret });
    }

    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto kem = make_kem();
        if (!kem) return Result<KeyPair>::err("sntrup761: algorithm not available in liboqs build");

        SecureBuffer pk(kem->length_public_key);
        SecureBuffer sk(kem->length_secret_key);
        if (OQS_KEM_keypair(kem.get(), pk.data(), sk.data()) != OQS_SUCCESS)
            return Result<KeyPair>::err("sntrup761: keypair generation failed");
        return Result<KeyPair>::ok(KeyPair{ std::move(pk), std::move(sk) });
    }

    [[nodiscard]] static Result<EncapsResult>
    encapsulate(std::span<const uint8_t> public_key) {
        auto kem = make_kem();
        if (!kem) return Result<EncapsResult>::err("sntrup761: algorithm not available");
        if (public_key.size() != kem->length_public_key)
            return Result<EncapsResult>::err("sntrup761: invalid public key length");

        SecureBuffer ct(kem->length_ciphertext);
        SecureBuffer ss(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem.get(), ct.data(), ss.data(), public_key.data()) != OQS_SUCCESS)
            return Result<EncapsResult>::err("sntrup761: encapsulation failed");
        return Result<EncapsResult>::ok(EncapsResult{ std::move(ct), std::move(ss) });
    }

    [[nodiscard]] static Result<SecureBuffer>
    decapsulate(std::span<const uint8_t> ciphertext, std::span<const uint8_t> secret_key) {
        auto kem = make_kem();
        if (!kem) return Result<SecureBuffer>::err("sntrup761: algorithm not available");
        if (ciphertext.size() != kem->length_ciphertext)
            return Result<SecureBuffer>::err("sntrup761: invalid ciphertext length");
        if (secret_key.size() != kem->length_secret_key)
            return Result<SecureBuffer>::err("sntrup761: invalid secret key length");

        SecureBuffer ss(kem->length_shared_secret);
        if (OQS_KEM_decaps(kem.get(), ss.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("sntrup761: decapsulation failed");
        return Result<SecureBuffer>::ok(std::move(ss));
    }

private:
    struct KemDeleter { void operator()(OQS_KEM* k) { if (k) OQS_KEM_free(k); } };
    using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;
    [[nodiscard]] static KemPtr make_kem() {
        return KemPtr(OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SntrupX25519 — the X25519 + sntrup761 hybrid KEM.
// ─────────────────────────────────────────────────────────────────────────────
class SntrupX25519 {
public:
    static constexpr std::size_t X25519_PUBLIC_BYTES = 32;
    static constexpr std::size_t X25519_SECRET_BYTES = 32;
    static constexpr std::size_t SHARED_SECRET_BYTES = 32;

    // Domain-separation label — DISTINCT from HybridKem's, so the two hybrids
    // never derive the same key even from identical component inputs.
    static constexpr std::string_view COMBINER_LABEL =
        "cryptolib/hybrid-kem/X25519-sntrup761/v1";

    struct KeyPair {
        SecureBuffer public_key;   // x25519_pub ‖ sntrup_pub
        SecureBuffer secret_key;   // x25519_sec ‖ sntrup_sec
    };
    struct EncapsResult {
        SecureBuffer ciphertext;     // x25519_eph_pub ‖ sntrup_ct
        SecureBuffer shared_secret;  // 32 bytes
    };
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t ciphertext;
        std::size_t shared_secret;
    };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto s = Sntrup761::sizes();
        if (s.is_err()) return Result<Sizes>::err(s.error().message);
        return Result<Sizes>::ok(Sizes{
            X25519_PUBLIC_BYTES + s.value().public_key,
            X25519_SECRET_BYTES + s.value().secret_key,
            X25519_PUBLIC_BYTES + s.value().ciphertext,
            SHARED_SECRET_BYTES });
    }

    /// Generate a hybrid keypair (one X25519 keypair + one sntrup761 keypair).
    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto x = asymmetric::X25519::generate_keypair();
        auto s = Sntrup761::generate_keypair();
        if (s.is_err()) return Result<KeyPair>::err(s.error().message);

        return Result<KeyPair>::ok(KeyPair{
            concat(x.public_key.span(), s.value().public_key.span()),
            concat(x.secret_key.span(), s.value().secret_key.span()) });
    }

    /// Encapsulate to a hybrid public key → (ciphertext, 32-byte shared secret).
    [[nodiscard]] static Result<EncapsResult>
    encapsulate(std::span<const uint8_t> public_key) {
        auto sk = Sntrup761::sizes();
        if (sk.is_err()) return Result<EncapsResult>::err(sk.error().message);
        if (public_key.size() != X25519_PUBLIC_BYTES + sk.value().public_key)
            return Result<EncapsResult>::err("SntrupX25519: invalid public key length");

        auto x_pub = public_key.first(X25519_PUBLIC_BYTES);
        auto s_pub = public_key.subspan(X25519_PUBLIC_BYTES);

        // X25519: ephemeral keypair; ct_x is the ephemeral public key.
        auto eph = asymmetric::X25519::generate_keypair();
        auto ss_x = asymmetric::X25519::shared_secret(eph.secret_key.span(), x_pub);
        if (ss_x.is_err()) return Result<EncapsResult>::err(ss_x.error().message);

        // sntrup761: encapsulate to its public key.
        auto enc = Sntrup761::encapsulate(s_pub);
        if (enc.is_err()) return Result<EncapsResult>::err(enc.error().message);

        auto ss = combine(enc.value().shared_secret.span(), ss_x.value().span(),
                          enc.value().ciphertext.span(), eph.public_key.span(), x_pub);
        if (ss.is_err()) return Result<EncapsResult>::err(ss.error().message);

        return Result<EncapsResult>::ok(EncapsResult{
            concat(eph.public_key.span(), enc.value().ciphertext.span()),
            std::move(ss.value()) });
    }

    /// Decapsulate with the hybrid secret key → 32-byte shared secret.
    [[nodiscard]] static Result<SecureBuffer>
    decapsulate(std::span<const uint8_t> ciphertext,
                std::span<const uint8_t> secret_key) {
        auto sk = Sntrup761::sizes();
        if (sk.is_err()) return Result<SecureBuffer>::err(sk.error().message);
        if (ciphertext.size() != X25519_PUBLIC_BYTES + sk.value().ciphertext)
            return Result<SecureBuffer>::err("SntrupX25519: invalid ciphertext length");
        if (secret_key.size() != X25519_SECRET_BYTES + sk.value().secret_key)
            return Result<SecureBuffer>::err("SntrupX25519: invalid secret key length");

        auto ct_x  = ciphertext.first(X25519_PUBLIC_BYTES);   // ephemeral X25519 pub
        auto ct_s  = ciphertext.subspan(X25519_PUBLIC_BYTES);
        auto x_sec = secret_key.first(X25519_SECRET_BYTES);
        auto s_sec = secret_key.subspan(X25519_SECRET_BYTES);

        auto ss_x = asymmetric::X25519::shared_secret(x_sec, ct_x);
        if (ss_x.is_err()) return Result<SecureBuffer>::err(ss_x.error().message);

        auto ss_s = Sntrup761::decapsulate(ct_s, s_sec);
        if (ss_s.is_err()) return Result<SecureBuffer>::err(ss_s.error().message);

        // Reconstruct the recipient's X25519 public key to bind it into the
        // combiner transcript (the encapsulator had it from the public key).
        std::array<uint8_t, X25519_PUBLIC_BYTES> x_pub{};
        crypto_scalarmult_base(x_pub.data(), x_sec.data());

        return combine(ss_s.value().span(), ss_x.value().span(),
                       ct_s, ct_x, std::span<const uint8_t>{x_pub});
    }

private:
    [[nodiscard]] static SecureBuffer
    concat(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer out(a.size() + b.size());
        std::memcpy(out.data(), a.data(), a.size());
        std::memcpy(out.data() + a.size(), b.data(), b.size());
        return out;
    }

    /// The KEM combiner. See the header banner for the construction + model.
    [[nodiscard]] static Result<SecureBuffer>
    combine(std::span<const uint8_t> ss_sntrup,
            std::span<const uint8_t> ss_x25519,
            std::span<const uint8_t> ct_sntrup,
            std::span<const uint8_t> ct_x25519,
            std::span<const uint8_t> pk_x25519) {
        // IKM = ss_sntrup ‖ ss_x25519   (both secrets; kept in locked memory)
        SecureBuffer ikm = concat(ss_sntrup, ss_x25519);

        // info = ct_sntrup ‖ ct_x25519 ‖ pk_x25519   (public transcript binding)
        std::vector<uint8_t> info;
        info.reserve(ct_sntrup.size() + ct_x25519.size() + pk_x25519.size());
        info.insert(info.end(), ct_sntrup.begin(),  ct_sntrup.end());
        info.insert(info.end(), ct_x25519.begin(), ct_x25519.end());
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
