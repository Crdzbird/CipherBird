#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::pq::HybridKem — X25519 + ML-KEM-768 hybrid key encapsulation       ║
 * ║                                                                            ║
 * ║  A hybrid KEM derives one shared secret from TWO independent KEMs:          ║
 * ║                                                                            ║
 * ║    • X25519   — classical elliptic-curve Diffie–Hellman (RFC 7748)         ║
 * ║    • ML-KEM-768 — post-quantum lattice KEM (FIPS 203, NIST Level 3)        ║
 * ║                                                                            ║
 * ║  The combined secret stays secure as long as AT LEAST ONE of the two       ║
 * ║  remains unbroken:                                                         ║
 * ║    – if a quantum computer breaks X25519, ML-KEM still protects it;        ║
 * ║    – if lattice cryptanalysis breaks ML-KEM, X25519 still protects it.     ║
 * ║  This is the industry direction for key agreement during the PQC           ║
 * ║  migration (cf. NIST IR 8547; TLS X25519MLKEM768; the X-Wing KEM).         ║
 * ║                                                                            ║
 * ║  ── Combiner ──────────────────────────────────────────────────────────   ║
 * ║  This is CryptoLib's OWN domain-separated combiner. It is NOT wire-          ║
 * ║  compatible with TLS's X25519MLKEM768 codepoint or the X-Wing draft        ║
 * ║  (both fix SHA3/SHAKE and exact label bytes). Do not expect interop;       ║
 * ║  use it for CryptoLib-to-CryptoLib hybrid key agreement.                    ║
 * ║                                                                            ║
 * ║     PRK = HKDF-Extract(salt = LABEL, IKM = ss_mlkem ‖ ss_x25519)            ║
 * ║     ss  = HKDF-Expand (PRK, info = ct_mlkem ‖ ct_x25519 ‖ pk_x25519, 32)    ║
 * ║                                                                            ║
 * ║  Both component shared secrets feed the IKM (so either being secret and     ║
 * ║  random makes the output pseudorandom), and the transcript — both           ║
 * ║  ciphertexts plus the recipient's X25519 public key — is bound into the     ║
 * ║  expand step. Binding ct_x25519/pk_x25519 is what lifts the (only          ║
 * ║  passively-secure) raw X25519 DH to contribute CCA security, mirroring     ║
 * ║  the X-Wing rationale. ML-KEM-768 carries IND-CCA2 on its own.             ║
 * ║                                                                            ║
 * ║  SECURITY MODEL: combiner robustness is argued in the random-oracle model   ║
 * ║  for HKDF-SHA256 — the standard assumption for hybrid-KEM combiners.        ║
 * ║                                                                            ║
 * ║  ── Wire layout (deterministic concatenation) ─────────────────────────    ║
 * ║     public_key = x25519_pub(32) ‖ mlkem_pub                                 ║
 * ║     secret_key = x25519_sec(32) ‖ mlkem_sec                                 ║
 * ║     ciphertext = x25519_eph_pub(32) ‖ mlkem_ct                              ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "asymmetric.hpp"   // crypto::asymmetric::X25519
#include "hash.hpp"         // crypto::hash::HkdfSha256
#include "pq.hpp"           // crypto::pq::MlKem

#include <sodium.h>         // crypto_scalarmult_base
#include <array>
#include <cstdint>
#include <cstring>          // std::memcpy
#include <span>
#include <string_view>
#include <vector>

namespace crypto::pq {

class HybridKem {
public:
    // Fixed to the industry-standard pairing (X25519 + ML-KEM-768 / NIST L3).
    static constexpr std::size_t X25519_PUBLIC_BYTES = 32;
    static constexpr std::size_t X25519_SECRET_BYTES = 32;
    static constexpr std::size_t SHARED_SECRET_BYTES = 32;
    static constexpr MlKem::Level ML_KEM_LEVEL       = MlKem::Level::KEM_768;

    // Domain-separation label for the combiner (CryptoLib-defined, versioned).
    static constexpr std::string_view COMBINER_LABEL =
        "cryptolib/hybrid-kem/X25519-ML-KEM-768/v1";

    struct KeyPair {
        SecureBuffer public_key;   // x25519_pub ‖ mlkem_pub
        SecureBuffer secret_key;   // x25519_sec ‖ mlkem_sec
    };

    struct EncapsResult {
        SecureBuffer ciphertext;     // x25519_eph_pub ‖ mlkem_ct
        SecureBuffer shared_secret;  // 32 bytes
    };

    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t ciphertext;
        std::size_t shared_secret;
    };

    [[nodiscard]] static Result<Sizes> sizes() {
        auto m = MlKem::sizes(ML_KEM_LEVEL);
        if (m.is_err()) return Result<Sizes>::err(m.error().message);
        const auto& s = m.value();
        return Result<Sizes>::ok(Sizes{
            X25519_PUBLIC_BYTES + s.public_key,
            X25519_SECRET_BYTES + s.secret_key,
            X25519_PUBLIC_BYTES + s.ciphertext,
            SHARED_SECRET_BYTES });
    }

    /// Generate a hybrid keypair (one X25519 keypair + one ML-KEM-768 keypair).
    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        auto x = asymmetric::X25519::generate_keypair();
        auto m = MlKem::generate_keypair(ML_KEM_LEVEL);
        if (m.is_err()) return Result<KeyPair>::err(m.error().message);

        return Result<KeyPair>::ok(KeyPair{
            concat(x.public_key.span(), m.value().public_key.span()),
            concat(x.secret_key.span(), m.value().secret_key.span()) });
    }

    /// Encapsulate to a hybrid public key → (ciphertext, 32-byte shared secret).
    [[nodiscard]] static Result<EncapsResult>
    encapsulate(std::span<const uint8_t> public_key) {
        auto mk = MlKem::sizes(ML_KEM_LEVEL);
        if (mk.is_err()) return Result<EncapsResult>::err(mk.error().message);
        if (public_key.size() != X25519_PUBLIC_BYTES + mk.value().public_key)
            return Result<EncapsResult>::err("HybridKem: invalid public key length");

        auto x_pub = public_key.first(X25519_PUBLIC_BYTES);
        auto m_pub = public_key.subspan(X25519_PUBLIC_BYTES);

        // X25519: ephemeral keypair; ct_x is the ephemeral public key.
        auto eph = asymmetric::X25519::generate_keypair();
        auto ss_x = asymmetric::X25519::shared_secret(eph.secret_key.span(), x_pub);
        if (ss_x.is_err()) return Result<EncapsResult>::err(ss_x.error().message);

        // ML-KEM: encapsulate to its public key.
        auto enc = MlKem::encapsulate(m_pub, ML_KEM_LEVEL);
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
        auto mk = MlKem::sizes(ML_KEM_LEVEL);
        if (mk.is_err()) return Result<SecureBuffer>::err(mk.error().message);
        if (ciphertext.size() != X25519_PUBLIC_BYTES + mk.value().ciphertext)
            return Result<SecureBuffer>::err("HybridKem: invalid ciphertext length");
        if (secret_key.size() != X25519_SECRET_BYTES + mk.value().secret_key)
            return Result<SecureBuffer>::err("HybridKem: invalid secret key length");

        auto ct_x  = ciphertext.first(X25519_PUBLIC_BYTES);   // ephemeral X25519 pub
        auto ct_m  = ciphertext.subspan(X25519_PUBLIC_BYTES);
        auto x_sec = secret_key.first(X25519_SECRET_BYTES);
        auto m_sec = secret_key.subspan(X25519_SECRET_BYTES);

        auto ss_x = asymmetric::X25519::shared_secret(x_sec, ct_x);
        if (ss_x.is_err()) return Result<SecureBuffer>::err(ss_x.error().message);

        auto ss_m = MlKem::decapsulate(ct_m, m_sec, ML_KEM_LEVEL);
        if (ss_m.is_err()) return Result<SecureBuffer>::err(ss_m.error().message);

        // Reconstruct the recipient's X25519 public key to bind it into the
        // combiner transcript (the encapsulator had it from the public key).
        std::array<uint8_t, X25519_PUBLIC_BYTES> x_pub{};
        crypto_scalarmult_base(x_pub.data(), x_sec.data());

        return combine(ss_m.value().span(), ss_x.value().span(),
                       ct_m, ct_x, std::span<const uint8_t>{x_pub});
    }

private:
    /// Concatenate two byte spans into a SecureBuffer (secret-safe).
    [[nodiscard]] static SecureBuffer
    concat(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        SecureBuffer out(a.size() + b.size());
        std::memcpy(out.data(), a.data(), a.size());
        std::memcpy(out.data() + a.size(), b.data(), b.size());
        return out;
    }

    /// The KEM combiner. See the header banner for the construction + model.
    [[nodiscard]] static Result<SecureBuffer>
    combine(std::span<const uint8_t> ss_mlkem,
            std::span<const uint8_t> ss_x25519,
            std::span<const uint8_t> ct_mlkem,
            std::span<const uint8_t> ct_x25519,
            std::span<const uint8_t> pk_x25519) {
        // IKM = ss_mlkem ‖ ss_x25519   (both secrets; kept in locked memory)
        SecureBuffer ikm = concat(ss_mlkem, ss_x25519);

        // info = ct_mlkem ‖ ct_x25519 ‖ pk_x25519   (public transcript binding)
        std::vector<uint8_t> info;
        info.reserve(ct_mlkem.size() + ct_x25519.size() + pk_x25519.size());
        info.insert(info.end(), ct_mlkem.begin(),  ct_mlkem.end());
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
