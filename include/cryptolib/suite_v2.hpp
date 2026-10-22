#pragma once
/**
 * crypto::Suite2: signed sealed envelopes whose signature binds the
 * recipient, the KEM ciphertext and the AAD (assessment r2, M5), over the
 * standards-track X-Wing KEM by default (M4). Suite v1 signed only the
 * plaintext, so a signed message could be re-sealed to another recipient
 * and still verify; v2 cannot.
 *
 * Wire: "CSV2" | suite(1) | kem_ct_len(4 LE) | kem_ct | body, where body is
 * the committing AEAD of (sig_len(4 LE) | sig | plaintext) under
 * HKDF(shared_secret, "cryptolib/suite/v2/key") with the envelope header
 * and the caller's AAD as associated data. The signature (Ed25519 +
 * ML-DSA-65) covers "cryptolib/suite/v2/sig" | suite | len(recipient_kem_public)
 * | recipient_kem_public | len(kem_ct) | kem_ct | len(aad) | aad | plaintext.
 * New suite ids, so v1 and v2 envelopes never parse as each other.
 */
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include "types.hpp"
#include "hash.hpp"
#include "committing.hpp"
#include "hybrid_sig.hpp"
#include "xwing.hpp"
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
#include "hybrid_kem.hpp"
#endif
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

class Suite2 {
public:
    static constexpr std::array<uint8_t, 4> MAGIC = {'C', 'S', 'V', '2'};
    /// X-Wing with the Ed25519 + ML-DSA-65 signature: the default everywhere.
    static constexpr uint8_t SUITE_XWING_SIG = 0x11;
    /// The library-native X25519 + ML-KEM-768 combiner; full profile only.
    static constexpr uint8_t SUITE_HYBRID_SIG = 0x12;
    static constexpr std::string_view L_SIG = "cryptolib/suite/v2/sig";
    static constexpr std::string_view L_KEY = "cryptolib/suite/v2/key";

    using Sig = pq::HybridSig;

    [[nodiscard]] static Result<PublicBuffer>
    seal(std::span<const uint8_t> plaintext, std::span<const uint8_t> recipient_kem_public,
         std::span<const uint8_t> signer_sig_secret, std::span<const uint8_t> aad = {},
         uint8_t suite = SUITE_XWING_SIG) {
        auto kem = encapsulate(suite, recipient_kem_public);
        if (kem.is_err()) return Result<PublicBuffer>::err(kem.error().message);
        auto to_sign = transcript(suite, recipient_kem_public, kem.value().ciphertext.span(), aad, plaintext);
        auto sig = Sig::sign(to_sign, signer_sig_secret);
        if (sig.is_err()) return Result<PublicBuffer>::err(sig.error().message);
        std::vector<uint8_t> inner;
        put_u32(inner, static_cast<uint32_t>(sig.value().size()));
        inner.insert(inner.end(), sig.value().span().begin(), sig.value().span().end());
        inner.insert(inner.end(), plaintext.begin(), plaintext.end());
        auto head = header(suite, kem.value().ciphertext.span());
        auto key = derive_key(kem.value().shared_secret.span());
        if (key.is_err()) { sodium_memzero(inner.data(), inner.size()); return Result<PublicBuffer>::err(key.error().message); }
        auto body = symmetric::CommittingAead::encrypt(inner, key.value().span(), full_aad(head, aad));
        sodium_memzero(inner.data(), inner.size());
        if (body.is_err()) return body;
        std::vector<uint8_t> out(head);
        out.insert(out.end(), body.value().span().begin(), body.value().span().end());
        return Result<PublicBuffer>::ok(PublicBuffer(std::move(out)));
    }

    /// Returns the plaintext only if the signature over recipient, KEM
    /// ciphertext, AAD and plaintext verifies against [signer_sig_public].
    [[nodiscard]] static Result<SecureBuffer>
    open(std::span<const uint8_t> envelope, std::span<const uint8_t> recipient_kem_secret,
         std::span<const uint8_t> recipient_kem_public, std::span<const uint8_t> signer_sig_public,
         std::span<const uint8_t> aad = {}) {
        uint8_t suite = 0;
        std::span<const uint8_t> kem_ct, body;
        if (auto e = unframe(envelope, suite, kem_ct, body); e.is_err()) return Result<SecureBuffer>::err(e.error().message);
        auto ss = decapsulate(suite, kem_ct, recipient_kem_secret);
        if (ss.is_err()) return Result<SecureBuffer>::err(ss.error().message);
        auto key = derive_key(ss.value().span());
        if (key.is_err()) return Result<SecureBuffer>::err(key.error().message);
        auto head = header(suite, kem_ct);
        auto inner = symmetric::CommittingAead::decrypt(body, key.value().span(), full_aad(head, aad));
        if (inner.is_err()) return Result<SecureBuffer>::err("Suite2: authentication failed");
        auto s = inner.value().span();
        auto sizes = Sig::sizes();
        if (sizes.is_err()) return Result<SecureBuffer>::err(sizes.error().message);
        if (s.size() < 4) return Result<SecureBuffer>::err("Suite2: signed body truncated");
        const std::size_t sig_len = get_u32(s.data());
        if (sig_len != sizes.value().signature || sig_len > s.size() - 4)
            return Result<SecureBuffer>::err("Suite2: invalid signature length");
        auto sig = s.subspan(4, sig_len);
        auto pt = s.subspan(4 + sig_len);
        auto to_sign = transcript(suite, recipient_kem_public, kem_ct, aad, pt);
        if (Sig::verify(to_sign, sig, signer_sig_public).is_err())
            return Result<SecureBuffer>::err("Suite2: signature verification failed");
        return Result<SecureBuffer>::ok(SecureBuffer(pt.data(), pt.size()));
    }

    /// What the signature covers; exposed so a verifier can audit the binding.
    [[nodiscard]] static std::vector<uint8_t>
    transcript(uint8_t suite, std::span<const uint8_t> recipient_kem_public, std::span<const uint8_t> kem_ct,
               std::span<const uint8_t> aad, std::span<const uint8_t> plaintext) {
        std::vector<uint8_t> t(L_SIG.begin(), L_SIG.end());
        t.push_back(suite);
        put_lp(t, recipient_kem_public);
        put_lp(t, kem_ct);
        put_lp(t, aad);
        t.insert(t.end(), plaintext.begin(), plaintext.end());
        return t;
    }

    [[nodiscard]] static Result<uint8_t> suite_of(std::span<const uint8_t> envelope) {
        uint8_t suite = 0;
        std::span<const uint8_t> kem_ct, body;
        if (auto e = unframe(envelope, suite, kem_ct, body); e.is_err()) return Result<uint8_t>::err(e.error().message);
        return Result<uint8_t>::ok(suite);
    }

private:
    struct Kem { SecureBuffer ciphertext; SecureBuffer shared_secret; };

    static Result<Kem> encapsulate(uint8_t suite, std::span<const uint8_t> pk) {
        if (suite == SUITE_XWING_SIG) {
            auto e = pq::XWing::encapsulate(pk);
            if (e.is_err()) return Result<Kem>::err(e.error().message);
            return Result<Kem>::ok(Kem{ std::move(e.value().ciphertext), std::move(e.value().shared_secret) });
        }
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
        if (suite == SUITE_HYBRID_SIG) {
            auto e = pq::HybridKem::encapsulate(pk);
            if (e.is_err()) return Result<Kem>::err(e.error().message);
            return Result<Kem>::ok(Kem{ std::move(e.value().ciphertext), std::move(e.value().shared_secret) });
        }
#endif
        return Result<Kem>::err("Suite2: unknown or unavailable suite");
    }
    static Result<SecureBuffer> decapsulate(uint8_t suite, std::span<const uint8_t> ct, std::span<const uint8_t> sk) {
        if (suite == SUITE_XWING_SIG) return pq::XWing::decapsulate(ct, sk);
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
        if (suite == SUITE_HYBRID_SIG) return pq::HybridKem::decapsulate(ct, sk);
#endif
        return Result<SecureBuffer>::err("Suite2: unknown or unavailable suite");
    }
    static Result<SecureBuffer> derive_key(std::span<const uint8_t> ss) {
        return hash::HkdfSha256::derive(ss, {}, L_KEY, symmetric::CommittingAead::KEY_BYTES);
    }
    static std::vector<uint8_t> header(uint8_t suite, std::span<const uint8_t> kem_ct) {
        std::vector<uint8_t> h(MAGIC.begin(), MAGIC.end());
        h.push_back(suite);
        put_u32(h, static_cast<uint32_t>(kem_ct.size()));
        h.insert(h.end(), kem_ct.begin(), kem_ct.end());
        return h;
    }
    static std::vector<uint8_t> full_aad(const std::vector<uint8_t>& head, std::span<const uint8_t> aad) {
        std::vector<uint8_t> a(head);
        a.insert(a.end(), aad.begin(), aad.end());
        return a;
    }
    static Result<void> unframe(std::span<const uint8_t> env, uint8_t& suite,
                                std::span<const uint8_t>& kem_ct, std::span<const uint8_t>& body) {
        constexpr std::size_t HDR = 4 + 1 + 4;
        if (env.size() < HDR) return Result<void>::err("Suite2: envelope too short");
        if (std::memcmp(env.data(), MAGIC.data(), 4) != 0) return Result<void>::err("Suite2: bad magic");
        suite = env[4];
        if (suite != SUITE_XWING_SIG && suite != SUITE_HYBRID_SIG) return Result<void>::err("Suite2: unknown suite");
        const std::size_t ct_len = get_u32(env.data() + 5);
        if (ct_len > env.size() - HDR) return Result<void>::err("Suite2: envelope truncated");
        kem_ct = env.subspan(HDR, ct_len);
        body = env.subspan(HDR + ct_len);
        return Result<void>::ok();
    }
    static void put_u32(std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
    static uint32_t get_u32(const uint8_t* p) {
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= static_cast<uint32_t>(p[i]) << (8 * i);
        return x;
    }
    static void put_lp(std::vector<uint8_t>& v, std::span<const uint8_t> b) {
        put_u32(v, static_cast<uint32_t>(b.size()));
        v.insert(v.end(), b.begin(), b.end());
    }
};

}
#endif
