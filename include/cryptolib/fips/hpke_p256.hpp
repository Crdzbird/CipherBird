#pragma once
/**
 * crypto::fips::HpkeP256: RFC 9180 base mode with DHKEM(P-256, HKDF-SHA256)
 * (KEM id 0x0010), HKDF-SHA256 (0x0001) and AES-256-GCM (0x0002), every
 * step an approved operation of the provider: ECDH on P-256 (KAS-ECC-SSC),
 * HKDF, AES-GCM. One-shot seal and open; the enc is the 65-byte ephemeral
 * public key. Byte-compatible with any RFC 9180 implementation of the same
 * suite (the AEAD nonce is the RFC's base_nonce XOR sequence 0).
 */
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
#include "primitives.hpp"
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::fips {

class HpkeP256 {
public:
    static constexpr uint16_t KEM_ID = 0x0010, KDF_ID = 0x0001, AEAD_ID = 0x0002;
    static constexpr std::size_t NSECRET = 32, NENC = 65, NPK = 65, NSK = 32, NK = 32, NN = 12;
    struct Sealed { PublicBuffer enc; PublicBuffer ct; };

    [[nodiscard]] static Result<P256::KeyPair> generate_keypair() { return P256::generate_keypair(); }

    [[nodiscard]] static Result<Sealed>
    seal(std::span<const uint8_t> pkR, std::span<const uint8_t> info,
         std::span<const uint8_t> aad, std::span<const uint8_t> plaintext) {
        auto eph = P256::generate_keypair();
        if (eph.is_err()) return Result<Sealed>::err(eph.error().message);
        auto dh = P256::ecdh(eph.value().private_key.span(), pkR);
        if (dh.is_err()) return Result<Sealed>::err(dh.error().message);
        std::vector<uint8_t> kem_context(eph.value().public_key.span().begin(), eph.value().public_key.span().end());
        kem_context.insert(kem_context.end(), pkR.begin(), pkR.end());
        auto shared = extract_and_expand(dh.value().span(), kem_context);
        if (shared.is_err()) return Result<Sealed>::err(shared.error().message);
        auto keys = key_schedule(shared.value().span(), info);
        if (keys.is_err()) return Result<Sealed>::err(keys.error().message);
        auto ct = aead_seal(keys.value().first.span(), keys.value().second.span(), aad, plaintext);
        if (ct.is_err()) return Result<Sealed>::err(ct.error().message);
        return Result<Sealed>::ok(Sealed{ std::move(eph.value().public_key), std::move(ct.value()) });
    }

    [[nodiscard]] static Result<SecureBuffer>
    open(std::span<const uint8_t> enc, std::span<const uint8_t> skR, std::span<const uint8_t> pkR,
         std::span<const uint8_t> info, std::span<const uint8_t> aad, std::span<const uint8_t> ct) {
        if (pkR.size() != P256::PUBLIC_BYTES) return Result<SecureBuffer>::err("fips: HPKE recipient public key must be 65 bytes");
        auto dh = P256::ecdh(skR, enc);
        if (dh.is_err()) return Result<SecureBuffer>::err(dh.error().message);
        std::vector<uint8_t> kem_context(enc.begin(), enc.end());
        kem_context.insert(kem_context.end(), pkR.begin(), pkR.end());
        auto shared = extract_and_expand(dh.value().span(), kem_context);
        if (shared.is_err()) return Result<SecureBuffer>::err(shared.error().message);
        auto keys = key_schedule(shared.value().span(), info);
        if (keys.is_err()) return Result<SecureBuffer>::err(keys.error().message);
        return aead_open(keys.value().first.span(), keys.value().second.span(), aad, ct);
    }

private:
    static std::vector<uint8_t> kem_suite_id() { return { 'K', 'E', 'M', 0x00, 0x10 }; }
    static std::vector<uint8_t> hpke_suite_id() { return { 'H', 'P', 'K', 'E', 0x00, 0x10, 0x00, 0x01, 0x00, 0x02 }; }
    static void put(std::vector<uint8_t>& v, std::span<const uint8_t> s) { v.insert(v.end(), s.begin(), s.end()); }
    static void put(std::vector<uint8_t>& v, std::string_view s) { v.insert(v.end(), s.begin(), s.end()); }

    static Result<SecureBuffer> labeled_extract(const std::vector<uint8_t>& suite_id, std::span<const uint8_t> salt,
                                                std::string_view label, std::span<const uint8_t> ikm) {
        std::vector<uint8_t> li;
        put(li, "HPKE-v1"); put(li, suite_id); put(li, label); put(li, ikm);
        auto prk = Hkdf::derive(Hash::Sha256, li, salt, {}, 32, Hkdf::Mode::ExtractOnly);
        OPENSSL_cleanse(li.data(), li.size());
        return prk;
    }
    static Result<SecureBuffer> labeled_expand(const std::vector<uint8_t>& suite_id, std::span<const uint8_t> prk,
                                               std::string_view label, std::span<const uint8_t> info, std::size_t L) {
        std::vector<uint8_t> li;
        li.push_back(static_cast<uint8_t>((L >> 8) & 0xff));
        li.push_back(static_cast<uint8_t>(L & 0xff));
        put(li, "HPKE-v1"); put(li, suite_id); put(li, label); put(li, info);
        return Hkdf::derive(Hash::Sha256, prk, {}, li, L, Hkdf::Mode::ExpandOnly);
    }
    static Result<SecureBuffer> extract_and_expand(std::span<const uint8_t> dh, std::span<const uint8_t> kem_context) {
        auto sid = kem_suite_id();
        auto eae_prk = labeled_extract(sid, {}, "eae_prk", dh);
        if (eae_prk.is_err()) return eae_prk;
        return labeled_expand(sid, eae_prk.value().span(), "shared_secret", kem_context, NSECRET);
    }
    /* (key, base_nonce) for mode_base */
    static Result<std::pair<SecureBuffer, SecureBuffer>> key_schedule(std::span<const uint8_t> shared_secret,
                                                                      std::span<const uint8_t> info) {
        using R = Result<std::pair<SecureBuffer, SecureBuffer>>;
        auto sid = hpke_suite_id();
        auto psk_id_hash = labeled_extract(sid, {}, "psk_id_hash", {});
        auto info_hash = labeled_extract(sid, {}, "info_hash", info);
        if (psk_id_hash.is_err() || info_hash.is_err()) return R::err("fips HPKE: key schedule failed");
        std::vector<uint8_t> ksc;
        ksc.push_back(0x00);
        put(ksc, psk_id_hash.value().span());
        put(ksc, info_hash.value().span());
        auto secret = labeled_extract(sid, shared_secret, "secret", {});
        if (secret.is_err()) return R::err(secret.error().message);
        auto key = labeled_expand(sid, secret.value().span(), "key", ksc, NK);
        auto base_nonce = labeled_expand(sid, secret.value().span(), "base_nonce", ksc, NN);
        if (key.is_err() || base_nonce.is_err()) return R::err("fips HPKE: key schedule failed");
        return R::ok({ std::move(key.value()), std::move(base_nonce.value()) });
    }
    /* AES-256-GCM with the RFC nonce (sequence 0), through the provider with an external IV */
    /* derived by the key schedule, which SP 800-38D 8.2.1 allows for a single message per key. */
    static Result<PublicBuffer> aead_seal(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                          std::span<const uint8_t> aad, std::span<const uint8_t> pt) {
        if (!crypto::detail::fits_int(pt.size()) || !crypto::detail::fits_int(aad.size()))
            return Result<PublicBuffer>::err("fips HPKE: input too large");
        detail::Cipher cipher{ EVP_CIPHER_fetch(nullptr, "AES-256-GCM", Provider::PROPERTIES) };
        detail::CipherCtx ctx{ EVP_CIPHER_CTX_new() };
        if (!cipher || !ctx) return Result<PublicBuffer>::err("fips HPKE: AES-256-GCM not available");
        PublicBuffer out(pt.size() + 16);
        int len = 0, fin = 0;
        if (EVP_EncryptInit_ex2(ctx.get(), cipher.get(), key.data(), nonce.data(), nullptr) != 1 ||
            (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
            (!pt.empty() && EVP_EncryptUpdate(ctx.get(), out.data(), &len, pt.data(), static_cast<int>(pt.size())) != 1) ||
            EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + pt.size()) != 1)
            return Result<PublicBuffer>::err("fips HPKE: seal failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }
    static Result<SecureBuffer> aead_open(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                          std::span<const uint8_t> aad, std::span<const uint8_t> ct) {
        if (ct.size() < 16) return Result<SecureBuffer>::err("fips HPKE: ciphertext too short");
        if (!crypto::detail::fits_int(ct.size()) || !crypto::detail::fits_int(aad.size()))
            return Result<SecureBuffer>::err("fips HPKE: input too large");
        detail::Cipher cipher{ EVP_CIPHER_fetch(nullptr, "AES-256-GCM", Provider::PROPERTIES) };
        detail::CipherCtx ctx{ EVP_CIPHER_CTX_new() };
        if (!cipher || !ctx) return Result<SecureBuffer>::err("fips HPKE: AES-256-GCM not available");
        const std::size_t n = ct.size() - 16;
        uint8_t tag[16];
        std::memcpy(tag, ct.data() + n, 16);
        SecureBuffer out(n);
        int len = 0, fin = 0;
        if (EVP_DecryptInit_ex2(ctx.get(), cipher.get(), key.data(), nonce.data(), nullptr) != 1 ||
            (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
            (n > 0 && EVP_DecryptUpdate(ctx.get(), out.data(), &len, ct.data(), static_cast<int>(n)) != 1) ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1 ||
            EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1)
            return Result<SecureBuffer>::err("fips HPKE: authentication failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

}
#endif
