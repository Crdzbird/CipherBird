#pragma once
/**
 * Approved operations of the fips profile, each a fetch with fips=yes into
 * the OpenSSL FIPS Provider: SHA-2 and SHA-3 digests, HMAC, HKDF (SP 800-56C
 * KDA), PBKDF2 (SP 800-132), AES-256-GCM (SP 800-38D with the module's own
 * IV generation), CTR_DRBG randomness, and P-256 key agreement (KAS-ECC-SSC)
 * and signatures (ECDSA). Every function fails closed when the provider is
 * not initialised or the algorithm is not available in approved mode.
 */
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
#include "provider.hpp"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::fips {

namespace detail {
struct MdFree     { void operator()(EVP_MD* p) const { if (p) EVP_MD_free(p); } };
struct MdCtxFree  { void operator()(EVP_MD_CTX* p) const { if (p) EVP_MD_CTX_free(p); } };
struct MacFree    { void operator()(EVP_MAC* p) const { if (p) EVP_MAC_free(p); } };
struct MacCtxFree { void operator()(EVP_MAC_CTX* p) const { if (p) EVP_MAC_CTX_free(p); } };
struct KdfFree    { void operator()(EVP_KDF* p) const { if (p) EVP_KDF_free(p); } };
struct KdfCtxFree { void operator()(EVP_KDF_CTX* p) const { if (p) EVP_KDF_CTX_free(p); } };
struct CipherFree { void operator()(EVP_CIPHER* p) const { if (p) EVP_CIPHER_free(p); } };
struct CipherCtxFree { void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); } };
struct PkeyFree   { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); } };
struct BnFree     { void operator()(BIGNUM* p) const { if (p) BN_clear_free(p); } };
using Md = std::unique_ptr<EVP_MD, MdFree>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;
using Mac = std::unique_ptr<EVP_MAC, MacFree>;
using MacCtx = std::unique_ptr<EVP_MAC_CTX, MacCtxFree>;
using Kdf = std::unique_ptr<EVP_KDF, KdfFree>;
using KdfCtx = std::unique_ptr<EVP_KDF_CTX, KdfCtxFree>;
using Cipher = std::unique_ptr<EVP_CIPHER, CipherFree>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree>;
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using Bn = std::unique_ptr<BIGNUM, BnFree>;
struct EcGroupFree { void operator()(EC_GROUP* g) const noexcept { EC_GROUP_free(g); } };
struct EcPointFree { void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); } };
using EcGroup = std::unique_ptr<EC_GROUP, EcGroupFree>;
using EcPoint = std::unique_ptr<EC_POINT, EcPointFree>;
inline char* mutable_name(const char* s) { return const_cast<char*>(s); }
}

/* Digests */
enum class Hash { Sha256, Sha384, Sha512, Sha3_256 };

inline const char* hash_name(Hash h) {
    switch (h) {
        case Hash::Sha256: return "SHA256";
        case Hash::Sha384: return "SHA384";
        case Hash::Sha512: return "SHA512";
        case Hash::Sha3_256: return "SHA3-256";
    }
    return "SHA256";
}
inline std::size_t hash_bytes(Hash h) { return h == Hash::Sha256 || h == Hash::Sha3_256 ? 32 : h == Hash::Sha384 ? 48 : 64; }

class Digest {
public:
    [[nodiscard]] static Result<PublicBuffer> compute(Hash h, std::span<const uint8_t> msg) {
        if (auto r = require_ready(); r.is_err()) return Result<PublicBuffer>::err(r.error().message);
        detail::Md md{ EVP_MD_fetch(nullptr, hash_name(h), Provider::PROPERTIES) };
        detail::MdCtx ctx{ EVP_MD_CTX_new() };
        if (!md || !ctx) return Result<PublicBuffer>::err("fips: digest not available in approved mode");
        PublicBuffer out(hash_bytes(h));
        unsigned int len = 0;
        if (EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1 ||
            (!msg.empty() && EVP_DigestUpdate(ctx.get(), msg.data(), msg.size()) != 1) ||
            EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1 || len != out.size())
            return Result<PublicBuffer>::err("fips: digest failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }
};

/* HMAC */
class Hmac {
public:
    [[nodiscard]] static Result<SecureBuffer>
    compute(Hash h, std::span<const uint8_t> key, std::span<const uint8_t> msg) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        if (key.size() < 14) return Result<SecureBuffer>::err("fips: HMAC keys below 112 bits are not approved");
        detail::Mac mac{ EVP_MAC_fetch(nullptr, "HMAC", Provider::PROPERTIES) };
        if (!mac) return Result<SecureBuffer>::err("fips: HMAC not available in approved mode");
        detail::MacCtx ctx{ EVP_MAC_CTX_new(mac.get()) };
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, detail::mutable_name(hash_name(h)), 0),
            OSSL_PARAM_END
        };
        SecureBuffer out(hash_bytes(h));
        std::size_t len = 0;
        if (!ctx || EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1 ||
            (!msg.empty() && EVP_MAC_update(ctx.get(), msg.data(), msg.size()) != 1) ||
            EVP_MAC_final(ctx.get(), out.data(), &len, out.size()) != 1 || len != out.size())
            return Result<SecureBuffer>::err("fips: HMAC failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static bool verify(Hash h, std::span<const uint8_t> key, std::span<const uint8_t> msg,
                                     std::span<const uint8_t> tag) {
        auto t = compute(h, key, msg);
        if (t.is_err() || t.value().size() != tag.size()) return false;
        return CRYPTO_memcmp(t.value().data(), tag.data(), tag.size()) == 0;
    }
};

/* HKDF (SP 800-56C rev 2 KDA) */
class Hkdf {
public:
    enum class Mode { ExtractAndExpand, ExtractOnly, ExpandOnly };

    [[nodiscard]] static Result<SecureBuffer>
    derive(Hash h, std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
           std::span<const uint8_t> info, std::size_t out_len, Mode mode = Mode::ExtractAndExpand) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        if (out_len == 0) return Result<SecureBuffer>::err("fips: HKDF output length must be positive");
        detail::Kdf kdf{ EVP_KDF_fetch(nullptr, "HKDF", Provider::PROPERTIES) };
        if (!kdf) return Result<SecureBuffer>::err("fips: HKDF not available in approved mode");
        detail::KdfCtx ctx{ EVP_KDF_CTX_new(kdf.get()) };
        int m = mode == Mode::ExtractOnly ? EVP_KDF_HKDF_MODE_EXTRACT_ONLY
              : mode == Mode::ExpandOnly ? EVP_KDF_HKDF_MODE_EXPAND_ONLY : EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        std::vector<OSSL_PARAM> params;
        params.push_back(OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, detail::mutable_name(hash_name(h)), 0));
        params.push_back(OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &m));
        params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size()));
        if (!salt.empty()) params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size()));
        if (!info.empty()) params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size()));
        params.push_back(OSSL_PARAM_construct_end());
        SecureBuffer out(mode == Mode::ExtractOnly ? hash_bytes(h) : out_len);
        if (!ctx || EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) != 1)
            return Result<SecureBuffer>::err("fips: HKDF failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

/* PBKDF2 (SP 800-132) */
class Pbkdf2 {
public:
    static constexpr std::size_t MIN_SALT_BYTES = 16;
    static constexpr unsigned MIN_ITERATIONS = 1000;
    static constexpr unsigned DEFAULT_ITERATIONS = 600000;

    /// The provider enforces the SP 800-132 bounds (salt, iterations, key
    /// length) in approved mode; the checks here only give clearer errors.
    [[nodiscard]] static Result<SecureBuffer>
    derive(Hash h, std::span<const uint8_t> password, std::span<const uint8_t> salt,
           unsigned iterations, std::size_t out_len) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        if (salt.size() < MIN_SALT_BYTES) return Result<SecureBuffer>::err("fips: PBKDF2 salt must be at least 16 bytes");
        if (iterations < MIN_ITERATIONS) return Result<SecureBuffer>::err("fips: PBKDF2 needs at least 1000 iterations");
        if (out_len < 14) return Result<SecureBuffer>::err("fips: PBKDF2 keys below 112 bits are not approved");
        detail::Kdf kdf{ EVP_KDF_fetch(nullptr, "PBKDF2", Provider::PROPERTIES) };
        if (!kdf) return Result<SecureBuffer>::err("fips: PBKDF2 not available in approved mode");
        detail::KdfCtx ctx{ EVP_KDF_CTX_new(kdf.get()) };
        unsigned iter = iterations;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, detail::mutable_name(hash_name(h)), 0),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<uint8_t*>(password.data()), password.size()),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size()),
            OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter),
            OSSL_PARAM_construct_end()
        };
        SecureBuffer out(out_len);
        if (!ctx || EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1)
            return Result<SecureBuffer>::err("fips: PBKDF2 failed (the module rejects weak parameters)");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

/* Randomness: the module's CTR_DRBG */
class Random {
public:
    [[nodiscard]] static Result<SecureBuffer> bytes(std::size_t n) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        SecureBuffer out(n);
        if (n > 0 && RAND_bytes_ex(nullptr, out.data(), n, 0) != 1)
            return Result<SecureBuffer>::err("fips: DRBG failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

/* AES-256-GCM */
/// Wire: iv(12) | ciphertext | tag(16). The IV comes from the module (SP
/// 800-38D 8.2.1 internal generation), never from the caller.
class Aes256Gcm {
public:
    static constexpr std::size_t KEY_BYTES = 32, IV_BYTES = 12, TAG_BYTES = 16;

    [[nodiscard]] static Result<PublicBuffer>
    encrypt(std::span<const uint8_t> key, std::span<const uint8_t> plaintext, std::span<const uint8_t> aad = {}) {
        if (auto r = require_ready(); r.is_err()) return Result<PublicBuffer>::err(r.error().message);
        if (key.size() != KEY_BYTES) return Result<PublicBuffer>::err("fips: AES-256-GCM key must be 32 bytes");
        if (!crypto::detail::fits_int(plaintext.size()) || !crypto::detail::fits_int(aad.size()))
            return Result<PublicBuffer>::err("fips: input too large");
        detail::Cipher cipher{ EVP_CIPHER_fetch(nullptr, "AES-256-GCM", Provider::PROPERTIES) };
        detail::CipherCtx ctx{ EVP_CIPHER_CTX_new() };
        if (!cipher || !ctx) return Result<PublicBuffer>::err("fips: AES-256-GCM not available in approved mode");
        PublicBuffer out(IV_BYTES + plaintext.size() + TAG_BYTES);
        uint8_t* iv = out.data();
        uint8_t* ct = out.data() + IV_BYTES;
        int len = 0, fin = 0;
        /* SP 800-38D 8.2.2 construction inside the module: a 32-bit fixed
         * field and a 64-bit invocation field, both drawn from the provider
         * DRBG, on a context that is used for exactly one encryption. */
        uint8_t fixed[4];
        if (RAND_bytes_ex(nullptr, fixed, sizeof fixed, 0) != 1)
            return Result<PublicBuffer>::err("fips: DRBG unavailable");
        if (EVP_EncryptInit_ex2(ctx.get(), cipher.get(), key.data(), nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IV_FIXED, static_cast<int>(sizeof fixed), fixed) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_IV_GEN, static_cast<int>(IV_BYTES), iv) != 1)
            return Result<PublicBuffer>::err("fips: AES-256-GCM IV generation failed");
        if ((!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
            (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), ct, &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) ||
            EVP_EncryptFinal_ex(ctx.get(), ct + len, &fin) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(TAG_BYTES), ct + plaintext.size()) != 1)
            return Result<PublicBuffer>::err("fips: AES-256-GCM encryption failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> key, std::span<const uint8_t> wire, std::span<const uint8_t> aad = {}) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        if (key.size() != KEY_BYTES) return Result<SecureBuffer>::err("fips: AES-256-GCM key must be 32 bytes");
        if (wire.size() < IV_BYTES + TAG_BYTES) return Result<SecureBuffer>::err("fips: ciphertext too short");
        if (!crypto::detail::fits_int(wire.size()) || !crypto::detail::fits_int(aad.size()))
            return Result<SecureBuffer>::err("fips: input too large");
        detail::Cipher cipher{ EVP_CIPHER_fetch(nullptr, "AES-256-GCM", Provider::PROPERTIES) };
        detail::CipherCtx ctx{ EVP_CIPHER_CTX_new() };
        if (!cipher || !ctx) return Result<SecureBuffer>::err("fips: AES-256-GCM not available in approved mode");
        const std::size_t ct_len = wire.size() - IV_BYTES - TAG_BYTES;
        const uint8_t* iv = wire.data();
        const uint8_t* ct = wire.data() + IV_BYTES;
        uint8_t tag[TAG_BYTES];
        std::memcpy(tag, ct + ct_len, TAG_BYTES);
        SecureBuffer out(ct_len);
        int len = 0, fin = 0;
        if (EVP_DecryptInit_ex2(ctx.get(), cipher.get(), key.data(), iv, nullptr) != 1 ||
            (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
            (ct_len > 0 && EVP_DecryptUpdate(ctx.get(), out.data(), &len, ct, static_cast<int>(ct_len)) != 1) ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(TAG_BYTES), tag) != 1 ||
            EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1)
            return Result<SecureBuffer>::err("fips: AES-256-GCM authentication failed");
        return Result<SecureBuffer>::ok(std::move(out));
    }
};

/* P-256: ECDH (KAS-ECC-SSC) and ECDSA */
/// Public keys are the 65-byte uncompressed point; private keys the 32-byte
/// scalar; signatures DER-encoded ECDSA over SHA-256.
class P256 {
public:
    static constexpr std::size_t PUBLIC_BYTES = 65, PRIVATE_BYTES = 32, SHARED_BYTES = 32;
    struct KeyPair { PublicBuffer public_key; SecureBuffer private_key; };

    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        if (auto r = require_ready(); r.is_err()) return Result<KeyPair>::err(r.error().message);
        detail::Pkey key{ EVP_PKEY_Q_keygen(nullptr, Provider::PROPERTIES, "EC", "P-256") };
        if (!key) return Result<KeyPair>::err("fips: P-256 key generation failed");
        return export_pair(key.get());
    }

    [[nodiscard]] static Result<SecureBuffer>
    ecdh(std::span<const uint8_t> private_key, std::span<const uint8_t> peer_public) {
        if (auto r = require_ready(); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        auto mine = import_private(private_key);
        auto peer = import_public(peer_public);
        if (!mine || !peer) return Result<SecureBuffer>::err("fips: invalid P-256 key");
        detail::PkeyCtx ctx{ EVP_PKEY_CTX_new_from_pkey(nullptr, mine.get(), Provider::PROPERTIES) };
        std::size_t len = 0;
        if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1 ||
            EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1)
            return Result<SecureBuffer>::err("fips: ECDH failed");
        SecureBuffer out(len);
        if (EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1) return Result<SecureBuffer>::err("fips: ECDH failed");
        out.resize(len);
        return Result<SecureBuffer>::ok(std::move(out));
    }

    [[nodiscard]] static Result<PublicBuffer>
    sign(std::span<const uint8_t> private_key, std::span<const uint8_t> message) {
        if (auto r = require_ready(); r.is_err()) return Result<PublicBuffer>::err(r.error().message);
        auto key = import_private(private_key);
        if (!key) return Result<PublicBuffer>::err("fips: invalid P-256 private key");
        detail::MdCtx ctx{ EVP_MD_CTX_new() };
        std::size_t len = 0;
        if (!ctx || EVP_DigestSignInit_ex(ctx.get(), nullptr, "SHA256", nullptr, Provider::PROPERTIES, key.get(), nullptr) != 1 ||
            EVP_DigestSign(ctx.get(), nullptr, &len, message.data(), message.size()) != 1)
            return Result<PublicBuffer>::err("fips: ECDSA signing failed");
        PublicBuffer sig(len);
        if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1)
            return Result<PublicBuffer>::err("fips: ECDSA signing failed");
        sig.resize(len);
        return Result<PublicBuffer>::ok(std::move(sig));
    }

    [[nodiscard]] static bool
    verify(std::span<const uint8_t> public_key, std::span<const uint8_t> message, std::span<const uint8_t> signature) {
        if (!Provider::is_ready()) return false;
        auto key = import_public(public_key);
        if (!key) return false;
        detail::MdCtx ctx{ EVP_MD_CTX_new() };
        if (!ctx || EVP_DigestVerifyInit_ex(ctx.get(), nullptr, "SHA256", nullptr, Provider::PROPERTIES, key.get(), nullptr) != 1)
            return false;
        return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
    }

    /// The public point of a 32-byte private scalar. The provider does not
    /// derive a public key from a private one, so this scalar multiplication
    /// runs in libcrypto outside the validated boundary; a strict deployment
    /// keeps the public key the module exported at generation and never
    /// needs this call. Every keyed service (keygen, ECDH, ECDSA) stays in
    /// the module.
    [[nodiscard]] static Result<PublicBuffer> public_key_of(std::span<const uint8_t> private_key) {
        if (private_key.size() != PRIVATE_BYTES) return Result<PublicBuffer>::err("fips: P-256 private key must be 32 bytes");
        detail::Bn d{ BN_bin2bn(private_key.data(), static_cast<int>(private_key.size()), nullptr) };
        detail::EcGroup group{ EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1) };
        if (!d || !group) return Result<PublicBuffer>::err("fips: P-256 group unavailable");
        if (BN_is_zero(d.get()) || BN_cmp(d.get(), EC_GROUP_get0_order(group.get())) >= 0)
            return Result<PublicBuffer>::err("fips: P-256 private key out of range");
        detail::EcPoint q{ EC_POINT_new(group.get()) };
        if (!q || EC_POINT_mul(group.get(), q.get(), d.get(), nullptr, nullptr, nullptr) != 1)
            return Result<PublicBuffer>::err("fips: P-256 public key derivation failed");
        PublicBuffer out(PUBLIC_BYTES);
        if (EC_POINT_point2oct(group.get(), q.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), PUBLIC_BYTES, nullptr) != PUBLIC_BYTES)
            return Result<PublicBuffer>::err("fips: P-256 public key derivation failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }

private:
    static Result<KeyPair> export_pair(EVP_PKEY* key) {
        KeyPair kp{ PublicBuffer(PUBLIC_BYTES), SecureBuffer(PRIVATE_BYTES) };
        std::size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, kp.public_key.data(), PUBLIC_BYTES, &len) != 1 || len != PUBLIC_BYTES)
            return Result<KeyPair>::err("fips: P-256 public key export failed");
        BIGNUM* raw = nullptr;
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &raw) != 1) return Result<KeyPair>::err("fips: P-256 private key export failed");
        detail::Bn d{ raw };
        if (BN_bn2binpad(d.get(), kp.private_key.data(), PRIVATE_BYTES) != static_cast<int>(PRIVATE_BYTES))
            return Result<KeyPair>::err("fips: P-256 private key export failed");
        return Result<KeyPair>::ok(std::move(kp));
    }

    static detail::Pkey import_public(std::span<const uint8_t> pub) {
        if (pub.size() != PUBLIC_BYTES || pub[0] != 0x04) return {};
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, detail::mutable_name("P-256"), 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t*>(pub.data()), pub.size()),
            OSSL_PARAM_END
        };
        return from_params(params, EVP_PKEY_PUBLIC_KEY);
    }

    static detail::Pkey import_private(std::span<const uint8_t> priv) {
        if (priv.size() != PRIVATE_BYTES) return {};
        detail::Bn d{ BN_bin2bn(priv.data(), static_cast<int>(priv.size()), nullptr) };
        if (!d) return {};
        detail::Pkey key;
        {
            OSSL_PARAM params[] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, detail::mutable_name("P-256"), 0),
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0),
                OSSL_PARAM_END
            };
            unsigned char dbuf[PRIVATE_BYTES];
            if (BN_bn2nativepad(d.get(), dbuf, PRIVATE_BYTES) != static_cast<int>(PRIVATE_BYTES)) return {};
            params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, dbuf, PRIVATE_BYTES);
            key = from_params(params, EVP_PKEY_KEYPAIR);
            OPENSSL_cleanse(dbuf, sizeof dbuf);
        }
        return key;
    }

    static detail::Pkey from_params(OSSL_PARAM* params, int selection) {
        detail::PkeyCtx ctx{ EVP_PKEY_CTX_new_from_name(nullptr, "EC", Provider::PROPERTIES) };
        EVP_PKEY* raw = nullptr;
        if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 || EVP_PKEY_fromdata(ctx.get(), &raw, selection, params) != 1) {
            if (raw) EVP_PKEY_free(raw);
            return {};
        }
        detail::Pkey key{ raw };
        if (selection == EVP_PKEY_PUBLIC_KEY) {
            detail::PkeyCtx check{ EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), Provider::PROPERTIES) };
            if (!check || EVP_PKEY_public_check(check.get()) != 1) return {};
        }
        return key;
    }
};

}
#endif
