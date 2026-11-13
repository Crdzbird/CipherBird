/// P-256 (secp256r1, prime256v1) ECDSA with SHA-256: the ES256 of JWS
/// (RFC 7518) and the signature Apple push, WebCrypto and most hardware
/// tokens speak.
///
/// A thin wrapper over OpenSSL libcrypto: every curve operation (the scalar
/// multiplication that derives a public key, signing, verifying, the
/// on-curve check of a public point) runs in libcrypto through EVP and the
/// EC_GROUP and EC_POINT interfaces. This file only marshals buffers, checks
/// ranges against the group order and parses the fixed PKCS#8 shape.
///
/// Keys and signatures:
///   secret key  32 bytes, the scalar d big-endian, 1 <= d < n
///   public key  65 bytes, the uncompressed point 0x04 || X || Y
///   signature   64 bytes, r || s big-endian (IEEE P1363, the JWS form)
///
/// Nonces are deterministic (RFC 6979) wherever the linked libcrypto offers
/// them (OpenSSL 3.2 and later), so signing draws no randomness and the
/// RFC 6979 A.2.5 answers are reproduced exactly. With an older libcrypto
/// the nonce is libcrypto's own, which mixes the private key and the digest
/// into its random draw; DETERMINISTIC_NONCES says which one was compiled.
///
/// High-s signatures are produced and accepted: neither FIPS 186-5 nor JWS
/// normalises s, and Go, CryptoKit and WebCrypto emit both halves of the
/// range. A P-256 signature is therefore malleable ((r, n - s) verifies
/// too) and must never serve as a unique identifier. secp256k1 in this
/// library is different because the EVM and Bitcoin rules require low-s.
///
/// Guarded by CRYPTOLIB_HAS_P256: set when OpenSSL is linked and was built
/// with EC and ECDSA. The trimmed libcrypto of the shipped mobile and web
/// engines is configured no-ec, so the class is absent there and the C ABI
/// reports the feature unavailable.
#pragma once

#ifdef CRYPTOLIB_HAS_OPENSSL
#include <openssl/opensslconf.h>
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#define CRYPTOLIB_HAS_P256 1
#endif
#endif

#ifdef CRYPTOLIB_HAS_P256

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <sodium.h>

#include "types.hpp"

namespace crypto::ec {

struct P256KeyPair {
    PublicBuffer public_key;
    SecureBuffer secret_key;
};

namespace p256_detail {

struct BnFree { void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); } };
struct GroupFree { void operator()(EC_GROUP* p) const noexcept { EC_GROUP_free(p); } };
struct PointFree { void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); } };
struct PkeyFree { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct MdCtxFree { void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); } };
struct SigFree { void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); } };
using Bn = std::unique_ptr<BIGNUM, BnFree>;
using Group = std::unique_ptr<EC_GROUP, GroupFree>;
using Point = std::unique_ptr<EC_POINT, PointFree>;
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;
using Sig = std::unique_ptr<ECDSA_SIG, SigFree>;

/// The group order n of P-256 (FIPS 186-5, SP 800-186), big-endian.
inline constexpr uint8_t ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

/// DER of id-ecPublicKey (1.2.840.10045.2.1) and prime256v1
/// (1.2.840.10045.3.1.7), contents only.
inline constexpr uint8_t OID_EC_PUBLIC_KEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
inline constexpr uint8_t OID_PRIME256V1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

/// 1 <= v < n for a 32-byte big-endian v, in constant time.
inline bool in_scalar_range(const uint8_t* v) noexcept {
    unsigned borrow = 0;
    for (int i = 31; i >= 0; --i) {
        const unsigned diff = static_cast<unsigned>(v[i]) - static_cast<unsigned>(ORDER[i]) - borrow;
        borrow = (diff >> 8) & 1u;
    }
    const unsigned nonzero = sodium_is_zero(v, 32) ? 0u : 1u;
    return (borrow & nonzero) == 1u;
}

/// One DER element: its contents, with the reader advanced past it.
struct Der {
    const uint8_t* p;
    std::size_t n;
};

/// Reads one element with the given tag from in: definite length in its
/// shortest form, at most two length bytes, wholly inside in.
inline bool der_take(Der& in, uint8_t tag, Der& out) noexcept {
    if (in.n < 2 || in.p[0] != tag) return false;
    std::size_t len = in.p[1];
    std::size_t header = 2;
    if (len & 0x80u) {
        const std::size_t k = len & 0x7Fu;
        if (k == 0 || k > 2 || in.n < 2 + k) return false;
        len = 0;
        for (std::size_t i = 0; i < k; ++i) len = (len << 8) | in.p[2 + i];
        if (len < 0x80u || (k == 2 && len < 0x100u)) return false;
        header = 2 + k;
    }
    if (in.n - header < len) return false;
    out = Der{in.p + header, len};
    in.p += header + len;
    in.n -= header + len;
    return true;
}

inline bool der_is(const Der& d, const uint8_t* want, std::size_t want_len) noexcept {
    return d.n == want_len && std::memcmp(d.p, want, want_len) == 0;
}

inline bool is_space(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

inline bool is_base64_text(char c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' ||
           c == '=' || is_space(c);
}

}

class P256 {
public:
    static constexpr std::size_t SECRET_KEY_BYTES = 32;
    static constexpr std::size_t PUBLIC_KEY_BYTES = 65;
    static constexpr std::size_t SIGNATURE_BYTES = 64;
    /// The largest PKCS#8 input the importers read; a P-256 key is about
    /// 138 bytes of DER and 240 of PEM.
    static constexpr std::size_t MAX_PKCS8_BYTES = 4096;
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    static constexpr bool DETERMINISTIC_NONCES = true;
#else
    static constexpr bool DETERMINISTIC_NONCES = false;
#endif

    /// Whether libcrypto offers the curve at run time.
    [[nodiscard]] static bool available() noexcept {
        static const bool ok = [] {
            p256_detail::Group g{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
            return g != nullptr;
        }();
        return ok;
    }

    /// A fresh key pair: the scalar is drawn from libsodium's CSPRNG by
    /// rejection (FIPS 186-5 A.2.2) and the public point derived from it.
    [[nodiscard]] static Result<P256KeyPair> generate_keypair() {
        SecureBuffer sk(SECRET_KEY_BYTES);
        do {
            randombytes_buf(sk.data(), SECRET_KEY_BYTES);
        } while (!p256_detail::in_scalar_range(sk.data()));
        auto pk = derive(sk.data());
        if (pk.is_err()) return Result<P256KeyPair>::err(pk.error().message);
        return Result<P256KeyPair>::ok(P256KeyPair{std::move(pk.value()), std::move(sk)});
    }

    /// The 65-byte public key of a 32-byte secret key.
    [[nodiscard]] static Result<PublicBuffer> public_key(std::span<const uint8_t> secret_key) {
        if (secret_key.size() != SECRET_KEY_BYTES) return Result<PublicBuffer>::err("p256: secret key must be 32 bytes");
        if (!p256_detail::in_scalar_range(secret_key.data()))
            return Result<PublicBuffer>::err("p256: secret key out of range");
        return derive(secret_key.data());
    }

    /// ECDSA over SHA-256(message): the 64-byte r || s.
    [[nodiscard]] static Result<PublicBuffer> sign(std::span<const uint8_t> secret_key,
                                                   std::span<const uint8_t> message) {
        if (secret_key.size() != SECRET_KEY_BYTES) return Result<PublicBuffer>::err("p256: secret key must be 32 bytes");
        if (!p256_detail::in_scalar_range(secret_key.data()))
            return Result<PublicBuffer>::err("p256: secret key out of range");
        p256_detail::Pkey key = import_secret(secret_key.data());
        p256_detail::MdCtx ctx{EVP_MD_CTX_new()};
        EVP_PKEY_CTX* pctx = nullptr;
        if (!key || !ctx ||
            EVP_DigestSignInit_ex(ctx.get(), &pctx, "SHA256", nullptr, nullptr, key.get(), nullptr) != 1)
            return Result<PublicBuffer>::err("p256: signing failed");
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
        unsigned int nonce_type = 1;
        OSSL_PARAM nonce[] = {OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
                              OSSL_PARAM_construct_end()};
        if (EVP_PKEY_CTX_set_params(pctx, nonce) != 1)
            return Result<PublicBuffer>::err("p256: deterministic nonces are unavailable");
#endif
        static const uint8_t EMPTY = 0;
        const uint8_t* msg = message.empty() ? &EMPTY : message.data();
        unsigned char der[MAX_DER_SIGNATURE];
        std::size_t der_len = sizeof der;
        if (EVP_DigestSign(ctx.get(), der, &der_len, msg, message.size()) != 1)
            return Result<PublicBuffer>::err("p256: signing failed");
        const unsigned char* cursor = der;
        p256_detail::Sig sig{d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der_len))};
        PublicBuffer out(SIGNATURE_BYTES);
        if (!sig || cursor != der + der_len ||
            BN_bn2binpad(ECDSA_SIG_get0_r(sig.get()), out.data(), 32) != 32 ||
            BN_bn2binpad(ECDSA_SIG_get0_s(sig.get()), out.data() + 32, 32) != 32)
            return Result<PublicBuffer>::err("p256: signing failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }

    /// True only for a 64-byte signature with 1 <= r, s < n that verifies
    /// over SHA-256(message) under a 65-byte uncompressed public key whose
    /// point is on the curve. Both halves of the s range are accepted.
    [[nodiscard]] static bool verify(std::span<const uint8_t> public_key, std::span<const uint8_t> message,
                                     std::span<const uint8_t> signature) noexcept {
        try {
            if (signature.size() != SIGNATURE_BYTES || !p256_detail::in_scalar_range(signature.data()) ||
                !p256_detail::in_scalar_range(signature.data() + 32))
                return false;
            p256_detail::Pkey key = import_public(public_key);
            if (!key) return false;
            p256_detail::Bn r{BN_bin2bn(signature.data(), 32, nullptr)};
            p256_detail::Bn s{BN_bin2bn(signature.data() + 32, 32, nullptr)};
            p256_detail::Sig sig{ECDSA_SIG_new()};
            if (!r || !s || !sig || ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1) return false;
            (void)r.release();
            (void)s.release();
            unsigned char der[MAX_DER_SIGNATURE];
            const int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
            if (der_len <= 0 || der_len > static_cast<int>(sizeof der)) return false;
            unsigned char* cursor = der;
            if (i2d_ECDSA_SIG(sig.get(), &cursor) != der_len) return false;
            p256_detail::MdCtx ctx{EVP_MD_CTX_new()};
            if (!ctx ||
                EVP_DigestVerifyInit_ex(ctx.get(), nullptr, "SHA256", nullptr, nullptr, key.get(), nullptr) != 1)
                return false;
            static const uint8_t EMPTY = 0;
            const uint8_t* msg = message.empty() ? &EMPTY : message.data();
            return EVP_DigestVerify(ctx.get(), der, static_cast<std::size_t>(der_len), msg, message.size()) == 1;
        } catch (...) {
            return false;
        }
    }

    /// Whether public_key is a 65-byte uncompressed point on the curve with
    /// both coordinates below the field prime (SP 800-56A full validation,
    /// as libcrypto performs it).
    [[nodiscard]] static bool valid_public_key(std::span<const uint8_t> public_key) noexcept {
        try {
            return import_public(public_key) != nullptr;
        } catch (...) {
            return false;
        }
    }

    /// Imports an unencrypted PKCS#8 PrivateKeyInfo (RFC 5208) holding an
    /// ECPrivateKey (RFC 5915), DER. Refused: any trailing byte, a version
    /// other than 0, an algorithm other than id-ecPublicKey, a curve other
    /// than prime256v1 (in the algorithm or in the key's own parameters),
    /// attributes, an EncryptedPrivateKeyInfo, a scalar that is not exactly
    /// 32 bytes or not in 1..n-1, a public key that is not the uncompressed
    /// point of that scalar, and any indefinite or non-minimal length.
    [[nodiscard]] static Result<P256KeyPair> from_pkcs8_der(std::span<const uint8_t> der) {
        using namespace p256_detail;
        using R = Result<P256KeyPair>;
        if (der.empty() || der.size() > MAX_PKCS8_BYTES) return R::err("p256: PKCS#8 input has an unsupported size");
        Der all{der.data(), der.size()};
        Der info{};
        if (!der_take(all, 0x30, info) || all.n != 0) return R::err("p256: not a DER PKCS#8 PrivateKeyInfo");
        Der version{};
        if (!der_take(info, 0x02, version)) {
            Der probe = info;
            Der first{};
            if (der_take(probe, 0x30, first)) return R::err("p256: encrypted PKCS#8 is not supported");
            return R::err("p256: not a DER PKCS#8 PrivateKeyInfo");
        }
        static constexpr uint8_t V0[] = {0x00};
        if (!der_is(version, V0, 1)) return R::err("p256: unsupported PKCS#8 version");
        Der algorithm{}, oid{}, curve{};
        if (!der_take(info, 0x30, algorithm) || !der_take(algorithm, 0x06, oid))
            return R::err("p256: malformed PKCS#8 algorithm");
        if (!der_is(oid, OID_EC_PUBLIC_KEY, sizeof OID_EC_PUBLIC_KEY))
            return R::err("p256: the key algorithm is not id-ecPublicKey");
        if (!der_take(algorithm, 0x06, curve) || algorithm.n != 0 ||
            !der_is(curve, OID_PRIME256V1, sizeof OID_PRIME256V1))
            return R::err("p256: the curve is not P-256");
        Der wrapped{};
        if (!der_take(info, 0x04, wrapped)) return R::err("p256: malformed PKCS#8 private key");
        if (info.n != 0) return R::err("p256: PKCS#8 attributes are not supported");
        Der ec{}, ec_version{}, scalar{};
        if (!der_take(wrapped, 0x30, ec) || wrapped.n != 0 || !der_take(ec, 0x02, ec_version))
            return R::err("p256: malformed ECPrivateKey");
        static constexpr uint8_t V1[] = {0x01};
        if (!der_is(ec_version, V1, 1)) return R::err("p256: unsupported ECPrivateKey version");
        if (!der_take(ec, 0x04, scalar) || scalar.n != SECRET_KEY_BYTES)
            return R::err("p256: the private scalar must be 32 bytes");
        Der tagged{}, inner{};
        if (ec.n != 0 && ec.p[0] == 0xA0) {
            if (!der_take(ec, 0xA0, tagged) || !der_take(tagged, 0x06, inner) || tagged.n != 0 ||
                !der_is(inner, OID_PRIME256V1, sizeof OID_PRIME256V1))
                return R::err("p256: the curve is not P-256");
        }
        Der embedded{nullptr, 0};
        if (ec.n != 0) {
            if (!der_take(ec, 0xA1, tagged) || !der_take(tagged, 0x03, inner) || tagged.n != 0 || ec.n != 0)
                return R::err("p256: malformed ECPrivateKey");
            if (inner.n != 1 + PUBLIC_KEY_BYTES || inner.p[0] != 0x00 || inner.p[1] != 0x04)
                return R::err("p256: the embedded public key is not an uncompressed point");
            embedded = Der{inner.p + 1, PUBLIC_KEY_BYTES};
        }
        if (!in_scalar_range(scalar.p)) return R::err("p256: the private scalar is out of range");
        SecureBuffer sk(scalar.p, SECRET_KEY_BYTES);
        auto pk = derive(sk.data());
        if (pk.is_err()) return R::err(pk.error().message);
        if (embedded.p != nullptr && sodium_memcmp(embedded.p, pk.value().data(), PUBLIC_KEY_BYTES) != 0)
            return R::err("p256: the embedded public key does not match the private scalar");
        return R::ok(P256KeyPair{std::move(pk.value()), std::move(sk)});
    }

    /// from_pkcs8_der on one PEM block (RFC 7468) labelled PRIVATE KEY.
    /// Only whitespace may surround the block; the body is padded base64.
    /// ENCRYPTED PRIVATE KEY and EC PRIVATE KEY blocks are refused by name.
    [[nodiscard]] static Result<P256KeyPair> from_pkcs8_pem(std::span<const uint8_t> pem) {
        using namespace p256_detail;
        using R = Result<P256KeyPair>;
        if (pem.empty() || pem.size() > MAX_PKCS8_BYTES) return R::err("p256: PKCS#8 input has an unsupported size");
        std::string_view text(reinterpret_cast<const char*>(pem.data()), pem.size());
        while (!text.empty() && is_space(text.front())) text.remove_prefix(1);
        while (!text.empty() && is_space(text.back())) text.remove_suffix(1);
        static constexpr std::string_view BEGIN = "-----BEGIN PRIVATE KEY-----";
        static constexpr std::string_view END = "-----END PRIVATE KEY-----";
        if (text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
            return R::err("p256: encrypted PKCS#8 is not supported");
        if (text.starts_with("-----BEGIN EC PRIVATE KEY-----"))
            return R::err("p256: an EC PRIVATE KEY block is SEC 1, not PKCS#8");
        if (text.size() < BEGIN.size() + END.size() || !text.starts_with(BEGIN) || !text.ends_with(END))
            return R::err("p256: not a PKCS#8 PRIVATE KEY block");
        const std::string_view body = text.substr(BEGIN.size(), text.size() - BEGIN.size() - END.size());
        for (const char c : body) {
            if (!is_base64_text(c)) return R::err("p256: the PEM body is not base64");
        }
        SecureBuffer der(body.size() / 4 * 3 + 3);
        std::size_t der_len = 0;
        const char* stop = nullptr;
        if (sodium_base642bin(der.data(), der.size(), body.data(), body.size(), " \t\r\n", &der_len, &stop,
                              sodium_base64_VARIANT_ORIGINAL) != 0 ||
            stop != body.data() + body.size() || der_len == 0)
            return R::err("p256: the PEM body is not base64");
        return from_pkcs8_der(std::span<const uint8_t>(der.data(), der_len));
    }

private:
    /// The longest DER ECDSA signature of two 32-byte integers is 72 bytes.
    static constexpr std::size_t MAX_DER_SIGNATURE = 80;

    static Result<PublicBuffer> derive(const uint8_t* d32) {
        p256_detail::Bn d{BN_bin2bn(d32, 32, nullptr)};
        p256_detail::Group group{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
        if (!d || !group) return Result<PublicBuffer>::err("p256: the curve is unavailable");
        BN_set_flags(d.get(), BN_FLG_CONSTTIME);
        p256_detail::Point q{EC_POINT_new(group.get())};
        PublicBuffer out(PUBLIC_KEY_BYTES);
        if (!q || EC_POINT_mul(group.get(), q.get(), d.get(), nullptr, nullptr, nullptr) != 1 ||
            EC_POINT_point2oct(group.get(), q.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), PUBLIC_KEY_BYTES,
                               nullptr) != PUBLIC_KEY_BYTES)
            return Result<PublicBuffer>::err("p256: public key derivation failed");
        return Result<PublicBuffer>::ok(std::move(out));
    }

    static p256_detail::Pkey from_params(OSSL_PARAM* params, int selection) {
        p256_detail::PkeyCtx ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
        EVP_PKEY* raw = nullptr;
        if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
            EVP_PKEY_fromdata(ctx.get(), &raw, selection, params) != 1) {
            if (raw) EVP_PKEY_free(raw);
            return {};
        }
        return p256_detail::Pkey{raw};
    }

    static p256_detail::Pkey import_secret(const uint8_t* d32) {
        p256_detail::Bn d{BN_bin2bn(d32, 32, nullptr)};
        if (!d) return {};
        unsigned char native[SECRET_KEY_BYTES];
        p256_detail::Pkey key;
        if (BN_bn2nativepad(d.get(), native, SECRET_KEY_BYTES) == static_cast<int>(SECRET_KEY_BYTES)) {
            char group[] = "P-256";
            OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
                                   OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, native, SECRET_KEY_BYTES),
                                   OSSL_PARAM_construct_end()};
            key = from_params(params, EVP_PKEY_KEYPAIR);
        }
        OPENSSL_cleanse(native, sizeof native);
        return key;
    }

    static p256_detail::Pkey import_public(std::span<const uint8_t> pub) {
        if (pub.size() != PUBLIC_KEY_BYTES || pub[0] != 0x04) return {};
        char group[] = "P-256";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t*>(pub.data()), pub.size()),
            OSSL_PARAM_construct_end()};
        p256_detail::Pkey key = from_params(params, EVP_PKEY_PUBLIC_KEY);
        if (!key) return {};
        p256_detail::PkeyCtx check{EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr)};
        if (!check || EVP_PKEY_public_check(check.get()) != 1) return {};
        return key;
    }
};

}

#endif
