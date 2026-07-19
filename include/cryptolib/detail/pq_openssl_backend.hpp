#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// OpenSSL EVP backend for the standardized post-quantum algorithms
// (ML-KEM / ML-DSA / SLH-DSA). Selected at build time with
// -DCRYPTOLIB_PQ_BACKEND_OPENSSL; otherwise pq.hpp uses liboqs.
//
// Why: OpenSSL's ML-KEM/ML-DSA/SLH-DSA (3.5+) are on the FIPS-validation track,
// whereas liboqs is explicitly NOT FIPS-validated and is where side-channel
// hardening still lags. The raw key/ciphertext/signature encodings produced and
// consumed here are byte-identical to liboqs/FIPS — verified against the NIST
// ACVP vectors in tests/test_kat_pqc.cpp — so this is a drop-in for the library's
// wire formats: envelopes, the C ABI, and every language binding are unaffected.
//
// liboqs stays linked for algorithms OpenSSL does not provide (e.g. HQC) and for
// size metadata (see pq.hpp sizes()).
//
// All functions return the same Result<T> the rest of pq.hpp uses and keep key
// material in SecureBuffer (auto-zeroed). No OpenSSL error string is surfaced —
// callers get a fixed message, so a decrypt/verify error never doubles as an
// oracle distinguishing failure modes.
// ─────────────────────────────────────────────────────────────────────────────

#include "../types.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

namespace crypto::pq::ossl_backend {

struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
struct CtxDeleter { void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); } };
using Ctx = std::unique_ptr<EVP_PKEY_CTX, CtxDeleter>;
struct MdCtxDeleter { void operator()(EVP_MD_CTX* m) const { EVP_MD_CTX_free(m); } };
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

using KeyPairBytes = std::pair<SecureBuffer, SecureBuffer>; // (public, private)
using KemOutput    = std::pair<SecureBuffer, SecureBuffer>; // (ciphertext, shared_secret)

// Import a raw key (FIPS octet-string encoding) as an EVP_PKEY.
// param_name is OSSL_PKEY_PARAM_PUB_KEY or OSSL_PKEY_PARAM_PRIV_KEY;
// selection is EVP_PKEY_PUBLIC_KEY or EVP_PKEY_KEYPAIR.
inline Pkey import_key(const char* alg, const char* param_name,
                       std::span<const uint8_t> raw, int selection) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(param_name, const_cast<uint8_t*>(raw.data()), raw.size()),
        OSSL_PARAM_END
    };
    Ctx ctx(EVP_PKEY_CTX_new_from_name(nullptr, alg, nullptr));
    if (!ctx) return {};
    EVP_PKEY* p = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &p, selection, params) != 1) {
        if (p) EVP_PKEY_free(p);
        return {};
    }
    return Pkey(p);
}

// A zero-length octet_string param still needs a non-NULL pointer, otherwise
// OpenSSL treats it as unset. This yields a valid pointer for an empty context.
inline OSSL_PARAM context_param(std::span<const uint8_t> ctx_str) {
    static const uint8_t empty = 0;
    const uint8_t* p = ctx_str.empty() ? &empty : ctx_str.data();
    return OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, const_cast<uint8_t*>(p), ctx_str.size());
}

inline Result<KeyPairBytes> keygen(const char* alg) {
    Pkey pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, alg));
    if (!pkey) return Result<KeyPairBytes>::err("PQ(OpenSSL): keypair generation failed");

    uint8_t pub[4096], priv[8192];
    std::size_t publen = 0, privlen = 0;
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof pub, &publen) != 1 ||
        EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv, sizeof priv, &privlen) != 1)
        return Result<KeyPairBytes>::err("PQ(OpenSSL): key export failed");

    SecureBuffer pk(publen), sk(privlen);
    std::copy(pub, pub + publen, pk.data());
    std::copy(priv, priv + privlen, sk.data());
    return Result<KeyPairBytes>::ok(KeyPairBytes{ std::move(pk), std::move(sk) });
}

inline Result<KemOutput> kem_encapsulate(const char* alg, std::span<const uint8_t> public_key) {
    Pkey pkey = import_key(alg, OSSL_PKEY_PARAM_PUB_KEY, public_key, EVP_PKEY_PUBLIC_KEY);
    if (!pkey) return Result<KemOutput>::err("ML-KEM(OpenSSL): invalid public key");

    Ctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    std::size_t ctlen = 0, sslen = 0;
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) != 1 ||
        EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctlen, nullptr, &sslen) != 1)
        return Result<KemOutput>::err("ML-KEM(OpenSSL): encapsulation failed");

    SecureBuffer ct(ctlen), ss(sslen);
    if (EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ctlen, ss.data(), &sslen) != 1)
        return Result<KemOutput>::err("ML-KEM(OpenSSL): encapsulation failed");
    ct.resize(ctlen);
    ss.resize(sslen);
    return Result<KemOutput>::ok(KemOutput{ std::move(ct), std::move(ss) });
}

inline Result<SecureBuffer> kem_decapsulate(const char* alg, std::span<const uint8_t> ciphertext,
                                            std::span<const uint8_t> secret_key) {
    Pkey pkey = import_key(alg, OSSL_PKEY_PARAM_PRIV_KEY, secret_key, EVP_PKEY_KEYPAIR);
    if (!pkey) return Result<SecureBuffer>::err("ML-KEM(OpenSSL): invalid secret key");

    Ctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    std::size_t sslen = 0;
    // ML-KEM has implicit rejection: decapsulation of a bad ciphertext still
    // succeeds and yields a pseudo-random secret. No branch distinguishes it.
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) != 1 ||
        EVP_PKEY_decapsulate(ctx.get(), nullptr, &sslen, ciphertext.data(), ciphertext.size()) != 1)
        return Result<SecureBuffer>::err("ML-KEM(OpenSSL): decapsulation failed");

    SecureBuffer ss(sslen);
    if (EVP_PKEY_decapsulate(ctx.get(), ss.data(), &sslen, ciphertext.data(), ciphertext.size()) != 1)
        return Result<SecureBuffer>::err("ML-KEM(OpenSSL): decapsulation failed");
    ss.resize(sslen);
    return Result<SecureBuffer>::ok(std::move(ss));
}

// Sign the pure external message with an optional domain-separation context.
inline Result<SecureBuffer> sig_sign(const char* alg, std::span<const uint8_t> message,
                                     std::span<const uint8_t> context,
                                     std::span<const uint8_t> secret_key) {
    Pkey pkey = import_key(alg, OSSL_PKEY_PARAM_PRIV_KEY, secret_key, EVP_PKEY_KEYPAIR);
    if (!pkey) return Result<SecureBuffer>::err("PQ-SIG(OpenSSL): invalid secret key");

    OSSL_PARAM params[] = { context_param(context), OSSL_PARAM_END };
    MdCtx mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestSignInit_ex(mctx.get(), nullptr, nullptr, nullptr, nullptr,
                                       pkey.get(), params) != 1)
        return Result<SecureBuffer>::err("PQ-SIG(OpenSSL): signing failed");

    std::size_t siglen = 0;
    if (EVP_DigestSign(mctx.get(), nullptr, &siglen, message.data(), message.size()) != 1)
        return Result<SecureBuffer>::err("PQ-SIG(OpenSSL): signing failed");
    SecureBuffer sig(siglen);
    if (EVP_DigestSign(mctx.get(), sig.data(), &siglen, message.data(), message.size()) != 1)
        return Result<SecureBuffer>::err("PQ-SIG(OpenSSL): signing failed");
    sig.resize(siglen);
    return Result<SecureBuffer>::ok(std::move(sig));
}

inline Result<void> sig_verify(const char* alg, std::span<const uint8_t> message,
                               std::span<const uint8_t> signature,
                               std::span<const uint8_t> context,
                               std::span<const uint8_t> public_key) {
    Pkey pkey = import_key(alg, OSSL_PKEY_PARAM_PUB_KEY, public_key, EVP_PKEY_PUBLIC_KEY);
    if (!pkey) return Result<void>::err("PQ-SIG(OpenSSL): invalid public key");

    OSSL_PARAM params[] = { context_param(context), OSSL_PARAM_END };
    MdCtx mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestVerifyInit_ex(mctx.get(), nullptr, nullptr, nullptr, nullptr,
                                         pkey.get(), params) != 1)
        return Result<void>::err("PQ-SIG(OpenSSL): signature verification failed");

    if (EVP_DigestVerify(mctx.get(), signature.data(), signature.size(),
                         message.data(), message.size()) != 1)
        return Result<void>::err("PQ-SIG(OpenSSL): signature verification failed");
    return Result<void>::ok();
}

} // namespace crypto::pq::ossl_backend
