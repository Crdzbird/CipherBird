#pragma once
/* SHA3-256 and SHAKE256 through OpenSSL EVP (FIPS 202). The library's own */
/* keccak.hpp implements the Ethereum padding, not the SHA-3 padding, so the */
/* standards-track KEMs take these from libcrypto. */
#ifdef CRYPTOLIB_HAS_OPENSSL
#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace crypto::detail {

struct MdCtxFree { void operator()(EVP_MD_CTX* c) const { if (c) EVP_MD_CTX_free(c); } };
struct MdFree    { void operator()(EVP_MD* m) const { if (m) EVP_MD_free(m); } };

/// SHA3-256 of the concatenation of `parts`. Returns false if libcrypto fails.
inline bool sha3_256(std::span<const std::span<const uint8_t>> parts, uint8_t out[32]) {
    std::unique_ptr<EVP_MD, MdFree> md{ EVP_MD_fetch(nullptr, "SHA3-256", nullptr) };
    std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx{ EVP_MD_CTX_new() };
    if (!md || !ctx || EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1) return false;
    for (auto part : parts)
        if (!part.empty() && EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) return false;
    unsigned int len = 0;
    return EVP_DigestFinal_ex(ctx.get(), out, &len) == 1 && len == 32;
}

/// SHAKE256(input, out_len bytes).
inline bool shake256(std::span<const uint8_t> input, uint8_t* out, std::size_t out_len) {
    std::unique_ptr<EVP_MD, MdFree> md{ EVP_MD_fetch(nullptr, "SHAKE256", nullptr) };
    std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx{ EVP_MD_CTX_new() };
    if (!md || !ctx || EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1) return false;
    if (!input.empty() && EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) return false;
    return EVP_DigestFinalXOF(ctx.get(), out, out_len) == 1;
}

}
#endif
