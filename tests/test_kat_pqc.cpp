// Official post-quantum known-answer tests.
//
// Where the FIPS-203/204/205 *size* checks in test_kat.cpp only assert that our
// key/signature lengths match the standard, these run real NIST ACVP vectors
// through the actual code paths:
//
//   * ML-KEM-768   — decapsulation: Decaps(dk, c) must equal the reference K.
//   * ML-DSA-65    — sigVer: verify() must ACCEPT valid and REJECT tampered
//                    signatures, under the vector's domain-separation context.
//   * SLH-DSA-128f — sigVer: same, for the hash-based signature.
//
// A round-trip test only proves the library agrees with itself; these pin it to
// the standard and to an independent (liboqs-validated) reference, catching a
// wrong-but-self-consistent implementation, a truncation at the FFI boundary, or
// an upstream regression. Vectors live in vectors/pqc_kat_vectors.hpp (official,
// committed; regenerate with vectors/extract_pqc_kat.py).
#include "test_framework.hpp"

#include <cryptolib/pq.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#if defined(CRYPTOLIB_HAS_PQ)

#include "vectors/pqc_kat_vectors.hpp"

namespace {

std::vector<uint8_t> unhex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

bool same(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

// ── ML-KEM-768 decapsulation ──────────────────────────────────────────────
TEST("kat/ml-kem-768/decap/acvp") {
    using K = crypto::pq::MlKem;
    for (const auto& v : kat::pqc::ml_kem_768_decap) {
        const auto dk = unhex(v.dk_hex);
        const auto c  = unhex(v.c_hex);
        const auto k  = unhex(v.k_hex);
        auto ss = K::decapsulate(c, dk, K::Level::KEM_768);
        if (ss.is_err() || !same(ss.value().span(), k))
            std::fprintf(stderr, "    ML-KEM-768 decap tc=%d mismatch\n", v.tc);
        CHECK(ss.is_ok());
        CHECK(same(ss.value().span(), k));
    }
}

// ── ML-DSA-65 signature verification ──────────────────────────────────────
TEST("kat/ml-dsa-65/sigver/acvp") {
    using D = crypto::pq::MlDsa;
    for (const auto& v : kat::pqc::ml_dsa_65_sigver) {
        const auto pk  = unhex(v.pk_hex);
        const auto msg = unhex(v.msg_hex);
        const auto ctx = unhex(v.ctx_hex);
        const auto sig = unhex(v.sig_hex);
        const bool accepted =
            D::verify_with_context(msg, sig, ctx, pk, D::Level::DSA_65).is_ok();
        if (accepted != v.expect_valid)
            std::fprintf(stderr, "    ML-DSA-65 sigVer tc=%d: got %s, expected %s\n",
                         v.tc, accepted ? "accept" : "reject",
                         v.expect_valid ? "accept" : "reject");
        CHECK(accepted == v.expect_valid);
    }
}

// ── SLH-DSA-SHA2-128f signature verification ──────────────────────────────
TEST("kat/slh-dsa-128f/sigver/acvp") {
    using S = crypto::pq::SlhDsa;
    for (const auto& v : kat::pqc::slh_dsa_128f_sigver) {
        const auto pk  = unhex(v.pk_hex);
        const auto msg = unhex(v.msg_hex);
        const auto ctx = unhex(v.ctx_hex);
        const auto sig = unhex(v.sig_hex);
        const bool accepted =
            S::verify_with_context(msg, sig, ctx, pk,
                                   S::Level::L128f, S::HashFamily::SHA2).is_ok();
        if (accepted != v.expect_valid)
            std::fprintf(stderr, "    SLH-DSA-128f sigVer tc=%d: got %s, expected %s\n",
                         v.tc, accepted ? "accept" : "reject",
                         v.expect_valid ? "accept" : "reject");
        CHECK(accepted == v.expect_valid);
    }
}

#endif // CRYPTOLIB_HAS_PQ

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_kat_pqc() {
#if defined(CRYPTOLIB_HAS_PQ)
    RUN("kat/ml-kem-768/decap/acvp");
    RUN("kat/ml-dsa-65/sigver/acvp");
    RUN("kat/slh-dsa-128f/sigver/acvp");
#endif
}
