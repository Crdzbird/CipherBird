#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

using crypto::pq::HybridSig;
using crypto::pq::MlDsa;

static std::span<const uint8_t> sv(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

TEST("hybrid-sig/sizes") {
    auto sz = HybridSig::sizes();
    REQUIRE(sz.is_ok());
    auto md = MlDsa::sizes(MlDsa::Level::DSA_65);
    REQUIRE(md.is_ok());
    CHECK(sz.value().public_key == 32 + md.value().public_key);
    CHECK(sz.value().secret_key == 64 + md.value().secret_key);
    CHECK(sz.value().signature == 64 + md.value().signature);

    auto kp = HybridSig::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == sz.value().public_key);
    CHECK(kp.value().secret_key.size() == sz.value().secret_key);
}

TEST("hybrid-sig/sign-verify-round-trip") {
    auto kp = HybridSig::generate_keypair();
    REQUIRE(kp.is_ok());
    auto sig = HybridSig::sign(sv("hybrid signed message"), kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    auto ok = HybridSig::verify(sv("hybrid signed message"), sig.value().span(),
                                kp.value().public_key.span());
    CHECK(ok.is_ok());
}

TEST("hybrid-sig/tampered-message-rejected") {
    auto kp = HybridSig::generate_keypair();
    auto sig = HybridSig::sign(sv("original"), kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    auto bad = HybridSig::verify(sv("tampered"), sig.value().span(), kp.value().public_key.span());
    CHECK(bad.is_err());
}

TEST("hybrid-sig/wrong-public-key-rejected") {
    auto kp1 = HybridSig::generate_keypair();
    auto kp2 = HybridSig::generate_keypair();
    auto sig = HybridSig::sign(sv("msg"), kp1.value().secret_key.span());
    REQUIRE(sig.is_ok());
    auto bad = HybridSig::verify(sv("msg"), sig.value().span(), kp2.value().public_key.span());
    CHECK(bad.is_err());
}

TEST("hybrid-sig/both-components-required") {
    // Flipping a byte in the Ed25519 half (first 64) OR the ML-DSA half must fail.
    auto kp = HybridSig::generate_keypair();
    auto sig = HybridSig::sign(sv("msg"), kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    std::vector<uint8_t> edBad(sig.value().span().begin(), sig.value().span().end());
    edBad[0] ^= 0x01;  // Ed25519 half
    CHECK(HybridSig::verify(sv("msg"), edBad, kp.value().public_key.span()).is_err());

    std::vector<uint8_t> mdBad(sig.value().span().begin(), sig.value().span().end());
    mdBad[100] ^= 0x01;  // ML-DSA half (past byte 64)
    CHECK(HybridSig::verify(sv("msg"), mdBad, kp.value().public_key.span()).is_err());
}

TEST("hybrid-sig/bad-lengths-rejected") {
    auto kp = HybridSig::generate_keypair();
    std::vector<uint8_t> shortSig(32, 0);
    CHECK(HybridSig::verify(sv("m"), shortSig, kp.value().public_key.span()).is_err());
    std::vector<uint8_t> shortKey(16, 0);
    CHECK(HybridSig::sign(sv("m"), shortKey).is_err());
}

void run_tests_hybrid_sig() {
    RUN("hybrid-sig/sizes");
    RUN("hybrid-sig/sign-verify-round-trip");
    RUN("hybrid-sig/tampered-message-rejected");
    RUN("hybrid-sig/wrong-public-key-rejected");
    RUN("hybrid-sig/both-components-required");
    RUN("hybrid-sig/bad-lengths-rejected");
}

#else
void run_tests_hybrid_sig() {}
#endif
