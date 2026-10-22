#include "test_framework.hpp"
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include "vectors/xwing_draft11.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace test;
using crypto::pq::XWing;

namespace {
std::vector<uint8_t> unhex(const char* h) {
    std::string s(h);
    std::vector<uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(std::stoul(s.substr(2 * i, 2), nullptr, 16));
    return out;
}
std::vector<uint8_t> bytes(const crypto::SecureBuffer& b) { return { b.span().begin(), b.span().end() }; }
}

TEST("xwing/draft11-known-answer-vectors") {
    for (std::size_t i = 0; i < xwing_draft11::COUNT; ++i) {
        const auto& v = xwing_draft11::VECTORS[i];
        auto kp = XWing::keypair_from_seed(unhex(v.seed));
        REQUIRE(kp.is_ok());
        CHECK(bytes(kp.value().public_key) == unhex(v.pk));
        auto enc = XWing::encapsulate_derand(unhex(v.pk), unhex(v.eseed));
        REQUIRE(enc.is_ok());
        CHECK(bytes(enc.value().ciphertext) == unhex(v.ct));
        CHECK(bytes(enc.value().shared_secret) == unhex(v.ss));
        auto dec = XWing::decapsulate(unhex(v.ct), unhex(v.seed));
        REQUIRE(dec.is_ok());
        CHECK(bytes(dec.value()) == unhex(v.ss));
    }
}

TEST("xwing/round-trip-and-tamper") {
    auto kp = XWing::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == XWing::PK_BYTES);
    CHECK(kp.value().secret_key.size() == XWing::SEED_BYTES);
    auto enc = XWing::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    auto dec = XWing::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    REQUIRE(dec.is_ok());
    CHECK(bytes(dec.value()) == bytes(enc.value().shared_secret));
    auto forged = bytes(enc.value().ciphertext);
    forged[3] ^= 1;
    auto wrong = XWing::decapsulate(forged, kp.value().secret_key.span());
    REQUIRE(wrong.is_ok());
    CHECK(bytes(wrong.value()) != bytes(enc.value().shared_secret));
    forged = bytes(enc.value().ciphertext);
    forged[XWing::CT_M_BYTES + 5] ^= 1;
    wrong = XWing::decapsulate(forged, kp.value().secret_key.span());
    REQUIRE(wrong.is_ok());
    CHECK(bytes(wrong.value()) != bytes(enc.value().shared_secret));
    CHECK(XWing::decapsulate(std::vector<uint8_t>(10, 0), kp.value().secret_key.span()).is_err());
    CHECK(XWing::encapsulate(std::vector<uint8_t>(10, 0)).is_err());
}

void run_tests_xwing() {
    RUN("xwing/draft11-known-answer-vectors");
    RUN("xwing/round-trip-and-tamper");
}
#else
void run_tests_xwing() {}
#endif
