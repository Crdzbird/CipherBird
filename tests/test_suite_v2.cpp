#include "test_framework.hpp"
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include <cstdint>
#include <utility>
#include <string>
#include <vector>

using namespace test;
using crypto::Suite2;
using crypto::pq::HybridSig;
using crypto::pq::XWing;

namespace {
std::vector<uint8_t> bytes(std::span<const uint8_t> s) { return { s.begin(), s.end() }; }
std::vector<uint8_t> text(const char* s) { std::string t(s); return { t.begin(), t.end() }; }
}

TEST("suite_v2/xwing-round-trip-with-aad") {
    auto bob = std::move(XWing::generate_keypair().value());
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto env = Suite2::seal(text("wire 100 EUR"), bob.public_key.span(), alice.secret_key.span(), text("ctx"));
    REQUIRE(env.is_ok());
    CHECK(Suite2::suite_of(env.value().span()).value() == Suite2::SUITE_XWING_SIG);
    auto pt = Suite2::open(env.value().span(), bob.secret_key.span(), bob.public_key.span(),
                           alice.public_key.span(), text("ctx"));
    REQUIRE(pt.is_ok());
    CHECK(bytes(pt.value().span()) == text("wire 100 EUR"));
    CHECK(Suite2::open(env.value().span(), bob.secret_key.span(), bob.public_key.span(),
                       alice.public_key.span(), text("other")).is_err());
}

TEST("suite_v2/signature-binds-recipient") {
    auto bob = std::move(XWing::generate_keypair().value());
    auto carol = std::move(XWing::generate_keypair().value());
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto env = Suite2::seal(text("for bob only"), bob.public_key.span(), alice.secret_key.span()).value();
    auto opened = Suite2::open(env.span(), bob.secret_key.span(), bob.public_key.span(), alice.public_key.span());
    REQUIRE(opened.is_ok());
    auto bob_pt = bytes(opened.value().span());
    auto env_c = Suite2::seal(bob_pt, carol.public_key.span(), alice.secret_key.span()).value();
    CHECK(Suite2::open(env_c.span(), carol.secret_key.span(), carol.public_key.span(), alice.public_key.span()).is_ok());
    auto t_bob = Suite2::transcript(Suite2::SUITE_XWING_SIG, bob.public_key.span(), {}, {}, bob_pt);
    auto t_carol = Suite2::transcript(Suite2::SUITE_XWING_SIG, carol.public_key.span(), {}, {}, bob_pt);
    CHECK(t_bob != t_carol);
    CHECK(Suite2::open(env.span(), bob.secret_key.span(), carol.public_key.span(), alice.public_key.span()).is_err());
}

TEST("suite_v2/wrong-signer-and-tamper-rejected") {
    auto bob = std::move(XWing::generate_keypair().value());
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto mallory = std::move(HybridSig::generate_keypair().value());
    auto env = Suite2::seal(text("hello"), bob.public_key.span(), alice.secret_key.span()).value();
    CHECK(Suite2::open(env.span(), bob.secret_key.span(), bob.public_key.span(), mallory.public_key.span()).is_err());
    auto t = bytes(env.span());
    t[t.size() - 1] ^= 1;
    CHECK(Suite2::open(t, bob.secret_key.span(), bob.public_key.span(), alice.public_key.span()).is_err());
    t = bytes(env.span());
    t[9 + 7] ^= 1;
    CHECK(Suite2::open(t, bob.secret_key.span(), bob.public_key.span(), alice.public_key.span()).is_err());
    t = bytes(env.span());
    t[4] = 0x01;
    CHECK(Suite2::open(t, bob.secret_key.span(), bob.public_key.span(), alice.public_key.span()).is_err());
    CHECK(Suite2::open(std::vector<uint8_t>(5, 0), bob.secret_key.span(), bob.public_key.span(), alice.public_key.span()).is_err());
}

#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
TEST("suite_v2/native-hybrid-suite-round-trip") {
    auto bob = std::move(crypto::pq::HybridKem::generate_keypair().value());
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto env = Suite2::seal(text("native"), bob.public_key.span(), alice.secret_key.span(), {}, Suite2::SUITE_HYBRID_SIG);
    REQUIRE(env.is_ok());
    CHECK(Suite2::suite_of(env.value().span()).value() == Suite2::SUITE_HYBRID_SIG);
    auto pt = Suite2::open(env.value().span(), bob.secret_key.span(), bob.public_key.span(), alice.public_key.span());
    REQUIRE(pt.is_ok());
    CHECK(bytes(pt.value().span()) == text("native"));
}
#else
TEST("suite_v2/native-hybrid-suite-unavailable") {
    auto alice = std::move(HybridSig::generate_keypair().value());
    CHECK(Suite2::seal(text("x"), std::vector<uint8_t>(1216, 0), alice.secret_key.span(), {}, Suite2::SUITE_HYBRID_SIG).is_err());
}
#endif

void run_tests_suite_v2() {
    RUN("suite_v2/xwing-round-trip-with-aad");
    RUN("suite_v2/signature-binds-recipient");
    RUN("suite_v2/wrong-signer-and-tamper-rejected");
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    RUN("suite_v2/native-hybrid-suite-round-trip");
#else
    RUN("suite_v2/native-hybrid-suite-unavailable");
#endif
}
#else
void run_tests_suite_v2() {}
#endif
