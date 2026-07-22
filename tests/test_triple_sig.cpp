#include "test_framework.hpp"
#include <cstring>
#include <vector>
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

using crypto::pq::TripleSig;

// ─── Ed25519 + ML-DSA-65 + SLH-DSA triple signature tests ───────────────────
// Verifies only if all three verify → unforgeable while ANY one stands.

namespace {
std::vector<uint8_t> msg(const char* s) {
    return { reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s) + std::strlen(s) };
}
}

TEST("triplesig/sizes") {
    auto sz = TripleSig::sizes();
    REQUIRE(sz.is_ok());
    // ed(32/64/64) + ML-DSA-65(1952/4032/3309) + SLH-DSA-128f(32/64/17088).
    CHECK(sz.value().public_key == 32 + 1952 + 32);
    CHECK(sz.value().secret_key == 64 + 4032 + 64);
    CHECK(sz.value().signature  == 64 + 3309 + 17088);
}

TEST("triplesig/sign-verify-round-trip") {
    auto kp = TripleSig::generate_keypair();
    REQUIRE(kp.is_ok());
    auto m = msg("transfer 100 to acct #42");
    auto sig = TripleSig::sign(m, kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK_OK(TripleSig::verify(m, sig.value().span(), kp.value().public_key.span()));
}

TEST("triplesig/tampered-message-rejected") {
    auto kp = TripleSig::generate_keypair();
    REQUIRE(kp.is_ok());
    auto m = msg("original");
    auto sig = TripleSig::sign(m, kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    auto m2 = msg("0riginal");
    CHECK_ERR(TripleSig::verify(m2, sig.value().span(), kp.value().public_key.span()));
}

TEST("triplesig/wrong-public-key-rejected") {
    auto kp = TripleSig::generate_keypair();
    auto other = TripleSig::generate_keypair();
    REQUIRE(kp.is_ok());
    REQUIRE(other.is_ok());
    auto m = msg("hi");
    auto sig = TripleSig::sign(m, kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK_ERR(TripleSig::verify(m, sig.value().span(), other.value().public_key.span()));
}

// Tamper each of the three signature legs — verification must fail (all-must-pass).
// Offsets: ed [0,64), mldsa [64, 3373), slhdsa [3373, end).
TEST("triplesig/tamper-each-leg-rejected") {
    auto kp = TripleSig::generate_keypair();
    REQUIRE(kp.is_ok());
    auto m = msg("resolution");
    auto sig = TripleSig::sign(m, kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    for (std::size_t off : {std::size_t{0}, std::size_t{100}, std::size_t{4000}}) {
        std::vector<uint8_t> s(sig.value().span().begin(), sig.value().span().end());
        s[off] ^= 0x01;
        CHECK_ERR(TripleSig::verify(m, s, kp.value().public_key.span()));
    }
}

TEST("triplesig/bad-lengths-rejected") {
    auto kp = TripleSig::generate_keypair();
    REQUIRE(kp.is_ok());
    auto m = msg("hi");
    std::vector<uint8_t> short_sk(16, 0x00);
    CHECK_ERR(TripleSig::sign(m, short_sk));
    std::vector<uint8_t> short_sig(16, 0x00);
    CHECK_ERR(TripleSig::verify(m, short_sig, kp.value().public_key.span()));
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_triple_sig() {
#ifdef CRYPTOLIB_HAS_PQ
    RUN("triplesig/sizes");
    RUN("triplesig/sign-verify-round-trip");
    RUN("triplesig/tampered-message-rejected");
    RUN("triplesig/wrong-public-key-rejected");
    RUN("triplesig/tamper-each-leg-rejected");
    RUN("triplesig/bad-lengths-rejected");
#endif
}
