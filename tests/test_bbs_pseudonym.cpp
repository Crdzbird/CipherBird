// crypto::Bbs pseudonym/blind extension — foundation KAT.
// Validates the PSEUDONYM_ and BLIND_..._PSEUDONYM_ ciphersuite GENERATORS
// byte-exact against draft-irtf-cfrg-bbs-per-verifier-linkability-02 §12.1.1 /
// §12.1.2. This proves the suite plumbing (api_id → seed/DST → generator
// sequence) before the ZK layers are built on top of it.
#include "test_framework.hpp"

#include <cryptolib/bbs.hpp>

#include <array>
#include <string>
#include <string_view>
#include <vector>

using crypto::Bbs;

namespace {
std::string tohex(std::span<const uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 0xF]); }
    return s;
}

// draft §12.1.1 — api_id "..._H2G_HM2S_PSEUDONYM_" generators (Q1, H_0..H_9).
const char* PSEUDO_Q1 = "a87fa55cfc29d0d0ef43b7816018c6162b9c4a5ddd5239ed24d9799f8e105c267d81ccb22f6379853c4070c28c71f13c";
const char* PSEUDO_H0 = "8c6de69580b83b7c6d773857ae64b4495955eb06e67ebc5855af89c72cd8d9bea9fd7f71eca20c6a3388dfa67b1e7ccf";
const char* PSEUDO_H1 = "aed1785c1c00d00893413e5011ecdc98706958a2ccf175be8a42afa56ef19c86ca6c14afe7e74a72596704fe34b6611d";
const char* PSEUDO_H9 = "a435ee46442dd320426a1eb163176154bb144a7f829900d0e14ec7c28d882572acc1b4f670ef7cf5b41a4bea2efae6c6";

// draft §12.1.2 — api_id "BLIND_..._PSEUDONYM_" blind generators (Q1, J_0..J_5).
const char* BLIND_Q1 = "a264ef107598f1caaeb323b65164bcea80e88814810efc61ea27412e879c7cb9344b1b513118d3cf5c79bfa81268ef36";
const char* BLIND_J0 = "8af923aaeaad46bf889049b2e5de19ff17778343114e589d716cde6eaa553c9e54fd6805afb244e445be2939ac789b35";
const char* BLIND_J5 = "8852ab63577b0a382df12320c5fc900bce57680d47e371ced873399bd9c5adc793ee890a919fb9c293e55acb4ab0312b";
} // namespace

TEST("bbs_pseudonym/kat/pseudonym-generators") {
    // 11 generators: index 0 = Q1, 1 = H_0, ... 10 = H_9.
    auto g = Bbs::generators_for_test(11, Bbs::API_ID_PSEUDONYM);
    REQUIRE(g.size() == 11);
    CHECK(tohex(g[0]) == PSEUDO_Q1);
    CHECK(tohex(g[1]) == PSEUDO_H0);
    CHECK(tohex(g[2]) == PSEUDO_H1);
    CHECK(tohex(g[10]) == PSEUDO_H9);
}

TEST("bbs_pseudonym/kat/blind-generators") {
    // 7 generators: index 0 = Q1, 1 = J_0, ... 6 = J_5.
    auto g = Bbs::generators_for_test(7, Bbs::API_ID_BLIND_PSEUDONYM);
    REQUIRE(g.size() == 7);
    CHECK(tohex(g[0]) == BLIND_Q1);
    CHECK(tohex(g[1]) == BLIND_J0);
    CHECK(tohex(g[6]) == BLIND_J5);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_bbs_pseudonym() {
    RUN("bbs_pseudonym/kat/pseudonym-generators");
    RUN("bbs_pseudonym/kat/blind-generators");
}
