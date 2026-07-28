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

namespace {
std::vector<uint8_t> unhex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> o;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) o.push_back((nib(h[i]) << 4) | nib(h[i + 1]));
    return o;
}
// draft-irtf-cfrg-bbs-blind-signatures-02 §9. The blind Commit uses the blind
// INTERFACE api_id = ciphersuite_id || "BLIND_H2G_HM2S_" (generators then prepend
// another "BLIND_"); the mock-scalar dst uses the base ciphersuite.
constexpr std::string_view BASE_API_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";
constexpr std::string_view COMMIT_MOCK_SEED = "3.141592653589793238462643383279";
constexpr std::string_view COMMIT_MOCK_DST =
    "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_";
} // namespace

// draft §9.1.3.1 — CoreCommit with no committed messages.
TEST("bbs_pseudonym/kat/commit-no-messages") {
    auto out = Bbs::commit_deterministic_for_test({}, BASE_API_ID, COMMIT_MOCK_SEED, COMMIT_MOCK_DST);
    CHECK(tohex({out.data(), out.size()}) ==
        "849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef"
        "60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09"
        "ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf"
        "5306bcabf3e7cc95f5ba98cdd9bf3768");
}

// draft §9.1.3.2 — CoreCommit with 4 committed messages.
TEST("bbs_pseudonym/kat/commit-multi-messages") {
    auto m0 = unhex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
    auto m1 = unhex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
    auto m2 = unhex("835889a40744813a892eff9deb1edaeb");
    auto m3 = unhex("e1ca9729410dc6ba");
    std::vector<uint8_t> m4; // the fixture's trailing empty committed message
    std::vector<std::span<const uint8_t>> msgs = {
        {m0.data(), m0.size()}, {m1.data(), m1.size()}, {m2.data(), m2.size()},
        {m3.data(), m3.size()}, {m4.data(), m4.size()}};
    auto out = Bbs::commit_deterministic_for_test(msgs, BASE_API_ID, COMMIT_MOCK_SEED, COMMIT_MOCK_DST);
    CHECK(tohex({out.data(), out.size()}) ==
        "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cf"
        "e2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e"
        "82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885"
        "d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af"
        "8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5"
        "c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5d"
        "fff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928"
        "bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed"
        "3968b396a07f079b22b5bf2139e51a03");
}

// draft §9.1.4.1 — blind signature, no signer/committed messages.
TEST("bbs_pseudonym/kat/blind-sign-no-messages") {
    auto sk = unhex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto commit = unhex(
        "849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef"
        "60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09"
        "ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf"
        "5306bcabf3e7cc95f5ba98cdd9bf3768");
    auto sig = Bbs::blind_sign({sk.data(), sk.size()}, {pk.data(), pk.size()},
                               {commit.data(), commit.size()}, {header.data(), header.size()},
                               {}, BASE_API_ID);
    CHECK(tohex({sig.data(), sig.size()}) ==
        "ab54c35fb2af5c75d6368bc5772547e126d60a92205d011bb9ee5d1149432e91"
        "611fd376fe5b79d6ed7c2ba00a19b7434744945fd77bf02cd4628a6e5deeae50"
        "768116d55510251bb6a716a38340e184");
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_bbs_pseudonym() {
    RUN("bbs_pseudonym/kat/pseudonym-generators");
    RUN("bbs_pseudonym/kat/blind-generators");
    RUN("bbs_pseudonym/kat/commit-no-messages");
    RUN("bbs_pseudonym/kat/commit-multi-messages");
    RUN("bbs_pseudonym/kat/blind-sign-no-messages");
}
