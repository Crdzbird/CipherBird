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

// pvl draft §12.1.4.1 — BlindSignWithNym, no signer/committed messages (one
// hidden prover_nym → M=1). Signer adds J_M·signer_nym_entropy and binds
// length_nym_vector. Uses the pseudonym-suite api_id directly.
TEST("bbs_pseudonym/kat/blind-sign-with-nym") {
    auto sk = unhex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto commit = unhex(
        "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f"
        "27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae37"
        "2425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa"
        "30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a"
        "3ab54ec7fd0a8950dae339f396f2641b");
    auto entropy = unhex("3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5");
    auto sig = Bbs::blind_sign({sk.data(), sk.size()}, {pk.data(), pk.size()},
                               {commit.data(), commit.size()}, {header.data(), header.size()},
                               {}, Bbs::API_ID_PSEUDONYM,
                               {entropy.data(), entropy.size()}, /*length_nym_vector=*/1);
    CHECK(tohex({sig.data(), sig.size()}) ==
        "aabc3014c598f3cd8fcc162950ff9aa9ac93c0877d33d1cc0b71b31964e3b109"
        "715d5af307e580b498b0ec8c0b8f848028ba9d881be84bf405295f27f0213102"
        "8498c50c4fa3f6bb93483bf676ef1f1c");
}

// pvl §12.1.5.1 — pins the pseudonym-proof unified generator layout by
// reconstructing the domain (L=10 signer, M=5 committed, length_nym_vector=1).
TEST("bbs_pseudonym/kat/proof-domain") {
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto dom = Bbs::pseudonym_proof_domain_for_test({pk.data(), pk.size()},
                    {header.data(), header.size()}, /*L=*/10, /*M=*/5,
                    /*length_nym_vector=*/1, Bbs::API_ID_PSEUDONYM);
    CHECK(tohex({dom.data(), dom.size()}) ==
        "18a554af90e12ae7a81bd511901abfe1cf882387033796cc47df19b244a15894");
}

// pvl §12.1.5.1 — verify the OFFICIAL pseudonym-bound proof returns VALID
// (all committed + signer messages revealed; only the nym hidden). This is the
// byte-exact anchor for the whole verify path; a wrong-context proof must fail.
TEST("bbs_pseudonym/kat/proof-verify") {
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto ph = unhex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    auto ctx = unhex("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");
    auto nym = unhex("b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc3"
                     "4561848426aded0967e07fb333f79487");
    auto proof = unhex(
        "8b461b6d894ca153a2e1c05ac10c1bf21778b4ba08e9ca80949525afd86d533b"
        "f4b4f53ae3f7db67b9dcf55b5c4d3816b80b033b140c3bab14da11a54bb7afeb"
        "32c357cf6a1b73f100cbf1cb4e1c3fa1376a57d3be7e2f0395ec59b9e2c39c6b"
        "a744a214e5cec73752d3aa6ca1461cc38b4f69397282e8c9552b8f2add6e878f"
        "4edb8370003e141bacca3c3131bdbe016a02395e38459b716da68c90eedf33e1"
        "3d01684d271148dc05c11f934a11986c40664e63c3eddd2a7f84edac4b092dfa"
        "6eb0bc58b8ae5c44b7b4392b288e700f59c56be0674865eb7e89069c2f39fd0a"
        "2a61379d615db25d33473774ff72033304a8a62dbf5515d4475808a5f9fae605"
        "2f5031d741535af95294195a97e9f87336fa53bf566b1e88bc8987b6850b0f06"
        "fc7423d92910970ac6cf33a8a53d1fad10343839f7ad6c221366c10e96eb6794"
        "9f2bcfc83614232ee7a5f9f564fe2499");
    std::vector<std::vector<uint8_t>> msgs = {
        unhex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
        unhex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
        unhex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
        unhex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
        unhex("496694774c5604ab1b2544eababcf0f53278ff50"),
        unhex("515ae153e22aae04ad16f759e07237b4"),
        unhex("d183ddc6e2665aa4e2f088af"),
        unhex("ac55fb33a75909ed"),
        unhex("96012096"),
        {}, // signer message 9 (empty)
        unhex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
        unhex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
        unhex("835889a40744813a892eff9deb1edaeb"),
        unhex("e1ca9729410dc6ba"),
        {}, // committed message 4 (empty)
    };
    std::vector<std::span<const uint8_t>> dm;
    for (auto& m : msgs) dm.push_back({m.data(), m.size()});
    // Combined disclosed indexes: signer 0..9, committed j -> j+L+1 = 11..15.
    std::vector<std::size_t> di = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15};

    bool ok = Bbs::proof_verify_with_pseudonym(
        {pk.data(), pk.size()}, {proof.data(), proof.size()},
        {header.data(), header.size()}, {ph.data(), ph.size()},
        {ctx.data(), ctx.size()}, {nym.data(), nym.size()},
        /*L=*/10, /*length_nym_vector=*/1, dm, di, Bbs::API_ID_PSEUDONYM);
    CHECK(ok);

    // Wrong context_id → must fail.
    auto badctx = unhex("aaaa4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");
    bool bad = Bbs::proof_verify_with_pseudonym(
        {pk.data(), pk.size()}, {proof.data(), proof.size()},
        {header.data(), header.size()}, {ph.data(), ph.size()},
        {badctx.data(), badctx.size()}, {nym.data(), nym.size()},
        10, 1, dm, di, Bbs::API_ID_PSEUDONYM);
    CHECK(!bad);
}

// Full prover-flow round-trip: commit(prover_nym) -> blind-sign -> finalize ->
// CalculatePseudonym -> ProofGenWithPseudonym -> ProofVerifyWithPseudonym = VALID.
// (Byte-exact gen is impossible since the vectors hide prover_nym; the verifier
// being proven correct against the official proof makes this a reliable oracle.)
TEST("bbs_pseudonym/roundtrip/gen-verify") {
    auto sk = unhex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto ph  = unhex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    auto ctx = unhex("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");
    auto entropy = unhex("3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5");
    auto prover_nym = unhex("1234000000000000000000000000000000000000000000000000000000000000");
    constexpr std::string_view MOCK_DST =
        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_";
    const auto API = Bbs::API_ID_PSEUDONYM;

    auto sm0 = unhex("aa"), sm1 = unhex("bbbb");
    auto cm0 = unhex("cccccc"), cm1 = unhex("dd");
    std::vector<std::span<const uint8_t>> signer = {{sm0.data(), sm0.size()}, {sm1.data(), sm1.size()}};
    std::vector<std::span<const uint8_t>> committed = {{cm0.data(), cm0.size()}, {cm1.data(), cm1.size()}};
    std::vector<std::span<const uint8_t>> nyms = {{prover_nym.data(), prover_nym.size()}};

    auto commit = Bbs::commit_with_nym_for_test(committed, nyms, API, "3.141592653589793238462643383279", MOCK_DST);
    auto sig = Bbs::blind_sign({sk.data(), sk.size()}, {pk.data(), pk.size()},
                               {commit.commitment_with_proof.data(), commit.commitment_with_proof.size()},
                               {header.data(), header.size()}, signer, API,
                               {entropy.data(), entropy.size()}, /*length_nym_vector=*/1);
    auto nym_secrets_a = Bbs::finalize_nym_secrets(nyms, {entropy.data(), entropy.size()});
    std::vector<std::span<const uint8_t>> nym_secrets = {{nym_secrets_a[0].data(), nym_secrets_a[0].size()}};

    auto gen = Bbs::proof_gen_with_pseudonym(
        {pk.data(), pk.size()}, {sig.data(), sig.size()}, {header.data(), header.size()},
        {ph.data(), ph.size()}, {ctx.data(), ctx.size()}, signer, committed,
        {commit.secret_prover_blind.data(), commit.secret_prover_blind.size()}, nym_secrets,
        /*disclosed_signer=*/{0, 1}, /*disclosed_committed=*/{0, 1}, API);
    REQUIRE(gen.is_ok());
    auto& [proof, pseudonym] = gen.value();

    // The generated pseudonym equals CalculatePseudonym(ctx, nym_secrets).
    auto p2 = Bbs::calculate_pseudonym({ctx.data(), ctx.size()}, nym_secrets, API);
    CHECK(tohex({pseudonym.data(), pseudonym.size()}) == tohex({p2.data(), p2.size()}));

    // Verify: all signer + committed disclosed; combined indexes [0,1, 3,4].
    std::vector<std::span<const uint8_t>> dm = {
        {sm0.data(), sm0.size()}, {sm1.data(), sm1.size()}, {cm0.data(), cm0.size()}, {cm1.data(), cm1.size()}};
    std::vector<std::size_t> di = {0, 1, 3, 4};
    bool ok = Bbs::proof_verify_with_pseudonym(
        {pk.data(), pk.size()}, {proof.span().data(), proof.span().size()},
        {header.data(), header.size()}, {ph.data(), ph.size()}, {ctx.data(), ctx.size()},
        {pseudonym.data(), pseudonym.size()}, /*L=*/2, /*length_nym_vector=*/1, dm, di, API);
    CHECK(ok);
}

// draft §9.1.4.4 — standalone blind flow (no pseudonyms): multiple signer AND
// prover-committed messages. Byte-exact anchor for blind_sign-with-messages and
// VerifyBlindSign. 10 signer messages (trailing empty), 5 committed (trailing
// empty), a real secret_prover_blind.
TEST("bbs_pseudonym/kat/blind-sign-and-verify-full") {
    auto sk = unhex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    auto pk = unhex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28"
                    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f"
                    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    auto header = unhex("11223344556677889900aabbccddeeff");
    auto commit = unhex(
        "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cf"
        "e2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e"
        "82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885"
        "d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af"
        "8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5"
        "c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5d"
        "fff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928"
        "bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed"
        "3968b396a07f079b22b5bf2139e51a03");
    auto blind = unhex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");

    // 10 signer messages (last is empty).
    auto s0 = unhex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
    auto s1 = unhex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
    auto s2 = unhex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
    auto s3 = unhex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
    auto s4 = unhex("496694774c5604ab1b2544eababcf0f53278ff50");
    auto s5 = unhex("515ae153e22aae04ad16f759e07237b4");
    auto s6 = unhex("d183ddc6e2665aa4e2f088af");
    auto s7 = unhex("ac55fb33a75909ed");
    auto s8 = unhex("96012096");
    std::vector<uint8_t> s9;
    std::vector<std::span<const uint8_t>> signer = {
        {s0.data(), s0.size()}, {s1.data(), s1.size()}, {s2.data(), s2.size()},
        {s3.data(), s3.size()}, {s4.data(), s4.size()}, {s5.data(), s5.size()},
        {s6.data(), s6.size()}, {s7.data(), s7.size()}, {s8.data(), s8.size()},
        {s9.data(), s9.size()}};

    // 5 committed messages (last is empty).
    auto c0 = unhex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
    auto c1 = unhex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
    auto c2 = unhex("835889a40744813a892eff9deb1edaeb");
    auto c3 = unhex("e1ca9729410dc6ba");
    std::vector<uint8_t> c4;
    std::vector<std::span<const uint8_t>> committed = {
        {c0.data(), c0.size()}, {c1.data(), c1.size()}, {c2.data(), c2.size()},
        {c3.data(), c3.size()}, {c4.data(), c4.size()}};

    // blind_sign over the commitment + signer messages → the official signature.
    auto sig = Bbs::blind_sign({sk.data(), sk.size()}, {pk.data(), pk.size()},
                               {commit.data(), commit.size()}, {header.data(), header.size()},
                               signer, BASE_API_ID);
    CHECK(tohex({sig.data(), sig.size()}) ==
        "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c"
        "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc"
        "aa8feb7f3a236e92b2da38462358c48a");

    // VerifyBlindSign accepts; tampering the commitment or a message rejects.
    CHECK(Bbs::verify_blind_sign({pk.data(), pk.size()}, {sig.data(), sig.size()},
        {header.data(), header.size()}, signer, committed, {blind.data(), blind.size()}, BASE_API_ID));

    auto badblind = blind; badblind[0] ^= 1;
    CHECK(!Bbs::verify_blind_sign({pk.data(), pk.size()}, {sig.data(), sig.size()},
        {header.data(), header.size()}, signer, committed, {badblind.data(), badblind.size()}, BASE_API_ID));

    auto badc0 = c0; badc0[0] ^= 1;
    std::vector<std::span<const uint8_t>> badcommitted = committed;
    badcommitted[0] = {badc0.data(), badc0.size()};
    CHECK(!Bbs::verify_blind_sign({pk.data(), pk.size()}, {sig.data(), sig.size()},
        {header.data(), header.size()}, signer, badcommitted, {blind.data(), blind.size()}, BASE_API_ID));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_bbs_pseudonym() {
    RUN("bbs_pseudonym/kat/proof-domain");
    RUN("bbs_pseudonym/kat/proof-verify");
    RUN("bbs_pseudonym/roundtrip/gen-verify");
    RUN("bbs_pseudonym/kat/pseudonym-generators");
    RUN("bbs_pseudonym/kat/blind-generators");
    RUN("bbs_pseudonym/kat/commit-no-messages");
    RUN("bbs_pseudonym/kat/commit-multi-messages");
    RUN("bbs_pseudonym/kat/blind-sign-no-messages");
    RUN("bbs_pseudonym/kat/blind-sign-with-nym");
    RUN("bbs_pseudonym/kat/blind-sign-and-verify-full");
}
