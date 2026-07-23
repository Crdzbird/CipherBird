// crypto::Bbs — BBS Signatures (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256),
// validated against the official fixtures (signature + selective-disclosure proof)
// plus end-to-end sign/verify and selective-disclosure round trips.
#include "test_framework.hpp"

#include <cryptolib/bbs.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Bbs;

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
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }

const char* PK = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c";
const char* SK = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc";
const char* HEADER = "11223344556677889900aabbccddeeff";
// The 10 messages used by the multi-message fixtures.
const char* MSGS[10] = {
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
};

struct Owned {
    std::vector<std::vector<uint8_t>> store;
    std::vector<std::span<const uint8_t>> spans;
};
Owned messages(std::size_t n) {
    Owned o;
    for (std::size_t i = 0; i < n; ++i) o.store.push_back(unhex(MSGS[i]));
    for (auto& v : o.store) o.spans.push_back(sp(v));
    return o;
}
} // namespace

// Fixture: signature001 (single message) + signature004 (10 messages).
TEST("bbs/kat/sign-verify") {
    auto sk = unhex(SK), pk = unhex(PK), header = unhex(HEADER);
    CHECK(vec(Bbs::sk_to_pk(sp(sk)).value()) == pk);

    auto m1 = messages(1);
    auto s1 = Bbs::sign(sp(sk), sp(pk), sp(header), m1.spans);
    REQUIRE(s1.is_ok());
    CHECK(vec(s1.value()) == unhex(
        "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525"
        "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb"
        "4c892340be5969920d0916067b4565a0"));
    CHECK(Bbs::verify(sp(pk), s1.value().span(), sp(header), m1.spans));

    auto m10 = messages(10);
    auto s10 = Bbs::sign(sp(sk), sp(pk), sp(header), m10.spans);
    REQUIRE(s10.is_ok());
    CHECK(vec(s10.value()) == unhex(
        "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146"
        "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36"
        "32078557b2ace7d44caed846e1a0a1e8"));
    CHECK(Bbs::verify(sp(pk), s10.value().span(), sp(header), m10.spans));

    // A tampered message must not verify.
    auto bad = m10;
    auto tampered = unhex(MSGS[0]); tampered[0] ^= 0x01;
    bad.spans[0] = sp(tampered);
    CHECK(!Bbs::verify(sp(pk), s10.value().span(), sp(header), bad.spans));
}

// Fixture: proof001 — single message revealed, deterministic mocked randomness.
TEST("bbs/kat/proof") {
    auto pk = unhex(PK), header = unhex(HEADER);
    auto ph = unhex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    auto sig = unhex(
        "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525"
        "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb"
        "4c892340be5969920d0916067b4565a0");
    auto m1 = messages(1);
    std::vector<std::size_t> disclosed{0};

    // Mocked random scalars from the fixture trace (r1, r2, e~, r1~, r3~).
    auto r1  = unhex("60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337");
    auto r2  = unhex("2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811");
    auto et  = unhex("6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd");
    auto r1t = unhex("0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8");
    auto r3t = unhex("639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1");
    std::vector<std::span<const uint8_t>> rs{ sp(r1), sp(r2), sp(et), sp(r1t), sp(r3t) };

    auto proof = Bbs::proof_gen_deterministic(sp(pk), sp(sig), sp(header), sp(ph), m1.spans, disclosed, rs);
    REQUIRE(proof.is_ok());
    CHECK(vec(proof.value()) == unhex(
        "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104"
        "ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825"
        "788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aad"
        "aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32"
        "c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f"
        "94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf2"
        "9417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e"
        "940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d45"
        "5feeb04426193c57086c9b6d397d9418"));
    CHECK(Bbs::proof_verify(sp(pk), proof.value().span(), sp(header), sp(ph), m1.spans, disclosed));
}

// End-to-end selective disclosure with fresh randomness.
TEST("bbs/e2e/selective-disclosure") {
    auto km = unhex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
    auto kp = Bbs::keygen(sp(km));
    REQUIRE(kp.is_ok());
    auto header = unhex(HEADER);
    auto ph = unhex("aabbcc");
    auto m10 = messages(10);
    auto sig = Bbs::sign(kp.value().secret_key.span(), kp.value().public_key.span(), sp(header), m10.spans);
    REQUIRE(sig.is_ok());
    CHECK(Bbs::verify(kp.value().public_key.span(), sig.value().span(), sp(header), m10.spans));

    std::vector<std::size_t> disclosed{0, 3, 7};
    auto proof = Bbs::proof_gen(kp.value().public_key.span(), sig.value().span(), sp(header), sp(ph), m10.spans, disclosed);
    REQUIRE(proof.is_ok());

    std::vector<std::span<const uint8_t>> revealed{ m10.spans[0], m10.spans[3], m10.spans[7] };
    CHECK(Bbs::proof_verify(kp.value().public_key.span(), proof.value().span(), sp(header), sp(ph), revealed, disclosed));

    // A different presentation header must fail.
    auto ph2 = unhex("ddeeff");
    CHECK(!Bbs::proof_verify(kp.value().public_key.span(), proof.value().span(), sp(header), sp(ph2), revealed, disclosed));

    // A wrong revealed message must fail.
    auto wrong = unhex(MSGS[3]); wrong[0] ^= 0x01;
    std::vector<std::span<const uint8_t>> rev2{ m10.spans[0], sp(wrong), m10.spans[7] };
    CHECK(!Bbs::proof_verify(kp.value().public_key.span(), proof.value().span(), sp(header), sp(ph), rev2, disclosed));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_bbs() {
    RUN("bbs/kat/sign-verify");
    RUN("bbs/kat/proof");
    RUN("bbs/e2e/selective-disclosure");
}
