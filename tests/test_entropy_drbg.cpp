// crypto::entropy::HmacDrbg — HMAC-DRBG SHA-512 (SP 800-90A), validated against
// a NIST CAVP vector (drbgvectors_no_reseed, SHA-512, PR=False), plus the
// MediaEntropy beacon.
#include "test_framework.hpp"
#include <filesystem>
#include <cstring>
using namespace test;

using crypto::entropy::HmacDrbg;

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
std::vector<uint8_t> vec(std::span<const uint8_t> b) { return {b.begin(), b.end()}; }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }
}

// NIST CAVP HMAC_DRBG, [SHA-512] [PredictionResistance = False], COUNT = 0.
TEST("drbg/kat/cavp-hmac-sha512") {
    auto entropy = unhex("35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15");
    auto nonce   = unhex("f7328760be6168e6aa9fb54784989a11");

    auto d = HmacDrbg::instantiate(sp(entropy), sp(nonce));
    REQUIRE(d.is_ok());
    auto& drbg = d.value();
    // State after instantiate.
    CHECK(vec(drbg.v_state())   == unhex("cea2f72b6eaccbe494f176730445951a4ca7f0fcdc3312e1619b462ebcfd5f126f23b42353404b881a9d052aa38c78031529cb88fee640cedb9b200fc5e0c1b3"));
    CHECK(vec(drbg.key_state()) == unhex("07a654ea4953145b57f1bdd037ddd6a7f4116feeeff9ce0812509b2f60e01d1b7a096c1f0127469beb1c3ede6d27c2a0168ca8e650f437216c1b98a9e26041bf"));

    // First generate — output discarded per CAVP; check the resulting state.
    auto g1 = drbg.generate(256);
    REQUIRE(g1.is_ok());
    CHECK(vec(drbg.v_state())   == unhex("58541d0585467b99c7fc5f11e3136354d8dec23bf96a844710c5f38f9cb6119503f1de447e83274b08ad7fc1774193099453ca8cb44271556e51707831b0118d"));
    CHECK(vec(drbg.key_state()) == unhex("95e39a6773c93b602fb49a5926603afee5ae14cabe12569a80e64d4383a0eaf924cb8fbf14839efce3ea9529500ad5dbe08d55da7b5f2c82aefef21e6944dbf9"));

    // Second generate — this is the returned bit-string (2048 bits).
    auto g2 = drbg.generate(256);
    REQUIRE(g2.is_ok());
    CHECK(vec(g2.value().span()) == unhex(
        "e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3"
        "c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128"
        "a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8d"
        "c352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef23"
        "892d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb115"
        "38e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e7"
        "3ad361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce082551"
        "8987154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6"));
    CHECK(vec(drbg.v_state())   == unhex("8bf5f07540c522a54b102899932736e2c0ec7d48d13927e23ec73d667bcaef78195b79a5979520e9e32972bf961619367743daf171da79d024cbc92c765db16e"));
    CHECK(vec(drbg.key_state()) == unhex("8384f7aa846450f39c4b016c4650c14f19eec5b7d980c419838f55b212f8a074231237d99e65bc04966f6f36c5b90f340c998e0a2394617bd98be896e1e713f7"));
}

TEST("drbg/generate/streaming-and-limits") {
    auto seed = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto d = HmacDrbg::instantiate(sp(seed));
    REQUIRE(d.is_ok());
    // Pulling n bytes then reseeding-free continues the stream (distinct chunks).
    auto a = d.value().generate(100);
    auto b = d.value().generate(100);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(vec(a.value().span()) != vec(b.value().span()));
    // Insufficient entropy is rejected.
    auto tooshort = unhex("00112233");
    CHECK(HmacDrbg::instantiate(sp(tooshort)).is_err());
    // Oversized request is rejected.
    CHECK(d.value().generate(70000).is_err());
}

// MediaEntropy beacon: deterministic mode is fully reproducible from the media.
TEST("drbg/media-beacon-reproducible") {
    const char* photo = "/tmp/test_drbg_media.ppm";
    if (!std::filesystem::exists(photo))
        (void)crypto::stego::MediaGenerator::generate_ppm(photo, 128, 128);

    auto me1 = crypto::entropy::MediaEntropy::from_file_deterministic(photo);
    auto me2 = crypto::entropy::MediaEntropy::from_file_deterministic(photo);
    REQUIRE(me1.is_ok()); REQUIRE(me2.is_ok());
    auto d1 = me1.value().make_drbg("beacon");
    auto d2 = me2.value().make_drbg("beacon");
    REQUIRE(d1.is_ok()); REQUIRE(d2.is_ok());
    auto s1 = d1.value().generate(256);
    auto s2 = d2.value().generate(256);
    REQUIRE(s1.is_ok()); REQUIRE(s2.is_ok());
    CHECK(vec(s1.value().span()) == vec(s2.value().span()));  // same media → same beacon
    // A different personalization diverges the stream.
    auto d3 = me1.value().make_drbg("other");
    auto s3 = d3.value().generate(256);
    CHECK(vec(s3.value().span()) != vec(s1.value().span()));
    std::filesystem::remove(photo);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_entropy_drbg() {
    RUN("drbg/kat/cavp-hmac-sha512");
    RUN("drbg/generate/streaming-and-limits");
    RUN("drbg/media-beacon-reproducible");
}
