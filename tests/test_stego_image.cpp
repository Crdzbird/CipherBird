#include "test_framework.hpp"
#include <filesystem>
using namespace test;

using IS  = crypto::stego::ImageSteganographer;
using MG  = crypto::stego::MediaGenerator;

static const char* COVER = "/tmp/test_img_cover.ppm";
static const char* STEGO = "/tmp/test_img_stego.ppm";

static void ensure_cover() {
    if (!std::filesystem::exists(COVER))
        (void)MG::generate_ppm(COVER, 640, 480);
}

// ─── Round-trips ─────────────────────────────────────────────────────────────

TEST("stego_img/round-trip/small") {
    ensure_cover();
    std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    REQUIRE(IS::embed(COVER, payload, STEGO).is_ok());
    auto ext = IS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_img/round-trip/max-fill") {
    ensure_cover();
    // capacity() takes (w, h) → returns std::size_t directly, no Result wrapper
    std::size_t cap = IS::capacity(640, 480);
    REQUIRE(cap > 0);
    std::vector<uint8_t> big(cap, 0xCC);
    REQUIRE(IS::embed(COVER, big, STEGO).is_ok());
    auto ext = IS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == big);
}

TEST("stego_img/round-trip/binary-pattern") {
    ensure_cover();
    std::vector<uint8_t> pat;
    for (int i = 0; i < 64; i++) pat.push_back(static_cast<uint8_t>(i));
    REQUIRE(IS::embed(COVER, pat, STEGO).is_ok());
    auto ext = IS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == pat);
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

TEST("stego_img/capacity/640x480") {
    std::size_t cap = IS::capacity(640, 480);
    CHECK(cap > 4000);   // expect ~4786 B for 640×480
}

TEST("stego_img/capacity/small-image") {
    // 64×64 → (64/8)×(64/8) = 64 blocks × 8 bits = 64 bytes minus header
    std::size_t cap = IS::capacity(64, 64);
    CHECK(cap > 0);
    CHECK(cap < 200);
}

TEST("stego_img/capacity/scales-with-resolution") {
    std::size_t small_cap = IS::capacity(64,  64);
    std::size_t large_cap = IS::capacity(640, 480);
    CHECK(large_cap > small_cap * 10);
}

TEST("stego_img/oversized-payload-rejected") {
    ensure_cover();
    std::vector<uint8_t> huge(1'000'000, 0xFF);
    CHECK_ERR(IS::embed(COVER, huge, STEGO));
}

// ─── PSNR / quality ───────────────────────────────────────────────────────────

TEST("stego_img/psnr/above-threshold") {
    ensure_cover();
    std::vector<uint8_t> payload(256, 0xAB);
    REQUIRE(IS::embed(COVER, payload, STEGO).is_ok());
    // psnr() returns double directly — no Result wrapper
    double psnr = IS::psnr(COVER, STEGO);
    CHECK(psnr >= 40.0);
}

TEST("stego_img/psnr/lower-Q-is-subtler") {
    ensure_cover();
    std::vector<uint8_t> payload(64, 0x55);

    REQUIRE(IS::embed(COVER, payload, STEGO, 16).is_ok());
    double psnr16 = IS::psnr(COVER, STEGO);

    const char* STEGO8 = "/tmp/test_img_stego_q8.ppm";
    REQUIRE(IS::embed(COVER, payload, STEGO8, 8).is_ok());
    double psnr8 = IS::psnr(COVER, STEGO8);

    CHECK(psnr8 >= psnr16);  // lower Q step → less distortion → higher PSNR
}

// ─── Custom Q (quantization step) ────────────────────────────────────────────

TEST("stego_img/custom-Q/round-trip") {
    ensure_cover();
    // embed/extract take int Q directly (not StegoParams)
    std::vector<uint8_t> payload(64, 0x55);
    REQUIRE(IS::embed(COVER, payload, STEGO, 8).is_ok());
    auto ext = IS::extract(STEGO, 8);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_img/custom-Q/mismatched-Q-corrupts") {
    ensure_cover();
    std::vector<uint8_t> payload(16, 0x77);
    REQUIRE(IS::embed(COVER, payload, STEGO, 8).is_ok());
    auto ext = IS::extract(STEGO, 32);  // wrong Q → wrong bit boundaries
    if (ext.is_ok()) CHECK(ext.value() != payload);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_image() {
    RUN("stego_img/round-trip/small");
    RUN("stego_img/round-trip/max-fill");
    RUN("stego_img/round-trip/binary-pattern");
    RUN("stego_img/capacity/640x480");
    RUN("stego_img/capacity/small-image");
    RUN("stego_img/capacity/scales-with-resolution");
    RUN("stego_img/oversized-payload-rejected");
    RUN("stego_img/psnr/above-threshold");
    RUN("stego_img/psnr/lower-Q-is-subtler");
    RUN("stego_img/custom-Q/round-trip");
    RUN("stego_img/custom-Q/mismatched-Q-corrupts");
}
