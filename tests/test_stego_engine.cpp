#include "test_framework.hpp"
#include <filesystem>
using namespace test;

using SE = crypto::stego::StegoEngine;

static const char* IMG = "/tmp/test_eng_cover.ppm";
static const char* WAV = "/tmp/test_eng_cover.wav";
static const char* VID = "/tmp/test_eng_cover.crvf";

static void ensure_covers() {
    if (!std::filesystem::exists(IMG)) crypto::stego::MediaGenerator::generate_ppm(IMG, 640, 480);
    if (!std::filesystem::exists(WAV)) crypto::stego::MediaGenerator::generate_wav(WAV, 44100, 1, 10.0);
    if (!std::filesystem::exists(VID)) crypto::stego::MediaGenerator::generate_crvf(VID, 320, 240, 30, 60);
}

// ─── Raw embed / extract ─────────────────────────────────────────────────────

TEST("engine/raw/image-round-trip") {
    ensure_covers();
    std::vector<uint8_t> payload = {1, 2, 3, 4, 5, 6, 7, 8};
    auto r = SE::embed(IMG, payload, "/tmp/eng_stego.ppm");
    REQUIRE(r.is_ok());
    auto ext = SE::extract("/tmp/eng_stego.ppm");
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("engine/raw/audio-round-trip") {
    ensure_covers();
    std::vector<uint8_t> payload = {0xCA, 0xFE, 0xBA, 0xBE};
    auto r = SE::embed(WAV, payload, "/tmp/eng_stego.wav");
    REQUIRE(r.is_ok());
    auto ext = SE::extract("/tmp/eng_stego.wav");
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("engine/raw/video-round-trip") {
    ensure_covers();
    std::vector<uint8_t> payload = {0xFF, 0x00, 0xFF, 0x00};
    auto r = SE::embed(VID, payload, "/tmp/eng_stego.crvf");
    REQUIRE(r.is_ok());
    auto ext = SE::extract("/tmp/eng_stego.crvf");
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

// ─── Packet embed / extract ───────────────────────────────────────────────────

TEST("engine/packet/image-round-trip") {
    ensure_covers();
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));
    auto pkt   = vault.seal("engine packet test", "aad");
    REQUIRE(pkt.is_ok());

    auto r = SE::embed_packet(IMG, pkt.value(), "/tmp/eng_pkt_stego.ppm");
    REQUIRE(r.is_ok());
    auto ext = SE::extract_packet("/tmp/eng_pkt_stego.ppm");
    REQUIRE(ext.is_ok());
    auto pt = vault.open(ext.value(), "aad");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "engine packet test");
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

TEST("engine/capacity/image") {
    ensure_covers();
    auto r = SE::capacity(IMG);
    REQUIRE(r.is_ok());
    CHECK(r.value().max_payload_bytes > 4000);
}

TEST("engine/capacity/audio") {
    ensure_covers();
    auto r = SE::capacity(WAV);
    REQUIRE(r.is_ok());
    CHECK(r.value().max_payload_bytes > 500);
}

TEST("engine/capacity/video") {
    ensure_covers();
    auto r = SE::capacity(VID);
    REQUIRE(r.is_ok());
    CHECK(r.value().max_payload_bytes > 60'000);
}

TEST("engine/capacity/unknown-extension") {
    auto r = SE::capacity("/tmp/mystery.xyz");
    CHECK_ERR(r);
}

// ─── Quality ──────────────────────────────────────────────────────────────────

TEST("engine/quality/image-psnr") {
    ensure_covers();
    std::vector<uint8_t> p(128, 0x55);
    SE::embed(IMG, p, "/tmp/eng_q_stego.ppm");
    auto q = SE::quality(IMG, "/tmp/eng_q_stego.ppm");
    REQUIRE(q.is_ok());
    CHECK(q.value() >= 40.0);
}

TEST("engine/quality/audio-snr") {
    ensure_covers();
    std::vector<uint8_t> p(32, 0x33);
    SE::embed(WAV, p, "/tmp/eng_q_stego.wav");
    auto q = SE::quality(WAV, "/tmp/eng_q_stego.wav");
    REQUIRE(q.is_ok());
    CHECK(q.value() >= 20.0);
}

// ─── MediaGenerator ──────────────────────────────────────────────────────────

TEST("engine/generator/ppm") {
    auto r = crypto::stego::MediaGenerator::generate_ppm("/tmp/gen_test.ppm", 128, 128);
    CHECK_OK(r);
    CHECK(std::filesystem::exists("/tmp/gen_test.ppm"));
}

TEST("engine/generator/wav") {
    auto r = crypto::stego::MediaGenerator::generate_wav("/tmp/gen_test.wav", 44100, 1, 1.0);
    CHECK_OK(r);
    CHECK(std::filesystem::exists("/tmp/gen_test.wav"));
}

TEST("engine/generator/crvf") {
    auto r = crypto::stego::MediaGenerator::generate_crvf("/tmp/gen_test.crvf", 160, 120, 30, 10);
    CHECK_OK(r);
    CHECK(std::filesystem::exists("/tmp/gen_test.crvf"));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_engine() {
    RUN("engine/raw/image-round-trip");
    RUN("engine/raw/audio-round-trip");
    RUN("engine/raw/video-round-trip");
    RUN("engine/packet/image-round-trip");
    RUN("engine/capacity/image");
    RUN("engine/capacity/audio");
    RUN("engine/capacity/video");
    RUN("engine/capacity/unknown-extension");
    RUN("engine/quality/image-psnr");
    RUN("engine/quality/audio-snr");
    RUN("engine/generator/ppm");
    RUN("engine/generator/wav");
    RUN("engine/generator/crvf");
}
