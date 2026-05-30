#include "test_framework.hpp"
#include <filesystem>
using namespace test;

using AS = crypto::stego::AudioSteganographer;
using MG = crypto::stego::MediaGenerator;

static const char* COVER = "/tmp/test_aud_cover.wav";
static const char* STEGO = "/tmp/test_aud_stego.wav";

// 10 s × 44100 Hz mono = 441 000 samples
static constexpr std::size_t SAMPLES_10S = 44100 * 10;

static void ensure_cover() {
    if (!std::filesystem::exists(COVER))
        (void)MG::generate_wav(COVER, 44100, 1, 10.0);
}

// ─── Round-trips ─────────────────────────────────────────────────────────────

TEST("stego_aud/round-trip/small") {
    ensure_cover();
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC, 0xDD};
    REQUIRE(AS::embed(COVER, payload, STEGO).is_ok());
    auto ext = AS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_aud/round-trip/binary-pattern") {
    ensure_cover();
    std::vector<uint8_t> pat;
    for (int i = 0; i < 64; i++) pat.push_back(static_cast<uint8_t>(i));
    REQUIRE(AS::embed(COVER, pat, STEGO).is_ok());
    auto ext = AS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == pat);
}

TEST("stego_aud/round-trip/max-fill") {
    ensure_cover();
    // capacity(sample_count) returns std::size_t directly — no Result wrapper
    std::size_t cap = AS::capacity(SAMPLES_10S);
    REQUIRE(cap > 0);
    std::vector<uint8_t> big(cap, 0x77);
    REQUIRE(AS::embed(COVER, big, STEGO).is_ok());
    auto ext = AS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == big);
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

TEST("stego_aud/capacity/10s-mono") {
    // capacity() takes (sample_count, params) → returns std::size_t, not Result
    std::size_t cap = AS::capacity(SAMPLES_10S);
    CHECK(cap > 500);   // expect ~847 B for 10 s mono at default params
}

TEST("stego_aud/capacity/scales-with-duration") {
    std::size_t cap_5s  = AS::capacity(44100 * 5);
    std::size_t cap_10s = AS::capacity(44100 * 10);
    CHECK(cap_10s > cap_5s);
    CHECK(cap_10s >= cap_5s * 2 - 10);  // roughly linear, small header overhead
}

TEST("stego_aud/oversized-payload-rejected") {
    ensure_cover();
    std::vector<uint8_t> huge(100'000, 0xFF);
    CHECK_ERR(AS::embed(COVER, huge, STEGO));
}

// ─── SNR / quality ────────────────────────────────────────────────────────────

TEST("stego_aud/snr/above-threshold") {
    ensure_cover();
    std::vector<uint8_t> payload(64, 0x42);
    REQUIRE(AS::embed(COVER, payload, STEGO).is_ok());
    // snr() returns double directly — no Result wrapper
    double snr = AS::snr(COVER, STEGO);
    CHECK(snr >= 20.0);  // imperceptibility threshold
}

// ─── Custom StegoParams ───────────────────────────────────────────────────────

TEST("stego_aud/custom-params/larger-fft") {
    ensure_cover();
    crypto::stego::StegoParams p;
    p.audio_frame_size = 1024;
    p.audio_bin_start  = 40;
    p.audio_bin_count  = 4;
    std::vector<uint8_t> payload(32, 0x99);
    REQUIRE(AS::embed(COVER, payload, STEGO, p).is_ok());
    auto ext = AS::extract(STEGO, p);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_aud/custom-params/capacity-lower-with-fewer-bins") {
    // Fewer bins per frame → less capacity
    crypto::stego::StegoParams few;
    few.audio_bin_count = 2;
    crypto::stego::StegoParams many;
    many.audio_bin_count = 8;
    std::size_t cap_few  = AS::capacity(SAMPLES_10S, few);
    std::size_t cap_many = AS::capacity(SAMPLES_10S, many);
    CHECK(cap_many > cap_few);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_audio() {
    RUN("stego_aud/round-trip/small");
    RUN("stego_aud/round-trip/binary-pattern");
    RUN("stego_aud/round-trip/max-fill");
    RUN("stego_aud/capacity/10s-mono");
    RUN("stego_aud/capacity/scales-with-duration");
    RUN("stego_aud/oversized-payload-rejected");
    RUN("stego_aud/snr/above-threshold");
    RUN("stego_aud/custom-params/larger-fft");
    RUN("stego_aud/custom-params/capacity-lower-with-fewer-bins");
}
