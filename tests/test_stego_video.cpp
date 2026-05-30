#include "test_framework.hpp"
#include <filesystem>
using namespace test;

using VS = crypto::stego::VideoSteganographer;
using MG = crypto::stego::MediaGenerator;

static const char* COVER = "/tmp/test_vid_cover.crvf";
static const char* STEGO = "/tmp/test_vid_stego.crvf";

static void ensure_cover(int frames = 60) {
    if (!std::filesystem::exists(COVER))
        (void)MG::generate_crvf(COVER, 320, 240, 30, frames);
}

// ─── Round-trips ─────────────────────────────────────────────────────────────

TEST("stego_vid/round-trip/small") {
    ensure_cover();
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    REQUIRE(VS::embed(COVER, payload, STEGO).is_ok());
    auto ext = VS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_vid/round-trip/256-bytes") {
    ensure_cover();
    std::vector<uint8_t> pat;
    for (int i = 0; i < 256; i++) pat.push_back(static_cast<uint8_t>(i));
    REQUIRE(VS::embed(COVER, pat, STEGO).is_ok());
    auto ext = VS::extract(STEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == pat);
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

TEST("stego_vid/capacity/60-frames") {
    // capacity(frame_count, w, h) → std::size_t directly, no Result wrapper
    std::size_t cap = VS::capacity(60, 320, 240);
    CHECK(cap > 60'000);  // expect ~71 KB for 60 frames 320×240
}

TEST("stego_vid/capacity/scales-with-frames") {
    // Linear scaling: more frames → more capacity
    std::size_t cap10  = VS::capacity(10,  320, 240);
    std::size_t cap30  = VS::capacity(30,  320, 240);
    std::size_t cap60  = VS::capacity(60,  320, 240);
    std::size_t cap120 = VS::capacity(120, 320, 240);
    CHECK(cap30  > cap10);
    CHECK(cap60  > cap30);
    CHECK(cap120 > cap60);
    // Roughly linear: 60-frame capacity should be ~6× the 10-frame capacity
    CHECK(cap60 > cap10 * 4);
}

TEST("stego_vid/oversized-payload-rejected") {
    ensure_cover();
    std::vector<uint8_t> huge(10'000'000, 0xFF);
    CHECK_ERR(VS::embed(COVER, huge, STEGO));
}

// ─── CRVF header inspection ───────────────────────────────────────────────────

TEST("stego_vid/crvf-header/correct-metadata") {
    ensure_cover();
    auto r = VS::read_crvf(COVER);
    REQUIRE(r.is_ok());
    auto& [hdr, frames] = r.value();
    CHECK(hdr.width       == 320);
    CHECK(hdr.height      == 240);
    CHECK(hdr.fps_num     == 30);
    CHECK(hdr.frame_count == 60);
    CHECK(frames.size()   == 60);
    // Each frame is width × height × 3 bytes (RGB24)
    CHECK(frames[0].size() == 320u * 240u * 3u);
}

TEST("stego_vid/crvf-header/stego-preserves-metadata") {
    ensure_cover();
    std::vector<uint8_t> payload(256, 0xAB);
    REQUIRE(VS::embed(COVER, payload, STEGO).is_ok());
    auto r = VS::read_crvf(STEGO);
    REQUIRE(r.is_ok());
    auto& [hdr, frames] = r.value();
    CHECK(hdr.width       == 320);
    CHECK(hdr.height      == 240);
    CHECK(hdr.fps_num     == 30);
    CHECK(hdr.frame_count == 60);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_video() {
    RUN("stego_vid/round-trip/small");
    RUN("stego_vid/round-trip/256-bytes");
    RUN("stego_vid/capacity/60-frames");
    RUN("stego_vid/capacity/scales-with-frames");
    RUN("stego_vid/oversized-payload-rejected");
    RUN("stego_vid/crvf-header/correct-metadata");
    RUN("stego_vid/crvf-header/stego-preserves-metadata");
}
