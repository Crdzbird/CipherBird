// B1-extension: keyed whitening now works for EVERY carrier format (not just
// .ppm). Previously StegoEngine rejected a key on non-PPM carriers. These tests
// exercise the two non-image signature families (StegoParams: WAV, CRVF) and the
// int-Q family (BMP), checking keyed round-trip, wrong-key failure, and that no
// 'CSTG' signature survives in the extracted bit-stream.
#include "test_framework.hpp"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using SE = crypto::stego::StegoEngine;
namespace MG = crypto::stego;

namespace {
std::vector<uint8_t> key32(uint8_t b) { return std::vector<uint8_t>(32, b); }

crypto::stego::StegoParams keyed(const std::vector<uint8_t>& k) {
    crypto::stego::StegoParams p;
    p.key = k;
    return p;
}

// A 24-bit BMP (128x128, high-entropy noise). 128*3 = 384 is 4-aligned → no row
// padding; positive height → bottom-up rows, BGR pixel order.
void write_noise_bmp(const std::string& path, uint32_t seed) {
    const uint32_t W = 128, H = 128;
    const uint32_t row = W * 3, img = row * H, off = 54, fsz = off + img;
    auto u16 = [](std::vector<uint8_t>& v, uint16_t x){ v.push_back(x & 0xFF); v.push_back(x >> 8); };
    auto u32 = [](std::vector<uint8_t>& v, uint32_t x){ for (int i=0;i<4;++i) v.push_back((x >> (8*i)) & 0xFF); };
    std::vector<uint8_t> f;
    f.push_back('B'); f.push_back('M'); u32(f, fsz); u32(f, 0); u32(f, off);
    u32(f, 40); u32(f, W); u32(f, H); u16(f, 1); u16(f, 24);
    u32(f, 0); u32(f, img); u32(f, 2835); u32(f, 2835); u32(f, 0); u32(f, 0);
    uint32_t s = seed ? seed : 1;
    for (uint32_t i = 0; i < img; ++i) { s ^= s<<13; s ^= s>>17; s ^= s<<5; f.push_back(static_cast<uint8_t>(s)); }
    std::ofstream o(path, std::ios::binary);
    o.write(reinterpret_cast<const char*>(f.data()), static_cast<std::streamsize>(f.size()));
}

}

TEST("keyed_fmt/wav-round-trip") {
    const char* cover = "/tmp/test_kf_cover.wav";
    const char* out   = "/tmp/test_kf_out.wav";
    if (!std::filesystem::exists(cover)) MG::MediaGenerator::generate_wav(cover, 44100, 1, 10.0);

    std::string msg = "keyed whitening now covers WAV carriers too";
    std::vector<uint8_t> pt(msg.begin(), msg.end());
    auto key = key32(0x3c);

    auto e = SE::embed(cover, { pt.data(), pt.size() }, out, keyed(key));
    REQUIRE(e.is_ok());
    auto d = SE::extract(out, keyed(key));
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);
    // Wrong key → CRC fast-fail.
    CHECK(SE::extract(out, keyed(key32(0x99))).is_err());

    std::filesystem::remove(out);
}

TEST("keyed_fmt/crvf-round-trip") {
    const char* cover = "/tmp/test_kf_cover.crvf";
    const char* out   = "/tmp/test_kf_out.crvf";
    if (!std::filesystem::exists(cover)) MG::MediaGenerator::generate_crvf(cover, 320, 240, 30, 60);

    std::vector<uint8_t> pt(64, 0x5a);
    auto key = key32(0x71);
    auto e = SE::embed(cover, { pt.data(), pt.size() }, out, keyed(key));
    REQUIRE(e.is_ok());
    auto d = SE::extract(out, keyed(key));
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);
    CHECK(SE::extract(out, keyed(key32(0x11))).is_err());

    std::filesystem::remove(out);
}

TEST("keyed_fmt/bmp-round-trip-no-signature") {
    const char* cover = "/tmp/test_kf_cover.bmp";
    const char* out   = "/tmp/test_kf_out.bmp";
    write_noise_bmp(cover, 0xB19B00);

    std::string msg = "bmp keyed carrier — no CSTG please";
    std::vector<uint8_t> pt(msg.begin(), msg.end());
    auto key = key32(0x2d);

    auto e = SE::embed(cover, { pt.data(), pt.size() }, out, keyed(key));
    REQUIRE(e.is_ok());
    auto d = SE::extract(out, keyed(key));
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);
    // Whitening removes the recoverable 'CSTG' header structure: an UNKEYED
    // extract of the keyed carrier finds no valid magic and fails. (The magic
    // lives in DCT coefficients, so a raw byte scan is meaningless here — the
    // parse-level check is the correct signal for a DCT carrier.)
    CHECK(SE::extract(out).is_err());

    // Control: an UNKEYED embed→extract round-trips (the magic IS recoverable
    // without a key), proving the key is exactly what conceals it.
    const char* out_plain = "/tmp/test_kf_out_plain.bmp";
    REQUIRE(SE::embed(cover, { pt.data(), pt.size() }, out_plain).is_ok());
    CHECK(SE::extract(out_plain).is_ok());

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
    std::filesystem::remove(out_plain);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_keyed_formats() {
    RUN("keyed_fmt/wav-round-trip");
    RUN("keyed_fmt/crvf-round-trip");
    RUN("keyed_fmt/bmp-round-trip-no-signature");
}
