// Phase 1 hardening — keyed steganography (whitened header + permuted blocks)
// and the MediaEntropy HKDF labeled derive.
#include "test_framework.hpp"
#include <filesystem>
#include <cstring>
using namespace test;

using IS  = crypto::stego::ImageSteganographer;
using SE  = crypto::stego::StegoEngine;
using MG  = crypto::stego::MediaGenerator;

static const char* KCOVER = "/tmp/test_keyed_cover.ppm";
static const char* KSTEGO = "/tmp/test_keyed_stego.ppm";

static void ensure_cover() {
    if (!std::filesystem::exists(KCOVER))
        (void)MG::generate_ppm(KCOVER, 640, 480);
}
static std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }

// Contains a 'CSTG' magic anywhere in the byte buffer?
static bool has_magic(const std::vector<uint8_t>& b) {
    for (std::size_t i = 0; i + 4 <= b.size(); ++i)
        if (b[i] == 'C' && b[i+1] == 'S' && b[i+2] == 'T' && b[i+3] == 'G') return true;
    return false;
}

// ── B1 + B2: keyed round-trip ────────────────────────────────────────────────
TEST("stego_keyed/round-trip") {
    ensure_cover();
    std::vector<uint8_t> key(32, 0xA7);
    std::vector<uint8_t> payload = {'s','e','c','r','e','t',' ','m','s','g'};
    REQUIRE(IS::embed(KCOVER, sp(payload), KSTEGO, sp(key)).is_ok());
    auto ext = IS::extract(KSTEGO, sp(key));
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

TEST("stego_keyed/wrong-key-fails") {
    ensure_cover();
    std::vector<uint8_t> key(32, 0x11), wrong(32, 0x22);
    std::vector<uint8_t> payload(200, 0x5A);
    REQUIRE(IS::embed(KCOVER, sp(payload), KSTEGO, sp(key)).is_ok());
    // Wrong key → whitening + permutation both differ → header/CRC garbage → error.
    CHECK(IS::extract(KSTEGO, sp(wrong)).is_err());
    // Legacy (unkeyed) extract also cannot read a keyed stego.
    CHECK(IS::extract(KSTEGO).is_err());
}

// The whole point of B1: no 'CSTG' fingerprint survives in the recovered bits.
TEST("stego_keyed/no-magic-signature") {
    ensure_cover();
    std::vector<uint8_t> key(32, 0x3C);
    std::vector<uint8_t> payload(500, 0x00);
    REQUIRE(IS::embed(KCOVER, sp(payload), KSTEGO, sp(key)).is_ok());

    // Recover the raw bit-stream exactly as a steganalyst would: unkeyed DCT
    // extraction in raster order (no permutation, no un-whitening).
    auto img = IS::read_ppm(KSTEGO);
    REQUIRE(img.is_ok());
    auto& im = img.value();
    std::size_t maxs = IS::capacity(im.w, im.h) + 14;
    auto raw = crypto::stego::DctQimEngine::extract_bits(im.pixels, im.w, im.h, maxs, 16);
    CHECK(!has_magic(raw));   // no 'CSTG' anywhere in the whitened+permuted bits

    // Sanity: the legacy unkeyed embed IS detectable by the same scan — proving
    // the scan actually finds a magic when one is present.
    REQUIRE(IS::embed(KCOVER, sp(payload), "/tmp/test_keyed_nokey.ppm").is_ok());
    auto img2 = IS::read_ppm("/tmp/test_keyed_nokey.ppm");
    REQUIRE(img2.is_ok());
    auto& im2 = img2.value();
    auto raw2 = crypto::stego::DctQimEngine::extract_bits(
        im2.pixels, im2.w, im2.h, IS::capacity(im2.w, im2.h) + 14, 16);
    CHECK(has_magic(raw2));
    std::filesystem::remove("/tmp/test_keyed_nokey.ppm");
}

// Two embeds of DIFFERENT payloads under the same key must touch different bytes
// (whitening) — and both round-trip.
TEST("stego_keyed/distinct-payloads") {
    ensure_cover();
    std::vector<uint8_t> key(32, 0x99);
    std::vector<uint8_t> p1(300, 0x01), p2(300, 0x02);
    REQUIRE(IS::embed(KCOVER, sp(p1), "/tmp/test_keyed_a.ppm", sp(key)).is_ok());
    REQUIRE(IS::embed(KCOVER, sp(p2), "/tmp/test_keyed_b.ppm", sp(key)).is_ok());
    auto e1 = IS::extract("/tmp/test_keyed_a.ppm", sp(key));
    auto e2 = IS::extract("/tmp/test_keyed_b.ppm", sp(key));
    REQUIRE(e1.is_ok()); REQUIRE(e2.is_ok());
    CHECK(e1.value() == p1);
    CHECK(e2.value() == p2);
    std::filesystem::remove("/tmp/test_keyed_a.ppm");
    std::filesystem::remove("/tmp/test_keyed_b.ppm");
}

// Keyed path via the StegoEngine facade (params.key) + non-PPM key rejection.
TEST("stego_keyed/engine-facade") {
    ensure_cover();
    crypto::stego::StegoParams params;
    params.key = std::vector<uint8_t>(32, 0x44);
    std::vector<uint8_t> payload = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    REQUIRE(SE::embed(KCOVER, sp(payload), KSTEGO, params).is_ok());
    auto ext = SE::extract(KSTEGO, params);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
    // Unkeyed engine extract of a keyed stego → error (no magic to find).
    CHECK(SE::extract(KSTEGO).is_err());
}

// Backward compatibility: the legacy unkeyed path is unchanged.
TEST("stego_keyed/legacy-unkeyed-unchanged") {
    ensure_cover();
    std::vector<uint8_t> payload = {42, 43, 44, 45};
    REQUIRE(IS::embed(KCOVER, sp(payload), KSTEGO).is_ok());
    auto ext = IS::extract(KSTEGO);
    REQUIRE(ext.is_ok());
    CHECK(ext.value() == payload);
}

// ── A2: MediaEntropy HKDF labeled derive ─────────────────────────────────────
TEST("media_entropy/derive/labeled-independent") {
    const char* photo = "/tmp/test_keyed_entropy.ppm";
    if (!std::filesystem::exists(photo)) (void)MG::generate_ppm(photo, 128, 128);
    auto me = crypto::entropy::MediaEntropy::from_file_deterministic(photo);
    REQUIRE(me.is_ok());
    auto a = me.value().derive("label:a", 32);
    auto b = me.value().derive("label:b", 32);
    auto a2 = me.value().derive("label:a", 32);
    CHECK(a.size() == 32);
    CHECK(std::memcmp(a.data(), b.data(), 32) != 0);   // distinct labels ⇒ independent
    CHECK(std::memcmp(a.data(), a2.data(), 32) == 0);  // deterministic for a label
    auto long_key = me.value().derive("opaque:oprf_seed:v1", 64);
    CHECK(long_key.size() == 64);                      // arbitrary length
    std::filesystem::remove(photo);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_keyed() {
    RUN("stego_keyed/round-trip");
    RUN("stego_keyed/wrong-key-fails");
    RUN("stego_keyed/no-magic-signature");
    RUN("stego_keyed/distinct-payloads");
    RUN("stego_keyed/engine-facade");
    RUN("stego_keyed/legacy-unkeyed-unchanged");
    RUN("media_entropy/derive/labeled-independent");
}
