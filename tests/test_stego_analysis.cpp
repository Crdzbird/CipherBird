// crypto::stego::StegoAnalyzer — carrier validity, reference-based tamper
// detection, and the heuristic hidden-data probe. The honest-and-verifiable
// parts (validity, digest tamper, cipherbird-signature scan) get hard asserts;
// the LSB heuristic is checked only for the direction it can honestly claim
// (a smooth image LSB-embedded scores higher than the same image clean).
#include "test_framework.hpp"
#include "cipherbird_c.h"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::stego::StegoAnalyzer;
using SE = crypto::stego::StegoEngine;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }

// A smooth gradient PPM (natural-like: structured LSBs, unlike pure noise).
void write_gradient_ppm(const std::string& path, int w, int h) {
    std::ofstream f(path, std::ios::binary);
    f << "P6\n" << w << " " << h << "\n255\n";
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            uint8_t r = static_cast<uint8_t>((x * 255) / w);
            uint8_t g = static_cast<uint8_t>((y * 255) / h);
            uint8_t b = static_cast<uint8_t>(((x + y) * 255) / (w + h));
            f.put(static_cast<char>(r)); f.put(static_cast<char>(g)); f.put(static_cast<char>(b));
        }
}

// Overwrite the LSB of every byte after the PPM header with pseudo-random bits.
void lsb_stuff_ppm(const std::string& path) {
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    std::string magic; int w, h, mx; f >> magic >> w >> h >> mx; f.get();
    std::streampos start = f.tellg();
    f.seekg(0, std::ios::end); std::streamoff end = f.tellg();
    uint32_t s = 0x12345;
    for (std::streamoff off = start; off < end; ++off) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        f.seekg(off); char c; f.get(c);
        c = static_cast<char>((c & 0xFE) | (s & 1));
        f.seekp(off); f.put(c);
    }
}

std::string cut_copy(const std::string& src, const std::string& dst, std::size_t n) {
    std::ifstream in(src, std::ios::binary);
    std::vector<char> b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (n < b.size()) b.resize(n);
    std::ofstream out(dst, std::ios::binary);
    out.write(b.data(), static_cast<std::streamsize>(b.size()));
    return dst;
}

std::size_t file_size(const std::string& p) { return static_cast<std::size_t>(std::filesystem::file_size(p)); }
}

TEST("analysis/inspect-valid-and-mismatch") {
    const std::string ppm = "/tmp/test_an_ok.ppm";
    write_gradient_ppm(ppm, 64, 64);
    auto r = StegoAnalyzer::inspect(ppm);
    REQUIRE(r.is_ok());
    CHECK(r.value().parses);
    CHECK(r.value().format == crypto::stego::MediaFormat::PPM_IMAGE);
    CHECK(r.value().ext_matches);
    CHECK(r.value().width == 64);
    CHECK(r.value().height == 64);

    // Content/extension mismatch: PPM bytes under a .png name → parses but flags.
    const std::string mis = "/tmp/test_an_mismatch.png";
    write_gradient_ppm(mis, 32, 32);
    auto m = StegoAnalyzer::inspect(mis);
    REQUIRE(m.is_ok());
    CHECK(m.value().parses);
    CHECK(!m.value().ext_matches);

    // Garbage: not a recognised carrier.
    const std::string junk = "/tmp/test_an_junk.bin";
    { std::ofstream j(junk, std::ios::binary); const char* g = "not media at all!!"; j.write(g, 18); }
    auto jr = StegoAnalyzer::inspect(junk);
    REQUIRE(jr.is_ok());
    CHECK(!jr.value().parses);

    std::filesystem::remove(ppm); std::filesystem::remove(mis); std::filesystem::remove(junk);
}

TEST("analysis/content-digest-tamper") {
    const std::string ppm = "/tmp/test_an_digest.ppm";
    write_gradient_ppm(ppm, 48, 48);
    auto d1 = StegoAnalyzer::content_digest(ppm);
    REQUIRE(d1.is_ok());
    // Same file → same digest, and verify_digest agrees.
    auto d2 = StegoAnalyzer::content_digest(ppm);
    REQUIRE(d2.is_ok());
    CHECK(d1.value() == d2.value());
    auto v = StegoAnalyzer::verify_digest(ppm, sp(std::vector<uint8_t>(d1.value().begin(), d1.value().end())));
    REQUIRE(v.is_ok()); CHECK(v.value());

    // Flip one byte deep in the pixel body → digest changes, verify fails.
    { std::fstream f(ppm, std::ios::in | std::ios::out | std::ios::binary);
      f.seekp(1000); char c; f.seekg(1000); f.get(c); c ^= 0x01; f.seekp(1000); f.put(c); }
    auto v2 = StegoAnalyzer::verify_digest(ppm, sp(std::vector<uint8_t>(d1.value().begin(), d1.value().end())));
    REQUIRE(v2.is_ok()); CHECK(!v2.value());   // tamper detected against the stored reference

    std::filesystem::remove(ppm);
}

TEST("analysis/detect-cipherbird-payload") {
    const std::string cover = "/tmp/test_an_cover.ppm";
    const std::string stego = "/tmp/test_an_stego.ppm";
    const std::string clean = "/tmp/test_an_clean.ppm";
    write_gradient_ppm(cover, 128, 128);
    write_gradient_ppm(clean, 128, 128);

    // Unkeyed cipherbird embed → detect_hidden flags it definitively.
    std::vector<uint8_t> pt(60, 0x33);
    REQUIRE(SE::embed(cover, sp(pt), stego).is_ok());
    auto d = StegoAnalyzer::detect_hidden(stego);
    REQUIRE(d.is_ok());
    CHECK(d.value().cipherbird_payload);

    // A clean carrier: no recoverable cipherbird payload.
    auto c = StegoAnalyzer::detect_hidden(clean);
    REQUIRE(c.is_ok());
    CHECK(!c.value().cipherbird_payload);

    std::filesystem::remove(cover); std::filesystem::remove(stego); std::filesystem::remove(clean);
}

TEST("analysis/lsb-heuristic-direction") {
    // The chi-square LSB attack can honestly claim only a DIRECTION: a smooth
    // image that has been LSB-stuffed scores higher than the same image clean.
    const std::string clean = "/tmp/test_an_lsb_clean.ppm";
    const std::string dirty = "/tmp/test_an_lsb_dirty.ppm";
    write_gradient_ppm(clean, 256, 256);
    write_gradient_ppm(dirty, 256, 256);
    lsb_stuff_ppm(dirty);

    auto rc = StegoAnalyzer::detect_hidden(clean);
    auto rd = StegoAnalyzer::detect_hidden(dirty);
    REQUIRE(rc.is_ok()); REQUIRE(rd.is_ok());
    // Every report carries the honesty note.
    CHECK(!rc.value().note.empty());
    CHECK(rd.value().lsb_embedding_likelihood >= rc.value().lsb_embedding_likelihood);
    CHECK(rd.value().lsb_embedding_likelihood > 0.5);   // stuffed image reads as likely-embedded

    std::filesystem::remove(clean); std::filesystem::remove(dirty);
}

TEST("analysis/inspect-rejects-truncated-carriers") {
    using MG = crypto::stego::MediaGenerator;
    const std::string dir = "/tmp/test_an_trunc";
    std::filesystem::create_directories(dir);
    REQUIRE(MG::generate_ppm(dir + "/c.ppm", 64, 48).is_ok());
    REQUIRE(MG::generate_bmp(dir + "/c.bmp", 64, 48).is_ok());
    REQUIRE(MG::generate_png(dir + "/c.png", 64, 48).is_ok());
    REQUIRE(MG::generate_gif(dir + "/c.gif", 64, 48).is_ok());
    for (const char* ext : { ".ppm", ".bmp", ".png", ".gif" }) {
        const std::string full = dir + "/c" + ext;
        auto ok = StegoAnalyzer::inspect(full);
        REQUIRE(ok.is_ok());
        CHECK(ok.value().parses);
        CHECK(ok.value().width == 64);
        CHECK(ok.value().height == 48);
        const std::size_t size = file_size(full);
        for (std::size_t n : { std::size_t{10}, std::size_t{40}, size / 2, size - 2 }) {
            const std::string cut = cut_copy(full, dir + "/cut" + std::to_string(n) + ext, n);
            auto r = StegoAnalyzer::inspect(cut);
            REQUIRE(r.is_ok());
            CHECK(!r.value().parses);
            CHECK(r.value().width == 0);
            CHECK(r.value().height == 0);
            CHECK(r.value().detail.find("not a usable carrier") != std::string::npos);
        }
    }

    REQUIRE(MG::generate_wav(dir + "/c.wav", 8000, 1, 0.5).is_ok());
    REQUIRE(MG::generate_crvf(dir + "/c.crvf", 64, 48, 10, 3).is_ok());
    for (const char* ext : { ".wav", ".crvf" }) {
        const std::string full = dir + "/c" + ext;
        auto ok = StegoAnalyzer::inspect(full);
        REQUIRE(ok.is_ok());
        CHECK(ok.value().parses);
        const std::string cut = cut_copy(full, dir + "/half" + ext, file_size(full) / 2);
        auto r = StegoAnalyzer::inspect(cut);
        REQUIRE(r.is_ok());
        CHECK(!r.value().parses);
    }

    const std::string bmp10 = cut_copy(dir + "/c.bmp", dir + "/abi10.bmp", 10);
    CryptoFileInspection abi = cipherbird_stego_inspect(bmp10.c_str());
    CHECK(abi.error == nullptr);
    CHECK(abi.parses == 0);
    CHECK(abi.format == static_cast<uint8_t>(crypto::stego::MediaFormat::BMP_IMAGE));
    cipherbird_str_free(abi.detail);
    cipherbird_str_free(abi.error);
    std::filesystem::remove_all(dir);
}

TEST("analysis/capacity-bmp-png-gif") {
    using MG = crypto::stego::MediaGenerator;
    const std::string dir = "/tmp/test_an_cap";
    std::filesystem::create_directories(dir);
    REQUIRE(MG::generate_bmp(dir + "/c.bmp", 128, 96).is_ok());
    REQUIRE(MG::generate_png(dir + "/c.png", 128, 96).is_ok());
    REQUIRE(MG::generate_gif(dir + "/c.gif", 128, 96).is_ok());
    const std::size_t dct = crypto::stego::DctQimEngine::capacity(128, 96);
    const std::size_t lsb = crypto::stego::GifSteganographer::capacity(128, 96);
    struct Case { const char* ext; std::size_t want; };
    for (Case c : { Case{".bmp", dct}, Case{".png", dct}, Case{".gif", lsb} }) {
        const std::string cover = dir + "/c" + c.ext;
        const std::string out = dir + "/out" + c.ext;
        auto cap = SE::capacity(cover);
        REQUIRE(cap.is_ok());
        CHECK(c.want > 0);
        CHECK(cap.value().max_payload_bytes == c.want);
        CHECK(cipherbird_stego_capacity(cover.c_str()) == c.want);
        std::vector<uint8_t> full(c.want, 0x5A);
        REQUIRE(SE::embed(cover, sp(full), out).is_ok());
        auto back = SE::extract(out);
        REQUIRE(back.is_ok());
        CHECK(back.value() == full);
        full.push_back(0);
        CHECK(SE::embed(cover, sp(full), out).is_err());
        const std::string cut = cut_copy(cover, dir + "/cut" + c.ext, file_size(cover) / 2);
        CHECK(cipherbird_stego_capacity(cut.c_str()) == 0);
    }
    std::filesystem::remove_all(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_analysis() {
    RUN("analysis/inspect-valid-and-mismatch");
    RUN("analysis/content-digest-tamper");
    RUN("analysis/detect-cipherbird-payload");
    RUN("analysis/lsb-heuristic-direction");
    RUN("analysis/inspect-rejects-truncated-carriers");
    RUN("analysis/capacity-bmp-png-gif");
}
