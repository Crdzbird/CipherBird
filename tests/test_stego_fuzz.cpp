/**
 * test_stego_fuzz.cpp — malformed / hostile input regression tests.
 *
 * These feed crafted media headers (oversized or overflowing dimension and
 * count fields) to the extract paths. Each must return a clean error rather
 * than crashing. Run under -DCRYPTOLIB_SANITIZE=ON so any out-of-bounds access
 * or integer-overflow-driven allocation trips ASan/UBSan and fails the test.
 */

#include "test_framework.hpp"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

using namespace test;

namespace {

std::string tmp_path(const char* name) {
    auto p = std::filesystem::temp_directory_path() / name;
    return p.string();
}

void write_bytes(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
    v.push_back(uint8_t(x >> 16)); v.push_back(uint8_t(x >> 24));
}
void put_u16_le(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
}

} // namespace

// ── PPM: oversized ASCII dimensions must be rejected, not allocated ──────────
TEST("stego-fuzz/ppm/oversized-dimensions-rejected") {
    auto path = tmp_path("cstg_fuzz_oversized.ppm");
    // 99999 x 99999 would be ~30 GB if resized; both exceed MAX_IMAGE_DIM.
    std::string ppm = "P6\n99999 99999\n255\n";
    write_bytes(path, {ppm.begin(), ppm.end()});

    auto r = crypto::stego::ImageSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── PPM: dimensions that overflow w*h*3 must be rejected ─────────────────────
TEST("stego-fuzz/ppm/overflow-dimensions-rejected") {
    auto path = tmp_path("cstg_fuzz_overflow.ppm");
    // Each factor < 2^32 but the product wraps size_t; caught by dim cap first.
    std::string ppm = "P6\n4000000000 4000000000\n255\n";
    write_bytes(path, {ppm.begin(), ppm.end()});

    auto r = crypto::stego::ImageSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── BMP: oversized biWidth/biHeight must be rejected before the row copy ─────
TEST("stego-fuzz/bmp/oversized-dimensions-rejected") {
    auto path = tmp_path("cstg_fuzz_oversized.bmp");
    std::vector<uint8_t> bmp;
    // File header (14 bytes): 'B''M', size(4)=0, reserved(4)=0, pixel_offset(4)=54
    bmp.push_back('B'); bmp.push_back('M');
    put_u32_le(bmp, 0);
    put_u32_le(bmp, 0);
    put_u32_le(bmp, 54);
    // DIB header (40 bytes, BITMAPINFOHEADER)
    put_u32_le(bmp, 40);          // dib_size
    put_u32_le(bmp, 0x10000000);  // biWidth  ~268M > MAX_IMAGE_DIM
    put_u32_le(bmp, 0x10000000);  // biHeight ~268M > MAX_IMAGE_DIM
    put_u16_le(bmp, 1);           // planes
    put_u16_le(bmp, 24);          // bpp
    put_u32_le(bmp, 0);           // compression = BI_RGB
    put_u32_le(bmp, 0);           // image size
    put_u32_le(bmp, 2835);        // x ppm
    put_u32_le(bmp, 2835);        // y ppm
    put_u32_le(bmp, 0);           // colors used
    put_u32_le(bmp, 0);           // important colors
    write_bytes(path, bmp);

    auto r = crypto::stego::BmpSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── BMP: absurd DIB header size must be rejected, not allocated ──────────────
TEST("stego-fuzz/bmp/huge-dib-size-rejected") {
    auto path = tmp_path("cstg_fuzz_dib.bmp");
    std::vector<uint8_t> bmp;
    bmp.push_back('B'); bmp.push_back('M');
    put_u32_le(bmp, 0);
    put_u32_le(bmp, 0);
    put_u32_le(bmp, 54);
    put_u32_le(bmp, 0xFFFFFFF0);  // dib_size ~4 GB
    write_bytes(path, bmp);

    auto r = crypto::stego::BmpSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── CRVF: oversized frame dimensions must be rejected ────────────────────────
TEST("stego-fuzz/crvf/oversized-dimensions-rejected") {
    auto path = tmp_path("cstg_fuzz_dims.crvf");
    std::vector<uint8_t> v;
    v.push_back('C'); v.push_back('R'); v.push_back('V'); v.push_back('F');
    v.push_back(1);               // version
    put_u32_le(v, 100000);        // width  > MAX_IMAGE_DIM
    put_u32_le(v, 100000);        // height > MAX_IMAGE_DIM
    put_u32_le(v, 30);            // fps_num
    put_u16_le(v, 1);             // fps_den
    put_u32_le(v, 1);             // frame_count
    put_u16_le(v, 0);             // pixel_fmt
    write_bytes(path, v);

    auto r = crypto::stego::VideoSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── WAV: oversized data chunk must not over-allocate, returns clean error ────
TEST("stego-fuzz/wav/oversized-data-chunk-rejected") {
    auto path = tmp_path("cstg_fuzz_oversized.wav");
    std::vector<uint8_t> v;
    auto tag = [&](const char* s){ for (int i=0;i<4;++i) v.push_back(uint8_t(s[i])); };
    tag("RIFF"); put_u32_le(v, 0); tag("WAVE");
    tag("fmt "); put_u32_le(v, 16);
    put_u16_le(v, 1);       // PCM
    put_u16_le(v, 1);       // mono
    put_u32_le(v, 44100);   // sample rate
    put_u32_le(v, 88200);   // byte rate
    put_u16_le(v, 2);       // block align
    put_u16_le(v, 16);      // bits
    tag("data"); put_u32_le(v, 0xFFFFFFF0);  // claims ~4 GB, file has none
    write_bytes(path, v);

    auto r = crypto::stego::AudioSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── AVI: a LIST chunk size < 4 must not underflow the parse offsets ──────────
TEST("stego-fuzz/avi/undersized-list-chunk-rejected") {
    auto path = tmp_path("cstg_fuzz_underflow.avi");
    std::vector<uint8_t> v;
    auto tag = [&](const char* s){ for (int i=0;i<4;++i) v.push_back(uint8_t(s[i])); };
    tag("RIFF"); put_u32_le(v, 0); tag("AVI ");
    tag("LIST"); put_u32_le(v, 0);   // chunk_size 0 → (chunk_size - 4) would wrap
    tag("hdrl");
    write_bytes(path, v);

    auto r = crypto::stego::AviSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── Audio: caller-supplied non-power-of-two frame size must be rejected ───────
TEST("stego-fuzz/wav/bad-phase-params-rejected") {
    auto path = tmp_path("cstg_fuzz_params.wav");
    std::vector<uint8_t> v;
    auto tag = [&](const char* s){ for (int i=0;i<4;++i) v.push_back(uint8_t(s[i])); };
    const uint32_t samples = 2048;          // 4096 bytes of 16-bit PCM
    const uint32_t data_sz = samples * 2;
    tag("RIFF"); put_u32_le(v, 36 + data_sz); tag("WAVE");
    tag("fmt "); put_u32_le(v, 16);
    put_u16_le(v, 1); put_u16_le(v, 1);
    put_u32_le(v, 44100); put_u32_le(v, 88200);
    put_u16_le(v, 2); put_u16_le(v, 16);
    tag("data"); put_u32_le(v, data_sz);
    for (uint32_t i = 0; i < samples; ++i) put_u16_le(v, uint16_t(i));
    write_bytes(path, v);

    crypto::stego::StegoParams bad;
    bad.audio_frame_size = 300;  // not a power of two → invalid for radix-2 FFT
    auto r = crypto::stego::AudioSteganographer::extract(path, bad);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}

// ── Mutation smoke test ──────────────────────────────────────────────────────
// A local, deterministic stand-in for the libFuzzer targets (which need an LLVM
// clang runtime to link). Starts from valid-ish headers, applies random byte
// flips / truncations, and runs every parser. Under ASan/UBSan any out-of-bounds
// access or overflow aborts the test. Deterministic seed → reproducible.
namespace {

struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9e3779b97f4a7c15ULL) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    uint32_t u32() { return static_cast<uint32_t>(next() >> 32); }
};

void mutate(std::vector<uint8_t>& b, Rng& rng) {
    if (b.empty()) return;
    int ops = 1 + (rng.u32() % 6);
    for (int i = 0; i < ops; ++i) {
        switch (rng.u32() % 3) {
            case 0: b[rng.u32() % b.size()] ^= uint8_t(1u << (rng.u32() % 8)); break;
            case 1: b[rng.u32() % b.size()] = uint8_t(rng.u32()); break;
            case 2: if (b.size() > 1) b.resize(1 + (rng.u32() % b.size())); break;
        }
    }
}

template <class Fn>
void fuzz_format(const char* ext, const std::vector<uint8_t>& base, Fn extract) {
    Rng rng(0xC0FFEEull ^ std::hash<std::string>{}(ext));
    auto path = tmp_path((std::string("cstg_mut") + ext).c_str());
    for (int i = 0; i < 400; ++i) {
        auto b = base;
        mutate(b, rng);
        write_bytes(path, b);
        (void)extract(path);   // result ignored; ASan enforces memory safety
    }
    std::filesystem::remove(path);
}

} // namespace

TEST("stego-fuzz/mutation-smoke") {
    using namespace crypto::stego;

    // PPM (ASCII header + a few pixels)
    {
        std::string h = "P6\n8 8\n255\n";
        std::vector<uint8_t> base(h.begin(), h.end());
        base.resize(base.size() + 8 * 8 * 3, 0x80);
        fuzz_format(".ppm", base, [](const std::string& p){ return ImageSteganographer::extract(p); });
    }
    // BMP (14-byte file header + 40-byte BITMAPINFOHEADER + a little pixel data)
    {
        std::vector<uint8_t> base;
        auto u32=[&](uint32_t x){ base.push_back(x); base.push_back(x>>8); base.push_back(x>>16); base.push_back(x>>24); };
        auto u16=[&](uint16_t x){ base.push_back(x); base.push_back(x>>8); };
        base.push_back('B'); base.push_back('M'); u32(0); u32(0); u32(54);
        u32(40); u32(4); u32(4); u16(1); u16(24); u32(0); u32(0); u32(0); u32(0); u32(0); u32(0);
        base.resize(base.size() + 4*4*3, 0x40);
        fuzz_format(".bmp", base, [](const std::string& p){ return BmpSteganographer::extract(p); });
    }
    // GIF
    {
        std::string h = "GIF89a";
        std::vector<uint8_t> base(h.begin(), h.end());
        base.resize(base.size() + 64, 0x10);
        fuzz_format(".gif", base, [](const std::string& p){ return GifSteganographer::extract(p); });
    }
    // CRVF
    {
        std::vector<uint8_t> base;
        auto u32=[&](uint32_t x){ base.push_back(x); base.push_back(x>>8); base.push_back(x>>16); base.push_back(x>>24); };
        auto u16=[&](uint16_t x){ base.push_back(x); base.push_back(x>>8); };
        base.push_back('C'); base.push_back('R'); base.push_back('V'); base.push_back('F'); base.push_back(1);
        u32(8); u32(8); u32(30); u16(1); u32(1); u16(0);
        base.resize(base.size() + 8*8*3, 0x55);
        fuzz_format(".crvf", base, [](const std::string& p){ return VideoSteganographer::extract(p); });
    }
    // WAV
    {
        std::vector<uint8_t> base;
        auto tag=[&](const char* s){ for(int i=0;i<4;++i) base.push_back(s[i]); };
        auto u32=[&](uint32_t x){ base.push_back(x); base.push_back(x>>8); base.push_back(x>>16); base.push_back(x>>24); };
        auto u16=[&](uint16_t x){ base.push_back(x); base.push_back(x>>8); };
        tag("RIFF"); u32(0); tag("WAVE"); tag("fmt "); u32(16);
        u16(1); u16(1); u32(44100); u32(88200); u16(2); u16(16);
        tag("data"); u32(2048);
        base.resize(base.size() + 2048, 0);
        fuzz_format(".wav", base, [](const std::string& p){ return AudioSteganographer::extract(p); });
    }
    // AVI
    {
        std::vector<uint8_t> base;
        auto tag=[&](const char* s){ for(int i=0;i<4;++i) base.push_back(s[i]); };
        auto u32=[&](uint32_t x){ base.push_back(x); base.push_back(x>>8); base.push_back(x>>16); base.push_back(x>>24); };
        tag("RIFF"); u32(0); tag("AVI "); tag("LIST"); u32(64); tag("hdrl");
        base.resize(base.size() + 64, 0x22);
        fuzz_format(".avi", base, [](const std::string& p){ return AviSteganographer::extract(p); });
    }
    CHECK(true);  // reaching here without an ASan abort is the pass condition
}

// ── Packet deserialise: random buffers must never over-read ───────────────────
TEST("stego-fuzz/packet-deserialise-random") {
    Rng rng(0x1234567);
    for (int i = 0; i < 5000; ++i) {
        std::vector<uint8_t> b(rng.u32() % 80);
        for (auto& x : b) x = uint8_t(rng.u32());
        auto r = crypto::EncryptedPacket::deserialise(b);
        (void)r;
    }
    CHECK(true);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_fuzz() {
    RUN("stego-fuzz/mutation-smoke");
    RUN("stego-fuzz/packet-deserialise-random");
    RUN("stego-fuzz/ppm/oversized-dimensions-rejected");
    RUN("stego-fuzz/ppm/overflow-dimensions-rejected");
    RUN("stego-fuzz/bmp/oversized-dimensions-rejected");
    RUN("stego-fuzz/bmp/huge-dib-size-rejected");
    RUN("stego-fuzz/crvf/oversized-dimensions-rejected");
    RUN("stego-fuzz/crvf/huge-frame-count-rejected");
    RUN("stego-fuzz/wav/oversized-data-chunk-rejected");
    RUN("stego-fuzz/avi/undersized-list-chunk-rejected");
    RUN("stego-fuzz/wav/bad-phase-params-rejected");
}

// ── CRVF: huge frame_count with tiny file must not over-allocate ─────────────
// (dispatcher defined after the final test below)
TEST("stego-fuzz/crvf/huge-frame-count-rejected") {
    auto path = tmp_path("cstg_fuzz_frames.crvf");
    std::vector<uint8_t> v;
    v.push_back('C'); v.push_back('R'); v.push_back('V'); v.push_back('F');
    v.push_back(1);
    put_u32_le(v, 64);            // width  (valid)
    put_u32_le(v, 64);            // height (valid)
    put_u32_le(v, 30);
    put_u16_le(v, 1);
    put_u32_le(v, 0xFFFFFFFF);    // frame_count ~4 billion, no data follows
    put_u16_le(v, 0);
    write_bytes(path, v);

    auto r = crypto::stego::VideoSteganographer::extract(path);
    CHECK(r.is_err());
    std::filesystem::remove(path);
}
