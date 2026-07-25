// crypto::stego::StegoEngine::embed_encrypted / extract_decrypt — the
// always-encrypt path (AEAD-then-hide). One master key drives three
// domain-separated subkeys (AEAD, whitening, permutation). These are round-trip
// / wrong-key / tamper tests (no KAT — composition of vetted primitives).
#include "test_framework.hpp"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::stego::StegoEngine;

namespace {
std::vector<uint8_t> key32(uint8_t seed) { return std::vector<uint8_t>(32, seed); }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }

// Recover the raw embedded bit-stream (unkeyed, raster order) to prove no 'CSTG'
// magic survives in the ciphertext carrier.
bool file_contains(const std::string& path, std::string_view needle) {
    std::ifstream f(path, std::ios::binary);
    std::vector<char> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (std::size_t i = 0; i + needle.size() <= b.size(); ++i)
        if (std::memcmp(b.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}
}

TEST("stego_enc/round-trip") {
    const char* cover = "/tmp/test_stegoenc_cover.ppm";
    const char* out   = "/tmp/test_stegoenc_out.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::string secret = "attack at dawn — this must never be in the clear";
    std::vector<uint8_t> pt(secret.begin(), secret.end());
    auto key = key32(0xA5);

    auto e = StegoEngine::embed_encrypted(cover,
        { pt.data(), pt.size() }, out, sp(key));
    REQUIRE(e.is_ok());

    auto d = StegoEngine::extract_decrypt(out, sp(key));
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);

    // The cleartext secret must NOT be findable anywhere in the stego file.
    CHECK(!file_contains(out, secret));

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("stego_enc/wrong-key-fails") {
    const char* cover = "/tmp/test_stegoenc_cover2.ppm";
    const char* out   = "/tmp/test_stegoenc_out2.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::vector<uint8_t> pt(64, 0x2c);
    auto key   = key32(0x11);
    auto wrong = key32(0x22);

    REQUIRE(StegoEngine::embed_encrypted(cover, { pt.data(), pt.size() }, out, sp(key)).is_ok());
    // Wrong key: rejected (CRC/whitening fast-fail, or AEAD tag underneath).
    CHECK(StegoEngine::extract_decrypt(out, sp(wrong)).is_err());
    // Right key still works.
    auto ok = StegoEngine::extract_decrypt(out, sp(key));
    REQUIRE(ok.is_ok());
    CHECK(ok.value() == pt);

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("stego_enc/tamper-detected") {
    const char* cover = "/tmp/test_stegoenc_cover3.ppm";
    const char* out   = "/tmp/test_stegoenc_out3.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::vector<uint8_t> pt(96, 0x5e);
    auto key = key32(0x77);
    REQUIRE(StegoEngine::embed_encrypted(cover, { pt.data(), pt.size() }, out, sp(key)).is_ok());

    // Flip bytes deep in the pixel body (past the header) to disturb embedded bits.
    {
        std::fstream f(out, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(0, std::ios::end);
        std::streamoff sz = f.tellp();
        for (std::streamoff off = sz / 2; off < sz / 2 + 512 && off < sz; ++off) {
            f.seekg(off); char c; f.get(c);
            c = static_cast<char>(c ^ 0xFF);
            f.seekp(off); f.put(c);
        }
    }
    // Tamper must be caught (CRC or AEAD tag) — never silently wrong plaintext.
    auto d = StegoEngine::extract_decrypt(out, sp(key));
    CHECK(d.is_err() || d.value() != pt);

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("stego_enc/empty-key-rejected") {
    std::vector<uint8_t> pt(16, 0);
    std::vector<uint8_t> nokey;
    CHECK(StegoEngine::embed_encrypted("/tmp/nope.ppm",
        { pt.data(), pt.size() }, "/tmp/nope_out.ppm", sp(nokey)).is_err());
    CHECK(StegoEngine::extract_decrypt("/tmp/nope.ppm", sp(nokey)).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_encrypted() {
    RUN("stego_enc/round-trip");
    RUN("stego_enc/wrong-key-fails");
    RUN("stego_enc/tamper-detected");
    RUN("stego_enc/empty-key-rejected");
}
