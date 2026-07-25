// crypto::PhysicalSeal — two-factor "the photo is the key, the message hides in
// another photo" seal. Composition of MediaEntropy (deterministic) +
// XChaCha20-Poly1305 + keyed stego. Round-trip / wrong-key-media / wrong-cover /
// tamper / no-signature tests (no KAT — composition of vetted primitives).
#include "test_framework.hpp"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::PhysicalSeal;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }

// A distinct "key media" PPM whose pixel body is high-entropy (so it is a valid
// deterministic entropy source), seeded by `seed`.
void make_key_media(const std::string& path, uint32_t seed) {
    std::ofstream f(path, std::ios::binary);
    f << "P6\n64 64\n255\n";
    std::vector<uint8_t> body(64 * 64 * 3);
    uint32_t s = seed ? seed : 1;
    for (auto& b : body) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; b = static_cast<uint8_t>(s); }
    f.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
}

bool file_contains(const std::string& path, std::string_view needle) {
    std::ifstream f(path, std::ios::binary);
    std::vector<char> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (std::size_t i = 0; i + needle.size() <= b.size(); ++i)
        if (std::memcmp(b.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}
}

TEST("physical_seal/round-trip") {
    const std::string keym = "/tmp/test_pseal_key.ppm";
    const std::string cover = "/tmp/test_pseal_cover.ppm";
    const std::string out  = "/tmp/test_pseal_out.ppm";
    make_key_media(keym, 0xC0FFEE);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::string secret = "rendezvous 04:00, pier 7 — burn after reading";
    std::vector<uint8_t> pt(secret.begin(), secret.end());

    auto e = PhysicalSeal::seal(keym, secret, "op-context", cover, out);
    REQUIRE(e.is_ok());

    auto d = PhysicalSeal::open(keym, "op-context", out);
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);

    // Neither the cleartext nor the 'CSTG' stego signature survives in the carrier.
    CHECK(!file_contains(out, secret));
    CHECK(!file_contains(out, "CSTG"));

    std::filesystem::remove(keym);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("physical_seal/wrong-key-media-fails") {
    const std::string keym  = "/tmp/test_pseal_key2.ppm";
    const std::string wrong = "/tmp/test_pseal_key2_wrong.ppm";
    const std::string cover = "/tmp/test_pseal_cover2.ppm";
    const std::string out   = "/tmp/test_pseal_out2.ppm";
    make_key_media(keym, 0xAAAA1111);
    make_key_media(wrong, 0xBBBB2222);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    REQUIRE(PhysicalSeal::seal(keym, "top secret", "ctx", cover, out).is_ok());
    // A different key-media file yields different stego + AEAD keys → fail closed.
    CHECK(PhysicalSeal::open(wrong, "ctx", out).is_err());
    // The correct key media still opens it.
    REQUIRE(PhysicalSeal::open(keym, "ctx", out).is_ok());

    std::filesystem::remove(keym);
    std::filesystem::remove(wrong);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("physical_seal/wrong-aad-fails") {
    const std::string keym  = "/tmp/test_pseal_key3.ppm";
    const std::string cover = "/tmp/test_pseal_cover3.ppm";
    const std::string out   = "/tmp/test_pseal_out3.ppm";
    make_key_media(keym, 0x33334444);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    REQUIRE(PhysicalSeal::seal(keym, "payload", "context-A", cover, out).is_ok());
    CHECK(PhysicalSeal::open(keym, "context-B", out).is_err());  // AAD mismatch → AEAD tag fails
    REQUIRE(PhysicalSeal::open(keym, "context-A", out).is_ok());

    std::filesystem::remove(keym);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("physical_seal/tamper-detected") {
    const std::string keym  = "/tmp/test_pseal_key4.ppm";
    const std::string cover = "/tmp/test_pseal_cover4.ppm";
    const std::string out   = "/tmp/test_pseal_out4.ppm";
    make_key_media(keym, 0x55556666);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::vector<uint8_t> pt(80, 0x9a);
    const std::span<const uint8_t> no_aad{};
    REQUIRE(PhysicalSeal::seal(keym, sp(pt), no_aad, cover, out).is_ok());

    // Corrupt a swath of the pixel body.
    {
        std::fstream f(out, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(0, std::ios::end);
        std::streamoff sz = f.tellp();
        for (std::streamoff off = sz / 2; off < sz / 2 + 400 && off < sz; ++off) {
            f.seekg(off); char c; f.get(c); c = static_cast<char>(c ^ 0xFF);
            f.seekp(off); f.put(c);
        }
    }
    auto d = PhysicalSeal::open(keym, no_aad, out);
    CHECK(d.is_err() || d.value() != pt);   // caught by CRC or AEAD tag

    std::filesystem::remove(keym);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_physical_seal() {
    RUN("physical_seal/round-trip");
    RUN("physical_seal/wrong-key-media-fails");
    RUN("physical_seal/wrong-aad-fails");
    RUN("physical_seal/tamper-detected");
}
