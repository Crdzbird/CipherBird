// crypto::ImageFactorSeal — a shared reference image as an OPRF-gated second
// factor. Composition of crypto::Oprf + XChaCha20-Poly1305 + keyed stego.
// Round-trip / wrong-image / wrong-secret / oblivious-equivalence tests.
#include "test_framework.hpp"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::ImageFactorSeal;
using crypto::Oprf;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }
std::vector<uint8_t> vec(std::span<const uint8_t> b) { return { b.begin(), b.end() }; }

// High-entropy reference image (a valid deterministic OPRF-input source).
void make_image(const std::string& path, uint32_t seed) {
    std::ofstream f(path, std::ios::binary);
    f << "P6\n64 64\n255\n";
    std::vector<uint8_t> body(64 * 64 * 3);
    uint32_t s = seed ? seed : 1;
    for (auto& b : body) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; b = static_cast<uint8_t>(s); }
    f.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
}
std::vector<uint8_t> seed32(uint8_t b) { return std::vector<uint8_t>(32, b); }
}

TEST("image_factor/round-trip") {
    const std::string img = "/tmp/test_ifs_ref.ppm";
    const std::string cover = "/tmp/test_ifs_cover.ppm";
    const std::string out = "/tmp/test_ifs_out.ppm";
    make_image(img, 0xFEEDBEEF);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto secret = seed32(0x5a);
    std::string msg = "the reference photo unlocks this";
    std::vector<uint8_t> pt(msg.begin(), msg.end());

    auto e = ImageFactorSeal::seal(sp(secret), img, sp(pt), {}, cover, out);
    REQUIRE(e.is_ok());
    auto d = ImageFactorSeal::open(sp(secret), img, {}, out);
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);

    std::filesystem::remove(img);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("image_factor/wrong-image-fails") {
    const std::string img   = "/tmp/test_ifs_ref2.ppm";
    const std::string other = "/tmp/test_ifs_ref2_other.ppm";
    const std::string cover = "/tmp/test_ifs_cover2.ppm";
    const std::string out   = "/tmp/test_ifs_out2.ppm";
    make_image(img, 0x11112222);
    make_image(other, 0x33334444);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto secret = seed32(0x77);
    std::vector<uint8_t> pt(48, 0xC3);
    REQUIRE(ImageFactorSeal::seal(sp(secret), img, sp(pt), {}, cover, out).is_ok());
    // Same OPRF secret but a different reference image → different keys → fail.
    CHECK(ImageFactorSeal::open(sp(secret), other, {}, out).is_err());
    REQUIRE(ImageFactorSeal::open(sp(secret), img, {}, out).is_ok());

    std::filesystem::remove(img);
    std::filesystem::remove(other);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("image_factor/wrong-secret-fails") {
    const std::string img   = "/tmp/test_ifs_ref3.ppm";
    const std::string cover = "/tmp/test_ifs_cover3.ppm";
    const std::string out   = "/tmp/test_ifs_out3.ppm";
    make_image(img, 0x9999AAAA);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    std::vector<uint8_t> pt(48, 0x2b);
    REQUIRE(ImageFactorSeal::seal(sp(seed32(0x01)), img, sp(pt), {}, cover, out).is_ok());
    // Right image, wrong OPRF secret → fail.
    CHECK(ImageFactorSeal::open(sp(seed32(0x02)), img, {}, out).is_err());
    REQUIRE(ImageFactorSeal::open(sp(seed32(0x01)), img, {}, out).is_ok());

    std::filesystem::remove(img);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

// The oblivious path (client blinds, remote server evaluates with the OPRF
// secret, client finalizes) yields the SAME PRF as the local one-shot — so a
// carrier sealed locally opens with the obliviously-derived keys and vice-versa.
TEST("image_factor/oblivious-equivalence") {
    const std::string img   = "/tmp/test_ifs_ref4.ppm";
    const std::string cover = "/tmp/test_ifs_cover4.ppm";
    const std::string out   = "/tmp/test_ifs_out4.ppm";
    make_image(img, 0xDEAD10CC);
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    // Server holds the OPRF secret key.
    auto secret = seed32(0x42);
    auto kp = Oprf::derive_keypair(sp(secret));
    REQUIRE(kp.is_ok());

    // Client: blind the image, send blinded_element to the server.
    auto blinded = ImageFactorSeal::blind_image(img);
    REQUIRE(blinded.is_ok());
    // Server: blind_evaluate with its secret (never sees the image).
    auto evaluated = Oprf::blind_evaluate(kp.value().secret_key.span(),
                                          blinded.value().blinded_element.span());
    REQUIRE(evaluated.is_ok());
    // Client: finalize → 64-byte PRF.
    auto prf_obliv = ImageFactorSeal::finalize_prf(img,
                        blinded.value().blind.span(), evaluated.value().span());
    REQUIRE(prf_obliv.is_ok());

    // Seal locally, open with the obliviously-derived PRF — must match.
    std::vector<uint8_t> pt(40, 0x8e);
    REQUIRE(ImageFactorSeal::seal(sp(secret), img, sp(pt), {}, cover, out).is_ok());
    auto d = ImageFactorSeal::open_with_prf(prf_obliv.value().span(), {}, out);
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);

    std::filesystem::remove(img);
    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_oprf_image_seal() {
    RUN("image_factor/round-trip");
    RUN("image_factor/wrong-image-fails");
    RUN("image_factor/wrong-secret-fails");
    RUN("image_factor/oblivious-equivalence");
}
