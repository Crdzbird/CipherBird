// crypto::HpkeStegoSeal — keyed stego bound to an HPKE session. One HPKE session
// (RFC 9180 DHKEM-X25519 + HKDF-SHA256 + ChaCha20-Poly1305) governs both the
// AEAD ciphertext and the stego concealment key (via the exporter interface).
// Round-trip / wrong-recipient / wrong-info / tamper / no-signature tests.
#include "test_framework.hpp"
#include <sodium.h>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::HpkeStegoSeal;
using crypto::Hpke;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }
std::vector<uint8_t> bytes(std::string_view s) { return { s.begin(), s.end() }; }

bool file_contains(const std::string& path, std::string_view needle) {
    std::ifstream f(path, std::ios::binary);
    std::vector<char> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (std::size_t i = 0; i + needle.size() <= b.size(); ++i)
        if (std::memcmp(b.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}
const std::span<const uint8_t> NONE{};
}

TEST("hpke_stego/round-trip") {
    const std::string cover = "/tmp/test_hss_cover.ppm";
    const std::string out   = "/tmp/test_hss_out.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto recip = Hpke::generate_keypair();
    auto info = bytes("hpke-stego/session");
    auto aad  = bytes("hdr");
    std::string secret = "one session keys both cipher and cover";
    std::vector<uint8_t> pt(secret.begin(), secret.end());

    auto enc = HpkeStegoSeal::seal(recip.public_key.span(), sp(pt), sp(aad), sp(info), cover, out);
    REQUIRE(enc.is_ok());

    auto d = HpkeStegoSeal::open(recip.secret_key.span(), enc.value().span(), sp(aad), sp(info), out);
    REQUIRE(d.is_ok());
    CHECK(d.value() == pt);

    // No cleartext, no 'CSTG' signature in the carrier.
    CHECK(!file_contains(out, secret));
    CHECK(!file_contains(out, "CSTG"));

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("hpke_stego/wrong-recipient-fails") {
    const std::string cover = "/tmp/test_hss_cover2.ppm";
    const std::string out   = "/tmp/test_hss_out2.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto recip   = Hpke::generate_keypair();
    auto mallory = Hpke::generate_keypair();
    auto info = bytes("ctx");
    std::vector<uint8_t> pt(50, 0x1d);

    auto enc = HpkeStegoSeal::seal(recip.public_key.span(), sp(pt), NONE, sp(info), cover, out);
    REQUIRE(enc.is_ok());
    // Wrong recipient secret → wrong session → wrong stego key + AEAD → fail closed.
    CHECK(HpkeStegoSeal::open(mallory.secret_key.span(), enc.value().span(), NONE, sp(info), out).is_err());
    REQUIRE(HpkeStegoSeal::open(recip.secret_key.span(), enc.value().span(), NONE, sp(info), out).is_ok());

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("hpke_stego/wrong-info-fails") {
    const std::string cover = "/tmp/test_hss_cover3.ppm";
    const std::string out   = "/tmp/test_hss_out3.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto recip = Hpke::generate_keypair();
    std::vector<uint8_t> pt(50, 0x2e);
    auto enc = HpkeStegoSeal::seal(recip.public_key.span(), sp(pt), NONE, sp(bytes("info-A")), cover, out);
    REQUIRE(enc.is_ok());
    // A different HPKE info string yields a different session (and stego key).
    CHECK(HpkeStegoSeal::open(recip.secret_key.span(), enc.value().span(), NONE, sp(bytes("info-B")), out).is_err());
    REQUIRE(HpkeStegoSeal::open(recip.secret_key.span(), enc.value().span(), NONE, sp(bytes("info-A")), out).is_ok());

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

TEST("hpke_stego/tamper-detected") {
    const std::string cover = "/tmp/test_hss_cover4.ppm";
    const std::string out   = "/tmp/test_hss_out4.ppm";
    (void)crypto::stego::MediaGenerator::generate_ppm(cover, 256, 256);

    auto recip = Hpke::generate_keypair();
    auto info = bytes("ctx");
    std::vector<uint8_t> pt(72, 0x63);
    auto enc = HpkeStegoSeal::seal(recip.public_key.span(), sp(pt), NONE, sp(info), cover, out);
    REQUIRE(enc.is_ok());

    {
        // The keyed path scatters the payload across permuted blocks, so corrupt a
        // wide band (20%–80% of the carrier) to reliably overlap used blocks
        // regardless of the per-session permutation.
        std::fstream f(out, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(0, std::ios::end);
        std::streamoff sz = f.tellp();
        for (std::streamoff off = sz / 5; off < (sz * 4) / 5; ++off) {
            f.seekg(off); char c; f.get(c); c = static_cast<char>(c ^ 0xFF);
            f.seekp(off); f.put(c);
        }
    }
    auto d = HpkeStegoSeal::open(recip.secret_key.span(), enc.value().span(), NONE, sp(info), out);
    CHECK(d.is_err() || d.value() != pt);

    std::filesystem::remove(cover);
    std::filesystem::remove(out);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_hpke_stego_seal() {
    RUN("hpke_stego/round-trip");
    RUN("hpke_stego/wrong-recipient-fails");
    RUN("hpke_stego/wrong-info-fails");
    RUN("hpke_stego/tamper-detected");
}
