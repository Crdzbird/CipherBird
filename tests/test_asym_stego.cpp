#include "test_framework.hpp"
#include <filesystem>
using namespace test;

using AV = crypto::AsymmetricVault;

static const char* IMG = "/tmp/int_as_cover.ppm";
static const char* WAV = "/tmp/int_as_cover.wav";

static void ensure_covers() {
    if (!std::filesystem::exists(IMG)) crypto::stego::MediaGenerator::generate_ppm(IMG, 640, 480);
    if (!std::filesystem::exists(WAV)) crypto::stego::MediaGenerator::generate_wav(WAV, 44100, 1, 10.0);
}

TEST("asym_stego/alice-to-bob/image") {
    ensure_covers();
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();

    auto r = AV::seal_into(alice, bob.box_public.span(),
                           "Bob, midnight at the north dock.",
                           IMG, "/tmp/as_stego.ppm", "ctx");
    REQUIRE(r.is_ok());
    auto pt = AV::open_from(bob, alice.sign_public.span(), "/tmp/as_stego.ppm", "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "Bob, midnight at the north dock.");
}

TEST("asym_stego/alice-to-bob/audio") {
    ensure_covers();
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();

    auto r = AV::seal_into(alice, bob.box_public.span(),
                           "Audio covert channel.",
                           WAV, "/tmp/as_stego.wav", "wav");
    REQUIRE(r.is_ok());
    auto pt = AV::open_from(bob, alice.sign_public.span(), "/tmp/as_stego.wav", "wav");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "Audio covert channel.");
}

TEST("asym_stego/mallory-forge-rejected") {
    ensure_covers();
    auto alice   = AV::generate_bundle();
    auto bob     = AV::generate_bundle();
    auto mallory = AV::generate_bundle();

    // Mallory seals a forged message for Bob
    REQUIRE(AV::seal_into(mallory, bob.box_public.span(),
                          "wiring change instructions",
                          IMG, "/tmp/as_forge.ppm", "ctx").is_ok());
    // Bob verifies against Alice's signing key → must fail
    auto bad = AV::open_from(bob, alice.sign_public.span(), "/tmp/as_forge.ppm", "ctx");
    CHECK_ERR(bad);
}

TEST("asym_stego/wrong-aad-rejected") {
    ensure_covers();
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();

    REQUIRE(AV::seal_into(alice, bob.box_public.span(), "data",
                          IMG, "/tmp/as_aad.ppm", "correct").is_ok());
    auto bad = AV::open_from(bob, alice.sign_public.span(), "/tmp/as_aad.ppm", "wrong");
    CHECK_ERR(bad);
}

TEST("asym_stego/wrong-recipient-rejected") {
    ensure_covers();
    auto alice   = AV::generate_bundle();
    auto bob     = AV::generate_bundle();
    auto charlie = AV::generate_bundle();

    REQUIRE(AV::seal_into(alice, bob.box_public.span(), "bob only",
                          IMG, "/tmp/as_recip.ppm", "ctx").is_ok());
    // Charlie tries to decrypt
    auto bad = AV::open_from(charlie, alice.sign_public.span(), "/tmp/as_recip.ppm", "ctx");
    CHECK_ERR(bad);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_asym_stego() {
    RUN("asym_stego/alice-to-bob/image");
    RUN("asym_stego/alice-to-bob/audio");
    RUN("asym_stego/mallory-forge-rejected");
    RUN("asym_stego/wrong-aad-rejected");
    RUN("asym_stego/wrong-recipient-rejected");
}
