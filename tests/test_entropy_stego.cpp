#include "test_framework.hpp"
#include <filesystem>
using namespace test;

static const char* SRC = "/tmp/int_es_entropy.ppm";
static const char* IMG = "/tmp/int_es_cover.ppm";
static const char* WAV = "/tmp/int_es_cover.wav";

static void ensure_files() {
    if (!std::filesystem::exists(SRC)) {
        crypto::stego::MediaGeneratorParams p; p.ppm_seed = 0xE0E0E0EE;
        crypto::stego::MediaGenerator::generate_ppm(SRC, 256, 256, p);
    }
    if (!std::filesystem::exists(IMG)) crypto::stego::MediaGenerator::generate_ppm(IMG, 640, 480);
    if (!std::filesystem::exists(WAV)) crypto::stego::MediaGenerator::generate_wav(WAV, 44100, 1, 10.0);
}

TEST("entropy_stego/make-vault-and-seal-into") {
    ensure_files();
    auto me = crypto::entropy::MediaEntropy::from_file(SRC);
    REQUIRE(me.is_ok());
    auto vault = me.value().make_vault();
    REQUIRE(vault.is_ok());

    auto r = vault.value().seal_into(IMG, "entropy-seeded secret", "/tmp/es_stego.ppm", "ctx");
    REQUIRE(r.is_ok());
    auto pt = vault.value().open_from("/tmp/es_stego.ppm", "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "entropy-seeded secret");
}

TEST("entropy_stego/audio-carrier") {
    ensure_files();
    auto me    = crypto::entropy::MediaEntropy::from_file(SRC);
    REQUIRE(me.is_ok());
    auto vault = me.value().make_vault();
    REQUIRE(vault.is_ok());

    auto r = vault.value().seal_into(WAV, "covert audio channel", "/tmp/es_stego.wav", "wav-ctx");
    REQUIRE(r.is_ok());
    auto pt = vault.value().open_from("/tmp/es_stego.wav", "wav-ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "covert audio channel");
}

TEST("entropy_stego/different-entropy-sources-different-vaults") {
    ensure_files();
    // Two MediaEntropy objects from the same file produce different vaults
    // because system entropy is mixed on construction.
    auto me1 = crypto::entropy::MediaEntropy::from_file(SRC);
    auto me2 = crypto::entropy::MediaEntropy::from_file(SRC);
    REQUIRE(me1.is_ok()); REQUIRE(me2.is_ok());

    auto v1 = me1.value().make_vault(); REQUIRE(v1.is_ok());
    auto v2 = me2.value().make_vault(); REQUIRE(v2.is_ok());

    // v1 seals into image; v2 cannot open it
    REQUIRE(v1.value().seal_into(IMG, "test", "/tmp/es_diff.ppm", "aad").is_ok());
    auto bad = v2.value().open_from("/tmp/es_diff.ppm", "aad");
    CHECK_ERR(bad);
}

TEST("entropy_stego/vault-from-file-convenience") {
    ensure_files();
    auto v = crypto::entropy::vault_from_file(SRC);
    REQUIRE(v.is_ok());
    auto r = v.value().seal_into(IMG, "convenience path", "/tmp/es_conv.ppm", "c");
    REQUIRE(r.is_ok());
    auto pt = v.value().open_from("/tmp/es_conv.ppm", "c");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "convenience path");
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_entropy_stego() {
    RUN("entropy_stego/make-vault-and-seal-into");
    RUN("entropy_stego/audio-carrier");
    RUN("entropy_stego/different-entropy-sources-different-vaults");
    RUN("entropy_stego/vault-from-file-convenience");
}
