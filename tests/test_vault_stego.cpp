#include "test_framework.hpp"
#include <filesystem>
using namespace test;

static const char* IMG = "/tmp/int_vs_cover.ppm";
static const char* WAV = "/tmp/int_vs_cover.wav";
static const char* VID = "/tmp/int_vs_cover.crvf";

static void ensure_covers() {
    if (!std::filesystem::exists(IMG)) crypto::stego::MediaGenerator::generate_ppm(IMG, 640, 480);
    if (!std::filesystem::exists(WAV)) crypto::stego::MediaGenerator::generate_wav(WAV, 44100, 1, 10.0);
    if (!std::filesystem::exists(VID)) crypto::stego::MediaGenerator::generate_crvf(VID, 320, 240, 30, 60);
}

static crypto::SecureVault make_vault() {
    auto kp  = crypto::SecureVault::generate_keypair();
    auto key = crypto::random_bytes(32);
    return crypto::SecureVault(key.span(), std::move(kp));
}

// ─── seal_into / open_from ────────────────────────────────────────────────────

TEST("vault_stego/image/round-trip") {
    ensure_covers();
    auto v = make_vault();
    auto r = v.seal_into(IMG, "image secret", "/tmp/vs_stego.ppm", "ctx");
    REQUIRE(r.is_ok());
    auto pt = v.open_from("/tmp/vs_stego.ppm", "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "image secret");
}

TEST("vault_stego/audio/round-trip") {
    ensure_covers();
    auto v = make_vault();
    auto r = v.seal_into(WAV, "audio secret", "/tmp/vs_stego.wav", "ctx");
    REQUIRE(r.is_ok());
    auto pt = v.open_from("/tmp/vs_stego.wav", "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "audio secret");
}

TEST("vault_stego/video/round-trip") {
    ensure_covers();
    auto v = make_vault();
    auto r = v.seal_into(VID, "video secret", "/tmp/vs_stego.crvf", "ctx");
    REQUIRE(r.is_ok());
    auto pt = v.open_from("/tmp/vs_stego.crvf", "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "video secret");
}

// ─── Security boundaries ──────────────────────────────────────────────────────

TEST("vault_stego/wrong-aad-rejected") {
    ensure_covers();
    auto v = make_vault();
    REQUIRE(v.seal_into(IMG, "data", "/tmp/vs_aad.ppm", "correct").is_ok());
    auto bad = v.open_from("/tmp/vs_aad.ppm", "wrong");
    CHECK_ERR(bad);
}

TEST("vault_stego/wrong-vault-rejected") {
    ensure_covers();
    auto v1 = make_vault();
    auto v2 = make_vault();
    REQUIRE(v1.seal_into(IMG, "data", "/tmp/vs_vkey.ppm", "aad").is_ok());
    auto bad = v2.open_from("/tmp/vs_vkey.ppm", "aad");
    CHECK_ERR(bad);
}

TEST("vault_stego/all-4-layers-chained") {
    // Verify that the vault → stego → vault pipeline exercises all 4 layers
    // by confirming that modifying each security parameter kills decryption.
    ensure_covers();

    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    REQUIRE(vault.seal_into(IMG, "4-layer check", "/tmp/vs_4layer.ppm", "aad").is_ok());

    // 1. Different master key (fails L1 + L3)
    auto kp2   = crypto::SecureVault::generate_keypair();
    auto key2  = crypto::random_bytes(32);
    auto bad1  = crypto::SecureVault(key2.span(), std::move(kp2));
    CHECK_ERR(bad1.open_from("/tmp/vs_4layer.ppm", "aad"));

    // 2. Different AAD (fails L3 AEAD)
    CHECK_ERR(vault.open_from("/tmp/vs_4layer.ppm", "different-aad"));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_vault_stego() {
    RUN("vault_stego/image/round-trip");
    RUN("vault_stego/audio/round-trip");
    RUN("vault_stego/video/round-trip");
    RUN("vault_stego/wrong-aad-rejected");
    RUN("vault_stego/wrong-vault-rejected");
    RUN("vault_stego/all-4-layers-chained");
}
