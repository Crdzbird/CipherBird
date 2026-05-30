#include "test_framework.hpp"
#include <filesystem>
using namespace test;

static const char* ENTROPY_FILE = "/tmp/test_vault_entropy.ppm";

static void ensure_entropy_cover() {
    if (!std::filesystem::exists(ENTROPY_FILE))
        (void)crypto::stego::MediaGenerator::generate_ppm(ENTROPY_FILE, 64, 64);
}

// ─── SecureVault — basic pipeline ─────────────────────────────────────────────

TEST("vault/secure/round-trip") {
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt   = vault.seal("top secret data", "ctx");
    REQUIRE(pkt.is_ok());
    auto pt    = vault.open(pkt.value(), "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "top secret data");
}

TEST("vault/secure/wrong-aad-rejected") {
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt   = vault.seal("data", "correct-aad");
    REQUIRE(pkt.is_ok());
    CHECK_ERR(vault.open(pkt.value(), "wrong-aad"));
}

TEST("vault/secure/wrong-key-rejected") {
    auto kp1 = crypto::SecureVault::generate_keypair();
    auto kp2 = crypto::SecureVault::generate_keypair();
    auto k1  = crypto::random_bytes(32);
    auto k2  = crypto::random_bytes(32);
    auto v1  = crypto::SecureVault(k1.span(), std::move(kp1));
    auto v2  = crypto::SecureVault(k2.span(), std::move(kp2));

    auto pkt  = v1.seal("data", "aad");
    REQUIRE(pkt.is_ok());
    CHECK_ERR(v2.open(pkt.value(), "aad"));
}

TEST("vault/secure/public-key-accessible") {
    auto kp  = crypto::SecureVault::generate_keypair();
    auto key = crypto::random_bytes(32);
    auto v   = crypto::SecureVault(key.span(), std::move(kp));
    CHECK(v.public_key().size() == 32);
}

TEST("vault/secure/packet-serialise-round-trip") {
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt  = vault.seal("payload", "aad");
    REQUIRE(pkt.is_ok());
    auto flat = pkt.value().serialise();
    auto pkt2 = crypto::EncryptedPacket::deserialise(flat.span());
    REQUIRE(pkt2.is_ok());
    auto pt   = vault.open(pkt2.value(), "aad");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "payload");
}

TEST("vault/secure/empty-plaintext") {
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));
    auto pkt   = vault.seal("", "");
    REQUIRE(pkt.is_ok());
    auto pt    = vault.open(pkt.value(), "");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().size() == 0);
}

// ─── SecureVault — entropy boost ──────────────────────────────────────────────
//
// These tests verify that:
//   (a) sealing with entropy boost and opening with the same boost succeeds
//   (b) seal with boost + open WITHOUT boost fails
//   (c) seal WITHOUT boost + open with boost fails
//   (d) different entropy sources produce different ciphertexts (but same plain)
//   (e) the MediaEntropy convenience overload works identically to span overload

TEST("vault/secure/entropy-boost/round-trip-span") {
    // Use a deterministic entropy object so both seal and open derive the same boost
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());
    auto& me = me_r.value();

    auto boost = me.entropy_boost();    // 32-byte boost key
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt = vault.seal(
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("boosted"), 7 },
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("ctx"), 3 },
        boost.span());
    REQUIRE(pkt.is_ok());

    auto pt = vault.open(
        pkt.value(),
        vault.public_key(),
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("ctx"), 3 },
        boost.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "boosted");
}

TEST("vault/secure/entropy-boost/round-trip-media-entropy-overload") {
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());
    auto& me = me_r.value();

    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    // MediaEntropy overload — ergonomic API
    auto pkt = vault.seal("boosted data", "ctx", me);
    REQUIRE(pkt.is_ok());

    auto pt = vault.open(pkt.value(), "ctx", me);
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "boosted data");
}

TEST("vault/secure/entropy-boost/missing-boost-fails-open") {
    // Sealing WITH boost; opening WITHOUT must fail (wrong key derived)
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());

    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt = vault.seal("secret", "ctx", me_r.value());
    REQUIRE(pkt.is_ok());

    // Open without entropy boost → wrong derived key → decryption must fail
    auto bad = vault.open(pkt.value(), "ctx");
    CHECK_ERR(bad);
}

TEST("vault/secure/entropy-boost/spurious-boost-fails-open") {
    // Sealing WITHOUT boost; opening WITH boost must fail
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());

    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt = vault.seal("secret", "ctx");            // no boost
    REQUIRE(pkt.is_ok());

    auto bad = vault.open(pkt.value(), "ctx", me_r.value());  // boost present
    CHECK_ERR(bad);
}

TEST("vault/secure/entropy-boost/changes-ciphertext") {
    // Same plaintext + same vault + different entropy → different ciphertexts
    ensure_entropy_cover();
    auto me1_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me1_r.is_ok());
    auto& me1 = me1_r.value();

    // Create a second entropy object with different content
    const char* FILE2 = "/tmp/test_vault_entropy2.ppm";
    if (!std::filesystem::exists(FILE2)) {
        crypto::stego::MediaGeneratorParams p;
        p.ppm_seed = 0x12345678;   // different seed → different pixels
        (void)crypto::stego::MediaGenerator::generate_ppm(FILE2, 64, 64, p);
    }
    auto me2_r = crypto::entropy::MediaEntropy::from_file_deterministic(FILE2);
    REQUIRE(me2_r.is_ok());
    auto& me2 = me2_r.value();

    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt1 = vault.seal("same plaintext", "ctx", me1);
    auto pkt2 = vault.seal("same plaintext", "ctx", me2);
    REQUIRE(pkt1.is_ok());
    REQUIRE(pkt2.is_ok());

    // Different entropy → different ciphertext bytes
    CHECK(pkt1.value().ciphertext.to_hex() != pkt2.value().ciphertext.to_hex());

    // Each opens with its own entropy
    auto pt1 = vault.open(pkt1.value(), "ctx", me1);
    auto pt2 = vault.open(pkt2.value(), "ctx", me2);
    REQUIRE(pt1.is_ok());
    REQUIRE(pt2.is_ok());
    CHECK(pt1.value().to_string() == "same plaintext");
    CHECK(pt2.value().to_string() == "same plaintext");
}

TEST("vault/secure/entropy-boost/no-boost-same-as-before") {
    // Packets sealed WITHOUT boost are identical to the original seal() behaviour
    auto kp    = crypto::SecureVault::generate_keypair();
    auto key   = crypto::random_bytes(32);
    auto vault = crypto::SecureVault(key.span(), std::move(kp));

    auto pkt = vault.seal("data", "aad");   // original path
    REQUIRE(pkt.is_ok());
    auto pt  = vault.open(pkt.value(), "aad");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "data");
}

// ─── AsymmetricVault — basic pipeline ─────────────────────────────────────────

TEST("vault/asym/round-trip") {
    using AV   = crypto::AsymmetricVault;
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();

    auto pkt   = AV::seal("hello bob", alice, bob.box_public.span(), "ctx");
    REQUIRE(pkt.is_ok());
    auto pt    = AV::open(pkt.value(), bob, alice.sign_public.span(), "ctx");
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "hello bob");
}

TEST("vault/asym/forge-rejected") {
    using AV     = crypto::AsymmetricVault;
    auto alice   = AV::generate_bundle();
    auto bob     = AV::generate_bundle();
    auto mallory = AV::generate_bundle();

    auto forged  = AV::seal("fake", mallory, bob.box_public.span(), "ctx");
    REQUIRE(forged.is_ok());
    CHECK_ERR(AV::open(forged.value(), bob, alice.sign_public.span(), "ctx"));
}

TEST("vault/asym/wrong-aad-rejected") {
    using AV   = crypto::AsymmetricVault;
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();
    auto pkt   = AV::seal("data", alice, bob.box_public.span(), "aad1");
    REQUIRE(pkt.is_ok());
    CHECK_ERR(AV::open(pkt.value(), bob, alice.sign_public.span(), "aad2"));
}

TEST("vault/asym/wrong-recipient-rejected") {
    using AV    = crypto::AsymmetricVault;
    auto alice  = AV::generate_bundle();
    auto bob    = AV::generate_bundle();
    auto charlie = AV::generate_bundle();
    auto pkt    = AV::seal("for bob only", alice, bob.box_public.span(), "");
    REQUIRE(pkt.is_ok());
    CHECK_ERR(AV::open(pkt.value(), charlie, alice.sign_public.span(), ""));
}

// ─── AsymmetricVault — entropy boost ──────────────────────────────────────────

TEST("vault/asym/entropy-boost/round-trip") {
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());
    auto& me = me_r.value();

    using AV   = crypto::AsymmetricVault;
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();

    auto boost = me.entropy_boost();
    auto pkt   = AV::seal(
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("boosted msg"), 11 },
        alice, bob.box_public.span(),
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("ctx"), 3 },
        boost.span());
    REQUIRE(pkt.is_ok());

    auto pt = AV::open(
        pkt.value(), bob, alice.sign_public.span(),
        std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("ctx"), 3 },
        boost.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "boosted msg");
}

TEST("vault/asym/entropy-boost/media-entropy-overload") {
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());
    auto& me = me_r.value();

    using AV   = crypto::AsymmetricVault;
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();
    static constexpr char CTX2[] = "ctx", HELLO[] = "hello";
    auto aad_sp = std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(CTX2), 3 };
    auto pt_sp  = std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(HELLO), 5 };

    auto pkt = AV::seal(pt_sp, alice, bob.box_public.span(), aad_sp, me);
    REQUIRE(pkt.is_ok());
    auto pt  = AV::open(pkt.value(), bob, alice.sign_public.span(), aad_sp, me);
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "hello");
}

TEST("vault/asym/entropy-boost/missing-boost-fails") {
    ensure_entropy_cover();
    auto me_r = crypto::entropy::MediaEntropy::from_file_deterministic(ENTROPY_FILE);
    REQUIRE(me_r.is_ok());
    auto& me = me_r.value();

    using AV   = crypto::AsymmetricVault;
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();
    auto boost = me.entropy_boost();
    auto aad   = std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>("ctx"), 3 };
    static constexpr char SECRET[] = "secret";
    auto msg   = std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(SECRET), 6 };

    auto pkt = AV::seal(msg, alice, bob.box_public.span(), aad, boost.span());
    REQUIRE(pkt.is_ok());

    // Omit boost on open → wrong integrity tag → must fail
    auto bad = AV::open(pkt.value(), bob, alice.sign_public.span(), aad);
    CHECK_ERR(bad);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_vault() {
    RUN("vault/secure/round-trip");
    RUN("vault/secure/wrong-aad-rejected");
    RUN("vault/secure/wrong-key-rejected");
    RUN("vault/secure/public-key-accessible");
    RUN("vault/secure/packet-serialise-round-trip");
    RUN("vault/secure/empty-plaintext");
    // Entropy boost
    RUN("vault/secure/entropy-boost/round-trip-span");
    RUN("vault/secure/entropy-boost/round-trip-media-entropy-overload");
    RUN("vault/secure/entropy-boost/missing-boost-fails-open");
    RUN("vault/secure/entropy-boost/spurious-boost-fails-open");
    RUN("vault/secure/entropy-boost/changes-ciphertext");
    RUN("vault/secure/entropy-boost/no-boost-same-as-before");
    // AsymmetricVault
    RUN("vault/asym/round-trip");
    RUN("vault/asym/forge-rejected");
    RUN("vault/asym/wrong-aad-rejected");
    RUN("vault/asym/wrong-recipient-rejected");
    // AsymmetricVault entropy boost
    RUN("vault/asym/entropy-boost/round-trip");
    RUN("vault/asym/entropy-boost/media-entropy-overload");
    RUN("vault/asym/entropy-boost/missing-boost-fails");
}
