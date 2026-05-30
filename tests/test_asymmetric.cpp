#include "test_framework.hpp"
using namespace test;

// ─── Box ──────────────────────────────────────────────────────────────────────

TEST("asym/box/round-trip") {
    auto alice = crypto::asymmetric::Box::generate_keypair();
    auto bob   = crypto::asymmetric::Box::generate_keypair();
    auto ct    = crypto::asymmetric::Box::encrypt(
        sv2sp("secret msg"), bob.public_key.span(), alice.secret_key.span());
    REQUIRE(ct.is_ok());
    auto pt    = crypto::asymmetric::Box::decrypt(
        ct.value().span(), alice.public_key.span(), bob.secret_key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "secret msg");
}

TEST("asym/box/wrong-key-fails") {
    auto alice   = crypto::asymmetric::Box::generate_keypair();
    auto bob     = crypto::asymmetric::Box::generate_keypair();
    auto mallory = crypto::asymmetric::Box::generate_keypair();
    auto ct      = crypto::asymmetric::Box::encrypt(
        sv2sp("msg"), bob.public_key.span(), alice.secret_key.span());
    REQUIRE(ct.is_ok());
    auto bad     = crypto::asymmetric::Box::decrypt(
        ct.value().span(), alice.public_key.span(), mallory.secret_key.span());
    CHECK_ERR(bad);
}

// ─── SealedBox ───────────────────────────────────────────────────────────────

TEST("asym/sealedbox/round-trip") {
    auto bob = crypto::asymmetric::Box::generate_keypair();
    auto ct  = crypto::asymmetric::SealedBox::encrypt(
        sv2sp("anonymous message"), bob.public_key.span());
    REQUIRE(ct.is_ok());
    auto pt  = crypto::asymmetric::SealedBox::decrypt(
        ct.value().span(), bob.public_key.span(), bob.secret_key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "anonymous message");
}

// ─── Ed25519 ──────────────────────────────────────────────────────────────────

TEST("asym/ed25519/sign-verify") {
    auto kp  = crypto::asymmetric::Ed25519::generate_keypair();
    auto sig = crypto::asymmetric::Ed25519::sign(
        sv2sp("document"), kp.secret_key.span());
    REQUIRE(sig.is_ok());
    bool ok  = crypto::asymmetric::Ed25519::verify(
        sv2sp("document"), sig.value().span(), kp.public_key.span());
    CHECK(ok);
}

TEST("asym/ed25519/wrong-key-rejected") {
    auto kp1 = crypto::asymmetric::Ed25519::generate_keypair();
    auto kp2 = crypto::asymmetric::Ed25519::generate_keypair();
    auto sig  = crypto::asymmetric::Ed25519::sign(sv2sp("doc"), kp1.secret_key.span());
    REQUIRE(sig.is_ok());
    bool bad  = crypto::asymmetric::Ed25519::verify(
        sv2sp("doc"), sig.value().span(), kp2.public_key.span());
    CHECK(!bad);
}

TEST("asym/ed25519/tampered-message-rejected") {
    auto kp  = crypto::asymmetric::Ed25519::generate_keypair();
    auto sig = crypto::asymmetric::Ed25519::sign(sv2sp("original"), kp.secret_key.span());
    REQUIRE(sig.is_ok());
    bool bad = crypto::asymmetric::Ed25519::verify(
        sv2sp("tampered"), sig.value().span(), kp.public_key.span());
    CHECK(!bad);
}

// ─── X25519 ───────────────────────────────────────────────────────────────────

TEST("asym/x25519/shared-secret") {
    auto alice = crypto::asymmetric::X25519::generate_keypair();
    auto bob   = crypto::asymmetric::X25519::generate_keypair();
    auto sa    = crypto::asymmetric::X25519::shared_secret(
        alice.secret_key.span(), bob.public_key.span());
    auto sb    = crypto::asymmetric::X25519::shared_secret(
        bob.secret_key.span(), alice.public_key.span());
    REQUIRE(sa.is_ok()); REQUIRE(sb.is_ok());
    CHECK(sa.value().to_hex() == sb.value().to_hex());
}

TEST("asym/x25519/different-keys-different-secrets") {
    auto a = crypto::asymmetric::X25519::generate_keypair();
    auto b = crypto::asymmetric::X25519::generate_keypair();
    auto c = crypto::asymmetric::X25519::generate_keypair();
    auto s1 = crypto::asymmetric::X25519::shared_secret(a.secret_key.span(), b.public_key.span());
    auto s2 = crypto::asymmetric::X25519::shared_secret(a.secret_key.span(), c.public_key.span());
    REQUIRE(s1.is_ok()); REQUIRE(s2.is_ok());
    CHECK(s1.value().to_hex() != s2.value().to_hex());
}

// ─── HybridBox ────────────────────────────────────────────────────────────────

TEST("asym/hybridbox/round-trip") {
    // HybridBox takes raw key spans, not bundles
    auto alice_box  = crypto::asymmetric::Box::generate_keypair();
    auto alice_sign = crypto::asymmetric::Ed25519::generate_keypair();
    auto bob_box    = crypto::asymmetric::Box::generate_keypair();

    auto ct = crypto::asymmetric::HybridBox::encrypt(
        sv2sp("hybrid msg"),
        bob_box.public_key.span(),
        alice_box.secret_key.span(),
        alice_sign.secret_key.span());
    REQUIRE(ct.is_ok());

    auto pt = crypto::asymmetric::HybridBox::decrypt(
        ct.value(),
        alice_box.public_key.span(),
        bob_box.secret_key.span(),
        alice_sign.public_key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "hybrid msg");
}

TEST("asym/hybridbox/forge-rejected") {
    auto alice_box    = crypto::asymmetric::Box::generate_keypair();
    auto alice_sign   = crypto::asymmetric::Ed25519::generate_keypair();
    auto mallory_box  = crypto::asymmetric::Box::generate_keypair();
    auto mallory_sign = crypto::asymmetric::Ed25519::generate_keypair();
    auto bob_box      = crypto::asymmetric::Box::generate_keypair();

    auto forged = crypto::asymmetric::HybridBox::encrypt(
        sv2sp("fake msg"),
        bob_box.public_key.span(),
        mallory_box.secret_key.span(),
        mallory_sign.secret_key.span());
    REQUIRE(forged.is_ok());

    // Verify against alice's sign key → must fail
    auto bad = crypto::asymmetric::HybridBox::decrypt(
        forged.value(),
        mallory_box.public_key.span(),
        bob_box.secret_key.span(),
        alice_sign.public_key.span());
    CHECK_ERR(bad);
}

void run_tests_asymmetric() {
    RUN("asym/box/round-trip");
    RUN("asym/box/wrong-key-fails");
    RUN("asym/sealedbox/round-trip");
    RUN("asym/ed25519/sign-verify");
    RUN("asym/ed25519/wrong-key-rejected");
    RUN("asym/ed25519/tampered-message-rejected");
    RUN("asym/x25519/shared-secret");
    RUN("asym/x25519/different-keys-different-secrets");
    RUN("asym/hybridbox/round-trip");
    RUN("asym/hybridbox/forge-rejected");
}
