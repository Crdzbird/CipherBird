#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

// ─── ML-KEM (FIPS 203) tests ────────────────────────────────────────────────

TEST("pq/ml-kem/keypair-512") {
    auto kp = crypto::pq::MlKem::generate_keypair(crypto::pq::MlKem::Level::KEM_512);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 800);
    CHECK(kp.value().secret_key.size() == 1632);
}

TEST("pq/ml-kem/keypair-768") {
    auto kp = crypto::pq::MlKem::generate_keypair(crypto::pq::MlKem::Level::KEM_768);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 1184);
    CHECK(kp.value().secret_key.size() == 2400);
}

TEST("pq/ml-kem/keypair-1024") {
    auto kp = crypto::pq::MlKem::generate_keypair(crypto::pq::MlKem::Level::KEM_1024);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 1568);
    CHECK(kp.value().secret_key.size() == 3168);
}

TEST("pq/ml-kem/encaps-decaps-round-trip") {
    auto kp = crypto::pq::MlKem::generate_keypair();
    REQUIRE(kp.is_ok());

    auto enc = crypto::pq::MlKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    CHECK(enc.value().shared_secret.size() == 32);

    auto dec = crypto::pq::MlKem::decapsulate(
        enc.value().ciphertext.span(), kp.value().secret_key.span());
    REQUIRE(dec.is_ok());
    CHECK(dec.value().size() == 32);

    // Both sides must derive the same shared secret
    CHECK(enc.value().shared_secret.to_hex() == dec.value().to_hex());
}

TEST("pq/ml-kem/wrong-key-different-secret") {
    auto alice = crypto::pq::MlKem::generate_keypair();
    auto bob   = crypto::pq::MlKem::generate_keypair();
    REQUIRE(alice.is_ok()); REQUIRE(bob.is_ok());

    // Encapsulate to Alice's public key
    auto enc = crypto::pq::MlKem::encapsulate(alice.value().public_key.span());
    REQUIRE(enc.is_ok());

    // Bob tries to decapsulate with his own secret key — must not match
    auto dec = crypto::pq::MlKem::decapsulate(
        enc.value().ciphertext.span(), bob.value().secret_key.span());
    REQUIRE(dec.is_ok());  // ML-KEM always returns a value (implicit rejection)
    CHECK(enc.value().shared_secret.to_hex() != dec.value().to_hex());
}

TEST("pq/ml-kem/all-levels-round-trip") {
    for (auto level : { crypto::pq::MlKem::Level::KEM_512,
                        crypto::pq::MlKem::Level::KEM_768,
                        crypto::pq::MlKem::Level::KEM_1024 }) {
        auto kp = crypto::pq::MlKem::generate_keypair(level);
        REQUIRE(kp.is_ok());
        auto enc = crypto::pq::MlKem::encapsulate(kp.value().public_key.span(), level);
        REQUIRE(enc.is_ok());
        auto dec = crypto::pq::MlKem::decapsulate(
            enc.value().ciphertext.span(), kp.value().secret_key.span(), level);
        REQUIRE(dec.is_ok());
        CHECK(enc.value().shared_secret.to_hex() == dec.value().to_hex());
    }
}

TEST("pq/ml-kem/sizes-query") {
    auto s = crypto::pq::MlKem::sizes(crypto::pq::MlKem::Level::KEM_768);
    REQUIRE(s.is_ok());
    CHECK(s.value().public_key == 1184);
    CHECK(s.value().secret_key == 2400);
    CHECK(s.value().ciphertext == 1088);
    CHECK(s.value().shared_secret == 32);
}

TEST("pq/ml-kem/bad-public-key-length") {
    auto enc = crypto::pq::MlKem::encapsulate(
        std::span<const uint8_t>{}, crypto::pq::MlKem::Level::KEM_768);
    CHECK_ERR(enc);
}

// ─── ML-DSA (FIPS 204) tests ────────────────────────────────────────────────

TEST("pq/ml-dsa/keypair-44") {
    auto kp = crypto::pq::MlDsa::generate_keypair(crypto::pq::MlDsa::Level::DSA_44);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 1312);
    CHECK(kp.value().secret_key.size() == 2560);
}

TEST("pq/ml-dsa/keypair-65") {
    auto kp = crypto::pq::MlDsa::generate_keypair(crypto::pq::MlDsa::Level::DSA_65);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 1952);
    CHECK(kp.value().secret_key.size() == 4032);
}

TEST("pq/ml-dsa/keypair-87") {
    auto kp = crypto::pq::MlDsa::generate_keypair(crypto::pq::MlDsa::Level::DSA_87);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 2592);
    CHECK(kp.value().secret_key.size() == 4896);
}

TEST("pq/ml-dsa/sign-verify-round-trip") {
    auto kp = crypto::pq::MlDsa::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::pq::MlDsa::sign("Hello, post-quantum world!", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK(!sig.value().empty());

    auto v = crypto::pq::MlDsa::verify("Hello, post-quantum world!", sig.value().span(),
                                         kp.value().public_key.span());
    CHECK(v.is_ok());
}

TEST("pq/ml-dsa/tampered-message-rejected") {
    auto kp = crypto::pq::MlDsa::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::pq::MlDsa::sign("original message", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::pq::MlDsa::verify("tampered message", sig.value().span(),
                                         kp.value().public_key.span());
    CHECK(v.is_err());
}

TEST("pq/ml-dsa/wrong-public-key-rejected") {
    auto alice = crypto::pq::MlDsa::generate_keypair();
    auto bob   = crypto::pq::MlDsa::generate_keypair();
    REQUIRE(alice.is_ok()); REQUIRE(bob.is_ok());

    auto sig = crypto::pq::MlDsa::sign("signed by alice", alice.value().secret_key.span());
    REQUIRE(sig.is_ok());

    // Verify with Bob's public key — must fail
    auto v = crypto::pq::MlDsa::verify("signed by alice", sig.value().span(),
                                         bob.value().public_key.span());
    CHECK(v.is_err());
}

TEST("pq/ml-dsa/binary-message") {
    auto kp = crypto::pq::MlDsa::generate_keypair();
    REQUIRE(kp.is_ok());

    auto random_msg = crypto::random_bytes(4096);
    auto sig = crypto::pq::MlDsa::sign(random_msg.span(), kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::pq::MlDsa::verify(random_msg.span(), sig.value().span(),
                                         kp.value().public_key.span());
    CHECK(v.is_ok());
}

TEST("pq/ml-dsa/all-levels-round-trip") {
    for (auto level : { crypto::pq::MlDsa::Level::DSA_44,
                        crypto::pq::MlDsa::Level::DSA_65,
                        crypto::pq::MlDsa::Level::DSA_87 }) {
        auto kp = crypto::pq::MlDsa::generate_keypair(level);
        REQUIRE(kp.is_ok());
        auto sig = crypto::pq::MlDsa::sign("test", kp.value().secret_key.span(), level);
        REQUIRE(sig.is_ok());
        auto v = crypto::pq::MlDsa::verify("test", sig.value().span(),
                                              kp.value().public_key.span(), level);
        CHECK(v.is_ok());
    }
}

TEST("pq/ml-dsa/sizes-query") {
    auto s = crypto::pq::MlDsa::sizes(crypto::pq::MlDsa::Level::DSA_65);
    REQUIRE(s.is_ok());
    CHECK(s.value().public_key == 1952);
    CHECK(s.value().secret_key == 4032);
    CHECK(s.value().signature == 3309);
}

// ─── SLH-DSA (FIPS 205) tests ───────────────────────────────────────────────

TEST("pq/slh-dsa/keypair-128f-sha2") {
    auto kp = crypto::pq::SlhDsa::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == 32);
    CHECK(kp.value().secret_key.size() == 64);
}

TEST("pq/slh-dsa/sign-verify-round-trip") {
    auto kp = crypto::pq::SlhDsa::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::pq::SlhDsa::sign("SLH-DSA test message", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK(!sig.value().empty());

    auto v = crypto::pq::SlhDsa::verify("SLH-DSA test message", sig.value().span(),
                                          kp.value().public_key.span());
    CHECK(v.is_ok());
}

TEST("pq/slh-dsa/tampered-message-rejected") {
    auto kp = crypto::pq::SlhDsa::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::pq::SlhDsa::sign("original", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::pq::SlhDsa::verify("tampered", sig.value().span(),
                                          kp.value().public_key.span());
    CHECK(v.is_err());
}

TEST("pq/slh-dsa/wrong-key-rejected") {
    auto alice = crypto::pq::SlhDsa::generate_keypair();
    auto bob   = crypto::pq::SlhDsa::generate_keypair();
    REQUIRE(alice.is_ok()); REQUIRE(bob.is_ok());

    auto sig = crypto::pq::SlhDsa::sign("msg", alice.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::pq::SlhDsa::verify("msg", sig.value().span(),
                                          bob.value().public_key.span());
    CHECK(v.is_err());
}

TEST("pq/slh-dsa/shake-hash-family") {
    using SLH = crypto::pq::SlhDsa;

    auto kp = SLH::generate_keypair(SLH::Level::L128f, SLH::HashFamily::SHAKE);
    REQUIRE(kp.is_ok());

    auto sig = SLH::sign("shake test", kp.value().secret_key.span(),
                          SLH::Level::L128f, SLH::HashFamily::SHAKE);
    REQUIRE(sig.is_ok());

    auto v = SLH::verify("shake test", sig.value().span(), kp.value().public_key.span(),
                           SLH::Level::L128f, SLH::HashFamily::SHAKE);
    CHECK(v.is_ok());
}

TEST("pq/slh-dsa/128s-small-signatures") {
    using SLH = crypto::pq::SlhDsa;

    auto kp = SLH::generate_keypair(SLH::Level::L128s);
    REQUIRE(kp.is_ok());

    auto sig = SLH::sign("small sig test", kp.value().secret_key.span(), SLH::Level::L128s);
    REQUIRE(sig.is_ok());

    // 128s signatures should be ~7856 bytes (smaller than 128f ~17088)
    auto sizes_s = SLH::sizes(SLH::Level::L128s);
    auto sizes_f = SLH::sizes(SLH::Level::L128f);
    REQUIRE(sizes_s.is_ok()); REQUIRE(sizes_f.is_ok());
    CHECK(sizes_s.value().signature < sizes_f.value().signature);

    auto v = SLH::verify("small sig test", sig.value().span(),
                           kp.value().public_key.span(), SLH::Level::L128s);
    CHECK(v.is_ok());
}

TEST("pq/slh-dsa/sizes-query") {
    auto s = crypto::pq::SlhDsa::sizes(crypto::pq::SlhDsa::Level::L128f);
    REQUIRE(s.is_ok());
    CHECK(s.value().public_key == 32);
    CHECK(s.value().secret_key == 64);
    CHECK(s.value().signature == 17088);
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_pq() {
#ifdef CRYPTOLIB_HAS_PQ
    // ML-KEM
    RUN("pq/ml-kem/keypair-512");
    RUN("pq/ml-kem/keypair-768");
    RUN("pq/ml-kem/keypair-1024");
    RUN("pq/ml-kem/encaps-decaps-round-trip");
    RUN("pq/ml-kem/wrong-key-different-secret");
    RUN("pq/ml-kem/all-levels-round-trip");
    RUN("pq/ml-kem/sizes-query");
    RUN("pq/ml-kem/bad-public-key-length");
    // ML-DSA
    RUN("pq/ml-dsa/keypair-44");
    RUN("pq/ml-dsa/keypair-65");
    RUN("pq/ml-dsa/keypair-87");
    RUN("pq/ml-dsa/sign-verify-round-trip");
    RUN("pq/ml-dsa/tampered-message-rejected");
    RUN("pq/ml-dsa/wrong-public-key-rejected");
    RUN("pq/ml-dsa/binary-message");
    RUN("pq/ml-dsa/all-levels-round-trip");
    RUN("pq/ml-dsa/sizes-query");
    // SLH-DSA
    RUN("pq/slh-dsa/keypair-128f-sha2");
    RUN("pq/slh-dsa/sign-verify-round-trip");
    RUN("pq/slh-dsa/tampered-message-rejected");
    RUN("pq/slh-dsa/wrong-key-rejected");
    RUN("pq/slh-dsa/shake-hash-family");
    RUN("pq/slh-dsa/128s-small-signatures");
    RUN("pq/slh-dsa/sizes-query");
#endif
}
