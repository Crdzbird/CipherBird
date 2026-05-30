#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_BLS

TEST("bls/keypair/random") {
    auto kp = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().secret_key.size() == 32);
    CHECK(kp.value().public_key.size() == 48);
}

TEST("bls/keypair/from-ikm") {
    auto ikm = crypto::random_bytes(32);
    auto kp = crypto::bls::Bls12381::generate_keypair_from_ikm(ikm.span());
    REQUIRE(kp.is_ok());
    CHECK(kp.value().secret_key.size() == 32);
    CHECK(kp.value().public_key.size() == 48);
}

TEST("bls/keypair/from-ikm-deterministic") {
    auto ikm = crypto::random_bytes(64);
    auto a = crypto::bls::Bls12381::generate_keypair_from_ikm(ikm.span());
    auto b = crypto::bls::Bls12381::generate_keypair_from_ikm(ikm.span());
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().secret_key.to_hex() == b.value().secret_key.to_hex());
    CHECK(a.value().public_key.to_hex() == b.value().public_key.to_hex());
}

TEST("bls/keypair/from-ikm-too-short") {
    auto ikm = crypto::random_bytes(16);
    auto kp = crypto::bls::Bls12381::generate_keypair_from_ikm(ikm.span());
    CHECK_ERR(kp);
}

TEST("bls/sign-verify/round-trip") {
    auto kp = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::bls::Bls12381::sign("Hello BLS!", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK(sig.value().size() == 96);

    auto v = crypto::bls::Bls12381::verify("Hello BLS!", sig.value().span(),
                                            kp.value().public_key.span());
    CHECK(v.is_ok());
}

TEST("bls/sign-verify/binary-message") {
    auto kp = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(kp.is_ok());

    auto msg = crypto::random_bytes(1024);
    auto sig = crypto::bls::Bls12381::sign(msg.span(), kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::bls::Bls12381::verify(msg.span(), sig.value().span(),
                                            kp.value().public_key.span());
    CHECK(v.is_ok());
}

TEST("bls/sign-verify/tampered-message-rejected") {
    auto kp = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(kp.is_ok());

    auto sig = crypto::bls::Bls12381::sign("original", kp.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::bls::Bls12381::verify("tampered", sig.value().span(),
                                            kp.value().public_key.span());
    CHECK(v.is_err());
}

TEST("bls/sign-verify/wrong-key-rejected") {
    auto alice = crypto::bls::Bls12381::generate_keypair();
    auto bob   = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(alice.is_ok()); REQUIRE(bob.is_ok());

    auto sig = crypto::bls::Bls12381::sign("msg", alice.value().secret_key.span());
    REQUIRE(sig.is_ok());

    auto v = crypto::bls::Bls12381::verify("msg", sig.value().span(),
                                            bob.value().public_key.span());
    CHECK(v.is_err());
}

TEST("bls/aggregate/two-signatures") {
    auto alice = crypto::bls::Bls12381::generate_keypair();
    auto bob   = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(alice.is_ok()); REQUIRE(bob.is_ok());

    auto sig_a = crypto::bls::Bls12381::sign("message from alice",
                                              alice.value().secret_key.span());
    auto sig_b = crypto::bls::Bls12381::sign("message from bob",
                                              bob.value().secret_key.span());
    REQUIRE(sig_a.is_ok()); REQUIRE(sig_b.is_ok());

    std::vector<std::span<const uint8_t>> sigs = {
        sig_a.value().span(), sig_b.value().span()
    };
    auto agg = crypto::bls::Bls12381::aggregate_signatures(sigs);
    REQUIRE(agg.is_ok());
    CHECK(agg.value().size() == 96);

    // Verify aggregate
    std::vector<std::span<const uint8_t>> msgs = {
        sv2sp("message from alice"), sv2sp("message from bob")
    };
    std::vector<std::span<const uint8_t>> pks = {
        alice.value().public_key.span(), bob.value().public_key.span()
    };
    auto v = crypto::bls::Bls12381::aggregate_verify(msgs, pks, agg.value().span());
    CHECK(v.is_ok());
}

TEST("bls/aggregate/three-signers") {
    auto k1 = crypto::bls::Bls12381::generate_keypair();
    auto k2 = crypto::bls::Bls12381::generate_keypair();
    auto k3 = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(k1.is_ok()); REQUIRE(k2.is_ok()); REQUIRE(k3.is_ok());

    auto s1 = crypto::bls::Bls12381::sign("msg1", k1.value().secret_key.span());
    auto s2 = crypto::bls::Bls12381::sign("msg2", k2.value().secret_key.span());
    auto s3 = crypto::bls::Bls12381::sign("msg3", k3.value().secret_key.span());
    REQUIRE(s1.is_ok()); REQUIRE(s2.is_ok()); REQUIRE(s3.is_ok());

    std::vector<std::span<const uint8_t>> sigs = {
        s1.value().span(), s2.value().span(), s3.value().span()
    };
    auto agg = crypto::bls::Bls12381::aggregate_signatures(sigs);
    REQUIRE(agg.is_ok());

    std::vector<std::span<const uint8_t>> msgs = {
        sv2sp("msg1"), sv2sp("msg2"), sv2sp("msg3")
    };
    std::vector<std::span<const uint8_t>> pks = {
        k1.value().public_key.span(), k2.value().public_key.span(), k3.value().public_key.span()
    };
    auto v = crypto::bls::Bls12381::aggregate_verify(msgs, pks, agg.value().span());
    CHECK(v.is_ok());
}

TEST("bls/aggregate/tampered-message-rejected") {
    auto k1 = crypto::bls::Bls12381::generate_keypair();
    auto k2 = crypto::bls::Bls12381::generate_keypair();
    REQUIRE(k1.is_ok()); REQUIRE(k2.is_ok());

    auto s1 = crypto::bls::Bls12381::sign("msg1", k1.value().secret_key.span());
    auto s2 = crypto::bls::Bls12381::sign("msg2", k2.value().secret_key.span());
    REQUIRE(s1.is_ok()); REQUIRE(s2.is_ok());

    std::vector<std::span<const uint8_t>> sigs = {
        s1.value().span(), s2.value().span()
    };
    auto agg = crypto::bls::Bls12381::aggregate_signatures(sigs);
    REQUIRE(agg.is_ok());

    // Tamper one message
    std::vector<std::span<const uint8_t>> msgs = {
        sv2sp("msg1"), sv2sp("TAMPERED")
    };
    std::vector<std::span<const uint8_t>> pks = {
        k1.value().public_key.span(), k2.value().public_key.span()
    };
    auto v = crypto::bls::Bls12381::aggregate_verify(msgs, pks, agg.value().span());
    CHECK(v.is_err());
}

TEST("bls/aggregate/empty-rejected") {
    std::vector<std::span<const uint8_t>> empty;
    auto agg = crypto::bls::Bls12381::aggregate_signatures(empty);
    CHECK_ERR(agg);
}

#endif // CRYPTOLIB_HAS_BLS

void run_tests_bls() {
#ifdef CRYPTOLIB_HAS_BLS
    RUN("bls/keypair/random");
    RUN("bls/keypair/from-ikm");
    RUN("bls/keypair/from-ikm-deterministic");
    RUN("bls/keypair/from-ikm-too-short");
    RUN("bls/sign-verify/round-trip");
    RUN("bls/sign-verify/binary-message");
    RUN("bls/sign-verify/tampered-message-rejected");
    RUN("bls/sign-verify/wrong-key-rejected");
    RUN("bls/aggregate/two-signatures");
    RUN("bls/aggregate/three-signers");
    RUN("bls/aggregate/tampered-message-rejected");
    RUN("bls/aggregate/empty-rejected");
#endif
}
