#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

using crypto::pq::TripleHybridKem;

// ─── X25519 + ML-KEM-768 + sntrup761 triple-hybrid KEM tests ────────────────
// Maximum-assurance KEM: secure unless ALL THREE families break.

TEST("triple/keypair-sizes") {
    auto sz = TripleHybridKem::sizes();
    REQUIRE(sz.is_ok());
    // 32-byte X25519 + ML-KEM-768 (1184/2400/1088) + sntrup761 (1158/1763/1039).
    CHECK(sz.value().public_key == 32 + 1184 + 1158);
    CHECK(sz.value().secret_key == 32 + 2400 + 1763);
    CHECK(sz.value().ciphertext == 32 + 1088 + 1039);
    CHECK(sz.value().shared_secret == 32);

    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == sz.value().public_key);
    CHECK(kp.value().secret_key.size() == sz.value().secret_key);
}

TEST("triple/encaps-decaps-round-trip") {
    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = TripleHybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    CHECK(enc.value().shared_secret.size() == 32);
    auto dec = TripleHybridKem::decapsulate(enc.value().ciphertext.span(),
                                            kp.value().secret_key.span());
    REQUIRE(dec.is_ok());
    CHECK(crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
}

TEST("triple/decapsulate-is-deterministic") {
    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = TripleHybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    auto d1 = TripleHybridKem::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    auto d2 = TripleHybridKem::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    REQUIRE(d1.is_ok());
    REQUIRE(d2.is_ok());
    CHECK(crypto::secure_equal(d1.value().span(), d2.value().span()));
}

TEST("triple/wrong-secret-key-different-secret") {
    auto alice = TripleHybridKem::generate_keypair();
    auto mallory = TripleHybridKem::generate_keypair();
    REQUIRE(alice.is_ok());
    REQUIRE(mallory.is_ok());
    auto enc = TripleHybridKem::encapsulate(alice.value().public_key.span());
    REQUIRE(enc.is_ok());
    auto bad = TripleHybridKem::decapsulate(enc.value().ciphertext.span(),
                                            mallory.value().secret_key.span());
    REQUIRE(bad.is_ok());  // implicit rejection on the PQ legs
    CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), bad.value().span()));
}

// Tamper each of the three ciphertext legs — the derived secret must change.
// Offsets: x25519_eph [0,32), mlkem_ct [32,1120), sntrup_ct [1120,2159).
TEST("triple/tamper-each-leg") {
    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = TripleHybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    for (std::size_t off : {std::size_t{0}, std::size_t{40}, std::size_t{1130}}) {
        std::vector<uint8_t> ct(enc.value().ciphertext.span().begin(),
                                enc.value().ciphertext.span().end());
        ct[off] ^= 0x01;
        auto dec = TripleHybridKem::decapsulate(ct, kp.value().secret_key.span());
        if (dec.is_ok())
            CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
        else
            CHECK(true);  // low-order/invalid point rejected — also acceptable
    }
}

TEST("triple/independent-encapsulations-differ") {
    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto e1 = TripleHybridKem::encapsulate(kp.value().public_key.span());
    auto e2 = TripleHybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(e1.is_ok());
    REQUIRE(e2.is_ok());
    CHECK(!crypto::secure_equal(e1.value().ciphertext.span(), e2.value().ciphertext.span()));
    CHECK(!crypto::secure_equal(e1.value().shared_secret.span(), e2.value().shared_secret.span()));
}

TEST("triple/bad-lengths-rejected") {
    std::vector<uint8_t> too_short(100, 0x00);
    CHECK(TripleHybridKem::encapsulate(too_short).is_err());
    auto kp = TripleHybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = TripleHybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    CHECK(TripleHybridKem::decapsulate(too_short, kp.value().secret_key.span()).is_err());
    CHECK(TripleHybridKem::decapsulate(enc.value().ciphertext.span(), too_short).is_err());
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_triple_hybrid_kem() {
#ifdef CRYPTOLIB_HAS_PQ
    RUN("triple/keypair-sizes");
    RUN("triple/encaps-decaps-round-trip");
    RUN("triple/decapsulate-is-deterministic");
    RUN("triple/wrong-secret-key-different-secret");
    RUN("triple/tamper-each-leg");
    RUN("triple/independent-encapsulations-differ");
    RUN("triple/bad-lengths-rejected");
#endif
}
