#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

using crypto::pq::Sntrup761;
using crypto::pq::SntrupX25519;

// ─── X25519 + sntrup761 hybrid KEM tests ────────────────────────────────────
// Mirrors the ML-KEM hybrid suite. sntrup761 (NTRU Prime) is a different lattice
// family than ML-KEM, so this is the defense-in-diversity hybrid.

TEST("sntrup/keypair-sizes") {
    auto sz = SntrupX25519::sizes();
    REQUIRE(sz.is_ok());
    auto s = Sntrup761::sizes();
    REQUIRE(s.is_ok());
    // Fixed sntrup761 parameter sizes (liboqs): pk=1158, sk=1763, ct=1039, ss=32.
    CHECK(s.value().public_key == 1158);
    CHECK(s.value().secret_key == 1763);
    CHECK(s.value().ciphertext == 1039);
    CHECK(s.value().shared_secret == 32);
    // Hybrid = 32-byte X25519 part + the sntrup761 part.
    CHECK(sz.value().public_key == 32 + s.value().public_key);
    CHECK(sz.value().secret_key == 32 + s.value().secret_key);
    CHECK(sz.value().ciphertext == 32 + s.value().ciphertext);
    CHECK(sz.value().shared_secret == 32);

    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == sz.value().public_key);
    CHECK(kp.value().secret_key.size() == sz.value().secret_key);
}

TEST("sntrup/encaps-decaps-round-trip") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());

    auto enc = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    CHECK(enc.value().shared_secret.size() == 32);

    auto dec = SntrupX25519::decapsulate(enc.value().ciphertext.span(),
                                         kp.value().secret_key.span());
    REQUIRE(dec.is_ok());
    CHECK(dec.value().size() == 32);
    CHECK(crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
}

TEST("sntrup/decapsulate-is-deterministic") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    auto d1 = SntrupX25519::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    auto d2 = SntrupX25519::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    REQUIRE(d1.is_ok());
    REQUIRE(d2.is_ok());
    CHECK(crypto::secure_equal(d1.value().span(), d2.value().span()));
}

TEST("sntrup/wrong-secret-key-different-secret") {
    auto alice = SntrupX25519::generate_keypair();
    auto mallory = SntrupX25519::generate_keypair();
    REQUIRE(alice.is_ok());
    REQUIRE(mallory.is_ok());

    auto enc = SntrupX25519::encapsulate(alice.value().public_key.span());
    REQUIRE(enc.is_ok());

    auto bad = SntrupX25519::decapsulate(enc.value().ciphertext.span(),
                                         mallory.value().secret_key.span());
    REQUIRE(bad.is_ok());
    CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), bad.value().span()));
}

TEST("sntrup/tampered-sntrup-ciphertext") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    // Flip a byte in the sntrup761 portion (after the 32-byte X25519 prefix).
    std::vector<uint8_t> ct(enc.value().ciphertext.span().begin(),
                            enc.value().ciphertext.span().end());
    ct[40] ^= 0x01;

    auto dec = SntrupX25519::decapsulate(ct, kp.value().secret_key.span());
    REQUIRE(dec.is_ok());  // sntrup761 uses implicit rejection, so no error
    CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
}

TEST("sntrup/tampered-x25519-ciphertext") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    std::vector<uint8_t> ct(enc.value().ciphertext.span().begin(),
                            enc.value().ciphertext.span().end());
    ct[0] ^= 0x01;  // X25519 ephemeral public key (first 32 bytes)

    auto dec = SntrupX25519::decapsulate(ct, kp.value().secret_key.span());
    if (dec.is_ok())
        CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
    else
        CHECK(true);
}

// Cross-hybrid domain separation: sntrup and ML-KEM combiners use distinct
// labels, so even if the component secrets somehow matched, the derived keys
// would not — here we simply confirm independent encapsulations differ.
TEST("sntrup/independent-encapsulations-differ") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    auto e1 = SntrupX25519::encapsulate(kp.value().public_key.span());
    auto e2 = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(e1.is_ok());
    REQUIRE(e2.is_ok());
    CHECK(!crypto::secure_equal(e1.value().ciphertext.span(), e2.value().ciphertext.span()));
    CHECK(!crypto::secure_equal(e1.value().shared_secret.span(), e2.value().shared_secret.span()));
}

TEST("sntrup/bad-public-key-length") {
    std::vector<uint8_t> too_short(64, 0x00);
    auto enc = SntrupX25519::encapsulate(too_short);
    CHECK(enc.is_err());
}

TEST("sntrup/bad-ciphertext-and-secret-length") {
    auto kp = SntrupX25519::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = SntrupX25519::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    std::vector<uint8_t> short_ct(16, 0x00);
    CHECK(SntrupX25519::decapsulate(short_ct, kp.value().secret_key.span()).is_err());

    std::vector<uint8_t> short_sk(16, 0x00);
    CHECK(SntrupX25519::decapsulate(enc.value().ciphertext.span(), short_sk).is_err());
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_sntrup_x25519() {
#ifdef CRYPTOLIB_HAS_PQ
    RUN("sntrup/keypair-sizes");
    RUN("sntrup/encaps-decaps-round-trip");
    RUN("sntrup/decapsulate-is-deterministic");
    RUN("sntrup/wrong-secret-key-different-secret");
    RUN("sntrup/tampered-sntrup-ciphertext");
    RUN("sntrup/tampered-x25519-ciphertext");
    RUN("sntrup/independent-encapsulations-differ");
    RUN("sntrup/bad-public-key-length");
    RUN("sntrup/bad-ciphertext-and-secret-length");
#endif
}
