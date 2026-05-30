#include "test_framework.hpp"
using namespace test;

#ifdef CRYPTOLIB_HAS_PQ

using crypto::pq::HybridKem;
using crypto::pq::MlKem;

// ─── X25519 + ML-KEM-768 hybrid KEM tests ───────────────────────────────────

TEST("hybrid/keypair-sizes") {
    auto sz = HybridKem::sizes();
    REQUIRE(sz.is_ok());
    auto mk = MlKem::sizes(MlKem::Level::KEM_768);
    REQUIRE(mk.is_ok());
    // public/secret/ciphertext = 32-byte X25519 part + the ML-KEM-768 part.
    CHECK(sz.value().public_key == 32 + mk.value().public_key);
    CHECK(sz.value().secret_key == 32 + mk.value().secret_key);
    CHECK(sz.value().ciphertext == 32 + mk.value().ciphertext);
    CHECK(sz.value().shared_secret == 32);

    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.size() == sz.value().public_key);
    CHECK(kp.value().secret_key.size() == sz.value().secret_key);
}

TEST("hybrid/encaps-decaps-round-trip") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());

    auto enc = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());
    CHECK(enc.value().shared_secret.size() == 32);

    auto dec = HybridKem::decapsulate(enc.value().ciphertext.span(),
                                      kp.value().secret_key.span());
    REQUIRE(dec.is_ok());
    CHECK(dec.value().size() == 32);

    // Encapsulator and decapsulator must agree on the shared secret.
    CHECK(crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
}

TEST("hybrid/decapsulate-is-deterministic") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    auto d1 = HybridKem::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    auto d2 = HybridKem::decapsulate(enc.value().ciphertext.span(), kp.value().secret_key.span());
    REQUIRE(d1.is_ok());
    REQUIRE(d2.is_ok());
    CHECK(crypto::secure_equal(d1.value().span(), d2.value().span()));
}

TEST("hybrid/wrong-secret-key-different-secret") {
    auto alice = HybridKem::generate_keypair();
    auto mallory = HybridKem::generate_keypair();
    REQUIRE(alice.is_ok());
    REQUIRE(mallory.is_ok());

    auto enc = HybridKem::encapsulate(alice.value().public_key.span());
    REQUIRE(enc.is_ok());

    // Mallory's secret key decapsulates without error (ML-KEM implicit
    // rejection + X25519 always yields *a* secret) but must NOT recover the
    // shared secret Alice's key would.
    auto bad = HybridKem::decapsulate(enc.value().ciphertext.span(),
                                      mallory.value().secret_key.span());
    REQUIRE(bad.is_ok());
    CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), bad.value().span()));
}

TEST("hybrid/tampered-mlkem-ciphertext") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    // Flip a byte in the ML-KEM portion (after the 32-byte X25519 prefix).
    std::vector<uint8_t> ct(enc.value().ciphertext.span().begin(),
                            enc.value().ciphertext.span().end());
    ct[40] ^= 0x01;

    auto dec = HybridKem::decapsulate(ct, kp.value().secret_key.span());
    REQUIRE(dec.is_ok());  // ML-KEM uses implicit rejection, so no error
    CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
}

TEST("hybrid/tampered-x25519-ciphertext") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    // Flip a byte in the X25519 ephemeral public key (first 32 bytes).
    std::vector<uint8_t> ct(enc.value().ciphertext.span().begin(),
                            enc.value().ciphertext.span().end());
    ct[0] ^= 0x01;

    auto dec = HybridKem::decapsulate(ct, kp.value().secret_key.span());
    // Either the DH yields a different secret, or a low-order point is rejected
    // — both are acceptable; what must NOT happen is recovering the real secret.
    if (dec.is_ok())
        CHECK(!crypto::secure_equal(enc.value().shared_secret.span(), dec.value().span()));
    else
        CHECK(true);
}

TEST("hybrid/independent-encapsulations-differ") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto e1 = HybridKem::encapsulate(kp.value().public_key.span());
    auto e2 = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(e1.is_ok());
    REQUIRE(e2.is_ok());
    // Fresh randomness each time → different ciphertexts and different secrets.
    CHECK(!crypto::secure_equal(e1.value().ciphertext.span(), e2.value().ciphertext.span()));
    CHECK(!crypto::secure_equal(e1.value().shared_secret.span(), e2.value().shared_secret.span()));
}

TEST("hybrid/bad-public-key-length") {
    std::vector<uint8_t> too_short(64, 0x00);
    auto enc = HybridKem::encapsulate(too_short);
    CHECK(enc.is_err());
}

TEST("hybrid/bad-ciphertext-and-secret-length") {
    auto kp = HybridKem::generate_keypair();
    REQUIRE(kp.is_ok());
    auto enc = HybridKem::encapsulate(kp.value().public_key.span());
    REQUIRE(enc.is_ok());

    std::vector<uint8_t> short_ct(16, 0x00);
    CHECK(HybridKem::decapsulate(short_ct, kp.value().secret_key.span()).is_err());

    std::vector<uint8_t> short_sk(16, 0x00);
    CHECK(HybridKem::decapsulate(enc.value().ciphertext.span(), short_sk).is_err());
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_hybrid() {
#ifdef CRYPTOLIB_HAS_PQ
    RUN("hybrid/keypair-sizes");
    RUN("hybrid/encaps-decaps-round-trip");
    RUN("hybrid/decapsulate-is-deterministic");
    RUN("hybrid/wrong-secret-key-different-secret");
    RUN("hybrid/tampered-mlkem-ciphertext");
    RUN("hybrid/tampered-x25519-ciphertext");
    RUN("hybrid/independent-encapsulations-differ");
    RUN("hybrid/bad-public-key-length");
    RUN("hybrid/bad-ciphertext-and-secret-length");
#endif
}
