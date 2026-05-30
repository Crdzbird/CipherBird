#include "test_framework.hpp"
#include <sodium.h>
using namespace test;

using crypto::symmetric::CommittingAead;
using crypto::symmetric::XChaCha20Poly1305;

// ─── Committing AEAD (UtC) tests ─────────────────────────────────────────────

TEST("committing/round-trip") {
    auto key = CommittingAead::generate_key();
    auto pt = std::string_view("commit me");
    auto ct = CommittingAead::encrypt(pt, key.span(), "ctx");
    REQUIRE(ct.is_ok());
    // wire = 32-byte commitment + (nonce|ct|tag)
    CHECK(ct.value().size() >= 32 + 24 + 16);

    auto rt = CommittingAead::decrypt(ct.value().span(), key.span(),
        std::span<const uint8_t>{reinterpret_cast<const uint8_t*>("ctx"), 3});
    REQUIRE(rt.is_ok());
    CHECK(rt.value().to_string() == "commit me");
}

TEST("committing/wrong-key-fails") {
    auto k1 = CommittingAead::generate_key();
    auto k2 = CommittingAead::generate_key();
    auto ct = CommittingAead::encrypt(std::string_view("secret"), k1.span());
    REQUIRE(ct.is_ok());
    auto bad = CommittingAead::decrypt(ct.value().span(), k2.span());
    CHECK(bad.is_err());  // commitment mismatch → fail closed
}

TEST("committing/wrong-aad-fails") {
    auto key = CommittingAead::generate_key();
    auto ct = CommittingAead::encrypt(std::string_view("secret"), key.span(), "ctx-A");
    REQUIRE(ct.is_ok());
    auto bad = CommittingAead::decrypt(ct.value().span(), key.span(),
        std::span<const uint8_t>{reinterpret_cast<const uint8_t*>("ctx-B"), 5});
    CHECK(bad.is_err());  // AAD bound into the derived keys
}

TEST("committing/tampered-commitment-fails") {
    auto key = CommittingAead::generate_key();
    auto ct = CommittingAead::encrypt(std::string_view("secret"), key.span());
    REQUIRE(ct.is_ok());
    std::vector<uint8_t> w(ct.value().span().begin(), ct.value().span().end());
    w[0] ^= 0x01;  // flip a commitment byte
    auto bad = CommittingAead::decrypt(w, key.span());
    CHECK(bad.is_err());
}

TEST("committing/tampered-body-fails") {
    auto key = CommittingAead::generate_key();
    auto ct = CommittingAead::encrypt(std::string_view("secret"), key.span());
    REQUIRE(ct.is_ok());
    std::vector<uint8_t> w(ct.value().span().begin(), ct.value().span().end());
    w.back() ^= 0x01;  // flip a tag byte in the AEAD body
    auto bad = CommittingAead::decrypt(w, key.span());
    CHECK(bad.is_err());
}

TEST("committing/short-input-fails") {
    auto key = CommittingAead::generate_key();
    std::vector<uint8_t> tooShort(16, 0);
    CHECK(CommittingAead::decrypt(tooShort, key.span()).is_err());
    std::vector<uint8_t> badKey(16, 0);
    CHECK(CommittingAead::encrypt(std::string_view("x"), badKey).is_err());
}

TEST("committing/key-commitment-property") {
    // The core guarantee: a single ciphertext must NOT open under a second key.
    // Construct a normal committing ciphertext, then confirm no other generated
    // key decrypts it (sanity proxy for non-partitionability).
    auto k1 = CommittingAead::generate_key();
    auto ct = CommittingAead::encrypt(std::string_view("salamander"), k1.span());
    REQUIRE(ct.is_ok());
    bool anyOther = false;
    for (int i = 0; i < 64; ++i) {
        auto k = CommittingAead::generate_key();
        if (CommittingAead::decrypt(ct.value().span(), k.span()).is_ok()) { anyOther = true; break; }
    }
    CHECK(!anyOther);
}

TEST("committing/deterministic-commit-same-context") {
    // Same (key, aad) ⇒ same commitment prefix (commitment is to context, not msg).
    auto key = CommittingAead::generate_key();
    auto a = CommittingAead::encrypt(std::string_view("msg-1"), key.span(), "ctx");
    auto b = CommittingAead::encrypt(std::string_view("msg-2-different"), key.span(), "ctx");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    bool sameCommit = std::equal(a.value().span().begin(), a.value().span().begin() + 32,
                                 b.value().span().begin());
    CHECK(sameCommit);
    // ...but bodies differ (fresh nonce + different plaintext).
    bool sameBody = a.value().size() == b.value().size() &&
                    std::equal(a.value().span().begin() + 32, a.value().span().end(),
                               b.value().span().begin() + 32);
    CHECK(!sameBody);
}

// Differential check (the property fuzz_diff_aead.cpp fuzzes broadly): the
// XChaCha20-Poly1305 *wrapper* must interoperate byte-for-byte with raw
// libsodium — catches framing/length deviations in our wrapper.
TEST("diff/xchacha-wrapper-interops-with-libsodium") {
    auto key = XChaCha20Poly1305::generate_key();
    const std::string_view msg = "differential check payload";
    const std::string_view aad = "ctx";
    auto m = std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};
    auto a = std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(aad.data()), aad.size()};

    // CryptoLib encrypt → raw libsodium must decrypt to the same plaintext.
    auto w = XChaCha20Poly1305::encrypt(m, key.span(), a);
    REQUIRE(w.is_ok());
    auto wire = w.value().span();
    std::vector<uint8_t> ref(msg.size());
    unsigned long long ref_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ref.data(), &ref_len, nullptr,
        wire.data() + 24, wire.size() - 24, a.data(), a.size(),
        wire.data(), key.span().data());
    CHECK(rc == 0 && ref_len == msg.size() &&
          std::equal(ref.begin(), ref.end(), m.begin()));
}

void run_tests_committing() {
    RUN("committing/round-trip");
    RUN("committing/wrong-key-fails");
    RUN("committing/wrong-aad-fails");
    RUN("committing/tampered-commitment-fails");
    RUN("committing/tampered-body-fails");
    RUN("committing/short-input-fails");
    RUN("committing/key-commitment-property");
    RUN("committing/deterministic-commit-same-context");
    RUN("diff/xchacha-wrapper-interops-with-libsodium");
}
