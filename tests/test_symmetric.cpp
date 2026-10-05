#include "test_framework.hpp"
using namespace test;

using XC  = crypto::symmetric::XChaCha20Poly1305;
using AES = crypto::symmetric::Aes256Gcm;
using SS  = crypto::symmetric::SecretStream;

TEST("sym/xchacha/round-trip") {
    auto key = XC::generate_key();
    auto ct  = XC::encrypt("hello world", key.span());
    REQUIRE(ct.is_ok());
    auto pt  = XC::decrypt(ct.value().span(), key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "hello world");
}

TEST("sym/xchacha/wrong-key-fails") {
    auto key1 = XC::generate_key();
    auto key2 = XC::generate_key();
    auto ct   = XC::encrypt("secret", key1.span());
    REQUIRE(ct.is_ok());
    auto pt   = XC::decrypt(ct.value().span(), key2.span());
    CHECK_ERR(pt);
}

TEST("sym/xchacha/with-aad") {
    auto key = XC::generate_key();
    auto ct  = XC::encrypt("payload", key.span(), "context-aad");
    REQUIRE(ct.is_ok());
    auto pt  = XC::decrypt(ct.value().span(), key.span(),
                           sv2sp("context-aad"));
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "payload");
    auto bad = XC::decrypt(ct.value().span(), key.span(),
                           sv2sp("wrong-aad"));
    CHECK_ERR(bad);
}

TEST("sym/xchacha/nonce-unique") {
    auto key = XC::generate_key();
    auto c1  = XC::encrypt("same", key.span());
    auto c2  = XC::encrypt("same", key.span());
    REQUIRE(c1.is_ok()); REQUIRE(c2.is_ok());
    CHECK(c1.value().to_hex() != c2.value().to_hex());
}

TEST("sym/xchacha/empty-plaintext") {
    auto key = XC::generate_key();
    auto ct  = XC::encrypt("", key.span());
    REQUIRE(ct.is_ok());
    auto pt  = XC::decrypt(ct.value().span(), key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().size() == 0);
}

TEST("sym/aesgcm/round-trip") {
    if (!AES::is_available()) return;
    auto key = AES::generate_key();
    auto ct  = AES::encrypt(sv2sp("aes test"), key.span());
    REQUIRE(ct.is_ok());
    auto pt  = AES::decrypt(ct.value().span(), key.span());
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "aes test");
}

TEST("sym/aesgcm/wrong-key-fails") {
    if (!AES::is_available()) return;
    auto k1 = AES::generate_key();
    auto k2 = AES::generate_key();
    auto ct = AES::encrypt(sv2sp("data"), k1.span());
    REQUIRE(ct.is_ok());
    auto pt = AES::decrypt(ct.value().span(), k2.span());
    CHECK_ERR(pt);
}

TEST("sym/secretstream/round-trip") {
    auto key  = SS::generate_key();
    SS::Encryptor enc(key.span());
    // Copy header bytes so we can use it after enc is modified
    const auto& hdr_buf = enc.header();   // returns const SecureBuffer&
    std::vector<uint8_t> hdr_copy(hdr_buf.data(), hdr_buf.data() + hdr_buf.size());

    auto c1 = enc.push(sv2sp("chunk one"), SS::TAG_MESSAGE);
    auto c2 = enc.push_final(sv2sp("chunk two"));

    SS::Decryptor dec(key.span(), {hdr_copy.data(), hdr_copy.size()});
    auto p1 = dec.pull(c1.span());
    auto p2 = dec.pull(c2.span());
    REQUIRE(p1.is_ok()); REQUIRE(p2.is_ok());
    CHECK(p1.value().plaintext.to_string() == "chunk one");
    CHECK(p2.value().plaintext.to_string() == "chunk two");
}

void run_tests_symmetric() {
    RUN("sym/xchacha/round-trip");
    RUN("sym/xchacha/wrong-key-fails");
    RUN("sym/xchacha/with-aad");
    RUN("sym/xchacha/nonce-unique");
    RUN("sym/xchacha/empty-plaintext");
    RUN("sym/aesgcm/round-trip");
    RUN("sym/aesgcm/wrong-key-fails");
    RUN("sym/secretstream/round-trip");
}

TEST("sym/aes-gcm/portable-path-interchangeable") {
    REQUIRE(AES::portable_available());
    auto key = AES::generate_key();
    auto ct_portable = AES::encrypt_portable(sv2sp("portable in"), key.span(), sv2sp("aad"));
    REQUIRE(ct_portable.is_ok());
    CHECK(ct_portable.value().size() == 12 + 11 + 16);
    auto pt = AES::decrypt(ct_portable.value().span(), key.span(), sv2sp("aad"));
    REQUIRE(pt.is_ok());
    CHECK(pt.value().to_string() == "portable in");
    auto ct = AES::encrypt(sv2sp("hardware in"), key.span(), sv2sp("aad"));
    REQUIRE(ct.is_ok());
    auto pt2 = AES::decrypt_portable(ct.value().span(), key.span(), sv2sp("aad"));
    REQUIRE(pt2.is_ok());
    CHECK(pt2.value().to_string() == "hardware in");
    auto bad = AES::decrypt_portable(ct.value().span(), key.span(), sv2sp("other"));
    CHECK_ERR(bad);
    std::vector<uint8_t> tampered(ct_portable.value().span().begin(),
                                  ct_portable.value().span().end());
    tampered[12] ^= 1;
    CHECK_ERR(AES::decrypt_portable(tampered, key.span(), sv2sp("aad")));
    auto empty = AES::encrypt_portable({}, key.span());
    REQUIRE(empty.is_ok());
    auto empty_pt = AES::decrypt(empty.value().span(), key.span());
    REQUIRE(empty_pt.is_ok());
    CHECK(empty_pt.value().size() == 0);
}
