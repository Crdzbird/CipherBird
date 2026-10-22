/* The fips profile against a real OpenSSL FIPS Provider. The module location */
/* comes from CRYPTOLIB_FIPS_MODULE_DIR and CRYPTOLIB_FIPS_CONFIG; without */
/* them the suite reports the provider as unavailable and fails, because a */
/* fips build that cannot reach its module is not a working build. */
#include "test_framework.hpp"
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
#include <cryptolib/fips/fips.hpp>
#include <cstdint>
#include <string>
#include <vector>

using namespace test;
using namespace crypto::fips;
using crypto::PublicBuffer;

namespace {
std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(std::stoul(s.substr(2 * i, 2), nullptr, 16));
    return out;
}
template <class B> std::vector<uint8_t> vec(const B& b) { return { b.span().begin(), b.span().end() }; }
std::span<const uint8_t> sp(std::string_view s) { return { reinterpret_cast<const uint8_t*>(s.data()), s.size() }; }
}

TEST("fips/provider/loads-and-enters-approved-mode") {
    auto r = Provider::init();
    if (r.is_err()) std::fprintf(stderr, "  %s\n", r.error().message.c_str());
    REQUIRE(r.is_ok());
    auto st = Provider::status();
    CHECK(st.loaded && st.self_tests_passed && st.approved_mode);
    CHECK(st.provider_name == "fips");
    CHECK(Provider::init().is_ok());
}

/* The point of the profile: a non-approved algorithm is not merely unused, */
/* it cannot be fetched. */
TEST("fips/provider/non-approved-algorithms-are-unavailable") {
    EVP_CIPHER* chacha = EVP_CIPHER_fetch(nullptr, "ChaCha20-Poly1305", Provider::PROPERTIES);
    CHECK(chacha == nullptr);
    if (chacha) EVP_CIPHER_free(chacha);
    EVP_MD* md5 = EVP_MD_fetch(nullptr, "MD5", Provider::PROPERTIES);
    CHECK(md5 == nullptr);
    if (md5) EVP_MD_free(md5);
    EVP_CIPHER* gcm = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", Provider::PROPERTIES);
    CHECK(gcm != nullptr);
    if (gcm) EVP_CIPHER_free(gcm);
}

TEST("fips/digest/sha256-known-answer") {
    auto d = Digest::compute(Hash::Sha256, sp("abc"));
    REQUIRE(d.is_ok());
    CHECK(vec(d.value()) == unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    auto s3 = Digest::compute(Hash::Sha3_256, sp("abc"));
    REQUIRE(s3.is_ok());
    CHECK(vec(s3.value()) == unhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
}

/* RFC 4231 test case 1 (key = 20 x 0x0b, data "Hi There"). */
TEST("fips/hmac/sha256-rfc4231-case1") {
    std::vector<uint8_t> key(20, 0x0b);
    auto t = Hmac::compute(Hash::Sha256, key, sp("Hi There"));
    REQUIRE(t.is_ok());
    CHECK(vec(t.value()) == unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    CHECK(Hmac::verify(Hash::Sha256, key, sp("Hi There"), t.value().span()));
    CHECK(!Hmac::verify(Hash::Sha256, key, sp("Hi there"), t.value().span()));
}

/* RFC 5869 test case 1. */
TEST("fips/hkdf/sha256-rfc5869-case1") {
    auto okm = Hkdf::derive(Hash::Sha256, std::vector<uint8_t>(22, 0x0b),
                            unhex("000102030405060708090a0b0c"), unhex("f0f1f2f3f4f5f6f7f8f9"), 42);
    REQUIRE(okm.is_ok());
    CHECK(vec(okm.value()) == unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

TEST("fips/pbkdf2/policy-and-determinism") {
    std::vector<uint8_t> salt(16, 0x55);
    auto a = Pbkdf2::derive(Hash::Sha256, sp("correct horse battery staple"), salt, 1000, 32);
    auto b = Pbkdf2::derive(Hash::Sha256, sp("correct horse battery staple"), salt, 1000, 32);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(vec(a.value()) == vec(b.value()));
    salt[0] ^= 1;
    auto c = Pbkdf2::derive(Hash::Sha256, sp("correct horse battery staple"), salt, 1000, 32);
    REQUIRE(c.is_ok());
    CHECK(vec(c.value()) != vec(a.value()));
    CHECK(Pbkdf2::derive(Hash::Sha256, sp("pw"), std::vector<uint8_t>(8, 1), 1000, 32).is_err());
    CHECK(Pbkdf2::derive(Hash::Sha256, sp("pw"), salt, 10, 32).is_err());
}

TEST("fips/aes-256-gcm/round-trip-tamper-and-fresh-iv") {
    auto key = Random::bytes(32);
    REQUIRE(key.is_ok());
    auto c1 = Aes256Gcm::encrypt(key.value().span(), sp("cardholder data"), sp("ctx"));
    auto c2 = Aes256Gcm::encrypt(key.value().span(), sp("cardholder data"), sp("ctx"));
    REQUIRE(c1.is_ok()); REQUIRE(c2.is_ok());
    CHECK(vec(c1.value()) != vec(c2.value()));
    auto p = Aes256Gcm::decrypt(key.value().span(), c1.value().span(), sp("ctx"));
    REQUIRE(p.is_ok());
    CHECK(vec(p.value()) == vec(PublicBuffer(sp("cardholder data").data(), 15)));
    auto forged = vec(c1.value()); forged[20] ^= 1;
    CHECK(Aes256Gcm::decrypt(key.value().span(), forged, sp("ctx")).is_err());
    CHECK(Aes256Gcm::decrypt(key.value().span(), c1.value().span(), sp("other")).is_err());
}

TEST("fips/p256/ecdh-and-ecdsa") {
    auto a = P256::generate_keypair();
    auto b = P256::generate_keypair();
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().public_key.size() == 65 && a.value().private_key.size() == 32);
    auto s1 = P256::ecdh(a.value().private_key.span(), b.value().public_key.span());
    auto s2 = P256::ecdh(b.value().private_key.span(), a.value().public_key.span());
    REQUIRE(s1.is_ok()); REQUIRE(s2.is_ok());
    CHECK(vec(s1.value()) == vec(s2.value()));
    CHECK(vec(P256::public_key_of(a.value().private_key.span()).value()) == vec(a.value().public_key));
    auto sig = P256::sign(a.value().private_key.span(), sp("transaction 42"));
    REQUIRE(sig.is_ok());
    CHECK(P256::verify(a.value().public_key.span(), sp("transaction 42"), sig.value().span()));
    CHECK(!P256::verify(a.value().public_key.span(), sp("transaction 43"), sig.value().span()));
    CHECK(!P256::verify(b.value().public_key.span(), sp("transaction 42"), sig.value().span()));
    std::vector<uint8_t> bad(65, 0x04);
    CHECK(P256::ecdh(a.value().private_key.span(), bad).is_err());
}

TEST("fips/envelope/passphrase-and-key-slots") {
    auto e = Envelope::create();
    REQUIRE(e.is_ok());
    REQUIRE(e.value().add_passphrase_slot(sp("correct horse battery staple"), 1000).is_ok());
    auto factor = Random::bytes(32);
    REQUIRE(factor.is_ok());
    REQUIRE(e.value().add_key_slot(factor.value().span()).is_ok());
    auto blob = e.value().serialise();
    auto loaded = Envelope::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    auto m1 = loaded.value().unlock_with_passphrase(sp("correct horse battery staple"));
    auto m2 = Envelope::deserialise(blob.span()).value().unlock_with_key(factor.value().span());
    REQUIRE(m1.is_ok()); REQUIRE(m2.is_ok());
    CHECK(vec(m1.value()) == vec(m2.value()));
    CHECK(loaded.value().unlock_with_passphrase(sp("wrong")).is_err());
    auto forged = vec(blob); forged[forged.size() - 1] ^= 1;
    auto f = Envelope::deserialise(forged);
    REQUIRE(f.is_ok());
    CHECK(f.value().unlock_with_key(factor.value().span()).is_err());
}

TEST("fips/hpke-p256/round-trip-and-tamper") {
    auto kp = HpkeP256::generate_keypair();
    REQUIRE(kp.is_ok());
    auto sealed = HpkeP256::seal(kp.value().public_key.span(), sp("app info"), sp("aad"), sp("secret payload"));
    REQUIRE(sealed.is_ok());
    CHECK(sealed.value().enc.size() == 65);
    auto pt = HpkeP256::open(sealed.value().enc.span(), kp.value().private_key.span(), kp.value().public_key.span(), sp("app info"), sp("aad"), sealed.value().ct.span());
    REQUIRE(pt.is_ok());
    CHECK(vec(pt.value()) == vec(PublicBuffer(sp("secret payload").data(), 14)));
    CHECK(HpkeP256::open(sealed.value().enc.span(), kp.value().private_key.span(), kp.value().public_key.span(), sp("other info"), sp("aad"), sealed.value().ct.span()).is_err());
    auto forged = vec(sealed.value().ct); forged[0] ^= 1;
    CHECK(HpkeP256::open(sealed.value().enc.span(), kp.value().private_key.span(), kp.value().public_key.span(), sp("app info"), sp("aad"), forged).is_err());
}

void run_tests_fips_provider() {
    RUN("fips/provider/loads-and-enters-approved-mode");
    RUN("fips/provider/non-approved-algorithms-are-unavailable");
    RUN("fips/digest/sha256-known-answer");
    RUN("fips/hmac/sha256-rfc4231-case1");
    RUN("fips/hkdf/sha256-rfc5869-case1");
    RUN("fips/pbkdf2/policy-and-determinism");
    RUN("fips/aes-256-gcm/round-trip-tamper-and-fresh-iv");
    RUN("fips/p256/ecdh-and-ecdsa");
    RUN("fips/envelope/passphrase-and-key-slots");
    RUN("fips/hpke-p256/round-trip-and-tamper");
}
#else
void run_tests_fips_provider() {}
#endif
