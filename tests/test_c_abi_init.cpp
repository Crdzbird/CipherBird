#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
#include <stdexcept>
#include <string>
#include <vector>
using namespace test;

extern void (*cryptolib_testing_init_override)(void);

TEST("c-abi/init/success-returns-zero") {
    CHECK(cryptolib_init() == 0);
    CHECK(cryptolib_init() == 0);
}

TEST("c-abi/init/failure-returns-nonzero") {
    cryptolib_testing_init_override = [] { throw std::runtime_error("forced sodium_init failure"); };
    int rc = cryptolib_init();
    cryptolib_testing_init_override = nullptr;
    CHECK(rc != 0);
    CHECK(rc == -1);
    CHECK(cryptolib_init() == 0);
}

// A share record claiming a length near 2^32 must be refused by the parser;
// on a 32-bit size_t the old offset addition wrapped past the check.
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
TEST("c-abi/threshold/share-length-near-u32-max-rejected") {
    REQUIRE(cryptolib_init() == 0);
    const uint8_t pt[] = { 1, 2, 3 };
    CryptoBuffer shares{ nullptr, 0 };
    auto env = cryptolib_suite_seal_threshold(pt, sizeof pt, 3, 2, nullptr, 0, &shares);
    REQUIRE(env.error == nullptr);
    REQUIRE(shares.data != nullptr && shares.len > 5);
    std::vector<uint8_t> forged(shares.data, shares.data + shares.len);
    forged[1] = 0xff; forged[2] = 0xff; forged[3] = 0xff; forged[4] = 0xff;
    auto r = cryptolib_suite_open_threshold(env.buf.data, env.buf.len, forged.data(), forged.size(), nullptr, 0);
    CHECK(r.error != nullptr);
    if (r.error) cryptolib_str_free(r.error);
    cryptolib_buffer_free(&r.buf);
    cryptolib_buffer_free(&env.buf);
    cryptolib_buffer_free(&shares);
}

#endif

#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
TEST("c-abi/keyring/hardware-slot-functions") {
    REQUIRE(cryptolib_init() == 0);
    auto kr = cryptolib_keyring_create();
    REQUIRE(kr != nullptr);
    const uint8_t id[] = { 'k', '1' };
    auto factor = cryptolib_keyring_add_hardware_slot(kr, id, sizeof id);
    REQUIRE(factor.error == nullptr);
    CHECK(factor.buf.len == 32);
    CHECK(cryptolib_keyring_slot_type(kr, 0) == 2);
    CHECK(cryptolib_keyring_slot_type(kr, 1) == -1);
    const uint8_t blob[] = { 9, 9, 9, 9 };
    CHECK(cryptolib_keyring_set_hardware_blob(kr, 0, blob, sizeof blob) == 1);
    CHECK(cryptolib_keyring_set_hardware_blob(kr, 1, blob, sizeof blob) == 0);
    CryptoBuffer out_id{ nullptr, 0 }, out_blob{ nullptr, 0 };
    CHECK(cryptolib_keyring_hardware_slot(kr, 0, &out_id, &out_blob) == 1);
    CHECK(out_id.len == 2 && out_blob.len == 4);
    auto ser = cryptolib_keyring_serialise(kr);
    REQUIRE(ser.error == nullptr);
    char* err = nullptr;
    auto loaded = cryptolib_keyring_deserialise(ser.buf.data, ser.buf.len, &err);
    REQUIRE(loaded != nullptr);
    auto master = cryptolib_keyring_unlock_with_hardware(loaded, 0, factor.buf.data, factor.buf.len);
    CHECK(master.error == nullptr && master.buf.len == 32);
    auto bad = cryptolib_keyring_unlock_with_hardware(loaded, 0, blob, sizeof blob);
    CHECK(bad.error != nullptr);
    if (bad.error) cryptolib_str_free(bad.error);
    cryptolib_buffer_free(&bad.buf);
    cryptolib_buffer_free(&master.buf);
    cryptolib_buffer_free(&ser.buf);
    cryptolib_buffer_free(&out_id);
    cryptolib_buffer_free(&out_blob);
    cryptolib_buffer_free(&factor.buf);
    cryptolib_keyring_free(loaded);
    cryptolib_keyring_free(kr);
}

#endif


#if defined(CRYPTOLIB_HAS_SODIUM_CRYPTO) && defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
namespace {
CryptoKeyPair& bob_identity() { static CryptoKeyPair kp = cryptolib_hybrid_sig_keygen(); return kp; }
const uint8_t* bob_id_public() { return bob_identity().public_key.data; }
size_t bob_id_public_len() { return bob_identity().public_key.len; }
const uint8_t* bob_id_secret() { return bob_identity().secret_key.data; }
size_t bob_id_secret_len() { return bob_identity().secret_key.len; }
}
#endif

namespace {
std::vector<uint8_t> take(CryptoBuffer b) {
    std::vector<uint8_t> v(b.data, b.data + b.len);
    cryptolib_buffer_free(&b);
    return v;
}
std::vector<uint8_t> take_ok(CryptoBufferResult r) {
    if (r.error) {
        std::string e = r.error;
        cryptolib_str_free(r.error);
        throw std::runtime_error("C ABI error: " + e);
    }
    return take(r.buf);
}
std::vector<uint8_t> txt(const char* s) { std::string t(s); return { t.begin(), t.end() }; }
}

#if defined(CRYPTOLIB_HAS_SODIUM_CRYPTO) && defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
TEST("c-abi/v2/xwing-suite2-session2-round-trips") {
    auto bob = cryptolib_xwing_keygen();
    REQUIRE(bob.public_key.len == 1216 && bob.secret_key.len == 32);
    char* err = nullptr;
    auto enc = cryptolib_xwing_encapsulate(bob.public_key.data, bob.public_key.len, &err);
    REQUIRE(err == nullptr && enc.ciphertext.len == 1120);
    auto ss = take_ok(cryptolib_xwing_decapsulate(enc.ciphertext.data, enc.ciphertext.len, bob.secret_key.data, bob.secret_key.len));
    CHECK(ss == take(enc.shared_secret));
    cryptolib_buffer_free(&enc.ciphertext);

    auto alice = cryptolib_hybrid_sig_keygen();
    auto pt = txt("wire 100 EUR");
    auto aad = txt("ctx");
    auto env = take_ok(cryptolib_suite2_seal(pt.data(), pt.size(), bob.public_key.data, bob.public_key.len,
        alice.secret_key.data, alice.secret_key.len, aad.data(), aad.size(), CRYPTOLIB_SUITE2_XWING_SIG));
    CHECK(cryptolib_suite2_suite_of(env.data(), env.size()) == CRYPTOLIB_SUITE2_XWING_SIG);
    auto opened = take_ok(cryptolib_suite2_open(env.data(), env.size(), bob.secret_key.data, bob.secret_key.len,
        bob.public_key.data, bob.public_key.len, alice.public_key.data, alice.public_key.len, aad.data(), aad.size()));
    CHECK(opened == pt);
    auto wrong = cryptolib_suite2_open(env.data(), env.size(), bob.secret_key.data, bob.secret_key.len,
        bob.public_key.data, bob.public_key.len, alice.public_key.data, alice.public_key.len, nullptr, 0);
    CHECK(wrong.error != nullptr); cryptolib_str_free(wrong.error);

    auto prekey = cryptolib_session2_generate_prekey(alice.secret_key.data, alice.secret_key.len);
    REQUIRE(prekey.public_key.len > 1216 && prekey.secret_key.len == 32);
    auto kem_pub = take_ok(cryptolib_session2_verify_prekey(prekey.public_key.data, prekey.public_key.len,
        alice.public_key.data, alice.public_key.len));
    CHECK(kem_pub.size() == 1216);
    auto initiator = cryptolib_session2_initiate(prekey.public_key.data, prekey.public_key.len,
        alice.public_key.data, alice.public_key.len, bob_id_public(), bob_id_public_len(), bob_id_secret(), bob_id_secret_len(), &err);
    REQUIRE(initiator != nullptr && err == nullptr);
    auto hs = take_ok(cryptolib_session2_handshake(initiator));
    auto claimed = take_ok(cryptolib_session2_claimed_initiator(hs.data(), hs.size()));
    CHECK(claimed == std::vector<uint8_t>(bob_id_public(), bob_id_public() + bob_id_public_len()));
    auto responder = cryptolib_session2_accept(hs.data(), hs.size(), prekey.public_key.data, prekey.public_key.len,
        prekey.secret_key.data, prekey.secret_key.len, alice.public_key.data, alice.public_key.len,
        alice.secret_key.data, alice.secret_key.len, claimed.data(), claimed.size(), &err);
    REQUIRE(responder != nullptr && err == nullptr);
    auto m = take_ok(cryptolib_session2_encrypt(initiator, pt.data(), pt.size(), nullptr, 0));
    CHECK(take_ok(cryptolib_session2_decrypt(responder, m.data(), m.size(), nullptr, 0)) == pt);
    auto reply = take_ok(cryptolib_session2_encrypt(responder, aad.data(), aad.size(), nullptr, 0));
    CHECK(take_ok(cryptolib_session2_decrypt(initiator, reply.data(), reply.size(), nullptr, 0)) == aad);
    auto stranger = cryptolib_session2_accept(hs.data(), hs.size(), prekey.public_key.data, prekey.public_key.len,
        prekey.secret_key.data, prekey.secret_key.len, alice.public_key.data, alice.public_key.len,
        alice.secret_key.data, alice.secret_key.len, alice.public_key.data, alice.public_key.len, &err);
    CHECK(stranger == nullptr && err != nullptr); cryptolib_str_free(err);
    cryptolib_session2_free(initiator); cryptolib_session2_free(responder);
    cryptolib_keypair_free(&bob); cryptolib_keypair_free(&alice); cryptolib_keypair_free(&prekey);
    CHECK(cryptolib_hpke_kem_available(0x647A) == 1);
    auto hk = cryptolib_hpke_keygen_kem(0x0041);
    REQUIRE(hk.public_key.len == 1184 && hk.secret_key.len == 64);
    CryptoBuffer henc{nullptr, 0};
    auto s_ctx = cryptolib_hpke_setup_s_kem(0x0041, 0, 1, 0, hk.public_key.data, hk.public_key.len,
        nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, &henc, &err);
    REQUIRE(s_ctx != nullptr && err == nullptr && henc.len == 1088);
    auto r_ctx = cryptolib_hpke_setup_r_kem(0x0041, 0, 1, 0, henc.data, henc.len, hk.secret_key.data, hk.secret_key.len,
        nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, &err);
    REQUIRE(r_ctx != nullptr && err == nullptr);
    auto hct = take_ok(cryptolib_hpke_seal(s_ctx, nullptr, 0, pt.data(), pt.size()));
    CHECK(take_ok(cryptolib_hpke_open(r_ctx, nullptr, 0, hct.data(), hct.size())) == pt);
    cryptolib_hpke_context_free(s_ctx); cryptolib_hpke_context_free(r_ctx);
    cryptolib_buffer_free(&henc); cryptolib_keypair_free(&hk);
}
#endif

#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
TEST("c-abi/fips/init-digest-gcm-envelope") {
    CHECK(cryptolib_fips_available() == 1);
    auto r = cryptolib_fips_init(nullptr, nullptr);
    REQUIRE(r.ok == 1);
    auto st = cryptolib_fips_status();
    CHECK(st.loaded == 1 && st.self_tests_passed == 1 && st.approved_mode == 1);
    std::string pname(st.provider_name ? st.provider_name : "");
    CHECK(pname.find("fips") != std::string::npos || pname.find("FIPS") != std::string::npos);
    CHECK(std::string(st.provider_version ? st.provider_version : "") == "3.1.2");
    cryptolib_fips_status_free(&st);
    auto abc = txt("abc");
    auto d = take_ok(cryptolib_fips_digest(0, abc.data(), abc.size()));
    CHECK(d.size() == 32 && d[0] == 0xba && d[31] == 0xad);
    auto key = take_ok(cryptolib_fips_random(32));
    auto wire = take_ok(cryptolib_fips_aes_gcm_encrypt(key.data(), key.size(), abc.data(), abc.size(), nullptr, 0));
    CHECK(take_ok(cryptolib_fips_aes_gcm_decrypt(key.data(), key.size(), wire.data(), wire.size(), nullptr, 0)) == abc);
    char* err = nullptr;
    auto env = cryptolib_fips_envelope_create(&err);
    REQUIRE(env != nullptr);
    auto pass = txt("correct horse battery staple");
    auto a = cryptolib_fips_envelope_add_passphrase_slot(env, pass.data(), pass.size(), 1000);
    REQUIRE(a.ok == 1);
    auto blob = take_ok(cryptolib_fips_envelope_serialise(env));
    cryptolib_fips_envelope_free(env);
    auto env2 = cryptolib_fips_envelope_deserialise(blob.data(), blob.size(), &err);
    REQUIRE(env2 != nullptr);
    CHECK(cryptolib_fips_envelope_slot_count(env2) == 1);
    auto master = take_ok(cryptolib_fips_envelope_unlock_with_passphrase(env2, pass.data(), pass.size()));
    CHECK(master.size() == 32);
    cryptolib_fips_envelope_free(env2);
    auto kp = cryptolib_fips_p256_keygen();
    REQUIRE(kp.public_key.len == 65);
    CryptoBuffer enc{nullptr, 0};
    auto ct = take_ok(cryptolib_fips_hpke_p256_seal(kp.public_key.data, kp.public_key.len, nullptr, 0, nullptr, 0, abc.data(), abc.size(), &enc));
    CHECK(take_ok(cryptolib_fips_hpke_p256_open(enc.data, enc.len, kp.secret_key.data, kp.secret_key.len,
        kp.public_key.data, kp.public_key.len, nullptr, 0, nullptr, 0, ct.data(), ct.size())) == abc);
    cryptolib_buffer_free(&enc); cryptolib_keypair_free(&kp);
    CHECK(cryptolib_xwing_keygen().public_key.len == 0);
}
#else
TEST("c-abi/fips/unavailable-outside-the-fips-profile") {
    CHECK(cryptolib_fips_available() == 0);
    auto r = cryptolib_fips_digest(0, nullptr, 0);
    CHECK(r.error != nullptr); cryptolib_str_free(r.error);
    auto st = cryptolib_fips_status();
    CHECK(st.loaded == 0); cryptolib_fips_status_free(&st);
}
#endif

void run_tests_c_abi_init() {
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
    RUN("c-abi/threshold/share-length-near-u32-max-rejected");
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    RUN("c-abi/keyring/hardware-slot-functions");
#endif
    RUN("c-abi/init/success-returns-zero");
#if defined(CRYPTOLIB_HAS_SODIUM_CRYPTO) && defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
    RUN("c-abi/v2/xwing-suite2-session2-round-trips");
#endif
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
    RUN("c-abi/fips/init-digest-gcm-envelope");
#else
    RUN("c-abi/fips/unavailable-outside-the-fips-profile");
#endif
    RUN("c-abi/init/failure-returns-nonzero");
}
