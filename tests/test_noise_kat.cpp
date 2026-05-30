#include "test_framework.hpp"
#include "noise_xx_vector.h"
#include <sodium.h>
#include <string>
#include <vector>
using namespace test;

using crypto::NoiseXX;
using crypto::asymmetric::EncryptionKeyPair;

static std::vector<uint8_t> unhex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<uint8_t> o;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
static std::string hex(std::span<const uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (uint8_t x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 15]); }
    return s;
}
static EncryptionKeyPair kp_from_secret(std::span<const uint8_t> sec) {
    EncryptionKeyPair kp;
    kp.secret_key = crypto::SecureBuffer(sec.data(), sec.size());
    kp.public_key = crypto::SecureBuffer(32);
    crypto_scalarmult_base(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

// Byte-exact validation against rweather/noise-c's official vector for
// Noise_XX_25519_ChaChaPoly_SHA256. Both parties are made deterministic by
// injecting the vector's fixed ephemerals; every handshake message ciphertext,
// the handshake hash, and the transport ciphertexts must match exactly.
TEST("noise/kat/official-vector-byte-exact") {
    namespace V = noise_xx_vector;
    auto prologue = unhex(V::init_prologue);
    auto ini = NoiseXX::initiator(kp_from_secret(unhex(V::init_static)), prologue);
    auto res = NoiseXX::responder(kp_from_secret(unhex(V::resp_static)), prologue);
    ini.test_set_ephemeral(kp_from_secret(unhex(V::init_ephemeral)));
    res.test_set_ephemeral(kp_from_secret(unhex(V::resp_ephemeral)));

    // ── 3 handshake messages (alternating initiator/responder) ──
    // msg 0: initiator writes
    {
        auto m = ini.write_message(unhex(V::messages[0].payload));
        REQUIRE(m.is_ok());
        CHECK(hex(m.value().span()) == V::messages[0].ciphertext);
        auto p = res.read_message(unhex(V::messages[0].ciphertext));
        REQUIRE(p.is_ok());
        CHECK(hex(p.value().span()) == V::messages[0].payload);
    }
    // msg 1: responder writes
    {
        auto m = res.write_message(unhex(V::messages[1].payload));
        REQUIRE(m.is_ok());
        CHECK(hex(m.value().span()) == V::messages[1].ciphertext);
        auto p = ini.read_message(unhex(V::messages[1].ciphertext));
        REQUIRE(p.is_ok());
        CHECK(hex(p.value().span()) == V::messages[1].payload);
    }
    // msg 2: initiator writes → handshake complete
    {
        auto m = ini.write_message(unhex(V::messages[2].payload));
        REQUIRE(m.is_ok());
        CHECK(hex(m.value().span()) == V::messages[2].ciphertext);
        auto p = res.read_message(unhex(V::messages[2].ciphertext));
        REQUIRE(p.is_ok());
        CHECK(hex(p.value().span()) == V::messages[2].payload);
    }

    REQUIRE(ini.handshake_finished());
    REQUIRE(res.handshake_finished());
    // Both parties agree on the handshake hash, and it matches the vector.
    CHECK(hex(ini.handshake_hash()) == V::handshake_hash);
    CHECK(hex(res.handshake_hash()) == V::handshake_hash);

    // ── Transport messages (alternating: msg3 responder, msg4 initiator, msg5 responder) ──
    auto si = ini.into_session();
    auto sr = res.into_session();
    REQUIRE(si.is_ok()); REQUIRE(sr.is_ok());

    auto t3 = sr.value().send.encrypt(unhex(V::messages[3].payload));
    REQUIRE(t3.is_ok());
    CHECK(hex(t3.value().span()) == V::messages[3].ciphertext);

    auto t4 = si.value().send.encrypt(unhex(V::messages[4].payload));
    REQUIRE(t4.is_ok());
    CHECK(hex(t4.value().span()) == V::messages[4].ciphertext);

    auto t5 = sr.value().send.encrypt(unhex(V::messages[5].payload));
    REQUIRE(t5.is_ok());
    CHECK(hex(t5.value().span()) == V::messages[5].ciphertext);
}

void run_tests_noise_kat() {
    RUN("noise/kat/official-vector-byte-exact");
}
