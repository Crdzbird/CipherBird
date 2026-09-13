#include "test_framework.hpp"
#include <vector>
using namespace test;

using crypto::NoiseXX;
using crypto::asymmetric::X25519;

static std::span<const uint8_t> sv(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}
static bool eq(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    return crypto::secure_equal(a, b);
}

// Drive the full XX handshake; return the two completed parties via out-params.
static bool do_handshake(NoiseXX& ini, NoiseXX& res) {
    auto m1 = ini.write_message();              // -> e
    if (m1.is_err()) return false;
    if (res.read_message(m1.value().span()).is_err()) return false;
    auto m2 = res.write_message();              // <- e, ee, s, es
    if (m2.is_err()) return false;
    if (ini.read_message(m2.value().span()).is_err()) return false;
    auto m3 = ini.write_message();              // -> s, se
    if (m3.is_err()) return false;
    if (res.read_message(m3.value().span()).is_err()) return false;
    return ini.handshake_finished() && res.handshake_finished();
}

TEST("noise/xx-handshake-and-transport") {
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);
    REQUIRE(do_handshake(ini, res));

    auto si = ini.into_session();
    auto sr = res.into_session();
    REQUIRE(si.is_ok()); REQUIRE(sr.is_ok());

    // Initiator → responder.
    auto c1 = si.value().send.encrypt(sv("hello from initiator"));
    REQUIRE(c1.is_ok());
    auto p1 = sr.value().recv.decrypt(c1.value().span());
    REQUIRE(p1.is_ok());
    CHECK(p1.value().to_string() == "hello from initiator");

    // Responder → initiator.
    auto c2 = sr.value().send.encrypt(sv("reply from responder"));
    REQUIRE(c2.is_ok());
    auto p2 = si.value().recv.decrypt(c2.value().span());
    REQUIRE(p2.is_ok());
    CHECK(p2.value().to_string() == "reply from responder");

    // Multiple records advance the nonce correctly.
    auto a = si.value().send.encrypt(sv("msg-2"));
    auto b = si.value().send.encrypt(sv("msg-3"));
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(sr.value().recv.decrypt(a.value().span()).value().to_string() == "msg-2");
    CHECK(sr.value().recv.decrypt(b.value().span()).value().to_string() == "msg-3");
}

TEST("noise/decrypt-at-matches-sequential-decrypt") {
    // Differential against the path the KAT vector already validates: if
    // opening by explicit counter ever disagrees with walking the records
    // in order, one of them is wrong.
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);
    REQUIRE(do_handshake(ini, res));
    auto si = ini.into_session();
    auto sr = res.into_session();
    REQUIRE(si.is_ok()); REQUIRE(sr.is_ok());

    std::vector<crypto::SecureBuffer> records;
    const std::vector<std::string> texts = {"r0", "record one", "r2", "r3"};
    for (const auto& t : texts) {
        auto c = si.value().send.encrypt(sv(t));
        REQUIRE(c.is_ok());
        records.push_back(std::move(c.value()));
    }

    // Out of order on purpose: that is the whole point of the API.
    for (std::size_t i = records.size(); i-- > 0;) {
        auto p = sr.value().recv.decrypt_at(i, records[i].span());
        REQUIRE(p.is_ok());
        CHECK(p.value().to_string() == texts[i]);
    }

    // The session counter is untouched, so the sequential path still
    // opens record 0 — this is what makes the call re-entrant.
    auto seq = sr.value().recv.decrypt(records[0].span());
    REQUIRE(seq.is_ok());
    CHECK(seq.value().to_string() == texts[0]);
}

TEST("noise/decrypt-at-rejects-the-wrong-counter") {
    // The tag binds the counter, so a record only opens under the counter
    // its sender used. That is what stops a caller silently accepting
    // reordered records as if they were in sequence.
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);
    REQUIRE(do_handshake(ini, res));
    auto si = ini.into_session();
    auto sr = res.into_session();
    REQUIRE(si.is_ok()); REQUIRE(sr.is_ok());

    auto c0 = si.value().send.encrypt(sv("zero"));
    REQUIRE(c0.is_ok());
    CHECK(sr.value().recv.decrypt_at(1, c0.value().span()).is_err());
    CHECK(sr.value().recv.decrypt_at(0, c0.value().span()).is_ok());

    // Associated data is bound too.
    auto c1 = si.value().send.encrypt(sv("with-ad"), sv("context"));
    REQUIRE(c1.is_ok());
    CHECK(sr.value().recv.decrypt_at(1, c1.value().span(), sv("other")).is_err());
    CHECK(sr.value().recv.decrypt_at(1, c1.value().span(), sv("context")).is_ok());

    // A flipped ciphertext byte fails the tag rather than yielding bytes.
    auto c2 = si.value().send.encrypt(sv("tamper"));
    REQUIRE(c2.is_ok());
    std::vector<uint8_t> bad(c2.value().span().begin(), c2.value().span().end());
    bad[0] ^= 0x01;
    CHECK(sr.value().recv.decrypt_at(2, std::span<const uint8_t>{bad}).is_err());

    // The reserved maximum counter is refused outright.
    CHECK(sr.value().recv.decrypt_at(UINT64_MAX, c0.value().span()).is_err());
    // Too short to hold a tag.
    std::vector<uint8_t> stub(4, 0);
    CHECK(sr.value().recv.decrypt_at(0, std::span<const uint8_t>{stub}).is_err());
}

TEST("noise/decrypt-at-refuses-an-unkeyed-state") {
    // Defence in depth: a state that never split has no key, and calling
    // libsodium with an empty key buffer would be undefined.
    NoiseXX::CipherState fresh;
    std::vector<uint8_t> anything(32, 0);
    CHECK(fresh.decrypt_at(0, std::span<const uint8_t>{anything}).is_err());
}

TEST("noise/mutual-static-authentication") {
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);
    REQUIRE(do_handshake(ini, res));
    // Each side learned the peer's real static public key (pin this in apps).
    CHECK(eq(ini.remote_static().span(), rks.public_key.span()));
    CHECK(eq(res.remote_static().span(), iks.public_key.span()));
}

TEST("noise/handshake-payloads-delivered") {
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);

    auto m1 = ini.write_message(sv("hi"));
    REQUIRE(m1.is_ok());
    CHECK(res.read_message(m1.value().span()).value().to_string() == "hi");
    auto m2 = res.write_message(sv("welcome"));
    REQUIRE(m2.is_ok());
    CHECK(ini.read_message(m2.value().span()).value().to_string() == "welcome");
    auto m3 = ini.write_message(sv("thanks"));
    REQUIRE(m3.is_ok());
    CHECK(res.read_message(m3.value().span()).value().to_string() == "thanks");
}

TEST("noise/tampered-handshake-rejected") {
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);

    auto m1 = ini.write_message();
    REQUIRE(m1.is_ok());
    REQUIRE(res.read_message(m1.value().span()).is_ok());
    auto m2 = res.write_message();             // contains encrypted static (s, es)
    REQUIRE(m2.is_ok());
    std::vector<uint8_t> bad(m2.value().span().begin(), m2.value().span().end());
    bad.back() ^= 0x01;                          // tamper the AEAD tag region
    CHECK(ini.read_message(bad).is_err());
}

TEST("noise/tampered-transport-rejected") {
    auto iks = X25519::generate_keypair();
    auto rks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    auto res = NoiseXX::responder(rks);
    REQUIRE(do_handshake(ini, res));
    auto si = ini.into_session(); auto sr = res.into_session();
    auto c = si.value().send.encrypt(sv("secret"));
    REQUIRE(c.is_ok());
    std::vector<uint8_t> bad(c.value().span().begin(), c.value().span().end());
    bad.back() ^= 0x01;
    CHECK(sr.value().recv.decrypt(bad).is_err());
}

TEST("noise/out-of-turn-rejected") {
    auto iks = X25519::generate_keypair();
    auto ini = NoiseXX::initiator(iks);
    // Initiator's first action is write; reading first must fail.
    std::vector<uint8_t> junk(32, 0);
    CHECK(ini.read_message(junk).is_err());
    auto m1 = ini.write_message();
    REQUIRE(m1.is_ok());
    // After writing msg0 it's the peer's turn; writing again must fail.
    CHECK(ini.write_message().is_err());
}

void run_tests_noise() {
    RUN("noise/xx-handshake-and-transport");
    RUN("noise/decrypt-at-matches-sequential-decrypt");
    RUN("noise/decrypt-at-rejects-the-wrong-counter");
    RUN("noise/decrypt-at-refuses-an-unkeyed-state");
    RUN("noise/mutual-static-authentication");
    RUN("noise/handshake-payloads-delivered");
    RUN("noise/tampered-handshake-rejected");
    RUN("noise/tampered-transport-rejected");
    RUN("noise/out-of-turn-rejected");
}
