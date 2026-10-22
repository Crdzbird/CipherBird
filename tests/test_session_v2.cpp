#include "test_framework.hpp"
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include <cstdint>
#include <utility>
#include <string>
#include <vector>

using namespace test;
using crypto::SessionV2;
using crypto::pq::HybridSig;

namespace {
std::vector<uint8_t> bytes(std::span<const uint8_t> s) { return { s.begin(), s.end() }; }
std::vector<uint8_t> text(const char* s) { std::string t(s); return { t.begin(), t.end() }; }
}

TEST("session_v2/authenticated-handshake-and-ratchet") {
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto bob = std::move(HybridSig::generate_keypair().value());
    auto prekey = SessionV2::generate_prekey(bob.secret_key.span());
    REQUIRE(prekey.is_ok());
    CHECK(SessionV2::verify_prekey(prekey.value().bundle.span(), bob.public_key.span()).is_ok());
    CHECK(SessionV2::verify_prekey(prekey.value().bundle.span(), alice.public_key.span()).is_err());
    auto init = SessionV2::initiate(prekey.value().bundle.span(), bob.public_key.span(), alice);
    REQUIRE(init.is_ok());
    auto claimed = SessionV2::claimed_initiator(init.value().handshake.span());
    REQUIRE(claimed.is_ok());
    CHECK(bytes(claimed.value().span()) == bytes(alice.public_key.span()));
    auto resp = SessionV2::accept(init.value().handshake.span(), prekey.value(), bob, alice.public_key.span());
    REQUIRE(resp.is_ok());
    auto& a = init.value().channel;
    auto& b = resp.value();
    auto m1 = a.encrypt(text("first"), text("aad"));
    REQUIRE(m1.is_ok());
    auto p1 = b.decrypt(m1.value().span(), text("aad"));
    REQUIRE(p1.is_ok());
    CHECK(bytes(p1.value().span()) == text("first"));
    auto m2 = b.encrypt(text("reply"));
    REQUIRE(m2.is_ok());
    auto p2 = a.decrypt(m2.value().span());
    REQUIRE(p2.is_ok());
    CHECK(bytes(p2.value().span()) == text("reply"));
    auto m3 = a.encrypt(text("third"));
    REQUIRE(m3.is_ok());
    CHECK(bytes(b.decrypt(m3.value().span()).value().span()) == text("third"));
    CHECK(b.decrypt(m3.value().span()).is_err());
    CHECK(m3.value().span()[3] == '2');
}

TEST("session_v2/unexpected-initiator-rejected") {
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto mallory = std::move(HybridSig::generate_keypair().value());
    auto bob = std::move(HybridSig::generate_keypair().value());
    auto prekey = std::move(SessionV2::generate_prekey(bob.secret_key.span()).value());
    auto init = std::move(SessionV2::initiate(prekey.bundle.span(), bob.public_key.span(), mallory).value());
    CHECK(SessionV2::accept(init.handshake.span(), prekey, bob, alice.public_key.span()).is_err());
    CHECK(SessionV2::accept(init.handshake.span(), prekey, bob, {}).is_err());
    CHECK(SessionV2::accept(init.handshake.span(), prekey, bob, mallory.public_key.span()).is_ok());
}

TEST("session_v2/substituted-prekey-and-tampered-handshake-rejected") {
    auto alice = std::move(HybridSig::generate_keypair().value());
    auto bob = std::move(HybridSig::generate_keypair().value());
    auto mallory = std::move(HybridSig::generate_keypair().value());
    auto bob_prekey = std::move(SessionV2::generate_prekey(bob.secret_key.span()).value());
    auto fake = std::move(SessionV2::generate_prekey(mallory.secret_key.span()).value());
    CHECK(SessionV2::initiate(fake.bundle.span(), bob.public_key.span(), alice).is_err());
    auto init = std::move(SessionV2::initiate(bob_prekey.bundle.span(), bob.public_key.span(), alice).value());
    auto h = bytes(init.handshake.span());
    h[4 + 4 + 3] ^= 1;
    CHECK(SessionV2::accept(h, bob_prekey, bob, alice.public_key.span()).is_err());
    h = bytes(init.handshake.span());
    h[h.size() - 1] ^= 1;
    CHECK(SessionV2::accept(h, bob_prekey, bob, alice.public_key.span()).is_err());
    h = bytes(init.handshake.span());
    h.push_back(0);
    CHECK(SessionV2::accept(h, bob_prekey, bob, alice.public_key.span()).is_err());
    auto other = std::move(SessionV2::generate_prekey(bob.secret_key.span()).value());
    CHECK(SessionV2::accept(init.handshake.span(), other, bob, alice.public_key.span()).is_err());
    CHECK(SessionV2::accept(init.handshake.span(), bob_prekey, bob, alice.public_key.span()).is_ok());
}

void run_tests_session_v2() {
    RUN("session_v2/authenticated-handshake-and-ratchet");
    RUN("session_v2/unexpected-initiator-rejected");
    RUN("session_v2/substituted-prekey-and-tampered-handshake-rejected");
}
#else
void run_tests_session_v2() {}
#endif
