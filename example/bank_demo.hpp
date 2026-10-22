#pragma once
/**
 * The bank profile walk-through shared by showcase.cpp (full profile) and
 * showcase_bank.cpp (bank profile): X-Wing, HPKE with ML-KEM-768 and X-Wing,
 * Suite v2 recipient-bound envelopes and the Session v2 authenticated
 * ratchet. Every step reports through the caller's check callback so the
 * two programs count results the same way.
 */
#include <cryptolib/cryptolib.hpp>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
namespace bank_demo {

using Check = std::function<void(bool, const std::string&)>;

inline std::vector<uint8_t> text(std::string_view s) { return { s.begin(), s.end() }; }
inline std::vector<uint8_t> copy(std::span<const uint8_t> s) { return { s.begin(), s.end() }; }

inline void xwing(const Check& check) {
    using crypto::pq::XWing;
    auto bob = XWing::generate_keypair();
    check(bob.is_ok() && bob.value().public_key.size() == XWing::PK_BYTES, "X-Wing key pair: 1216-byte public key, 32-byte seed");
    auto enc = XWing::encapsulate(bob.value().public_key.span());
    check(enc.is_ok() && enc.value().ciphertext.size() == XWing::CT_BYTES, "X-Wing encapsulation: 1120-byte ciphertext");
    auto dec = XWing::decapsulate(enc.value().ciphertext.span(), bob.value().secret_key.span());
    check(dec.is_ok() && copy(dec.value().span()) == copy(enc.value().shared_secret.span()), "X-Wing decapsulation recovers the shared secret");
    auto again = XWing::keypair_from_seed(bob.value().secret_key.span());
    check(again.is_ok() && copy(again.value().public_key.span()) == copy(bob.value().public_key.span()), "the 32-byte seed regenerates the same key pair");
}

inline void hpke(const Check& check) {
    using crypto::Hpke;
    struct Named { Hpke::Kem kem; const char* name; };
    for (auto [kem, name] : { Named{Hpke::Kem::DhkemX25519, "DHKEM(X25519)"}, Named{Hpke::Kem::MlKem768, "ML-KEM-768"}, Named{Hpke::Kem::XWing, "X-Wing"} }) {
        auto kp = Hpke::generate_keypair(kem);
        auto sealed = Hpke::seal_base(kem, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm, kp.value().public_key.span(), text("statement"), text("ctx"), text("balance: 42"));
        auto opened = Hpke::open_base(kem, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm, sealed.value().enc.span(), kp.value().secret_key.span(), text("statement"), text("ctx"), sealed.value().ct.span());
        check(opened.is_ok() && copy(opened.value().span()) == text("balance: 42"), std::string("HPKE base mode round trip with ") + name);
    }
}

inline void suite_v2(const Check& check) {
    using crypto::Suite2;
    auto bob = std::move(crypto::pq::XWing::generate_keypair().value());
    auto carol = std::move(crypto::pq::XWing::generate_keypair().value());
    auto alice = std::move(crypto::pq::HybridSig::generate_keypair().value());
    auto env = Suite2::seal(text("wire 100 EUR"), bob.public_key.span(), alice.secret_key.span(), text("ctx"));
    check(env.is_ok() && Suite2::suite_of(env.value().span()).value() == Suite2::SUITE_XWING_SIG, "Suite v2 seal under X-Wing with the hybrid signature");
    auto pt = Suite2::open(env.value().span(), bob.secret_key.span(), bob.public_key.span(), alice.public_key.span(), text("ctx"));
    check(pt.is_ok() && copy(pt.value().span()) == text("wire 100 EUR"), "Bob opens it and the signature verifies");
    auto wrong_aad = Suite2::open(env.value().span(), bob.secret_key.span(), bob.public_key.span(), alice.public_key.span(), text("other"));
    check(wrong_aad.is_err(), "a different AAD is rejected");
    auto readdressed = Suite2::open(env.value().span(), bob.secret_key.span(), carol.public_key.span(), alice.public_key.span(), text("ctx"));
    check(readdressed.is_err(), "the signature is bound to the recipient: re-addressing fails");
}

inline void session_v2(const Check& check) {
    using crypto::SessionV2;
    auto alice = std::move(crypto::pq::HybridSig::generate_keypair().value());
    auto bob = std::move(crypto::pq::HybridSig::generate_keypair().value());
    auto mallory = std::move(crypto::pq::HybridSig::generate_keypair().value());
    auto prekey = SessionV2::generate_prekey(bob.secret_key.span());
    check(prekey.is_ok() && SessionV2::verify_prekey(prekey.value().bundle.span(), bob.public_key.span()).is_ok(), "Bob publishes a prekey bundle signed by his identity");
    check(SessionV2::verify_prekey(prekey.value().bundle.span(), mallory.public_key.span()).is_err(), "a bundle under the wrong identity is rejected");
    auto init = SessionV2::initiate(prekey.value().bundle.span(), bob.public_key.span(), alice);
    check(init.is_ok(), "Alice verifies the bundle and signs her handshake");
    auto claimed = SessionV2::claimed_initiator(init.value().handshake.span());
    check(claimed.is_ok() && copy(claimed.value().span()) == copy(alice.public_key.span()), "the handshake names Alice so Bob can look her up");
    check(SessionV2::accept(init.value().handshake.span(), prekey.value(), bob, mallory.public_key.span()).is_err(), "Bob refuses a handshake from an unexpected identity");
    auto resp = SessionV2::accept(init.value().handshake.span(), prekey.value(), bob, alice.public_key.span());
    check(resp.is_ok(), "Bob accepts Alice");
    auto& a = init.value().channel;
    auto& b = resp.value();
    auto m1 = a.encrypt(text("first"));
    auto p1 = b.decrypt(m1.value().span());
    auto m2 = b.encrypt(text("reply"));
    auto p2 = a.decrypt(m2.value().span());
    check(p1.is_ok() && copy(p1.value().span()) == text("first") && p2.is_ok() && copy(p2.value().span()) == text("reply"), "the ratchet turns in both directions");
    check(b.decrypt(m1.value().span()).is_err(), "a replayed message is rejected");
}

inline void run(const Check& check) {
    xwing(check);
    hpke(check);
    suite_v2(check);
    session_v2(check);
}

}
#endif
