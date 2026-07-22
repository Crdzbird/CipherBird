// crypto::Session — post-quantum forward-secret ratchet (hybrid KEM Double Ratchet).
#include "test_framework.hpp"

#include <cryptolib/session.hpp>

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#if defined(CRYPTOLIB_HAS_PQ)

using crypto::Session;

namespace {
std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }

// Establish a fresh Alice(initiator)/Bob(responder) session pair via the handshake.
struct Pair { Session alice; Session bob; };
Pair establish() {
    auto prekey = Session::generate_prekey();
    auto alice = Session::initiate(prekey.value().public_key.span());
    auto bob = Session::accept(alice.value().handshake().span(), prekey.value());
    return Pair{ std::move(alice.value()), std::move(bob.value()) };
}
} // namespace

TEST("session/handshake-first-message") {
    auto p = establish();
    auto m = p.alice.encrypt(bytes("hello bob"));
    CHECK_OK(m);
    auto out = p.bob.decrypt(m.value().span());
    CHECK_OK(out);
    CHECK(vec(out.value()) == bytes("hello bob"));
}

TEST("session/ping-pong-many-turns") {
    auto p = establish();
    // Alternate directions for many turns — each turn is a fresh KEM ratchet step.
    for (int i = 0; i < 12; ++i) {
        auto a = p.alice.encrypt(bytes("a" + std::to_string(i)));
        CHECK_OK(a);
        auto ra = p.bob.decrypt(a.value().span());
        CHECK_OK(ra);
        CHECK(vec(ra.value()) == bytes("a" + std::to_string(i)));

        auto b = p.bob.encrypt(bytes("b" + std::to_string(i)));
        CHECK_OK(b);
        auto rb = p.alice.decrypt(b.value().span());
        CHECK_OK(rb);
        CHECK(vec(rb.value()) == bytes("b" + std::to_string(i)));
    }
}

TEST("session/multiple-in-a-row-same-chain") {
    auto p = establish();
    // Alice sends several without Bob replying → same sending chain, N advances.
    std::vector<crypto::SecureBuffer> msgs;
    for (int i = 0; i < 5; ++i) {
        auto m = p.alice.encrypt(bytes("msg" + std::to_string(i)));
        CHECK_OK(m);
        msgs.push_back(std::move(m.value()));
    }
    for (int i = 0; i < 5; ++i) {
        auto out = p.bob.decrypt(msgs[i].span());
        CHECK_OK(out);
        CHECK(vec(out.value()) == bytes("msg" + std::to_string(i)));
    }
}

TEST("session/out-of-order-within-chain") {
    auto p = establish();
    std::vector<crypto::SecureBuffer> msgs;
    for (int i = 0; i < 4; ++i) {
        auto m = p.alice.encrypt(bytes("x" + std::to_string(i)));
        msgs.push_back(std::move(m.value()));
    }
    // Deliver 3, 1, 0, 2 — skipped-key handling must recover all.
    for (int idx : {3, 1, 0, 2}) {
        auto out = p.bob.decrypt(msgs[idx].span());
        CHECK_OK(out);
        CHECK(vec(out.value()) == bytes("x" + std::to_string(idx)));
    }
}

TEST("session/skipped-across-ratchet-turn") {
    auto p = establish();
    // Alice sends A0, A1 (chain 1). Bob replies B0 (turn). Alice sends A2 (chain 2).
    auto a0 = p.alice.encrypt(bytes("A0"));
    auto a1 = p.alice.encrypt(bytes("A1"));
    // Bob receives only A0, then replies (ratchets).
    CHECK_OK(p.bob.decrypt(a0.value().span()));
    auto b0 = p.bob.encrypt(bytes("B0"));
    CHECK_OK(p.alice.decrypt(b0.value().span()));      // Alice ratchets
    auto a2 = p.alice.encrypt(bytes("A2"));            // new sending chain
    // Bob now receives A2 (new chain) BEFORE the still-missing A1 (old chain).
    auto r2 = p.bob.decrypt(a2.value().span());
    CHECK_OK(r2);
    CHECK(vec(r2.value()) == bytes("A2"));
    auto r1 = p.bob.decrypt(a1.value().span());        // recovered from skipped store
    CHECK_OK(r1);
    CHECK(vec(r1.value()) == bytes("A1"));
}

TEST("session/aad-bound") {
    // Right AAD opens.
    {
        auto p = establish();
        auto m = p.alice.encrypt(bytes("hi"), bytes("context-A"));
        CHECK_OK(m);
        CHECK_OK(p.bob.decrypt(m.value().span(), bytes("context-A")));
    }
    // Wrong AAD fails — and (transactional) leaves the session usable for the
    // next legitimate message.
    {
        auto p = establish();
        auto m0 = p.alice.encrypt(bytes("first"), bytes("context-A"));
        CHECK_ERR(p.bob.decrypt(m0.value().span(), bytes("context-B")));  // rejected
        // The failed attempt must not have desynced Bob: the real message opens.
        CHECK_OK(p.bob.decrypt(m0.value().span(), bytes("context-A")));
    }
}

TEST("session/tamper-rejected") {
    auto p = establish();
    auto m = p.alice.encrypt(bytes("integrity"));
    CHECK_OK(m);
    auto buf = vec(m.value());
    buf[buf.size() - 1] ^= 0x01;                        // flip a ciphertext byte
    CHECK_ERR(p.bob.decrypt(buf));
}

TEST("session/tamper-header-rejected") {
    auto p = establish();
    auto m = p.alice.encrypt(bytes("integrity"));
    auto buf = vec(m.value());
    buf[5 + 4 + 10] ^= 0x01;                            // flip a byte inside the ratchet pubkey
    CHECK_ERR(p.bob.decrypt(buf));
}

TEST("session/wrong-prekey-fails") {
    auto prekey = Session::generate_prekey();
    auto other  = Session::generate_prekey();
    auto alice = Session::initiate(prekey.value().public_key.span());
    CHECK_OK(alice);
    // Accepting with the wrong prekey pair yields a different root → first message
    // fails to authenticate.
    auto bob = Session::accept(alice.value().handshake().span(), other.value());
    if (bob.is_ok()) {
        auto m = alice.value().encrypt(bytes("secret"));
        CHECK_ERR(bob.value().decrypt(m.value().span()));
    } else {
        CHECK(true);  // decapsulation/derivation already diverged — also acceptable
    }
}

TEST("session/responder-cannot-send-first") {
    auto prekey = Session::generate_prekey();
    auto alice = Session::initiate(prekey.value().public_key.span());
    auto bob = Session::accept(alice.value().handshake().span(), prekey.value());
    CHECK_OK(bob);
    // Bob has no sending chain until he receives — encrypt must fail closed.
    CHECK_ERR(bob.value().encrypt(bytes("premature")));
}

TEST("session/forward-secrecy-keys-differ") {
    auto p = establish();
    // Two consecutive messages in a chain must use independent keys → different
    // ciphertexts for identical plaintext (chain ratchet advanced).
    auto m0 = p.alice.encrypt(bytes("same"));
    auto m1 = p.alice.encrypt(bytes("same"));
    CHECK(!crypto::secure_equal(m0.value().span(), m1.value().span()));
}

#endif // CRYPTOLIB_HAS_PQ

void run_tests_session() {
#if defined(CRYPTOLIB_HAS_PQ)
    RUN("session/handshake-first-message");
    RUN("session/ping-pong-many-turns");
    RUN("session/multiple-in-a-row-same-chain");
    RUN("session/out-of-order-within-chain");
    RUN("session/skipped-across-ratchet-turn");
    RUN("session/aad-bound");
    RUN("session/tamper-rejected");
    RUN("session/tamper-header-rejected");
    RUN("session/wrong-prekey-fails");
    RUN("session/responder-cannot-send-first");
    RUN("session/forward-secrecy-keys-differ");
#endif
}
