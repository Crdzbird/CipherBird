// Flagship + Fortress — the two state-of-the-art sealed-messaging tiers.
// Both share one protocol core, so the same templated checks run against each.
#include "test_framework.hpp"

#include <cryptolib/flagship.hpp>

#include <cstring>
#include <string_view>
#include <vector>

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)

using namespace test;

namespace {
std::vector<uint8_t> bytes(std::string_view s) { return { s.begin(), s.end() }; }
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return { b.span().begin(), b.span().end() }; }
const std::vector<uint8_t> AAD     = bytes("flagship/aad");
const std::vector<uint8_t> PURPOSE = bytes("secure-note");

// ── One-shot ────────────────────────────────────────────────────────────────
template <class P>
void check_roundtrip() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    REQUIRE(r.is_ok());
    REQUIRE(s.is_ok());
    auto pt = bytes("meet at dawn — bring the triple key");
    auto env = P::seal(pt, r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    auto out = P::open(env.value().span(), r.value().secret_key.span(),
                       r.value().public_key.span(), s.value().public_key.span(), AAD, PURPOSE);
    REQUIRE(out.is_ok());
    CHECK(vec(out.value()) == pt);
}

template <class P>
void check_wrong_signer_rejected() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    auto impostor = P::generate_sender();
    auto env = P::seal(bytes("x"), r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    // Decrypts fine, but the signature is from the wrong signer → fail closed.
    CHECK_ERR(P::open(env.value().span(), r.value().secret_key.span(),
                      r.value().public_key.span(), impostor.value().public_key.span(), AAD, PURPOSE));
}

template <class P>
void check_wrong_recipient_key_rejected() {
    auto r = P::generate_recipient();
    auto mallory = P::generate_recipient();
    auto s = P::generate_sender();
    auto env = P::seal(bytes("x"), r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    // Wrong KEM secret → wrong shared secret → the key-committing AEAD rejects.
    CHECK_ERR(P::open(env.value().span(), mallory.value().secret_key.span(),
                      mallory.value().public_key.span(), s.value().public_key.span(), AAD, PURPOSE));
}

// The state-of-the-art property: a recipient cannot make a message they received
// verify as if it were addressed to a DIFFERENT recipient (surreptitious
// forwarding). The signature binds the intended recipient's public key.
template <class P>
void check_recipient_binding() {
    auto alice = P::generate_recipient();
    auto bob   = P::generate_recipient();
    auto s     = P::generate_sender();
    auto env = P::seal(bytes("for alice only"), alice.value().public_key.span(),
                       s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    // Alice's own secret decrypts, but claiming Bob as the bound recipient fails.
    CHECK_ERR(P::open(env.value().span(), alice.value().secret_key.span(),
                      bob.value().public_key.span(), s.value().public_key.span(), AAD, PURPOSE));
    // Correct recipient identity verifies.
    CHECK_OK(P::open(env.value().span(), alice.value().secret_key.span(),
                     alice.value().public_key.span(), s.value().public_key.span(), AAD, PURPOSE));
}

template <class P>
void check_aad_and_purpose_bound() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    auto env = P::seal(bytes("x"), r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    // Wrong AAD → AEAD rejects; wrong purpose → signature rejects.
    CHECK_ERR(P::open(env.value().span(), r.value().secret_key.span(), r.value().public_key.span(),
                      s.value().public_key.span(), bytes("other-aad"), PURPOSE));
    CHECK_ERR(P::open(env.value().span(), r.value().secret_key.span(), r.value().public_key.span(),
                      s.value().public_key.span(), AAD, bytes("other-purpose")));
}

template <class P>
void check_tamper_rejected() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    auto env = P::seal(bytes("integrity"), r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    auto buf = vec(env.value());
    buf[buf.size() - 1] ^= 0x01;
    CHECK_ERR(P::open(buf, r.value().secret_key.span(), r.value().public_key.span(),
                      s.value().public_key.span(), AAD, PURPOSE));
}

template <class P>
void check_inspect() {
    auto r = P::generate_recipient();
    auto other = P::generate_recipient();
    auto s = P::generate_sender();
    auto env = P::seal(bytes("x"), r.value().public_key.span(), s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    auto info = P::inspect(env.value().span());
    REQUIRE(info.is_ok());
    CHECK(info.value().version == 1);
    CHECK(info.value().suite == P::SUITE);
    CHECK(info.value().streaming == false);
    CHECK(info.value().kem_ciphertext_len > 0);
    // Addressing proof without any secret material.
    CHECK(P::addressed_to(env.value().span(), r.value().public_key.span()));
    CHECK(!P::addressed_to(env.value().span(), other.value().public_key.span()));
}

// ── Streaming ─────────────────────────────────────────────────────────────────
template <class P>
void check_stream_roundtrip() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    REQUIRE(r.is_ok());
    REQUIRE(s.is_ok());

    auto sealer = P::StreamSealer::begin(r.value().public_key.span(), s.value().secret_key.span(), PURPOSE);
    REQUIRE(sealer.is_ok());

    std::vector<std::vector<uint8_t>> chunks = { bytes("chunk-one "), bytes("chunk-two "), bytes("chunk-three") };
    std::vector<crypto::SecureBuffer> wire;
    for (std::size_t i = 0; i + 1 < chunks.size(); ++i) {
        auto ct = sealer.value().push(chunks[i]);
        REQUIRE(ct.is_ok());
        wire.push_back(std::move(ct.value()));
    }
    auto fin = sealer.value().finalize(chunks.back());
    REQUIRE(fin.is_ok());

    // Open.
    auto opener = P::StreamOpener::begin(sealer.value().preamble().span(), r.value().secret_key.span(),
                                         r.value().public_key.span(), s.value().public_key.span(), PURPOSE);
    REQUIRE(opener.is_ok());
    std::vector<uint8_t> reassembled;
    for (auto& ct : wire) {
        auto pc = opener.value().pull(ct.span());
        REQUIRE(pc.is_ok());
        CHECK(pc.value().final == false);
        auto p = vec(pc.value().plaintext);
        reassembled.insert(reassembled.end(), p.begin(), p.end());
    }
    auto last = opener.value().pull(fin.value().ciphertext.span());
    REQUIRE(last.is_ok());
    CHECK(last.value().final == true);
    auto lp = vec(last.value().plaintext);
    reassembled.insert(reassembled.end(), lp.begin(), lp.end());

    // Sender-authenticity verified at finalize (over the whole transcript).
    CHECK_OK(opener.value().finalize(fin.value().trailer.span()));

    std::vector<uint8_t> expected;
    for (auto& c : chunks) expected.insert(expected.end(), c.begin(), c.end());
    CHECK(reassembled == expected);
}

template <class P>
void check_stream_truncation_rejected() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    auto sealer = P::StreamSealer::begin(r.value().public_key.span(), s.value().secret_key.span(), PURPOSE);
    REQUIRE(sealer.is_ok());
    auto c0 = sealer.value().push(bytes("only chunk"));
    REQUIRE(c0.is_ok());
    auto fin = sealer.value().finalize(bytes("end"));
    REQUIRE(fin.is_ok());

    auto opener = P::StreamOpener::begin(sealer.value().preamble().span(), r.value().secret_key.span(),
                                         r.value().public_key.span(), s.value().public_key.span(), PURPOSE);
    REQUIRE(opener.is_ok());
    // Pull only the interior chunk, then finalize WITHOUT the FINAL chunk.
    auto p0 = opener.value().pull(c0.value().span());
    REQUIRE(p0.is_ok());
    CHECK_ERR(opener.value().finalize(fin.value().trailer.span()));  // no FINAL seen → truncation
}

template <class P>
void check_stream_wrong_signer_rejected() {
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    auto impostor = P::generate_sender();
    auto sealer = P::StreamSealer::begin(r.value().public_key.span(), s.value().secret_key.span(), PURPOSE);
    REQUIRE(sealer.is_ok());
    auto fin = sealer.value().finalize(bytes("payload"));
    REQUIRE(fin.is_ok());

    auto opener = P::StreamOpener::begin(sealer.value().preamble().span(), r.value().secret_key.span(),
                                         r.value().public_key.span(), impostor.value().public_key.span(), PURPOSE);
    REQUIRE(opener.is_ok());
    auto last = opener.value().pull(fin.value().ciphertext.span());
    REQUIRE(last.is_ok());
    CHECK(last.value().final == true);
    CHECK_ERR(opener.value().finalize(fin.value().trailer.span()));  // wrong signer
}

// Cross-tier confusion: a Fortress envelope must not open as Flagship.
void check_cross_tier_rejected() {
    auto r = crypto::Fortress::generate_recipient();
    auto s = crypto::Fortress::generate_sender();
    auto env = crypto::Fortress::seal(bytes("x"), r.value().public_key.span(),
                                      s.value().secret_key.span(), AAD, PURPOSE);
    REQUIRE(env.is_ok());
    // Flagship::open sees the wrong suite id (and wrong-sized KEM) → reject.
    auto rr = crypto::Flagship::generate_recipient();
    auto ss = crypto::Flagship::generate_sender();
    CHECK_ERR(crypto::Flagship::open(env.value().span(), rr.value().secret_key.span(),
                                     rr.value().public_key.span(), ss.value().public_key.span(), AAD, PURPOSE));
}
} // namespace

// ── Register both tiers ──────────────────────────────────────────────────────
TEST("flagship/roundtrip")                     { check_roundtrip<crypto::Flagship>(); }
TEST("flagship/wrong-signer-rejected")         { check_wrong_signer_rejected<crypto::Flagship>(); }
TEST("flagship/wrong-recipient-key-rejected")  { check_wrong_recipient_key_rejected<crypto::Flagship>(); }
TEST("flagship/recipient-binding")             { check_recipient_binding<crypto::Flagship>(); }
TEST("flagship/aad-and-purpose-bound")         { check_aad_and_purpose_bound<crypto::Flagship>(); }
TEST("flagship/tamper-rejected")               { check_tamper_rejected<crypto::Flagship>(); }
TEST("flagship/inspect")                       { check_inspect<crypto::Flagship>(); }
TEST("flagship/stream-roundtrip")              { check_stream_roundtrip<crypto::Flagship>(); }
TEST("flagship/stream-truncation-rejected")    { check_stream_truncation_rejected<crypto::Flagship>(); }
TEST("flagship/stream-wrong-signer-rejected")  { check_stream_wrong_signer_rejected<crypto::Flagship>(); }

TEST("fortress/roundtrip")                     { check_roundtrip<crypto::Fortress>(); }
TEST("fortress/wrong-signer-rejected")         { check_wrong_signer_rejected<crypto::Fortress>(); }
TEST("fortress/wrong-recipient-key-rejected")  { check_wrong_recipient_key_rejected<crypto::Fortress>(); }
TEST("fortress/recipient-binding")             { check_recipient_binding<crypto::Fortress>(); }
TEST("fortress/tamper-rejected")               { check_tamper_rejected<crypto::Fortress>(); }
TEST("fortress/inspect")                       { check_inspect<crypto::Fortress>(); }
TEST("fortress/stream-roundtrip")              { check_stream_roundtrip<crypto::Fortress>(); }
TEST("fortress/stream-truncation-rejected")    { check_stream_truncation_rejected<crypto::Fortress>(); }
TEST("suite/flagship-fortress-cross-tier-rejected") { check_cross_tier_rejected(); }

#endif // CRYPTOLIB_HAS_OPENSSL && CRYPTOLIB_HAS_PQ

void run_tests_flagship() {
#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)
    RUN("flagship/roundtrip");
    RUN("flagship/wrong-signer-rejected");
    RUN("flagship/wrong-recipient-key-rejected");
    RUN("flagship/recipient-binding");
    RUN("flagship/aad-and-purpose-bound");
    RUN("flagship/tamper-rejected");
    RUN("flagship/inspect");
    RUN("flagship/stream-roundtrip");
    RUN("flagship/stream-truncation-rejected");
    RUN("flagship/stream-wrong-signer-rejected");
    RUN("fortress/roundtrip");
    RUN("fortress/wrong-signer-rejected");
    RUN("fortress/wrong-recipient-key-rejected");
    RUN("fortress/recipient-binding");
    RUN("fortress/tamper-rejected");
    RUN("fortress/inspect");
    RUN("fortress/stream-roundtrip");
    RUN("fortress/stream-truncation-rejected");
    RUN("suite/flagship-fortress-cross-tier-rejected");
#endif
}
