/**
 * test_hardening.cpp — regression tests for specific security fixes.
 *
 *   - EncryptedPacket::deserialise bounds (no out-of-bounds read on crafted
 *     length prefixes; run under ASan to catch over-reads).
 *   - BLS aggregate_verify rejects duplicate messages (basic-scheme rogue-key
 *     defence).
 *   - Vault packets with a signature that is not exactly 64 bytes are rejected
 *     before Ed25519 verify (previously an out-of-bounds read and SEGV).
 *   - Suite and Flagship signed envelopes with a huge sig_len are rejected
 *     instead of wrapping the uint32_t bounds check.
 */

#include "test_framework.hpp"

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
#include <cryptolib/flagship.hpp>
#include <cryptolib/suite.hpp>
#endif

#include <cstdint>
#include <vector>

using namespace test;

// ── Packet deserialise: crafted truncation must error, not over-read ─────────
TEST("hardening/packet/truncated-after-salt-len") {
    // salt_len = 3 but only the salt bytes follow — no byte left for sig_len.
    // Previously this read one byte past the buffer.
    std::vector<uint8_t> raw = {3, 0xAA, 0xBB, 0xCC};
    auto r = crypto::EncryptedPacket::deserialise(raw);
    CHECK(r.is_err());
}

TEST("hardening/packet/empty-input") {
    std::vector<uint8_t> raw;
    auto r = crypto::EncryptedPacket::deserialise(raw);
    CHECK(r.is_err());
}

TEST("hardening/packet/salt-len-exceeds-buffer") {
    std::vector<uint8_t> raw = {200, 0x01, 0x02};  // claims 200-byte salt
    auto r = crypto::EncryptedPacket::deserialise(raw);
    CHECK(r.is_err());
}

TEST("hardening/packet/round-trip-still-works") {
    crypto::EncryptedPacket pkt{
        crypto::SecureBuffer(std::vector<uint8_t>(48, 0x11)),  // ciphertext
        crypto::SecureBuffer(std::vector<uint8_t>(64, 0x22)),  // signature
        crypto::SecureBuffer(std::vector<uint8_t>(16, 0x33))   // kdf_salt
    };
    auto wire = pkt.serialise();
    auto back = crypto::EncryptedPacket::deserialise(wire.span());
    REQUIRE(back.is_ok());
    CHECK(back.value().ciphertext.size() == 48);
    CHECK(back.value().signature.size() == 64);
    CHECK(back.value().kdf_salt.size() == 16);
}

#ifdef CRYPTOLIB_HAS_BLS
// ── BLS aggregate_verify must reject duplicate messages (rogue-key defence) ──
TEST("hardening/bls/duplicate-message-rejected") {
    using BLS = crypto::bls::Bls12381;
    auto kp1 = BLS::generate_keypair();
    auto kp2 = BLS::generate_keypair();
    REQUIRE(kp1.is_ok());
    REQUIRE(kp2.is_ok());

    std::string msg = "same message for both signers";
    auto sv = test::sv2sp(msg);

    auto sig1 = BLS::sign(sv, kp1.value().secret_key.span());
    auto sig2 = BLS::sign(sv, kp2.value().secret_key.span());
    REQUIRE(sig1.is_ok());
    REQUIRE(sig2.is_ok());

    auto agg = BLS::aggregate_signatures(
        { sig1.value().span(), sig2.value().span() });
    REQUIRE(agg.is_ok());

    // Both signers signed the SAME message — basic scheme must refuse this.
    auto r = BLS::aggregate_verify(
        { sv, sv },
        { kp1.value().public_key.span(), kp2.value().public_key.span() },
        agg.value().span());
    CHECK(r.is_err());
}

TEST("hardening/bls/distinct-messages-still-verify") {
    using BLS = crypto::bls::Bls12381;
    auto kp1 = BLS::generate_keypair();
    auto kp2 = BLS::generate_keypair();
    REQUIRE(kp1.is_ok());
    REQUIRE(kp2.is_ok());

    std::string m1 = "message one";
    std::string m2 = "message two";
    auto s1 = test::sv2sp(m1);
    auto s2 = test::sv2sp(m2);

    auto sig1 = BLS::sign(s1, kp1.value().secret_key.span());
    auto sig2 = BLS::sign(s2, kp2.value().secret_key.span());
    REQUIRE(sig1.is_ok());
    REQUIRE(sig2.is_ok());

    auto agg = BLS::aggregate_signatures(
        { sig1.value().span(), sig2.value().span() });
    REQUIRE(agg.is_ok());

    auto r = BLS::aggregate_verify(
        { s1, s2 },
        { kp1.value().public_key.span(), kp2.value().public_key.span() },
        agg.value().span());
    CHECK(r.is_ok());
}
#endif // CRYPTOLIB_HAS_BLS

// ── AsymmetricVault: tampering the transported box public key is rejected ────
TEST("hardening/asym-vault/tampered-box-public-rejected") {
    auto alice = crypto::AsymmetricVault::generate_bundle();
    auto bob   = crypto::AsymmetricVault::generate_bundle();

    auto sealed = crypto::AsymmetricVault::seal(
        std::string_view("attack at dawn"), alice, bob.box_public.span(),
        std::string_view("ctx"));
    REQUIRE(sealed.is_ok());
    auto& pkt = sealed.value();  // EncryptedPacket is non-copyable; tamper in place

    // Sanity: untampered packet opens.
    auto ok = crypto::AsymmetricVault::open(
        pkt, bob, alice.sign_public.span(), std::string_view("ctx"));
    CHECK(ok.is_ok());

    // The sender's box public key rides in kdf_salt. Flip a byte: now bound into
    // the signature, so verification must fail.
    pkt.kdf_salt.data()[0] ^= 0x01;
    auto bad = crypto::AsymmetricVault::open(
        pkt, bob, alice.sign_public.span(), std::string_view("ctx"));
    CHECK(bad.is_err());
}

// Vault packets: signature must be exactly 64 bytes.
TEST("hardening/packet/short-signature-rejected-by-deserialise") {
    std::vector<uint8_t> raw = {0x00, 0x00, 'x', 'y', 'z'};
    auto r = crypto::EncryptedPacket::deserialise(raw);
    CHECK(r.is_err());
}

TEST("hardening/vault/short-signature-rejected-by-open") {
    auto kp = crypto::SecureVault::generate_keypair();
    auto verifier = crypto::SecureVault::generate_keypair();
    std::vector<uint8_t> master(32, 7);
    crypto::SecureVault vault(master, std::move(kp));
    for (std::size_t len : {std::size_t(0), std::size_t(1), std::size_t(63), std::size_t(65)}) {
        crypto::EncryptedPacket pkt{
            crypto::SecureBuffer(std::vector<uint8_t>(48, 0x11)),
            crypto::SecureBuffer(std::vector<uint8_t>(len, 0x22)),
            crypto::SecureBuffer(std::vector<uint8_t>(16, 0x33))
        };
        auto r = vault.open(pkt, verifier.sign_public.span());
        CHECK(r.is_err());
    }
}

TEST("hardening/asym-vault/short-signature-rejected-by-open") {
    auto alice = crypto::AsymmetricVault::generate_bundle();
    auto bob   = crypto::AsymmetricVault::generate_bundle();
    auto sealed = crypto::AsymmetricVault::seal(
        std::string_view("attack at dawn"), alice, bob.box_public.span());
    REQUIRE(sealed.is_ok());
    auto& pkt = sealed.value();
    pkt.signature = crypto::SecureBuffer(std::vector<uint8_t>(3, 0x22));
    auto r = crypto::AsymmetricVault::open(pkt, bob, alice.sign_public.span());
    CHECK(r.is_err());
}

TEST("hardening/asym-vault/short-sender-box-key-rejected-by-open") {
    auto alice = crypto::AsymmetricVault::generate_bundle();
    auto bob   = crypto::AsymmetricVault::generate_bundle();
    auto sealed = crypto::AsymmetricVault::seal(
        std::string_view("attack at dawn"), alice, bob.box_public.span());
    REQUIRE(sealed.is_ok());
    auto& pkt = sealed.value();
    pkt.kdf_salt = crypto::SecureBuffer(std::vector<uint8_t>(4, 0x33));
    auto r = crypto::AsymmetricVault::open(pkt, bob, alice.sign_public.span());
    CHECK(r.is_err());
}

TEST("hardening/asym-vault/short-recipient-key-rejected-by-seal") {
    auto alice = crypto::AsymmetricVault::generate_bundle();
    std::vector<uint8_t> short_pk(5, 0x44);
    auto r = crypto::AsymmetricVault::seal(
        std::string_view("attack at dawn"), alice, short_pk);
    CHECK(r.is_err());
}

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)
namespace {
void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(x >> (8 * i)));
}

std::vector<uint8_t> huge_sig_inner() {
    std::vector<uint8_t> inner;
    put_u32_le(inner, 0xFFFFFFFDu);
    inner.insert(inner.end(), 8, 0x41);
    return inner;
}
}

// Suite signed envelope: sig_len near 2^32 must not wrap the bounds check.
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
TEST("hardening/suite/huge-sig-len-rejected") {
    auto rk = crypto::pq::HybridKem::generate_keypair();
    auto sk = crypto::pq::HybridSig::generate_keypair();
    REQUIRE(rk.is_ok());
    REQUIRE(sk.is_ok());
    auto enc = crypto::pq::HybridKem::encapsulate(rk.value().public_key.span());
    REQUIRE(enc.is_ok());
    auto inner = huge_sig_inner();
    auto env = crypto::MolecularVault::seal_with_key(
        inner, enc.value().shared_secret.span(), {});
    REQUIRE(env.is_ok());

    std::vector<uint8_t> out = {'C', 'S', 'S', 'P', crypto::Suite::VERSION,
                                crypto::Suite::SUITE_HYBRID_KEM_SIG};
    put_u32_le(out, static_cast<uint32_t>(enc.value().ciphertext.size()));
    auto ct = enc.value().ciphertext.span();
    out.insert(out.end(), ct.begin(), ct.end());
    auto es = env.value().span();
    out.insert(out.end(), es.begin(), es.end());

    auto r = crypto::Suite::open_signed_pq(
        out, rk.value().secret_key.span(), sk.value().public_key.span());
    CHECK(r.is_err());
}

TEST("hardening/suite/huge-kem-ct-len-rejected") {
    std::vector<uint8_t> out = {'C', 'S', 'S', 'P', crypto::Suite::VERSION,
                                crypto::Suite::SUITE_HYBRID_KEM_SIG};
    put_u32_le(out, 0xFFFFFFFFu);
    out.insert(out.end(), 16, 0x00);
    std::vector<uint8_t> dummy(32, 0);
    auto r = crypto::Suite::open_signed_pq(out, dummy, dummy);
    CHECK(r.is_err());
}

// Flagship one-shot envelope: same sig_len wraparound pattern.
TEST("hardening/flagship/huge-sig-len-rejected") {
    using P = crypto::Flagship;
    auto r = P::generate_recipient();
    auto s = P::generate_sender();
    REQUIRE(r.is_ok());
    REQUIRE(s.is_ok());
    std::vector<uint8_t> msg = {'h', 'i'};
    auto real = P::seal(msg, r.value().public_key.span(), s.value().secret_key.span());
    REQUIRE(real.is_ok());

    auto enc = crypto::pq::SntrupX25519::encapsulate(r.value().public_key.span());
    REQUIRE(enc.is_ok());
    constexpr std::size_t head_fixed = 4 + 1 + 1 + P::FP_BYTES + 4;
    REQUIRE(real.value().size() > head_fixed);
    std::vector<uint8_t> head(real.value().data(), real.value().data() + head_fixed);
    auto ct = enc.value().ciphertext.span();
    head.insert(head.end(), ct.begin(), ct.end());

    auto inner = huge_sig_inner();
    auto env = crypto::MolecularVault::seal_with_key(
        inner, enc.value().shared_secret.span(), head);
    REQUIRE(env.is_ok());
    std::vector<uint8_t> out = head;
    auto es = env.value().span();
    out.insert(out.end(), es.begin(), es.end());

    auto opened = P::open(out, r.value().secret_key.span(), r.value().public_key.span(),
                          s.value().public_key.span());
    CHECK(opened.is_err());
}
#endif
#endif

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_hardening() {
    RUN("hardening/asym-vault/tampered-box-public-rejected");
    RUN("hardening/packet/truncated-after-salt-len");
    RUN("hardening/packet/empty-input");
    RUN("hardening/packet/salt-len-exceeds-buffer");
    RUN("hardening/packet/round-trip-still-works");
    RUN("hardening/packet/short-signature-rejected-by-deserialise");
    RUN("hardening/vault/short-signature-rejected-by-open");
    RUN("hardening/asym-vault/short-signature-rejected-by-open");
    RUN("hardening/asym-vault/short-sender-box-key-rejected-by-open");
    RUN("hardening/asym-vault/short-recipient-key-rejected-by-seal");
#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
    RUN("hardening/suite/huge-sig-len-rejected");
#endif
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
    RUN("hardening/suite/huge-kem-ct-len-rejected");
#endif
#if defined(CRYPTOLIB_HAS_NATIVE_COMBINERS) && defined(CRYPTOLIB_HAS_MEDIA_ENTROPY)
    RUN("hardening/flagship/huge-sig-len-rejected");
#endif
#endif
#ifdef CRYPTOLIB_HAS_BLS
    RUN("hardening/bls/duplicate-message-rejected");
    RUN("hardening/bls/distinct-messages-still-verify");
#endif
}
