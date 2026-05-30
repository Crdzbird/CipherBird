/**
 * test_hardening.cpp — regression tests for specific security fixes.
 *
 *   - EncryptedPacket::deserialise bounds (no out-of-bounds read on crafted
 *     length prefixes; run under ASan to catch over-reads).
 *   - BLS aggregate_verify rejects duplicate messages (basic-scheme rogue-key
 *     defence).
 */

#include "test_framework.hpp"

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

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_hardening() {
    RUN("hardening/asym-vault/tampered-box-public-rejected");
    RUN("hardening/packet/truncated-after-salt-len");
    RUN("hardening/packet/empty-input");
    RUN("hardening/packet/salt-len-exceeds-buffer");
    RUN("hardening/packet/round-trip-still-works");
#ifdef CRYPTOLIB_HAS_BLS
    RUN("hardening/bls/duplicate-message-rejected");
    RUN("hardening/bls/distinct-messages-still-verify");
#endif
}
