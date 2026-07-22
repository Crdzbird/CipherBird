// Suite — the one-call advanced combinations. Round-trips, fail-closed paths,
// envelope framing, and cross-flow confusion (wrong magic) checks.
#include "test_framework.hpp"

#include <cryptolib/suite.hpp>

#include <array>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)

using crypto::SecureBuffer;
using crypto::Suite;

namespace {
std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }
std::vector<uint8_t> vec(const SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }

// Write a deterministic scratch file and clean it up.
struct ScratchFile {
std::filesystem::path p;
explicit ScratchFile(const char* name) {
    p = std::filesystem::temp_directory_path() / name;
    std::ofstream f(p, std::ios::binary);
    for (int i = 0; i < 4096; ++i) f.put(static_cast<char>(i * 37 + 11));
}
~ScratchFile() { std::error_code ec; std::filesystem::remove(p, ec); }
};
const std::vector<uint8_t> aad = bytes("suite/v1");
} // namespace

// ── PQ message ──────────────────────────────────────────────────────────
TEST("suite/pq/roundtrip") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    CHECK_OK(bob);
    auto pt = bytes("see you at dawn");
    auto env = Suite::seal_pq(pt, bob.value().public_key.span(), aad);
    CHECK_OK(env);
    auto out = Suite::open_pq(env.value().span(), bob.value().secret_key.span(), aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

// sntrup761 hybrid variant — open_pq auto-detects the KEM from the suite id.
TEST("suite/pq/sntrup-roundtrip") {
    auto bob = crypto::pq::SntrupX25519::generate_keypair();
    CHECK_OK(bob);
    auto pt = bytes("diversity hedge");
    auto env = Suite::seal_pq_sntrup(pt, bob.value().public_key.span(), aad);
    CHECK_OK(env);
    auto out = Suite::open_pq(env.value().span(), bob.value().secret_key.span(), aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

TEST("suite/signed-pq/sntrup-roundtrip") {
    auto bob = crypto::pq::SntrupX25519::generate_keypair();
    auto signer = crypto::pq::HybridSig::generate_keypair();
    CHECK_OK(signer);
    auto pt = bytes("board resolution");
    auto env = Suite::seal_signed_pq_sntrup(pt, bob.value().public_key.span(),
                                            signer.value().secret_key.span(), aad);
    CHECK_OK(env);
    auto out = Suite::open_signed_pq(env.value().span(), bob.value().secret_key.span(),
                                     signer.value().public_key.span(), aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
    // Wrong signer still rejected on the sntrup path.
    auto impostor = crypto::pq::HybridSig::generate_keypair();
    CHECK_ERR(Suite::open_signed_pq(env.value().span(), bob.value().secret_key.span(),
                                    impostor.value().public_key.span(), aad));
}

// Cross-KEM confusion: an ML-KEM secret must not open a sntrup envelope. The
// suite id selects sntrup decapsulation, so the (differently sized) ML-KEM key
// fails closed rather than silently producing a wrong secret.
TEST("suite/pq/cross-kem-rejected") {
    auto sntrup = crypto::pq::SntrupX25519::generate_keypair();
    auto mlkem  = crypto::pq::HybridKem::generate_keypair();
    auto env = Suite::seal_pq_sntrup(bytes("x"), sntrup.value().public_key.span(), aad);
    CHECK_OK(env);
    CHECK_ERR(Suite::open_pq(env.value().span(), mlkem.value().secret_key.span(), aad));
}

TEST("suite/pq/wrong-secret-fails") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto eve = crypto::pq::HybridKem::generate_keypair();
    auto env = Suite::seal_pq(bytes("x"), bob.value().public_key.span(), aad);
    CHECK_OK(env);
    CHECK_ERR(Suite::open_pq(env.value().span(), eve.value().secret_key.span(), aad));
}

TEST("suite/pq/wrong-aad-fails") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto env = Suite::seal_pq(bytes("x"), bob.value().public_key.span(), aad);
    CHECK_OK(env);
    CHECK_ERR(Suite::open_pq(env.value().span(), bob.value().secret_key.span(), bytes("other")));
}

TEST("suite/pq/tamper-fails") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto env = Suite::seal_pq(bytes("integrity"), bob.value().public_key.span(), aad);
    CHECK_OK(env);
    auto buf = vec(env.value());
    buf[buf.size() - 1] ^= 0x01;
    CHECK_ERR(Suite::open_pq(buf, bob.value().secret_key.span(), aad));
}

// ── Signed + PQ (flagship) ──────────────────────────────────────────────
TEST("suite/signed-pq/roundtrip") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto signer = crypto::pq::HybridSig::generate_keypair();
    CHECK_OK(signer);
    auto pt = bytes("transfer 100 to acct #42");
    auto env = Suite::seal_signed_pq(pt, bob.value().public_key.span(),
                                     signer.value().secret_key.span(), aad);
    CHECK_OK(env);
    auto out = Suite::open_signed_pq(env.value().span(), bob.value().secret_key.span(),
                                     signer.value().public_key.span(), aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

TEST("suite/signed-pq/wrong-signer-fails") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto signer = crypto::pq::HybridSig::generate_keypair();
    auto impostor = crypto::pq::HybridSig::generate_keypair();
    auto env = Suite::seal_signed_pq(bytes("x"), bob.value().public_key.span(),
                                     signer.value().secret_key.span(), aad);
    CHECK_OK(env);
    // Decryption succeeds but authentication must reject → no plaintext leaks.
    CHECK_ERR(Suite::open_signed_pq(env.value().span(), bob.value().secret_key.span(),
                                    impostor.value().public_key.span(), aad));
}

TEST("suite/signed-pq/tamper-fails") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto signer = crypto::pq::HybridSig::generate_keypair();
    auto env = Suite::seal_signed_pq(bytes("x"), bob.value().public_key.span(),
                                     signer.value().secret_key.span(), aad);
    auto buf = vec(env.value());
    buf[buf.size() - 1] ^= 0x01;
    CHECK_ERR(Suite::open_signed_pq(buf, bob.value().secret_key.span(),
                                    signer.value().public_key.span(), aad));
}

// Cross-flow confusion: a signed envelope must not open as a plain PQ one.
TEST("suite/envelope-type-confusion-rejected") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto signer = crypto::pq::HybridSig::generate_keypair();
    auto spq = Suite::seal_signed_pq(bytes("x"), bob.value().public_key.span(),
                                     signer.value().secret_key.span(), aad);
    CHECK_ERR(Suite::open_pq(spq.value().span(), bob.value().secret_key.span(), aad));

    auto pq = Suite::seal_pq(bytes("x"), bob.value().public_key.span(), aad);
    CHECK_ERR(Suite::open_signed_pq(pq.value().span(), bob.value().secret_key.span(),
                                    signer.value().public_key.span(), aad));
}

TEST("suite/rejects-truncated-envelope") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    std::array<uint8_t, 6> tiny{};
    CHECK_ERR(Suite::open_pq(tiny, bob.value().secret_key.span(), aad));
}

// Crypto-agility: the suite-id byte (header offset 5) is bound; an unknown or
// mismatched value must fail closed rather than be silently reinterpreted.
TEST("suite/rejects-unknown-suite-id") {
    auto bob = crypto::pq::HybridKem::generate_keypair();
    auto env = Suite::seal_pq(bytes("agility"), bob.value().public_key.span(), aad);
    CHECK_OK(env);
    auto buf = vec(env.value());
    buf[5] = 0x7F; // not a known suite id
    CHECK_ERR(Suite::open_pq(buf, bob.value().secret_key.span(), aad));
}

// ── File-as-key ─────────────────────────────────────────────────────────
TEST("suite/file/roundtrip-and-wrong-file-fails") {
    ScratchFile a("cryptolib_suite_key_a.bin");
    auto pt = bytes("launch codes");
    auto env = Suite::seal_with_file(pt, a.p, aad);
    CHECK_OK(env);
    auto out = Suite::open_with_file(env.value().span(), a.p, aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);

    // A different file derives a different master → fails closed.
    auto b = std::filesystem::temp_directory_path() / "cryptolib_suite_key_b.bin";
    { std::ofstream f(b, std::ios::binary); for (int i = 0; i < 4096; ++i) f.put(char(i)); }
    CHECK_ERR(Suite::open_with_file(env.value().span(), b, aad));
    std::error_code ec; std::filesystem::remove(b, ec);
}

// ── Keyring-guarded ─────────────────────────────────────────────────────
TEST("suite/keyring/either-slot-opens") {
    auto device = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();
    (void) kr.add_device_slot(device.span());
    (void) kr.add_passphrase_slot("cross-device pass", crypto::KdfParams::interactive());

    auto pt = bytes("root secret");
    auto env = Suite::seal_with_keyring_device(pt, kr, device.span(), aad);
    CHECK_OK(env);
    // Sealed via the device slot, opened via the passphrase slot — same master.
    auto out = Suite::open_with_keyring_passphrase(env.value().span(), kr,
                                                   "cross-device pass", aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

TEST("suite/keyring/wrong-factor-fails") {
    auto device = crypto::random_bytes(32);
    auto wrong = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();
    (void) kr.add_device_slot(device.span());
    auto env = Suite::seal_with_keyring_device(bytes("x"), kr, device.span(), aad);
    CHECK_OK(env);
    CHECK_ERR(Suite::open_with_keyring_device(env.value().span(), kr, wrong.span(), aad));
}

// ── Threshold (k-of-n) ──────────────────────────────────────────────────
TEST("suite/threshold/any-k-of-n-opens") {
    auto pt = bytes("board resolution");
    auto sealed = Suite::seal_threshold(pt, 5, 3, aad);
    CHECK_OK(sealed);
    CHECK(sealed.value().shares.size() == 5);

    // Any 3 shares (here #1, #3, #5) reconstruct the master.
    std::vector<crypto::Shamir::Share> quorum;
    quorum.push_back(std::move(sealed.value().shares[0]));
    quorum.push_back(std::move(sealed.value().shares[2]));
    quorum.push_back(std::move(sealed.value().shares[4]));
    auto out = Suite::open_threshold(sealed.value().envelope.span(), quorum, aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

TEST("suite/threshold/below-quorum-fails") {
    auto sealed = Suite::seal_threshold(bytes("x"), 5, 3, aad);
    CHECK_OK(sealed);
    std::vector<crypto::Shamir::Share> two;
    two.push_back(std::move(sealed.value().shares[0]));
    two.push_back(std::move(sealed.value().shares[1]));
    // Fewer than k shares reconstruct a WRONG master → AEAD fails closed.
    CHECK_ERR(Suite::open_threshold(sealed.value().envelope.span(), two, aad));
}

TEST("suite/threshold/rejects-bad-params") {
    CHECK_ERR(Suite::seal_threshold(bytes("x"), 3, 5, {})); // k > n
}

// ── EVM address ─────────────────────────────────────────────────────────
TEST("suite/evm-address/derives-20-bytes") {
    auto w = crypto::ec::Secp256k1::generate_keypair();
    auto addr = Suite::evm_address(w.public_key.span());
    CHECK_OK(addr);
    CHECK(addr.value().size() == 20);
}

TEST("suite/evm-address/rejects-bad-pubkey") {
    std::array<uint8_t, 33> compressed{};
    compressed[0] = 0x02;
    CHECK_ERR(Suite::evm_address(compressed));
}

void run_tests_suite() {
    RUN("suite/pq/roundtrip");
    RUN("suite/pq/wrong-secret-fails");
    RUN("suite/pq/wrong-aad-fails");
    RUN("suite/pq/tamper-fails");
    RUN("suite/signed-pq/roundtrip");
    RUN("suite/signed-pq/wrong-signer-fails");
    RUN("suite/signed-pq/tamper-fails");
    RUN("suite/envelope-type-confusion-rejected");
    RUN("suite/rejects-truncated-envelope");
    RUN("suite/rejects-unknown-suite-id");
    RUN("suite/pq/sntrup-roundtrip");
    RUN("suite/signed-pq/sntrup-roundtrip");
    RUN("suite/pq/cross-kem-rejected");
    RUN("suite/file/roundtrip-and-wrong-file-fails");
    RUN("suite/keyring/either-slot-opens");
    RUN("suite/keyring/wrong-factor-fails");
    RUN("suite/threshold/any-k-of-n-opens");
    RUN("suite/threshold/below-quorum-fails");
    RUN("suite/threshold/rejects-bad-params");
    RUN("suite/evm-address/derives-20-bytes");
    RUN("suite/evm-address/rejects-bad-pubkey");
}

#else
void run_tests_suite() {
    std::printf("    SKIP suite (needs OpenSSL + PQ)\n");
}
#endif
