// MolecularVault — round-trips, authentication, and framing checks.
// The construction is pure composition; these tests assert seal→open recovers
// the plaintext and that every tamper/wrong-input path fails closed.
#include "test_framework.hpp"

#include <cryptolib/molecular_vault.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::MolecularVault;
using crypto::SecureBuffer;

namespace {
std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }
std::vector<uint8_t> vec(const SecureBuffer& b) {
    return {b.span().begin(), b.span().end()};
}
// Fast Argon2id params so the suite stays quick; production uses SENSITIVE+.
MolecularVault::KdfParams fast() { return {2 /*ops*/, 1u << 20 /*1 MiB*/}; }
} // namespace

TEST("molecular/passphrase/roundtrip") {
    auto pt = bytes("the launch codes are 0000");
    auto aad = bytes("ctx:v1|user-42");
    auto env = MolecularVault::seal(pt, "correct horse battery staple", aad, fast());
    CHECK_OK(env);
    auto out = MolecularVault::open(env.value().span(), "correct horse battery staple", aad);
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
}

TEST("molecular/passphrase/wrong-passphrase-fails") {
    auto env = MolecularVault::seal(bytes("secret"), "right-pass", {}, fast());
    CHECK_OK(env);
    CHECK_ERR(MolecularVault::open(env.value().span(), "wrong-pass", {}));
}

TEST("molecular/passphrase/wrong-aad-fails") {
    auto env = MolecularVault::seal(bytes("secret"), "p", bytes("aad-A"), fast());
    CHECK_OK(env);
    CHECK_ERR(MolecularVault::open(env.value().span(), "p", bytes("aad-B")));
}

TEST("molecular/tamper-body-fails") {
    auto env = MolecularVault::seal(bytes("integrity matters"), "p", {}, fast());
    CHECK_OK(env);
    auto buf = vec(env.value());
    buf[buf.size() - 1] ^= 0x01; // flip last ciphertext byte
    CHECK_ERR(MolecularVault::open(buf, "p", {}));
}

TEST("molecular/tamper-salt-fails") {
    auto env = MolecularVault::seal(bytes("integrity matters"), "p", {}, fast());
    CHECK_OK(env);
    auto buf = vec(env.value());
    buf[24] ^= 0x01; // flip a salt byte → wrong derived key
    CHECK_ERR(MolecularVault::open(buf, "p", {}));
}

TEST("molecular/distinct-salt-distinct-ciphertext") {
    auto pt = bytes("same plaintext, same passphrase");
    auto a = MolecularVault::seal(pt, "p", {}, fast());
    auto b = MolecularVault::seal(pt, "p", {}, fast());
    CHECK_OK(a); CHECK_OK(b);
    CHECK(vec(a.value()) != vec(b.value())); // random per-seal salt
}

TEST("molecular/rawkey/roundtrip") {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i * 7 + 1);
    auto pt = bytes("keyed with a full-entropy master (e.g. from hybrid KEM)");
    auto env = MolecularVault::seal_with_key(pt, key, bytes("h"));
    CHECK_OK(env);
    auto out = MolecularVault::open_with_key(env.value().span(), key, bytes("h"));
    CHECK_OK(out);
    CHECK(vec(out.value()) == pt);
    key[0] ^= 0xff;
    CHECK_ERR(MolecularVault::open_with_key(env.value().span(), key, bytes("h")));
}

TEST("molecular/rawkey/rejects-bad-key-length") {
    std::array<uint8_t, 16> shortKey{};
    CHECK_ERR(MolecularVault::seal_with_key(bytes("x"), shortKey, {}));
}

TEST("molecular/empty-plaintext-roundtrip") {
    auto env = MolecularVault::seal({}, "p", {}, fast());
    CHECK_OK(env);
    auto out = MolecularVault::open(env.value().span(), "p", {});
    CHECK_OK(out);
    CHECK(out.value().span().empty());
}

TEST("molecular/rejects-empty-passphrase") {
    CHECK_ERR(MolecularVault::seal(bytes("x"), "", {}, fast()));
}

TEST("molecular/rejects-truncated-envelope") {
    std::array<uint8_t, 8> tiny{};
    CHECK_ERR(MolecularVault::open(tiny, "p", {}));
}

void run_tests_molecular_vault() {
    // AES-256-GCM-SIV needs OpenSSL; skip the whole suite if unavailable.
    if (!MolecularVault::is_available()) {
        std::printf("    SKIP molecular_vault (AES-256-GCM-SIV / OpenSSL unavailable)\n");
        return;
    }
    RUN("molecular/passphrase/roundtrip");
    RUN("molecular/passphrase/wrong-passphrase-fails");
    RUN("molecular/passphrase/wrong-aad-fails");
    RUN("molecular/tamper-body-fails");
    RUN("molecular/tamper-salt-fails");
    RUN("molecular/distinct-salt-distinct-ciphertext");
    RUN("molecular/rawkey/roundtrip");
    RUN("molecular/rawkey/rejects-bad-key-length");
    RUN("molecular/empty-plaintext-roundtrip");
    RUN("molecular/rejects-empty-passphrase");
    RUN("molecular/rejects-truncated-envelope");
}
