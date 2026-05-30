#include "test_framework.hpp"
using namespace test;

// ─── SecureBuffer ─────────────────────────────────────────────────────────────

TEST("types/securebuffer/default-construct") {
    crypto::SecureBuffer b;
    CHECK(b.size() == 0);
    CHECK(b.data() == nullptr || b.size() == 0);
}

TEST("types/securebuffer/sized-construct") {
    crypto::SecureBuffer b(32);
    CHECK(b.size() == 32);
    // sodium allocates locked memory; just verify it's accessible
    b.data()[0] = 0xAB;
    CHECK(b.data()[0] == 0xAB);
}

TEST("types/securebuffer/from-span") {
    std::vector<uint8_t> src = {1, 2, 3, 4, 5};
    crypto::SecureBuffer b(src.data(), src.size());
    CHECK(b.size() == 5);
    CHECK(b.data()[0] == 1);
    CHECK(b.data()[4] == 5);
}

TEST("types/securebuffer/move-semantics") {
    crypto::SecureBuffer a(16);
    a.data()[0] = 0xFF;
    crypto::SecureBuffer b(std::move(a));
    CHECK(b.data()[0] == 0xFF);
    CHECK(b.size() == 16);
    // a is in valid but empty state after move
    CHECK(a.size() == 0);
}

TEST("types/securebuffer/to-string") {
    std::string_view s = "hello";
    crypto::SecureBuffer b(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    CHECK(b.to_string() == "hello");
}

TEST("types/securebuffer/to-hex") {
    uint8_t raw[] = {0x00, 0xFF, 0xAB};
    crypto::SecureBuffer b(raw, 3);
    auto h = b.to_hex();
    CHECK(h == "00ffab");
}

TEST("types/securebuffer/span") {
    crypto::SecureBuffer b(8);
    b.data()[0] = 42;
    auto sp = b.span();
    CHECK(sp.size() == 8);
    CHECK(sp[0] == 42);
}

// ─── Result<T> ────────────────────────────────────────────────────────────────

TEST("types/result/ok") {
    auto r = crypto::Result<int>::ok(42);
    CHECK(r.is_ok());
    CHECK(!r.is_err());
    CHECK(r.value() == 42);
}

TEST("types/result/err") {
    auto r = crypto::Result<int>::err("something went wrong");
    CHECK(r.is_err());
    CHECK(!r.is_ok());
    CHECK(r.error().message == "something went wrong");
}

TEST("types/result/void-ok") {
    auto r = crypto::Result<void>::ok();
    CHECK(r.is_ok());
    CHECK(!r.is_err());
}

TEST("types/result/void-err") {
    auto r = crypto::Result<void>::err("failed");
    CHECK(r.is_err());
    CHECK(r.error().message == "failed");
}

TEST("types/result/securebuffer-ok") {
    auto r = crypto::Result<crypto::SecureBuffer>::ok(crypto::SecureBuffer(8));
    CHECK(r.is_ok());
    CHECK(r.value().size() == 8);
}

// ─── EncryptedPacket serialise / deserialise ──────────────────────────────────

TEST("types/packet/round-trip") {
    crypto::EncryptedPacket pkt;
    pkt.ciphertext = crypto::SecureBuffer(48);  // nonce(24) + minimal ct(8) + mac(16)
    pkt.signature  = crypto::SecureBuffer(64);
    pkt.kdf_salt   = crypto::SecureBuffer(16);
    pkt.kdf_salt.data()[0] = 0x42;
    pkt.signature.data()[0]  = 0xBE;
    pkt.ciphertext.data()[0] = 0xEF;

    auto flat = pkt.serialise();
    CHECK(flat.size() > 0);

    auto r = crypto::EncryptedPacket::deserialise(flat.span());
    CHECK_OK(r);
    auto& p2 = r.value();
    CHECK(p2.kdf_salt.data()[0]   == 0x42);
    CHECK(p2.signature.data()[0]  == 0xBE);
    CHECK(p2.ciphertext.data()[0] == 0xEF);
    CHECK(p2.kdf_salt.size()   == 16);
    CHECK(p2.signature.size()  == 64);
    CHECK(p2.ciphertext.size() == 48);
}

TEST("types/packet/truncated") {
    // Empty input has no salt-length byte to read.
    auto r0 = crypto::EncryptedPacket::deserialise({});
    CHECK_ERR(r0);

    // salt_len = 16 declared, but only 3 bytes follow → truncated salt.
    uint8_t trunc[4] = {16, 0, 0, 0};
    auto r1 = crypto::EncryptedPacket::deserialise({trunc, 4});
    CHECK_ERR(r1);

    // salt consumes all remaining bytes, leaving none for the sig-length byte.
    uint8_t trunc2[4] = {3, 0xAA, 0xBB, 0xCC};
    auto r2 = crypto::EncryptedPacket::deserialise({trunc2, 4});
    CHECK_ERR(r2);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_types() {
    RUN("types/securebuffer/default-construct");
    RUN("types/securebuffer/sized-construct");
    RUN("types/securebuffer/from-span");
    RUN("types/securebuffer/move-semantics");
    RUN("types/securebuffer/to-string");
    RUN("types/securebuffer/to-hex");
    RUN("types/securebuffer/span");
    RUN("types/result/ok");
    RUN("types/result/err");
    RUN("types/result/void-ok");
    RUN("types/result/void-err");
    RUN("types/result/securebuffer-ok");
    RUN("types/packet/round-trip");
    RUN("types/packet/truncated");
}
