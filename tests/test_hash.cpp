#include "test_framework.hpp"
using namespace test;

TEST("hash/blake2b/one-shot") {
    auto r = crypto::hash::Blake2b::digest("hello");
    CHECK_OK(r);
    CHECK(r.value().size() == 64);
}

TEST("hash/blake2b/deterministic") {
    auto a = crypto::hash::Blake2b::digest("same input");
    auto b = crypto::hash::Blake2b::digest("same input");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());
}

TEST("hash/blake2b/different-inputs") {
    auto a = crypto::hash::Blake2b::digest("aaa");
    auto b = crypto::hash::Blake2b::digest("aab");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() != b.value().to_hex());
}

TEST("hash/blake2b/streaming-equals-oneshot") {
    std::string_view msg = "The quick brown fox jumps over the lazy dog";
    auto one = crypto::hash::Blake2b::digest(msg);
    REQUIRE(one.is_ok());

    crypto::hash::Blake2b::Stream st;
    st.update(sv2sp(msg.substr(0, 10)));
    st.update(sv2sp(msg.substr(10)));
    auto two = st.finalize();
    CHECK(one.value().to_hex() == two.to_hex());
}

TEST("hash/blake2b/keyed") {
    // Blake2b keyed: pass key as second span argument
    auto key = crypto::random_bytes(32);
    auto a   = crypto::hash::Blake2b::digest(sv2sp("msg"), key.span());
    auto b   = crypto::hash::Blake2b::digest(sv2sp("msg"), key.span());
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());

    auto key2 = crypto::random_bytes(32);
    auto c    = crypto::hash::Blake2b::digest(sv2sp("msg"), key2.span());
    REQUIRE(c.is_ok());
    CHECK(a.value().to_hex() != c.value().to_hex());
}

TEST("hash/sha256/known-vector") {
    // SHA-256("") starts with e3b0c442
    auto r = crypto::hash::Sha256::digest("");
    REQUIRE(r.is_ok());
    CHECK(r.value().to_hex().substr(0, 8) == "e3b0c442");
}

TEST("hash/sha256/deterministic") {
    auto a = crypto::hash::Sha256::digest("cryptolib");
    auto b = crypto::hash::Sha256::digest("cryptolib");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());
}

TEST("hash/sha512/known-vector") {
    // SHA-512("") starts with cf83e135
    auto r = crypto::hash::Sha512::digest("");
    REQUIRE(r.is_ok());
    CHECK(r.value().to_hex().substr(0, 8) == "cf83e135");
    CHECK(r.value().size() == 64);
}

TEST("hash/argon2id/basic-kdf") {
    uint8_t salt_data[16] = {};
    auto r = crypto::hash::Argon2id::derive_key(
        "password", {salt_data, 16}, 32,
        crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    CHECK_OK(r);
    CHECK(r.value().size() == 32);
}

TEST("hash/argon2id/deterministic") {
    uint8_t salt_data[16] = {};
    std::span<const uint8_t> s{salt_data, 16};
    auto a = crypto::hash::Argon2id::derive_key("pw", s, 32,
        crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    auto b = crypto::hash::Argon2id::derive_key("pw", s, 32,
        crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());
}

TEST("hash/argon2id/different-passwords") {
    uint8_t salt_data[16] = {};
    std::span<const uint8_t> s{salt_data, 16};
    auto a = crypto::hash::Argon2id::derive_key("pw1", s, 32,
        crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    auto b = crypto::hash::Argon2id::derive_key("pw2", s, 32,
        crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() != b.value().to_hex());
}

TEST("hash/hmac-sha512/basic") {
    auto key = crypto::random_bytes(crypto::hash::HmacSha512::KEY_BYTES);
    auto r = crypto::hash::HmacSha512::compute(sv2sp("message"), key.span());
    CHECK_OK(r);
    CHECK(r.value().size() == 64);
}

TEST("hash/hmac-sha512/key-dependent") {
    auto k1 = crypto::random_bytes(crypto::hash::HmacSha512::KEY_BYTES);
    auto k2 = crypto::random_bytes(crypto::hash::HmacSha512::KEY_BYTES);
    auto a = crypto::hash::HmacSha512::compute(sv2sp("msg"), k1.span());
    auto b = crypto::hash::HmacSha512::compute(sv2sp("msg"), k2.span());
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() != b.value().to_hex());
}

// ─── BLAKE3 tests ────────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_BLAKE3

TEST("hash/blake3/one-shot") {
    auto r = crypto::hash::Blake3::digest("hello");
    CHECK_OK(r);
    CHECK(r.value().size() == 32);
}

TEST("hash/blake3/deterministic") {
    auto a = crypto::hash::Blake3::digest("same input");
    auto b = crypto::hash::Blake3::digest("same input");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());
}

TEST("hash/blake3/different-inputs") {
    auto a = crypto::hash::Blake3::digest("aaa");
    auto b = crypto::hash::Blake3::digest("aab");
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() != b.value().to_hex());
}

TEST("hash/blake3/known-vector") {
    // BLAKE3("") known first 8 hex chars: af1349b9
    auto r = crypto::hash::Blake3::digest("");
    REQUIRE(r.is_ok());
    CHECK(r.value().to_hex().substr(0, 8) == "af1349b9");
}

TEST("hash/blake3/extendable-output") {
    auto r32 = crypto::hash::Blake3::digest("test", 32);
    auto r64 = crypto::hash::Blake3::digest("test", 64);
    REQUIRE(r32.is_ok()); REQUIRE(r64.is_ok());
    CHECK(r32.value().size() == 32);
    CHECK(r64.value().size() == 64);
    // First 32 bytes of 64-byte output should equal the 32-byte output
    CHECK(r64.value().to_hex().substr(0, 64) == r32.value().to_hex());
}

TEST("hash/blake3/keyed-mac") {
    auto key = crypto::random_bytes(32);
    auto a = crypto::hash::Blake3::keyed(sv2sp("message"), key.span());
    auto b = crypto::hash::Blake3::keyed(sv2sp("message"), key.span());
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());

    // Different key → different MAC
    auto key2 = crypto::random_bytes(32);
    auto c = crypto::hash::Blake3::keyed(sv2sp("message"), key2.span());
    REQUIRE(c.is_ok());
    CHECK(a.value().to_hex() != c.value().to_hex());
}

TEST("hash/blake3/keyed-bad-key-length") {
    auto key16 = crypto::random_bytes(16);
    auto r = crypto::hash::Blake3::keyed(sv2sp("msg"), key16.span());
    CHECK_ERR(r);
}

TEST("hash/blake3/derive-key") {
    auto ikm = crypto::random_bytes(64);
    auto a = crypto::hash::Blake3::derive_key("cryptolib test context", ikm.span(), 32);
    auto b = crypto::hash::Blake3::derive_key("cryptolib test context", ikm.span(), 32);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());

    // Different context → different key
    auto c = crypto::hash::Blake3::derive_key("other context", ikm.span(), 32);
    REQUIRE(c.is_ok());
    CHECK(a.value().to_hex() != c.value().to_hex());
}

TEST("hash/blake3/streaming-equals-oneshot") {
    std::string_view msg = "The quick brown fox jumps over the lazy dog";
    auto one = crypto::hash::Blake3::digest(msg);
    REQUIRE(one.is_ok());

    crypto::hash::Blake3::Stream st;
    st.update(sv2sp(msg.substr(0, 10)));
    st.update(sv2sp(msg.substr(10)));
    auto two = st.finalize();
    CHECK(one.value().to_hex() == two.to_hex());
}

TEST("hash/blake3/streaming-keyed") {
    auto key = crypto::random_bytes(32);
    auto one = crypto::hash::Blake3::keyed(sv2sp("hello world"), key.span());
    REQUIRE(one.is_ok());

    crypto::hash::Blake3::Stream st(key.span());
    st.update(sv2sp("hello "));
    st.update(sv2sp("world"));
    auto two = st.finalize();
    CHECK(one.value().to_hex() == two.to_hex());
}

#endif // CRYPTOLIB_HAS_BLAKE3

// ─── HMAC-SHA256 tests ───────────────────────────────────────────────────────

TEST("hash/hmac-sha256/basic") {
    auto key = crypto::random_bytes(crypto::hash::HmacSha256::KEY_BYTES);
    auto r = crypto::hash::HmacSha256::compute(sv2sp("message"), key.span());
    CHECK_OK(r);
    CHECK(r.value().size() == 32);
}

TEST("hash/hmac-sha256/verify") {
    auto key = crypto::random_bytes(crypto::hash::HmacSha256::KEY_BYTES);
    auto r = crypto::hash::HmacSha256::compute(sv2sp("message"), key.span());
    REQUIRE(r.is_ok());
    CHECK(crypto::hash::HmacSha256::verify(sv2sp("message"), r.value().span(), key.span()));
    CHECK(!crypto::hash::HmacSha256::verify(sv2sp("tampered"), r.value().span(), key.span()));
}

// ─── HKDF-SHA256 tests ──────────────────────────────────────────────────────

TEST("hkdf/extract-expand-basic") {
    auto ikm = crypto::random_bytes(32);
    auto salt = crypto::random_bytes(32);
    auto prk = crypto::hash::HkdfSha256::extract(salt.span(), ikm.span());
    REQUIRE(prk.is_ok());
    CHECK(prk.value().size() == 32);

    auto okm = crypto::hash::HkdfSha256::expand(prk.value().span(), "test info", 64);
    REQUIRE(okm.is_ok());
    CHECK(okm.value().size() == 64);
}

TEST("hkdf/deterministic") {
    auto ikm = crypto::random_bytes(32);
    auto salt = crypto::random_bytes(16);
    auto a = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "ctx", 48);
    auto b = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "ctx", 48);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() == b.value().to_hex());
}

TEST("hkdf/different-info-different-output") {
    auto ikm = crypto::random_bytes(32);
    auto salt = crypto::random_bytes(16);
    auto a = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "info-a", 32);
    auto b = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "info-b", 32);
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());
    CHECK(a.value().to_hex() != b.value().to_hex());
}

TEST("hkdf/empty-salt-works") {
    auto ikm = crypto::random_bytes(32);
    std::span<const uint8_t> empty_salt{};
    auto r = crypto::hash::HkdfSha256::derive(ikm.span(), empty_salt, "info", 32);
    CHECK_OK(r);
    CHECK(r.value().size() == 32);
}

TEST("hkdf/long-output") {
    auto ikm = crypto::random_bytes(32);
    auto salt = crypto::random_bytes(16);
    // Request 255 * 32 = 8160 bytes (maximum allowed)
    auto r = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "long", 8160);
    CHECK_OK(r);
    CHECK(r.value().size() == 8160);
}

TEST("hkdf/too-long-output-fails") {
    auto ikm = crypto::random_bytes(32);
    auto salt = crypto::random_bytes(16);
    auto r = crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(), "fail", 8161);
    CHECK_ERR(r);
}

TEST("hkdf/rfc5869-test-vector-1") {
    // RFC 5869 Test Case 1 (HKDF-SHA256)
    uint8_t ikm_data[22];  std::memset(ikm_data, 0x0b, 22);
    uint8_t salt_data[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                            0x08,0x09,0x0a,0x0b,0x0c };
    uint8_t info_data[] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };

    auto prk = crypto::hash::HkdfSha256::extract(
        {salt_data, sizeof(salt_data)}, {ikm_data, sizeof(ikm_data)});
    REQUIRE(prk.is_ok());
    CHECK(prk.value().to_hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    auto okm = crypto::hash::HkdfSha256::expand(
        prk.value().span(), {info_data, sizeof(info_data)}, 42);
    REQUIRE(okm.is_ok());
    CHECK(okm.value().to_hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

void run_tests_hash() {
    RUN("hash/blake2b/one-shot");
    RUN("hash/blake2b/deterministic");
    RUN("hash/blake2b/different-inputs");
    RUN("hash/blake2b/streaming-equals-oneshot");
    RUN("hash/blake2b/keyed");
    RUN("hash/sha256/known-vector");
    RUN("hash/sha256/deterministic");
    RUN("hash/sha512/known-vector");
    RUN("hash/argon2id/basic-kdf");
    RUN("hash/argon2id/deterministic");
    RUN("hash/argon2id/different-passwords");
    RUN("hash/hmac-sha512/basic");
    RUN("hash/hmac-sha512/key-dependent");
#ifdef CRYPTOLIB_HAS_BLAKE3
    RUN("hash/blake3/one-shot");
    RUN("hash/blake3/deterministic");
    RUN("hash/blake3/different-inputs");
    RUN("hash/blake3/known-vector");
    RUN("hash/blake3/extendable-output");
    RUN("hash/blake3/keyed-mac");
    RUN("hash/blake3/keyed-bad-key-length");
    RUN("hash/blake3/derive-key");
    RUN("hash/blake3/streaming-equals-oneshot");
    RUN("hash/blake3/streaming-keyed");
#endif
    RUN("hash/hmac-sha256/basic");
    RUN("hash/hmac-sha256/verify");
    RUN("hkdf/extract-expand-basic");
    RUN("hkdf/deterministic");
    RUN("hkdf/different-info-different-output");
    RUN("hkdf/empty-salt-works");
    RUN("hkdf/long-output");
    RUN("hkdf/too-long-output-fails");
    RUN("hkdf/rfc5869-test-vector-1");
}
