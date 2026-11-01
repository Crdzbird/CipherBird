#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
#include <string>
#include <vector>
using namespace test;

using B2 = crypto::hash::Blake2b;

namespace {

std::string hex_of(const uint8_t* p, size_t n) {
    std::string s(n * 2 + 1, '\0');
    sodium_bin2hex(s.data(), s.size(), p, n);
    s.resize(n * 2);
    return s;
}

std::vector<uint8_t> counting(size_t n, uint8_t start = 0) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(start + i);
    return v;
}

std::string abi_hex(CryptoBufferResult r) {
    if (r.error) { cryptolib_str_free(r.error); cryptolib_buffer_free(&r.buf); return "error"; }
    std::string s = hex_of(r.buf.data, r.buf.len);
    cryptolib_buffer_free(&r.buf);
    return s;
}

bool abi_fails(CryptoBufferResult r) {
    const bool failed = r.error != nullptr && r.buf.data == nullptr && r.buf.len == 0;
    if (r.error) cryptolib_str_free(r.error);
    cryptolib_buffer_free(&r.buf);
    return failed;
}

std::string b2(std::span<const uint8_t> msg, std::span<const uint8_t> key, size_t out_len) {
    return abi_hex(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), key.size(), out_len));
}

const char* const kGenerichashExp32 =
    "a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463";
const char* const kGenerichashExp56 =
    "703d8e552236b2090143444545f0a61a809d8ef9843bcf6883f61671fb31c8d6"
    "ac9fd373e7f9f79a0c72fa6a37dc655ba1fb01a5f41e36d1";
const char* const kGenerichashExp64 =
    "bd965bf31e87d70327536f2a341cebc4768eca275fa05ef98f7f1b71a0351298"
    "de006fba73fe6733ed01d75801b4a928e54231b38e38c562b2e33ea1284992fa";

}

TEST("paseto/blake2b-keyed/libsodium-generichash-exp-32-56-64") {
    REQUIRE(cryptolib_init() == 0);
    for (size_t n : {size_t{32}, size_t{56}, size_t{64}}) {
        const auto key = counting(n);
        const auto msg = counting(n - 1);
        const char* want = n == 32 ? kGenerichashExp32 : n == 56 ? kGenerichashExp56 : kGenerichashExp64;
        CHECK(b2(msg, key, n) == want);
        auto cpp = B2::compute(msg, key, n);
        REQUIRE(cpp.is_ok());
        CHECK(cpp.value().to_hex() == want);
    }
}

TEST("paseto/blake2b-keyed/blake2-reference-kat-64") {
    const auto key = counting(64);
    CHECK(b2({}, key, 64) ==
          "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
          "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568");
    const uint8_t zero = 0;
    CHECK(b2({&zero, 1}, key, 64) ==
          "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
          "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd");
}

TEST("paseto/blake2b-keyed/v4-local-shaped-inputs-match-python-hashlib") {
    const auto key = counting(32, 0x70);
    std::string ek = "paseto-encryption-key";
    std::string ak = "paseto-auth-key-for-aead";
    std::vector<uint8_t> m1(ek.begin(), ek.end()), m2(ak.begin(), ak.end());
    m1.resize(m1.size() + 32, 0);
    m2.resize(m2.size() + 32, 0);
    CHECK(b2(m1, key, 56) ==
          "c32b8e1c522550c8854d5177eb2ca96acc2072e3ca58407e0ee2f6470e92e49f"
          "129a23d170eddce49867d4888d276390abf7e48e550feb7c");
    CHECK(b2(m2, key, 32) ==
          "3d6d4c0504cbefdc54a562967ca276d0a99e0120cf154cc8624feb26da3a73e9");
}

TEST("paseto/blake2b-keyed/unkeyed-length-is-a-parameter-not-a-truncation") {
    const auto abc = sv2sp("abc");
    CHECK(b2(abc, {}, 64) ==
          "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
          "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    CHECK(b2(abc, {}, 32) ==
          "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    CHECK(b2(abc, {}, 1) == "6b");
    CHECK(abi_hex(cryptolib_blake2b(abc.data(), abc.size(), nullptr, 0)) == b2(abc, {}, 64));
    const uint8_t ignored = 0;
    CHECK(abi_hex(cryptolib_blake2b_keyed(abc.data(), abc.size(), &ignored, 0, 32)) == b2(abc, {}, 32));
}

TEST("paseto/blake2b-keyed/rejects-bad-lengths-and-null-pointers") {
    const auto key = counting(64);
    const auto msg = sv2sp("m");
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 32, 0)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 32, 65)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 32, SIZE_MAX)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 1, 32)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 15, 32)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), key.data(), 65, 32)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(nullptr, 1, key.data(), 32, 32)));
    CHECK(abi_fails(cryptolib_blake2b_keyed(msg.data(), msg.size(), nullptr, 32, 32)));
    CHECK(b2(msg, std::span<const uint8_t>(key.data(), 16), 32) != "error");
    CHECK(abi_hex(cryptolib_blake2b_keyed(nullptr, 0, key.data(), 32, 32)) == b2({}, std::span<const uint8_t>(key.data(), 32), 32));
    CHECK_ERR(B2::compute(msg, std::span<const uint8_t>(key.data(), 15), 32));
    CHECK_ERR(B2::compute(msg, key, 0));
}

void run_tests_paseto_primitives() {
    RUN("paseto/blake2b-keyed/libsodium-generichash-exp-32-56-64");
    RUN("paseto/blake2b-keyed/blake2-reference-kat-64");
    RUN("paseto/blake2b-keyed/v4-local-shaped-inputs-match-python-hashlib");
    RUN("paseto/blake2b-keyed/unkeyed-length-is-a-parameter-not-a-truncation");
    RUN("paseto/blake2b-keyed/rejects-bad-lengths-and-null-pointers");
}
