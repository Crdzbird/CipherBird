#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
#include <stdexcept>
#include <vector>
using namespace test;

extern void (*cryptolib_testing_init_override)(void);

TEST("c-abi/init/success-returns-zero") {
    CHECK(cryptolib_init() == 0);
    CHECK(cryptolib_init() == 0);
}

TEST("c-abi/init/failure-returns-nonzero") {
    cryptolib_testing_init_override = [] { throw std::runtime_error("forced sodium_init failure"); };
    int rc = cryptolib_init();
    cryptolib_testing_init_override = nullptr;
    CHECK(rc != 0);
    CHECK(rc == -1);
    CHECK(cryptolib_init() == 0);
}

// A share record claiming a length near 2^32 must be refused by the parser;
// on a 32-bit size_t the old offset addition wrapped past the check.
TEST("c-abi/threshold/share-length-near-u32-max-rejected") {
    REQUIRE(cryptolib_init() == 0);
    const uint8_t pt[] = { 1, 2, 3 };
    CryptoBuffer shares{ nullptr, 0 };
    auto env = cryptolib_suite_seal_threshold(pt, sizeof pt, 3, 2, nullptr, 0, &shares);
    REQUIRE(env.error == nullptr);
    REQUIRE(shares.data != nullptr && shares.len > 5);
    std::vector<uint8_t> forged(shares.data, shares.data + shares.len);
    forged[1] = 0xff; forged[2] = 0xff; forged[3] = 0xff; forged[4] = 0xff;
    auto r = cryptolib_suite_open_threshold(env.buf.data, env.buf.len, forged.data(), forged.size(), nullptr, 0);
    CHECK(r.error != nullptr);
    if (r.error) cryptolib_str_free(r.error);
    cryptolib_buffer_free(&r.buf);
    cryptolib_buffer_free(&env.buf);
    cryptolib_buffer_free(&shares);
}

TEST("c-abi/keyring/hardware-slot-functions") {
    REQUIRE(cryptolib_init() == 0);
    auto kr = cryptolib_keyring_create();
    REQUIRE(kr != nullptr);
    const uint8_t id[] = { 'k', '1' };
    auto factor = cryptolib_keyring_add_hardware_slot(kr, id, sizeof id);
    REQUIRE(factor.error == nullptr);
    CHECK(factor.buf.len == 32);
    CHECK(cryptolib_keyring_slot_type(kr, 0) == 2);
    CHECK(cryptolib_keyring_slot_type(kr, 1) == -1);
    const uint8_t blob[] = { 9, 9, 9, 9 };
    CHECK(cryptolib_keyring_set_hardware_blob(kr, 0, blob, sizeof blob) == 1);
    CHECK(cryptolib_keyring_set_hardware_blob(kr, 1, blob, sizeof blob) == 0);
    CryptoBuffer out_id{ nullptr, 0 }, out_blob{ nullptr, 0 };
    CHECK(cryptolib_keyring_hardware_slot(kr, 0, &out_id, &out_blob) == 1);
    CHECK(out_id.len == 2 && out_blob.len == 4);
    auto ser = cryptolib_keyring_serialise(kr);
    REQUIRE(ser.error == nullptr);
    char* err = nullptr;
    auto loaded = cryptolib_keyring_deserialise(ser.buf.data, ser.buf.len, &err);
    REQUIRE(loaded != nullptr);
    auto master = cryptolib_keyring_unlock_with_hardware(loaded, 0, factor.buf.data, factor.buf.len);
    CHECK(master.error == nullptr && master.buf.len == 32);
    auto bad = cryptolib_keyring_unlock_with_hardware(loaded, 0, blob, sizeof blob);
    CHECK(bad.error != nullptr);
    if (bad.error) cryptolib_str_free(bad.error);
    cryptolib_buffer_free(&bad.buf);
    cryptolib_buffer_free(&master.buf);
    cryptolib_buffer_free(&ser.buf);
    cryptolib_buffer_free(&out_id);
    cryptolib_buffer_free(&out_blob);
    cryptolib_buffer_free(&factor.buf);
    cryptolib_keyring_free(loaded);
    cryptolib_keyring_free(kr);
}

void run_tests_c_abi_init() {
    RUN("c-abi/threshold/share-length-near-u32-max-rejected");
    RUN("c-abi/keyring/hardware-slot-functions");
    RUN("c-abi/init/success-returns-zero");
    RUN("c-abi/init/failure-returns-nonzero");
}
