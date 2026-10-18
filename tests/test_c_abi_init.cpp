#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
#include <stdexcept>
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

void run_tests_c_abi_init() {
    RUN("c-abi/init/success-returns-zero");
    RUN("c-abi/init/failure-returns-nonzero");
}
