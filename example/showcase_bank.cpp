/**
 * Bank profile showcase: builds in the bank and full profiles and walks
 * through the standards-track surface a regulated deployment uses (see
 * bank_demo.hpp). Exit status is non-zero if any check fails.
 */
#include "bank_demo.hpp"
#include <cstdlib>
#include <iostream>

int main() {
    crypto::init();
    int pass = 0, fail = 0;
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
    std::cout << "CipherBird bank profile showcase\n\n";
    bank_demo::run([&](bool ok, const std::string& label) {
        std::cout << (ok ? "  [OK]   " : "  [FAIL] ") << label << "\n";
        (ok ? pass : fail)++;
    });
#else
    std::cout << "this build has no PQ and OpenSSL support; nothing to show\n";
#endif
    std::cout << "\n  Passed: " << pass << "  Failed: " << fail << "\n";
    return fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
