/**
 * ct_probe.cpp — constant-time verification harness (ctgrind / TIMECOP method).
 *
 * Marks secret buffers as "undefined" to Valgrind's memcheck; any branch or
 * memory access whose address/condition depends on those bytes is reported as
 * "Conditional jump or move depends on uninitialised value(s)". A CLEAN run
 * means the exercised secret-dependent paths are constant-time.
 *
 *   cmake -S . -B build/ct -DCRYPTOLIB_CT_VALGRIND=ON -DCRYPTOLIB_BUILD_BRIDGE=OFF
 *   cmake --build build/ct --target ct_probe
 *   valgrind --tool=memcheck --error-exitcode=1 ./build/ct/ct_probe
 *
 * Valgrind is Linux-only in practice (unreliable on arm64 macOS), so this runs
 * in CI. Without the header the CT_SECRET markers are no-ops, so the harness
 * still compiles and runs everywhere (exercising the code paths, just not the
 * timing analysis).
 */

#if defined(__has_include)
#  if __has_include(<valgrind/memcheck.h>)
#    include <valgrind/memcheck.h>
#    define CT_SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#  endif
#endif
#ifndef CT_SECRET
#  define CT_SECRET(p, n) ((void)(p), (void)(n))
#endif

#include <cryptolib/cryptolib.hpp>
#include <span>
#include <string_view>

int main() {
    crypto::init();

    // 1. secure_equal — must not branch on the contents being compared.
    {
        auto a = crypto::random_bytes(32);
        auto b = crypto::random_bytes(32);
        CT_SECRET(a.data(), a.size());
        CT_SECRET(b.data(), b.size());
        volatile bool eq = crypto::secure_equal(a.span(), b.span());
        (void)eq;
    }

    // 2. Committing AEAD decrypt — commitment compare + AEAD with a secret key.
    {
        auto key = crypto::symmetric::CommittingAead::generate_key();
        auto ct  = crypto::symmetric::CommittingAead::encrypt(std::string_view("ct-probe"), key.span());
        CT_SECRET(key.data(), key.size());
        auto d = crypto::symmetric::CommittingAead::decrypt(ct.value().span(), key.span());
        (void)d;
    }

#ifdef CRYPTOLIB_HAS_PQ
    // 3. ML-KEM decapsulate — secret-key-dependent path.
    {
        auto kp = crypto::pq::MlKem::generate_keypair();
        auto enc = crypto::pq::MlKem::encapsulate(kp.value().public_key.span());
        auto sk = std::move(kp.value().secret_key);
        CT_SECRET(sk.data(), sk.size());
        auto ss = crypto::pq::MlKem::decapsulate(enc.value().ciphertext.span(), sk.span());
        (void)ss;
    }
#endif

    // 4. Keyring unlock — device-factor compare path.
    {
        auto factor = crypto::random_bytes(32);
        auto kr = crypto::Keyring::create();
        (void)kr.add_device_slot(factor.span());
        auto blob = kr.serialise();
        auto kr2 = crypto::Keyring::deserialise(blob.span());
        CT_SECRET(factor.data(), factor.size());
        auto m = kr2.value().unlock_with_device(factor.span());
        (void)m;
    }

    return 0;
}
