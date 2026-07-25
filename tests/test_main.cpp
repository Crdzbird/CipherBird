/**
 * test_main.cpp — entry point for the cryptolib test suite.
 *
 * Each test_*.cpp defines a void run_tests_<module>() function.
 * This file calls them all and reports a final summary.
 *
 * Test registration is done with the TEST() / SECTION() macros defined in
 * test_framework.hpp.  No external dependencies; pure C++20.
 */

#include "test_framework.hpp"

// ── forward declarations (each test file defines one of these) ───────────────
void run_tests_types();
void run_tests_hash();
void run_tests_symmetric();
void run_tests_committing();
void run_tests_aead_siv();
void run_tests_asymmetric();
void run_tests_vault();
void run_tests_media_entropy();
void run_tests_entropy_drbg();
void run_tests_entropy_health();
void run_tests_stego_image();
void run_tests_stego_audio();
void run_tests_stego_video();
void run_tests_stego_engine();
void run_tests_stego_keyed();
void run_tests_vault_stego();
void run_tests_entropy_stego();
void run_tests_asym_stego();
void run_tests_pq();
void run_tests_hybrid();
void run_tests_hybrid_sig();
void run_tests_bls();
void run_tests_stego_fuzz();
void run_tests_hardening();
void run_tests_kat();
void run_tests_kat_pqc();
void run_tests_sntrup_x25519();
void run_tests_triple_hybrid_kem();
void run_tests_triple_sig();
void run_tests_keyring();
void run_tests_keyring_rotation();
void run_tests_shamir();
void run_tests_molecular_vault();
void run_tests_suite();
void run_tests_flagship();
void run_tests_session();
void run_tests_frost();
void run_tests_ecvrf();
void run_tests_bbs();
void run_tests_oprf();
void run_tests_opaque();
void run_tests_hpke();
void run_tests_noise();
void run_tests_noise_kat();
void run_tests_concurrency();
void run_tests_evm_btc();

int main() {
    using namespace test;

    crypto::init();

    run_suite("types",          run_tests_types);
    run_suite("hash",           run_tests_hash);
    run_suite("symmetric",      run_tests_symmetric);
    run_suite("committing_aead", run_tests_committing);
    run_suite("aes_gcm_siv",    run_tests_aead_siv);
    run_suite("asymmetric",     run_tests_asymmetric);
    run_suite("vault",          run_tests_vault);
    run_suite("media_entropy",  run_tests_media_entropy);
    run_suite("entropy_drbg",   run_tests_entropy_drbg);
    run_suite("entropy_health", run_tests_entropy_health);
    run_suite("stego_image",    run_tests_stego_image);
    run_suite("stego_audio",    run_tests_stego_audio);
    run_suite("stego_video",    run_tests_stego_video);
    run_suite("stego_engine",   run_tests_stego_engine);
    run_suite("stego_keyed",    run_tests_stego_keyed);
    run_suite("vault_stego",    run_tests_vault_stego);
    run_suite("entropy_stego",  run_tests_entropy_stego);
    run_suite("asym_stego",     run_tests_asym_stego);
    run_suite("post_quantum",   run_tests_pq);
    run_suite("hybrid_kem",     run_tests_hybrid);
    run_suite("sntrup_x25519",  run_tests_sntrup_x25519);
    run_suite("triple_hybrid",  run_tests_triple_hybrid_kem);
    run_suite("triple_sig",     run_tests_triple_sig);
    run_suite("hybrid_sig",     run_tests_hybrid_sig);
    run_suite("bls12_381",      run_tests_bls);
    run_suite("stego_fuzz",     run_tests_stego_fuzz);
    run_suite("hardening",      run_tests_hardening);
    run_suite("known_answer",   run_tests_kat);
    run_suite("known_answer_pqc", run_tests_kat_pqc);
    run_suite("keyring",        run_tests_keyring);
    run_suite("keyring_rotation", run_tests_keyring_rotation);
    run_suite("shamir",         run_tests_shamir);
    run_suite("molecular_vault", run_tests_molecular_vault);
    run_suite("suite",          run_tests_suite);
    run_suite("flagship",       run_tests_flagship);
    run_suite("session",        run_tests_session);
    run_suite("frost",          run_tests_frost);
    run_suite("ecvrf",          run_tests_ecvrf);
    run_suite("bbs",            run_tests_bbs);
    run_suite("oprf",           run_tests_oprf);
    run_suite("opaque",         run_tests_opaque);
    run_suite("hpke",           run_tests_hpke);
    run_suite("noise_xx",       run_tests_noise);
    run_suite("noise_xx_kat",   run_tests_noise_kat);
    run_suite("concurrency",    run_tests_concurrency);
    run_suite("evm_btc",        run_tests_evm_btc);

    return report();
}
