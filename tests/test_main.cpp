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
void run_tests_entropy_live();
void run_tests_entropy_fortuna();
void run_tests_stego_encrypted();
void run_tests_physical_seal();
void run_tests_oprf_image_seal();
void run_tests_hpke_stego_seal();
void run_tests_stego_image();
void run_tests_stego_audio();
void run_tests_stego_video();
void run_tests_stego_engine();
void run_tests_stego_keyed();
void run_tests_stego_keyed_formats();
void run_tests_stego_fec();
void run_tests_stego_analysis();
void run_tests_vault_stego();
void run_tests_entropy_stego();
void run_tests_asym_stego();
void run_tests_pq();
void run_tests_hybrid();
void run_tests_hybrid_sig();
void run_tests_xwing();
void run_tests_suite_v2();
void run_tests_session_v2();
void run_tests_fips_provider();
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
void run_tests_c_abi_init();
void run_tests_flagship();
void run_tests_session();
void run_tests_frost();
void run_tests_ecvrf();
void run_tests_bbs();
void run_tests_bbs_pseudonym();
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

    run_suite("c_abi_init",     run_tests_c_abi_init);
    run_suite("types",          run_tests_types);
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
    run_suite("fips_provider",  run_tests_fips_provider);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("hash",           run_tests_hash);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("symmetric",      run_tests_symmetric);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("committing_aead", run_tests_committing);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("aes_gcm_siv",    run_tests_aead_siv);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("asymmetric",     run_tests_asymmetric);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("vault",          run_tests_vault);
#endif
#ifdef CRYPTOLIB_HAS_MEDIA_ENTROPY
    run_suite("media_entropy",  run_tests_media_entropy);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("entropy_drbg",   run_tests_entropy_drbg);
#endif
#ifdef CRYPTOLIB_HAS_MEDIA_ENTROPY
    run_suite("entropy_health", run_tests_entropy_health);
    run_suite("entropy_live",   run_tests_entropy_live);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("entropy_fortuna", run_tests_entropy_fortuna);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_image",    run_tests_stego_image);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_audio",    run_tests_stego_audio);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_video",    run_tests_stego_video);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_engine",   run_tests_stego_engine);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_keyed",    run_tests_stego_keyed);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_keyed_fmt", run_tests_stego_keyed_formats);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_fec",      run_tests_stego_fec);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_analysis", run_tests_stego_analysis);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_encrypted", run_tests_stego_encrypted);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("physical_seal",  run_tests_physical_seal);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("image_factor",   run_tests_oprf_image_seal);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("hpke_stego",     run_tests_hpke_stego_seal);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("vault_stego",    run_tests_vault_stego);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("entropy_stego",  run_tests_entropy_stego);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("asym_stego",     run_tests_asym_stego);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("post_quantum",   run_tests_pq);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("hybrid_kem",     run_tests_hybrid);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("sntrup_x25519",  run_tests_sntrup_x25519);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("triple_hybrid",  run_tests_triple_hybrid_kem);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("triple_sig",     run_tests_triple_sig);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("hybrid_sig",     run_tests_hybrid_sig);
    run_suite("xwing",          run_tests_xwing);
    run_suite("suite_v2",       run_tests_suite_v2);
    run_suite("session_v2",     run_tests_session_v2);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("bls12_381",      run_tests_bls);
#endif
#ifdef CRYPTOLIB_HAS_STEGO
    run_suite("stego_fuzz",     run_tests_stego_fuzz);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("hardening",      run_tests_hardening);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("known_answer",   run_tests_kat);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("known_answer_pqc", run_tests_kat_pqc);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("keyring",        run_tests_keyring);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("keyring_rotation", run_tests_keyring_rotation);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("shamir",         run_tests_shamir);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("molecular_vault", run_tests_molecular_vault);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("suite",          run_tests_suite);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("flagship",       run_tests_flagship);
#endif
#ifdef CRYPTOLIB_HAS_NATIVE_COMBINERS
    run_suite("session",        run_tests_session);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("frost",          run_tests_frost);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("ecvrf",          run_tests_ecvrf);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("bbs",            run_tests_bbs);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("bbs_pseudonym",  run_tests_bbs_pseudonym);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("oprf",           run_tests_oprf);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("opaque",         run_tests_opaque);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("hpke",           run_tests_hpke);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("noise_xx",       run_tests_noise);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("noise_xx_kat",   run_tests_noise_kat);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("concurrency",    run_tests_concurrency);
#endif
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    run_suite("evm_btc",        run_tests_evm_btc);
#endif

    return report();
}
