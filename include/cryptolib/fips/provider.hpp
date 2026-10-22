#pragma once
/**
 * crypto::fips::Provider: the OpenSSL FIPS Provider as the only source of
 * cryptography in the fips profile (assessment r2, C3).
 *
 * The validated module is the provider binary built and installed per its
 * security policy (OpenSSL FIPS Provider 3.1.2, CMVP certificate 4985,
 * FIPS 140-3 level 1), not this library. init() loads that module into the
 * default library context, runs its power-on self-tests, and switches the
 * default property query to fips=yes so every later fetch resolves inside
 * the module or fails. Nothing here performs cryptography on its own.
 */
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
#include "../types.hpp"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <cstdlib>
#include <mutex>
#include <string>

namespace crypto::fips {

/// How the module was located, for the audit log.
struct Status {
    bool loaded = false;
    bool self_tests_passed = false;
    bool approved_mode = false;
    std::string provider_name;
    std::string provider_version;
    std::string module_directory;
    std::string config_file;
};

class Provider {
public:
    /// Where the provider lives. Explicit arguments win; otherwise the
    /// environment variables CRYPTOLIB_FIPS_MODULE_DIR (the directory holding
    /// fips.so or fips.dylib) and CRYPTOLIB_FIPS_CONFIG (the OpenSSL config
    /// that includes the fipsmodule.cnf written by openssl fipsinstall).
    struct Location {
        std::string module_directory;
        std::string config_file;
    };

    /// Loads the module, verifies its self-tests and enables approved mode.
    /// Idempotent. Fails closed: on any error no fetch is made approved and
    /// is_ready() stays false.
    [[nodiscard]] static Result<void> init(Location where = {}) {
        std::lock_guard<std::mutex> lock(mutex());
        if (state().loaded && state().approved_mode) return Result<void>::ok();
        if (where.module_directory.empty()) {
            if (const char* d = std::getenv("CRYPTOLIB_FIPS_MODULE_DIR")) where.module_directory = d;
        }
        if (where.config_file.empty()) {
            if (const char* c = std::getenv("CRYPTOLIB_FIPS_CONFIG")) where.config_file = c;
        }
        if (!where.module_directory.empty() &&
            OSSL_PROVIDER_set_default_search_path(nullptr, where.module_directory.c_str()) != 1)
            return fail("fips: cannot set the module search path");
        if (where.config_file.empty())
            return fail("fips: no configuration; set CRYPTOLIB_FIPS_CONFIG to the file that includes fipsmodule.cnf");
        if (OSSL_LIB_CTX_load_config(nullptr, where.config_file.c_str()) != 1)
            return fail("fips: configuration failed to load: " + where.config_file);
        OSSL_PROVIDER* fips = OSSL_PROVIDER_load(nullptr, "fips");
        if (!fips) return fail("fips: the provider did not load (install path, config or self-test)");
        OSSL_PROVIDER* base = OSSL_PROVIDER_load(nullptr, "base");
        if (!base) return fail("fips: the base provider did not load");
        if (OSSL_PROVIDER_self_test(fips) != 1) return fail("fips: self-tests failed");
        if (EVP_default_properties_enable_fips(nullptr, 1) != 1) return fail("fips: cannot enable approved mode");
        if (EVP_default_properties_is_fips_enabled(nullptr) != 1) return fail("fips: approved mode is not enabled");
        Status& st = state();
        st.loaded = true;
        st.self_tests_passed = true;
        st.approved_mode = true;
        st.provider_name = OSSL_PROVIDER_get0_name(fips);
        st.module_directory = where.module_directory;
        st.config_file = where.config_file;
        if (const OSSL_PARAM* params = OSSL_PROVIDER_gettable_params(fips)) {
            (void)params;
            char* version = nullptr;
            OSSL_PARAM request[] = { OSSL_PARAM_utf8_ptr("version", &version, 0), OSSL_PARAM_END };
            if (OSSL_PROVIDER_get_params(fips, request) == 1 && version) st.provider_version = version;
        }
        return Result<void>::ok();
    }

    /// True once init() succeeded in this process.
    [[nodiscard]] static bool is_ready() {
        std::lock_guard<std::mutex> lock(mutex());
        return state().loaded && state().approved_mode;
    }

    [[nodiscard]] static Status status() {
        std::lock_guard<std::mutex> lock(mutex());
        return state();
    }

    /// The property query every fetch in this profile uses.
    static constexpr const char* PROPERTIES = "fips=yes";

private:
    static std::mutex& mutex() { static std::mutex m; return m; }
    static Status& state() { static Status s; return s; }
    static Result<void> fail(const std::string& what) {
        char buf[256] = {0};
        unsigned long e = ERR_get_error();
        std::string detail;
        if (e) { ERR_error_string_n(e, buf, sizeof buf); detail = std::string(": ") + buf; }
        ERR_clear_error();
        return Result<void>::err(what + detail);
    }
};

/// Guards every operation: a call before init() is an error, never a
/// silent fall-back to a non-approved implementation.
inline Result<void> require_ready() {
    if (!Provider::is_ready()) return Result<void>::err("fips: provider not initialised; call fips::Provider::init first");
    return Result<void>::ok();
}

}
#endif
