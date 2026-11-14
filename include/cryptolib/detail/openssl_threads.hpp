#pragma once
/// Calling libcrypto from many threads at once without hanging.
///
/// The default library context of OpenSSL 3 fills its tables lazily and
/// does not run that work once. Every thread that makes the first fetch
/// while the algorithm name map is still empty fills the map itself,
/// taking the map's write lock some hundreds of times, and the first fetch
/// of each operation type (digest, cipher, signature, ...) registers that
/// operation's names the same way. Each thread's first libcrypto call, and
/// its exit, also take a process-wide write lock to register its
/// thread-local state.
///
/// libcrypto's locks are pthread rwlocks. On macOS and iOS a thread waiting
/// for one while a signal interrupts it can miss its wakeup and wait
/// forever, although the lock is free (Apple FB24027930). The Go runtime
/// signals its threads all the time, so a Go server whose first P-256
/// signatures ran at once hung in cryptolib_p256_sign, every thread inside
/// ossl_namemap_add_name with no thread holding the lock.
///
/// Two defences, both per thread and lock free:
///   openssl_ready()  does libcrypto's first-use work exactly once, so the
///                    first concurrent calls find the tables built and
///                    almost never wait for a write lock;
///   SignalShield     on Apple platforms, holds asynchronous signals back
///                    from the calling thread while it is inside libcrypto,
///                    so no lock wait there can be interrupted. The signals
///                    stay pending and arrive as soon as the call returns.
#ifdef CRYPTOLIB_HAS_OPENSSL

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#if defined(__APPLE__)
#include <pthread.h>
#include <signal.h>
#endif

namespace crypto::detail {

/// Builds every method table of the default provider set: the name map, then
/// one table per operation type. A table that a trimmed libcrypto lacks is
/// simply empty.
inline void openssl_build_method_tables() noexcept {
    EVP_MD_do_all_provided(nullptr, [](EVP_MD*, void*) {}, nullptr);
    EVP_CIPHER_do_all_provided(nullptr, [](EVP_CIPHER*, void*) {}, nullptr);
    EVP_MAC_do_all_provided(nullptr, [](EVP_MAC*, void*) {}, nullptr);
    EVP_KDF_do_all_provided(nullptr, [](EVP_KDF*, void*) {}, nullptr);
    EVP_RAND_do_all_provided(nullptr, [](EVP_RAND*, void*) {}, nullptr);
    EVP_KEYMGMT_do_all_provided(nullptr, [](EVP_KEYMGMT*, void*) {}, nullptr);
    EVP_SIGNATURE_do_all_provided(nullptr, [](EVP_SIGNATURE*, void*) {}, nullptr);
    EVP_KEYEXCH_do_all_provided(nullptr, [](EVP_KEYEXCH*, void*) {}, nullptr);
    EVP_KEM_do_all_provided(nullptr, [](EVP_KEM*, void*) {}, nullptr);
    EVP_ASYM_CIPHER_do_all_provided(nullptr, [](EVP_ASYM_CIPHER*, void*) {}, nullptr);
}

/// True once libcrypto is initialised, its name map filled, its method
/// tables built and its primary random generator instantiated. The first
/// caller does the work while any concurrent first callers wait; every later
/// call only reads the result. Safe from any thread.
[[nodiscard]] inline bool openssl_ready() noexcept {
    static const bool ready = [] {
        if (OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr) != 1)
            return false;
        EVP_MD* sha256 = EVP_MD_fetch(nullptr, "SHA256", nullptr);
        if (sha256 == nullptr) return false;
        EVP_MD_free(sha256);
        openssl_build_method_tables();
        return RAND_get0_primary(nullptr) != nullptr;
    }();
    return ready;
}

#if defined(__APPLE__)

/// Blocks every asynchronous signal on the calling thread for its lifetime
/// and restores the previous mask when it ends. Signals raised by a fault
/// (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGSYS) and SIGABRT stay
/// deliverable. Scopes nest.
class SignalShield {
public:
    SignalShield() noexcept {
        sigset_t block;
        sigfillset(&block);
        for (const int s : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGSYS, SIGABRT}) sigdelset(&block, s);
        active_ = pthread_sigmask(SIG_BLOCK, &block, &saved_) == 0;
    }
    ~SignalShield() {
        if (active_) pthread_sigmask(SIG_SETMASK, &saved_, nullptr);
    }
    SignalShield(const SignalShield&) = delete;
    SignalShield& operator=(const SignalShield&) = delete;

private:
    sigset_t saved_{};
    bool active_ = false;
};

#else

/// Elsewhere pthread rwlock waits survive signals, so nothing is blocked.
class SignalShield {
public:
    SignalShield() noexcept {}
    ~SignalShield() {}
    SignalShield(const SignalShield&) = delete;
    SignalShield& operator=(const SignalShield&) = delete;
};

#endif

}

#endif
