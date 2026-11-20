#pragma once
/// Calling libcrypto from many threads at once without hanging.
///
/// The default library context of OpenSSL 3 fills its tables lazily and
/// does not run that work once. Every thread that makes the first fetch
/// while the algorithm name map is still empty fills the map itself,
/// taking the map's write lock some hundreds of times, and the first fetch
/// of each operation type (digest, cipher, signature, ...) registers that
/// operation's names the same way. Fetches keep taking the method store's
/// lock afterwards, and each thread's first libcrypto call, and its exit,
/// take a process-wide write lock to register its thread-local state.
///
/// libcrypto's locks are pthread rwlocks. On macOS and iOS a thread waiting
/// for one while a signal interrupts it can miss its wakeup and wait
/// forever, although the lock is free (Apple FB24027930). The Go runtime
/// signals its threads all the time, so a Go server whose first P-256
/// signatures ran at once hung in cipherbird_p256_sign, every thread inside
/// ossl_namemap_add_name with no thread holding the lock. Every other
/// family that reaches libcrypto hung the same way under the same test
/// (tests/test_openssl_threads.cpp), the warm library included.
///
/// Three defences, all per thread and lock free:
///   openssl_ready()  does libcrypto's first-use work exactly once, so the
///                    first concurrent calls find the tables built and
///                    almost never wait for a write lock;
///   SignalShield     on Apple platforms, holds asynchronous signals back
///                    from the calling thread while it is inside libcrypto,
///                    so no lock wait there can be interrupted. The signals
///                    stay pending and arrive as soon as the call returns;
///   thread exit      on Apple platforms, a thread that held a shield runs
///                    libcrypto's thread-local cleanup itself as it exits,
///                    with asynchronous signals blocked, before libcrypto's
///                    own destructor would run it unshielded.
/// OpensslCall bundles the first two for every entry point that reaches
/// libcrypto, directly or through liboqs.
#ifdef CIPHERBIRD_HAS_OPENSSL

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#if defined(__APPLE__)
#include <pthread.h>
#include <signal.h>
#endif

namespace crypto::detail {

#if defined(__APPLE__)

/// Every signal except those raised by a fault (SIGSEGV, SIGBUS, SIGFPE,
/// SIGILL, SIGTRAP, SIGSYS) and SIGABRT.
inline sigset_t async_signals() noexcept {
    sigset_t set;
    sigfillset(&set);
    for (const int s : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGSYS, SIGABRT}) sigdelset(&set, s);
    return set;
}

/// The destructor of thread_exit_key: blocks asynchronous signals for the
/// rest of the exiting thread's life, then runs libcrypto's thread-local
/// cleanup, which takes libcrypto's thread registry write lock. libcrypto's
/// own destructor then finds nothing left to clean.
inline void openssl_thread_exit(void*) noexcept {
    const sigset_t block = async_signals();
    pthread_sigmask(SIG_BLOCK, &block, nullptr);
    OPENSSL_thread_stop();
}

/// A pthread key whose destructor is openssl_thread_exit. Darwin runs a
/// thread's key destructors in key order, so this one runs before
/// libcrypto's as long as it was created first; openssl_ready() creates it
/// before it initialises libcrypto. Whether creation succeeded is in ok.
struct ThreadExitKey {
    pthread_key_t key{};
    bool ok = false;
};

inline const ThreadExitKey& thread_exit_key() noexcept {
    static const ThreadExitKey k = [] {
        ThreadExitKey made;
        made.ok = pthread_key_create(&made.key, openssl_thread_exit) == 0;
        return made;
    }();
    return k;
}

/// Blocks every asynchronous signal on the calling thread for its lifetime
/// and restores the previous mask when it ends. Signals raised by a fault
/// and SIGABRT stay deliverable. Scopes nest. Also marks the thread, so its
/// libcrypto cleanup at exit runs with signals blocked.
class SignalShield {
public:
    SignalShield() noexcept {
        const sigset_t block = async_signals();
        active_ = pthread_sigmask(SIG_BLOCK, &block, &saved_) == 0;
        const ThreadExitKey& exit_key = thread_exit_key();
        if (exit_key.ok && pthread_getspecific(exit_key.key) == nullptr)
            pthread_setspecific(exit_key.key, &exit_key);
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
/// call only reads the result. Safe from any thread. On Apple platforms it
/// creates the thread exit key first, so that key precedes libcrypto's.
[[nodiscard]] inline bool openssl_ready() noexcept {
    static const bool ready = [] {
#if defined(__APPLE__)
        (void)thread_exit_key();
#endif
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

/// What every entry point that reaches libcrypto holds for its whole call:
/// a SignalShield, then openssl_ready() under it. A caller checks ready()
/// before its first libcrypto call and fails cleanly when it is false.
/// Covers code that calls libcrypto indirectly too (liboqs draws its
/// randomness, SHA-2 and AES from libcrypto when built with OpenSSL).
class OpensslCall {
public:
    OpensslCall() noexcept : ready_(openssl_ready()) {}
    OpensslCall(const OpensslCall&) = delete;
    OpensslCall& operator=(const OpensslCall&) = delete;

    [[nodiscard]] bool ready() const noexcept { return ready_; }

private:
    SignalShield shield_;
    bool ready_;
};

}

#else

namespace crypto::detail {

/// Without libcrypto there is nothing to prepare or shield.
class OpensslCall {
public:
    OpensslCall() noexcept {}
    OpensslCall(const OpensslCall&) = delete;
    OpensslCall& operator=(const OpensslCall&) = delete;

    [[nodiscard]] bool ready() const noexcept { return true; }
};

}

#endif
