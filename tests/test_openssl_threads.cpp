/// Every libcrypto-backed family from many threads while signals arrive.
///
/// The P-256 calls hung in a Go server when their first concurrent calls met
/// the signals the Go runtime sends (docs/P256.md, tests/test_p256_threads.cpp).
/// The other families that reach libcrypto take the same pthread rwlocks:
/// AES-256-GCM over EVP, AES-256-GCM-SIV, SHA3-256 and SHAKE256, HPKE's
/// AES-GCM, ML-KEM-768 and X-Wing suites, and the post-quantum KEMs and signatures
/// (liboqs draws its randomness and its SHA-2 and AES from libcrypto, the
/// OpenSSL backend is libcrypto). Each test runs this binary again as a
/// child, so that libcrypto is cold or the scenario is isolated, and fails
/// when the child does not finish:
///
///   cold-start   kChildThreads threads make the process's first calls of
///                one family together while the main thread signals them
///                with pthread_kill; once with cryptolib_init first, once
///                with only libsodium initialised.
///   thread-exit  a warm process starts waves of short-lived threads that
///                make one call each and exit while being signalled, so
///                libcrypto's thread-local cleanup runs under signals.
#include "test_framework.hpp"
#include "cryptolib_c.h"
#include <cryptolib/cryptolib.hpp>
#ifdef CRYPTOLIB_HAS_OPENSSL
#include <cryptolib/detail/sha3_evp.hpp>
#include <cryptolib/hpke.hpp>
#endif
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <spawn.h>
#include <string_view>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern char** environ;

using namespace test;

namespace {

constexpr std::string_view kColdFlag = "--openssl-cold-start";
constexpr std::string_view kExitFlag = "--openssl-thread-exit";
constexpr int kChildThreads = 8;
constexpr int kExitWaves = 40;
constexpr int kExitThreads = 32;
constexpr auto kSignalStorm = std::chrono::milliseconds(500);
constexpr auto kChildGrace = std::chrono::seconds(10);
constexpr auto kChildDeadline = std::chrono::seconds(90);

const char* g_self = nullptr;

using Span = std::span<const uint8_t>;

Span bytes(std::string_view s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }

template <class A, class B>
bool same(const A& a, const B& b) {
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}

int aes_gcm_round(uint8_t tag) {
#ifdef CRYPTOLIB_HAS_OPENSSL
    using crypto::symmetric::Aes256Gcm;
    const uint8_t message[] = {'a', 'e', 's', '-', 'g', 'c', 'm', tag};
    const auto key = Aes256Gcm::generate_key();
    auto sealed = Aes256Gcm::encrypt_portable(message, key.span(), bytes("aad"));
    if (sealed.is_err()) return 1;
    auto opened = Aes256Gcm::decrypt_portable(sealed.value().span(), key.span(), bytes("aad"));
    return opened.is_ok() && same(opened.value().span(), Span(message)) ? 0 : 1;
#else
    (void)tag;
    return 0;
#endif
}

int gcm_siv_round(uint8_t tag) {
#ifdef CRYPTOLIB_HAS_OPENSSL
    using crypto::symmetric::Aes256GcmSiv;
    if (!Aes256GcmSiv::is_available()) return 0;
    const uint8_t message[] = {'g', 'c', 'm', '-', 's', 'i', 'v', tag};
    const auto key = Aes256GcmSiv::generate_key();
    auto sealed = Aes256GcmSiv::encrypt(message, key.span(), bytes("aad"));
    if (sealed.is_err()) return 1;
    auto opened = Aes256GcmSiv::decrypt(sealed.value().span(), key.span(), bytes("aad"));
    return opened.is_ok() && same(opened.value().span(), Span(message)) ? 0 : 1;
#else
    (void)tag;
    return 0;
#endif
}

int sha3_round(uint8_t tag) {
#ifdef CRYPTOLIB_HAS_OPENSSL
    const uint8_t message[] = {'s', 'h', 'a', '3', tag};
    const Span parts[] = {Span(message, 2), Span(message + 2, 3)};
    uint8_t split[32], whole[32], xof[64];
    const Span all[] = {Span(message)};
    if (!crypto::detail::sha3_256(parts, split) || !crypto::detail::sha3_256(all, whole)) return 1;
    if (!crypto::detail::shake256(message, xof, sizeof xof)) return 1;
    return std::memcmp(split, whole, sizeof whole) == 0 ? 0 : 1;
#else
    (void)tag;
    return 0;
#endif
}

int hpke_round(uint8_t tag) {
#if defined(CRYPTOLIB_HAS_OPENSSL)
    using crypto::Hpke;
    const uint8_t message[] = {'h', 'p', 'k', 'e', tag};
    int bad = 0;
    const auto kp = Hpke::generate_keypair();
    auto sealed = Hpke::seal_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm, kp.public_key.span(),
                                  bytes("info"), bytes("aad"), message);
    if (sealed.is_err()) return 1;
    auto opened = Hpke::open_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm, sealed.value().enc.span(),
                                  kp.secret_key.span(), bytes("info"), bytes("aad"), sealed.value().ct.span());
    if (opened.is_err() || !same(opened.value().span(), Span(message))) ++bad;
#ifdef CRYPTOLIB_HAS_PQ
    auto pq = Hpke::generate_keypair(Hpke::Kem::MlKem768);
    if (pq.is_err()) return bad + 1;
    auto pq_sealed = Hpke::seal_base(Hpke::Kem::MlKem768, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm,
                                     pq.value().public_key.span(), bytes("info"), bytes("aad"), message);
    if (pq_sealed.is_err()) return bad + 1;
    auto pq_opened = Hpke::open_base(Hpke::Kem::MlKem768, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm,
                                     pq_sealed.value().enc.span(), pq.value().secret_key.span(), bytes("info"),
                                     bytes("aad"), pq_sealed.value().ct.span());
    if (pq_opened.is_err() || !same(pq_opened.value().span(), Span(message))) ++bad;
    auto xw = Hpke::generate_keypair(Hpke::Kem::XWing);
    if (xw.is_err()) return bad + 1;
    auto xw_sealed = Hpke::seal_base(Hpke::Kem::XWing, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm,
                                     xw.value().public_key.span(), bytes("info"), bytes("aad"), message);
    if (xw_sealed.is_err()) return bad + 1;
    auto xw_opened = Hpke::open_base(Hpke::Kem::XWing, Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm,
                                     xw_sealed.value().enc.span(), xw.value().secret_key.span(), bytes("info"),
                                     bytes("aad"), xw_sealed.value().ct.span());
    if (xw_opened.is_err() || !same(xw_opened.value().span(), Span(message))) ++bad;
#endif
    return bad;
#else
    (void)tag;
    return 0;
#endif
}

int pq_round(uint8_t tag) {
#ifdef CRYPTOLIB_HAS_PQ
    using namespace crypto::pq;
    const uint8_t message[] = {'p', 'q', tag};
    int bad = 0;
    auto kem = MlKem::generate_keypair();
    if (kem.is_err()) return 1;
    auto enc = MlKem::encapsulate(kem.value().public_key.span());
    if (enc.is_err()) return 1;
    auto dec = MlKem::decapsulate(enc.value().ciphertext.span(), kem.value().secret_key.span());
    if (dec.is_err() || !same(dec.value().span(), enc.value().shared_secret.span())) ++bad;
    auto dsa = MlDsa::generate_keypair();
    if (dsa.is_err()) return bad + 1;
    auto sig = MlDsa::sign(message, dsa.value().secret_key.span());
    if (sig.is_err() || MlDsa::verify(message, sig.value().span(), dsa.value().public_key.span()).is_err()) ++bad;
    auto slh = SlhDsa::generate_keypair();
    if (slh.is_err()) return bad + 1;
    auto slh_sig = SlhDsa::sign(message, slh.value().secret_key.span());
    if (slh_sig.is_err() ||
        SlhDsa::verify(message, slh_sig.value().span(), slh.value().public_key.span()).is_err())
        ++bad;
    return bad;
#else
    (void)tag;
    return 0;
#endif
}

struct Family {
    std::string_view name;
    int (*round)(uint8_t);
};

constexpr Family kFamilies[] = {
    {"aes-gcm", aes_gcm_round}, {"gcm-siv", gcm_siv_round}, {"sha3", sha3_round},
    {"hpke", hpke_round},       {"pq", pq_round},
};

const Family* find_family(std::string_view name) {
    for (const auto& f : kFamilies)
        if (f.name == name) return &f;
    return nullptr;
}

/// A positive count from the environment, or fallback.
int env_count(const char* name, int fallback) {
    const char* v = std::getenv(name);
    const int n = v ? std::atoi(v) : 0;
    return n > 0 ? n : fallback;
}

void on_signal(int, siginfo_t*, void*) {}

void install_handler() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigaction(SIGURG, &sa, nullptr);
}

/// kChildThreads threads make the process's first calls of one family
/// together while the main thread signals them, as cold_child in
/// test_p256_threads.cpp does for P-256. The threads stay alive until the
/// end, so no signal lands on an exiting thread. Exit status 0 when every
/// call finished with the right answer, 1 for a wrong answer, 2 when a
/// thread never came back.
int cold_child(const Family& family, bool with_init) {
    install_handler();
    if (with_init ? cryptolib_init() != 0 : sodium_init() < 0) return 1;
    std::atomic<int> ready{0}, finished{0}, bad{0};
    std::atomic<bool> go{false}, release{false};
    std::vector<pthread_t> ids(kChildThreads);
    std::vector<std::thread> pool;
    for (int t = 0; t < kChildThreads; ++t) {
        pool.emplace_back([&, t] {
            ids[t] = pthread_self();
            ready.fetch_add(1);
            while (!go.load()) std::this_thread::yield();
            bad.fetch_add(family.round(static_cast<uint8_t>(t)));
            finished.fetch_add(1);
            while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        });
    }
    while (ready.load() < kChildThreads) std::this_thread::yield();
    go.store(true);
    const auto storm_end = std::chrono::steady_clock::now() + kSignalStorm;
    while (finished.load() < kChildThreads && std::chrono::steady_clock::now() < storm_end) {
        for (const pthread_t id : ids) pthread_kill(id, SIGURG);
    }
    const auto grace_end = std::chrono::steady_clock::now() + kChildGrace;
    while (finished.load() < kChildThreads && std::chrono::steady_clock::now() < grace_end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (finished.load() < kChildThreads) {
        std::printf("      %s: %d of %d threads still inside their first calls %lld s after the signals stopped\n",
                    std::string(family.name).c_str(), kChildThreads - finished.load(), kChildThreads,
                    static_cast<long long>(kChildGrace.count()));
        std::fflush(stdout);
        std::_Exit(2);
    }
    release.store(true);
    for (auto& th : pool) th.join();
    return bad.load() == 0 ? 0 : 1;
}

/// A warm process starts kExitWaves waves of kExitThreads threads. Each
/// thread makes one call of the family and returns, so libcrypto's
/// thread-local cleanup runs as it exits, while the main thread signals
/// every thread of the wave until a joiner has joined them all. Exit status
/// 0 when every wave ended with the right answers, 1 for a wrong answer, 2
/// when a thread never finished exiting.
int exit_child(const Family& family) {
    install_handler();
    if (cryptolib_init() != 0 || family.round(0xFF) != 0) return 1;
    const int waves = env_count("CRYPTOLIB_OPENSSL_EXIT_WAVES", kExitWaves);
    const int threads = env_count("CRYPTOLIB_OPENSSL_EXIT_THREADS", kExitThreads);
    std::atomic<int> bad{0};
    for (int wave = 0; wave < waves; ++wave) {
        std::vector<std::thread> pool;
        std::vector<pthread_t> ids(threads);
        std::vector<std::atomic<bool>> joined(threads);
        std::atomic<int> started{0}, done{0};
        for (int t = 0; t < threads; ++t) {
            pool.emplace_back([&, t] {
                ids[t] = pthread_self();
                started.fetch_add(1);
                bad.fetch_add(family.round(static_cast<uint8_t>(t)));
            });
        }
        while (started.load() < threads) std::this_thread::yield();
        std::thread joiner([&] {
            for (int t = 0; t < threads; ++t) {
                joined[t].store(true);
                pool[t].join();
                done.fetch_add(1);
            }
        });
        const auto storm_end = std::chrono::steady_clock::now() + kSignalStorm;
        while (done.load() < threads && std::chrono::steady_clock::now() < storm_end) {
            for (int t = 0; t < threads; ++t)
                if (!joined[t].load()) pthread_kill(ids[t], SIGURG);
        }
        const auto grace_end = std::chrono::steady_clock::now() + kChildGrace;
        while (done.load() < threads && std::chrono::steady_clock::now() < grace_end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (done.load() < threads) {
            std::printf("      %s: wave %d, %d of %d threads never finished exiting\n",
                        std::string(family.name).c_str(), wave, threads - done.load(), threads);
            std::fflush(stdout);
            std::_Exit(2);
        }
        joiner.join();
    }
    return bad.load() == 0 ? 0 : 1;
}

/// Runs this binary with flag, family and mode and returns its exit status,
/// or -1 when it could not start or did not end within kChildDeadline.
int run_child(std::string_view flag, std::string_view family, const char* mode) {
    if (g_self == nullptr) return -1;
    const std::string f(flag), n(family), m(mode);
    char* const argv[] = {const_cast<char*>(g_self), const_cast<char*>(f.c_str()), const_cast<char*>(n.c_str()),
                          const_cast<char*>(m.c_str()), nullptr};
    pid_t pid = 0;
    if (posix_spawn(&pid, g_self, nullptr, nullptr, argv, environ) != 0) return -1;
    const auto end = std::chrono::steady_clock::now() + kChildDeadline;
    int status = 0;
    while (std::chrono::steady_clock::now() < end) {
        const pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (done < 0) return -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

int repeat_from_env() { return env_count("CRYPTOLIB_OPENSSL_THREADS_REPEAT", 1); }

}

/// Called first by main(): runs a child scenario and returns its exit status
/// when argv asks for one, otherwise records this binary's path and returns
/// -1 so the suite runs.
int openssl_threads_child(int argc, char** argv) {
    if (argc >= 4 && (std::string_view(argv[1]) == kColdFlag || std::string_view(argv[1]) == kExitFlag)) {
        const Family* family = find_family(argv[2]);
        if (family == nullptr) return 1;
        if (std::string_view(argv[1]) == kExitFlag) return exit_child(*family);
        return cold_child(*family, std::string_view(argv[3]) == "init");
    }
    if (argc >= 1) g_self = argv[0];
    return -1;
}

TEST("openssl-threads/cold-start-under-signals") {
    REQUIRE(g_self != nullptr);
    const int repeat = repeat_from_env();
    for (int r = 0; r < repeat; ++r) {
        for (const auto& family : kFamilies) {
            for (const char* mode : {"bare", "init"}) {
                const int status = run_child(kColdFlag, family.name, mode);
                if (status != 0)
                    std::printf("      cold child (%s, %s) ended with %d\n", std::string(family.name).c_str(), mode,
                                status);
                CHECK_EQ(status, 0);
            }
        }
    }
}

TEST("openssl-threads/thread-exit-under-signals") {
    REQUIRE(g_self != nullptr);
    const int repeat = repeat_from_env();
    for (int r = 0; r < repeat; ++r) {
        for (const auto& family : kFamilies) {
            const int status = run_child(kExitFlag, family.name, "warm");
            if (status != 0)
                std::printf("      exit child (%s) ended with %d\n", std::string(family.name).c_str(), status);
            CHECK_EQ(status, 0);
        }
    }
}

void run_tests_openssl_threads() {
    RUN("openssl-threads/cold-start-under-signals");
    RUN("openssl-threads/thread-exit-under-signals");
}
