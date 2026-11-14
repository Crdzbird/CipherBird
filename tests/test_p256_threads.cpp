/// P-256 through the C ABI from many threads at once.
///
/// cold-start-under-signals reproduces the hang a Go server hit: the first
/// P-256 calls of a process, made by several threads together while signals
/// keep arriving, as the Go runtime sends them. Without the fix every
/// thread stays blocked in libcrypto (ossl_namemap_add_name, waiting for a
/// pthread rwlock no thread holds, Apple FB24027930). The scenario needs a
/// process whose libcrypto is still cold, so the test runs this binary again
/// as a child (--p256-cold-start) and fails if the child does not finish.
///
/// The other tests hammer a warm library and are meant to be run under
/// ThreadSanitizer as well (cmake -DCRYPTOLIB_TSAN=ON).
#include "test_framework.hpp"
#include "cryptolib_c.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
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

using Bytes = std::vector<uint8_t>;

const char* const kPem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY+CswOufc3tZq8lE\n"
    "Po6kGO5zjOLzF/kscuSONqd1FHahRANCAASkcmg2wgIEinXnLanT48k0734kS7Ut\n"
    "5+QWxsgXYKuevjC+TcBfa1F69FCJtY7mWuNQ49vGHtWSoxIREPo4V3fY\n"
    "-----END PRIVATE KEY-----\n";

constexpr int kThreads = 16;
constexpr int kRounds = 40;
constexpr auto kDeadline = std::chrono::seconds(120);

constexpr std::string_view kChildFlag = "--p256-cold-start";
constexpr int kChildThreads = 8;
constexpr auto kSignalStorm = std::chrono::milliseconds(500);
constexpr auto kChildGrace = std::chrono::seconds(10);
constexpr auto kChildDeadline = std::chrono::seconds(60);

const char* g_self = nullptr;

bool take(CryptoBufferResult r, Bytes& out) {
    const bool ok = r.error == nullptr && r.buf.data != nullptr;
    if (ok) out.assign(r.buf.data, r.buf.data + r.buf.len);
    cryptolib_buffer_free(&r.buf);
    cryptolib_str_free(r.error);
    return ok;
}

/// Every P-256 entry point once: import, sign, verify, public key, and a
/// fresh key pair that signs and verifies. Returns the wrong answers.
int one_round(uint8_t tag) {
    int bad = 0;
    const Bytes message = {'h', 'e', 'a', 'd', 'e', 'r', '.', 'c', 'l', 'a', 'i', 'm', 's', tag};
    Bytes pair;
    if (!take(cryptolib_p256_import_pkcs8_pem(reinterpret_cast<const uint8_t*>(kPem), std::strlen(kPem)), pair) ||
        pair.size() != 97)
        return 1;
    const Bytes sk(pair.begin(), pair.begin() + 32);
    const Bytes pk(pair.begin() + 32, pair.end());
    Bytes sig;
    if (!take(cryptolib_p256_sign(sk.data(), sk.size(), message.data(), message.size()), sig) || sig.size() != 64)
        ++bad;
    else if (cryptolib_p256_verify(pk.data(), pk.size(), message.data(), message.size(), sig.data(), sig.size()) != 1)
        ++bad;
    Bytes derived;
    if (!take(cryptolib_p256_public_key(sk.data(), sk.size()), derived) || derived != pk) ++bad;
    CryptoKeyPair kp = cryptolib_p256_keygen();
    if (kp.public_key.len != 65 || kp.secret_key.len != 32) {
        ++bad;
    } else {
        Bytes fresh;
        if (!take(cryptolib_p256_sign(kp.secret_key.data, kp.secret_key.len, message.data(), message.size()),
                  fresh) ||
            cryptolib_p256_verify(kp.public_key.data, kp.public_key.len, message.data(), message.size(),
                                  fresh.data(), fresh.size()) != 1)
            ++bad;
    }
    cryptolib_keypair_free(&kp);
    return bad;
}

int worker(int id) {
    int bad = 0;
    for (int round = 0; round < kRounds; ++round) {
        if (cryptolib_p256_available() == 0) ++bad;
        bad += one_round(static_cast<uint8_t>(id));
    }
    return bad;
}

void on_signal(int, siginfo_t*, void*) {}

/// The child: kChildThreads threads make the process's first P-256 calls
/// together while the main thread keeps signalling them, then the signals
/// stop and the threads have kChildGrace to finish. with_init calls
/// cryptolib_init() first; otherwise only libsodium is initialised and
/// libcrypto is first touched by the P-256 calls themselves. The threads
/// stay alive until the end, so no signal lands on a thread that is
/// exiting. Exit status 0 when every call finished with the right answer,
/// 1 for a wrong answer, 2 when a thread never came back.
int cold_child(bool with_init) {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigaction(SIGURG, &sa, nullptr);
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
            bad.fetch_add(one_round(static_cast<uint8_t>(t)));
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
        std::printf("      %d of %d threads still inside P-256 calls %lld s after the signals stopped\n",
                    kChildThreads - finished.load(), kChildThreads, static_cast<long long>(kChildGrace.count()));
        std::fflush(stdout);
        std::_Exit(2);
    }
    release.store(true);
    for (auto& th : pool) th.join();
    return bad.load() == 0 ? 0 : 1;
}

/// Runs this binary as a cold child and returns its exit status, or -1 when
/// it could not start or did not end within kChildDeadline.
int run_cold_child(const char* mode) {
    if (g_self == nullptr) return -1;
    char flag[64];
    char arg[16];
    std::snprintf(flag, sizeof flag, "%.*s", static_cast<int>(kChildFlag.size()), kChildFlag.data());
    std::snprintf(arg, sizeof arg, "%s", mode);
    char* const argv[] = {const_cast<char*>(g_self), flag, arg, nullptr};
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

}

/// Called first by main(): runs the cold child and returns its exit status
/// when argv asks for it, otherwise records this binary's path and returns
/// -1 so the suite runs.
int p256_threads_cold_child(int argc, char** argv) {
    if (argc >= 3 && std::string_view(argv[1]) == kChildFlag) return cold_child(std::string_view(argv[2]) == "init");
    if (argc >= 1) g_self = argv[0];
    return -1;
}

TEST("p256-threads/cold-start-under-signals") {
    if (cryptolib_p256_available() == 0) {
        std::printf("      (P-256 not in this build)\n");
        return;
    }
    REQUIRE(g_self != nullptr);
    for (const char* mode : {"bare", "init", "bare", "init", "bare", "init"}) {
        const int status = run_cold_child(mode);
        if (status != 0) std::printf("      cold child (%s) ended with %d\n", mode, status);
        CHECK_EQ(status, 0);
    }
}

TEST("p256-threads/mixed-calls-finish-and-agree") {
    if (cryptolib_p256_available() == 0) {
        std::printf("      (P-256 not in this build)\n");
        return;
    }
    std::atomic<int> bad{0};
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::mutex m;
    std::condition_variable cv;
    int finished = 0;
    std::vector<std::thread> pool;
    for (int t = 0; t < kThreads; ++t) {
        pool.emplace_back([&, t] {
            ready.fetch_add(1);
            while (!go.load()) std::this_thread::yield();
            bad.fetch_add(worker(t));
            std::lock_guard<std::mutex> lock(m);
            ++finished;
            cv.notify_one();
        });
    }
    while (ready.load() < kThreads) std::this_thread::yield();
    go.store(true);
    {
        std::unique_lock<std::mutex> lock(m);
        if (!cv.wait_for(lock, kDeadline, [&] { return finished == kThreads; })) {
            std::printf("      FAIL concurrent P-256 calls did not finish in %lld s (%d of %d threads done)\n",
                        static_cast<long long>(kDeadline.count()), finished, kThreads);
            std::fflush(stdout);
            std::_Exit(1);
        }
    }
    for (auto& th : pool) th.join();
    CHECK_EQ(bad.load(), 0);
}

TEST("p256-threads/same-key-same-signature") {
    if (cryptolib_p256_available() != 2) {
        std::printf("      (deterministic nonces not in this build)\n");
        return;
    }
    Bytes pair;
    REQUIRE(take(cryptolib_p256_import_pkcs8_pem(reinterpret_cast<const uint8_t*>(kPem), std::strlen(kPem)), pair));
    const Bytes sk(pair.begin(), pair.begin() + 32);
    const Bytes message = {'s', 'a', 'm', 'e'};
    Bytes expected;
    REQUIRE(take(cryptolib_p256_sign(sk.data(), sk.size(), message.data(), message.size()), expected));
    std::atomic<int> differ{0};
    std::vector<std::thread> pool;
    for (int t = 0; t < kThreads; ++t) {
        pool.emplace_back([&] {
            for (int round = 0; round < kRounds; ++round) {
                Bytes sig;
                if (!take(cryptolib_p256_sign(sk.data(), sk.size(), message.data(), message.size()), sig) ||
                    sig != expected)
                    differ.fetch_add(1);
            }
        });
    }
    for (auto& th : pool) th.join();
    CHECK_EQ(differ.load(), 0);
}

void run_tests_p256_threads() {
    RUN("p256-threads/cold-start-under-signals");
    RUN("p256-threads/mixed-calls-finish-and-agree");
    RUN("p256-threads/same-key-same-signature");
}
