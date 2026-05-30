#include "test_framework.hpp"
#include <atomic>
#include <thread>
#include <vector>
using namespace test;

// Exercises the library concurrently from many threads. Passes normally; its
// real purpose is to surface data races under ThreadSanitizer
// (cmake -DCRYPTOLIB_TSAN=ON). Each thread does INDEPENDENT operations — any
// race would be in shared/global state inside the library or its deps.

static std::span<const uint8_t> sv(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

TEST("concurrency/parallel-independent-ops") {
    constexpr int THREADS = 8;
    constexpr int ITERS = 50;
    std::atomic<int> ok{0}, bad{0};

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            // Stateless AEAD (committing) round-trip.
            auto key = crypto::symmetric::CommittingAead::generate_key();
            auto ct = crypto::symmetric::CommittingAead::encrypt(sv("race?"), key.span());
            if (ct.is_ok() &&
                crypto::symmetric::CommittingAead::decrypt(ct.value().span(), key.span()).is_ok())
                ok.fetch_add(1, std::memory_order_relaxed);
            else
                bad.fetch_add(1, std::memory_order_relaxed);

            // Per-instance keyring create → serialise → deserialise → unlock.
            auto factor = crypto::random_bytes(32);
            auto kr = crypto::Keyring::create();
            (void)kr.add_device_slot(factor.span());
            auto blob = kr.serialise();
            auto kr2 = crypto::Keyring::deserialise(blob.span());
            if (kr2.is_ok() && kr2.value().unlock_with_device(factor.span()).is_ok())
                ok.fetch_add(1, std::memory_order_relaxed);
            else
                bad.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::vector<std::thread> pool;
    for (int t = 0; t < THREADS; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    CHECK(bad.load() == 0);
    CHECK(ok.load() == THREADS * ITERS * 2);
}

void run_tests_concurrency() {
    RUN("concurrency/parallel-independent-ops");
}
