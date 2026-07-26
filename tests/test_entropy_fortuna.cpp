// crypto::entropy::FortunaPool — Fortuna-style pooled entropy accumulator.
// Composition of BLAKE2b pools + ChaCha20 generator. Determinism, reseed
// semantics, forward-secrecy (distinct successive blocks), and the catch-up
// pool schedule are validated behaviourally (no KAT — a novel accumulator).
#include "test_framework.hpp"
#include <sodium.h>
using namespace test;

using crypto::entropy::FortunaPool;

namespace {
std::vector<uint8_t> vec(std::span<const uint8_t> b) { return { b.begin(), b.end() }; }
std::vector<uint8_t> block(uint8_t v, std::size_t n = 16) { return std::vector<uint8_t>(n, v); }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }

// Feed an identical entropy sequence into a pool, then force a reseed.
void seed_identically(FortunaPool& p) {
    for (int i = 0; i < 40; ++i) p.add_entropy(static_cast<uint8_t>(i & 7), sp(block(static_cast<uint8_t>(i))));
    p.reseed_now();
}
}

TEST("fortuna/unseeded-generate-errs") {
    FortunaPool p;
    CHECK(!p.seeded());
    CHECK(p.generate(32).is_err());       // no entropy in → refuse to emit
}

TEST("fortuna/deterministic-across-instances") {
    FortunaPool a, b;
    seed_identically(a);
    seed_identically(b);
    REQUIRE(a.seeded()); REQUIRE(b.seeded());
    auto ra = a.generate(64);
    auto rb = b.generate(64);
    REQUIRE(ra.is_ok()); REQUIRE(rb.is_ok());
    CHECK(vec(ra.value().span()) == vec(rb.value().span()));  // same events → same stream
}

TEST("fortuna/successive-blocks-differ") {
    FortunaPool p;
    seed_identically(p);
    auto b1 = p.generate(64);
    auto b2 = p.generate(64);
    REQUIRE(b1.is_ok()); REQUIRE(b2.is_ok());
    // Post-request rekey (forward secrecy) → consecutive outputs are independent.
    CHECK(vec(b1.value().span()) != vec(b2.value().span()));
}

TEST("fortuna/divergent-entropy-diverges") {
    FortunaPool a, b;
    seed_identically(a);
    for (int i = 0; i < 40; ++i) b.add_entropy(static_cast<uint8_t>(i & 7), sp(block(static_cast<uint8_t>(i + 1))));
    b.reseed_now();
    auto ra = a.generate(64);
    auto rb = b.generate(64);
    REQUIRE(ra.is_ok()); REQUIRE(rb.is_ok());
    CHECK(vec(ra.value().span()) != vec(rb.value().span()));  // different entropy → different key
}

TEST("fortuna/auto-reseed-on-pool0-fill") {
    FortunaPool p;
    CHECK(p.reseed_count() == 0);
    // Push > MIN_RESEED_BYTES into pool 0 (every 32nd event lands there). 32*3=96
    // events guarantee pool 0 exceeds the 64-byte threshold with 16-byte events.
    for (int i = 0; i < 32 * 6; ++i) p.add_entropy(0, sp(block(static_cast<uint8_t>(i))));
    auto g = p.generate(16);              // triggers the automatic reseed
    REQUIRE(g.is_ok());
    CHECK(p.reseed_count() >= 1);
}

TEST("fortuna/reseed-count-advances") {
    FortunaPool p;
    seed_identically(p);
    auto r1 = p.reseed_count();
    p.reseed_now();
    p.reseed_now();
    CHECK(p.reseed_count() == r1 + 2);    // catch-up counter is monotone
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_entropy_fortuna() {
    RUN("fortuna/unseeded-generate-errs");
    RUN("fortuna/deterministic-across-instances");
    RUN("fortuna/successive-blocks-differ");
    RUN("fortuna/divergent-entropy-diverges");
    RUN("fortuna/auto-reseed-on-pool0-fill");
    RUN("fortuna/reseed-count-advances");
}
