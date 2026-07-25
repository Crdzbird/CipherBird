// crypto::entropy health tests — NIST SP 800-90B Most-Common-Value min-entropy
// (§6.3.1), Repetition-Count Test (§4.4.1), Adaptive-Proportion Test (§4.4.2).
// No compact official vector exists for these estimators, so we validate against
// analytically-known inputs where the expected verdict is unambiguous.
#include "test_framework.hpp"
#include <sodium.h>
#include <cmath>
#include <filesystem>
#include <fstream>
using namespace test;

using crypto::entropy::assess_health;
using crypto::entropy::HealthReport;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }
}

// A constant buffer has ZERO min-entropy: p̂ = 1 ⇒ H_mcv = 0. It must be flagged
// unhealthy, and its longest run equals its length.
TEST("health/constant-is-zero-entropy") {
    std::vector<uint8_t> zeros(4096, 0x00);
    auto r = assess_health(sp(zeros));
    CHECK(r.min_entropy_per_byte == 0.0);
    CHECK(r.longest_run == 4096);
    CHECK(!r.healthy(1.0));               // gated out by the min-entropy floor
}

// Uniform random bytes: p̂ ≈ 1/256, so the MCV estimate is high (well above 1
// bit/byte even after the confidence-interval haircut), and neither local test
// fires. This is the "good source" baseline.
TEST("health/uniform-random-is-healthy") {
    std::vector<uint8_t> rnd(65536);
    randombytes_buf(rnd.data(), rnd.size());
    auto r = assess_health(sp(rnd));
    CHECK(r.min_entropy_per_byte > 6.0);  // conservative; true value ≈ 7.9
    CHECK(r.rct_passed);
    CHECK(r.apt_passed);
    CHECK(r.healthy(1.0));
}

// A biased source — half the bytes are one fixed value, the rest uniform. p̂ ≈ 0.5
// ⇒ H_mcv ≈ 1 bit/byte, so it clears a 0.5-bit floor but not a 2-bit one.
TEST("health/biased-source-min-entropy") {
    std::vector<uint8_t> biased(65536);
    randombytes_buf(biased.data(), biased.size());
    for (std::size_t i = 0; i < biased.size(); i += 2) biased[i] = 0x7e; // ~50% fixed
    auto r = assess_health(sp(biased));
    CHECK(r.min_entropy_per_byte > 0.8);
    CHECK(r.min_entropy_per_byte < 1.3);
    CHECK(r.healthy(0.5));
    CHECK(!r.healthy(2.0));
}

// RCT fires on a long constant run even when the *overall* histogram looks rich:
// random bytes with a 200-byte run of 0x00 spliced in. H_mcv stays ≈ 7.9, so the
// RCT cutoff C = 1 + ceil(30/7.9) = 5, and a run of 200 ≫ 5 trips it.
TEST("health/rct-fires-on-long-run") {
    std::vector<uint8_t> data(65536);
    randombytes_buf(data.data(), data.size());
    for (std::size_t i = 1000; i < 1200; ++i) data[i] = 0x00; // 200-byte run
    auto r = assess_health(sp(data));
    CHECK(r.longest_run >= 200);
    CHECK(!r.rct_passed);
    CHECK(!r.healthy(1.0));               // any local-test failure ⇒ unhealthy
}

// Empty input is well-defined: zero entropy, tests trivially pass, not healthy.
TEST("health/empty-input") {
    auto r = assess_health({});
    CHECK(r.min_entropy_per_byte == 0.0);
    CHECK(!r.healthy(1.0));
}

// End-to-end via MediaEntropy: a generated photo is a healthy carrier; a
// solid-colour PPM is not (its pixel body is one repeated value).
TEST("health/media-file-assessment") {
    const char* good = "/tmp/test_health_good.ppm";
    const char* flat = "/tmp/test_health_flat.ppm";
    if (!std::filesystem::exists(good))
        (void)crypto::stego::MediaGenerator::generate_ppm(good, 128, 128);

    auto hg = crypto::entropy::MediaEntropy::assess_file_health(good);
    REQUIRE(hg.is_ok());
    CHECK(hg.value().min_entropy_per_byte > 1.0);

    // Build a solid-colour PPM by hand (header + all-identical pixels).
    {
        std::ofstream f(flat, std::ios::binary);
        f << "P6\n64 64\n255\n";
        std::vector<uint8_t> body(64 * 64 * 3, 0x40);
        f.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
    }
    auto hf = crypto::entropy::MediaEntropy::assess_file_health(flat);
    REQUIRE(hf.is_ok());
    CHECK(!hf.value().healthy(1.0));      // near-constant body ⇒ flagged

    std::filesystem::remove(good);
    std::filesystem::remove(flat);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_entropy_health() {
    RUN("health/constant-is-zero-entropy");
    RUN("health/uniform-random-is-healthy");
    RUN("health/biased-source-min-entropy");
    RUN("health/rct-fires-on-long-run");
    RUN("health/empty-input");
    RUN("health/media-file-assessment");
}
