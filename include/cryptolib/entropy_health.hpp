#pragma once

/**
 * crypto::entropy — Entropy health tests (NIST SP 800-90B)
 *
 * A source-quality check over a raw byte stream, used to flag a low-entropy
 * media file BEFORE trusting it (especially in deterministic "the file IS the
 * key" mode). Three signals, all from SP 800-90B:
 *
 *   min_entropy_per_byte — the Most-Common-Value estimate (§6.3.1): a real,
 *                          conservative min-entropy lower bound (0..8 bits/byte),
 *                          unlike the previous Shannon i.i.d. *upper* bound.
 *   rct                  — Repetition-Count Test (§4.4.1): flags an improbably
 *                          long run of one identical byte.
 *   apt                  — Adaptive-Proportion Test (§4.4.2): flags one value
 *                          dominating a 512-sample window.
 *
 * These are indicators, not guarantees — the MCV estimate is the primary signal;
 * RCT/APT catch gross local failures. `healthy(min_bits)` combines them.
 */

#include "types.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <span>

namespace crypto::entropy {

struct HealthReport {
    double      min_entropy_per_byte = 0.0; // MCV estimate, 0..8 bits/byte
    std::size_t longest_run          = 0;   // longest run of one identical byte
    std::size_t max_window_count     = 0;   // peak same-value count in any APT window
    bool        rct_passed           = true;
    bool        apt_passed           = true;

    /// A source is "healthy" if its estimated min-entropy clears `min_bits`
    /// per byte AND neither local test fired.
    [[nodiscard]] bool healthy(double min_bits = 1.0) const noexcept {
        return min_entropy_per_byte >= min_bits && rct_passed && apt_passed;
    }
};

/// Assess a byte buffer against the SP 800-90B tests.
[[nodiscard]] inline HealthReport assess_health(std::span<const uint8_t> data) {
    HealthReport r;
    const std::size_t n = data.size();
    if (n == 0) return r;

    // ── Most-Common-Value min-entropy (§6.3.1) ──────────────────────────────
    std::array<std::uint64_t, 256> hist{};
    for (uint8_t b : data) ++hist[b];
    std::uint64_t max_count = 0;
    for (auto c : hist) max_count = std::max(max_count, c);
    const double phat = static_cast<double>(max_count) / static_cast<double>(n);
    double pu = phat;
    if (n > 1 && phat < 1.0)
        pu = std::min(1.0, phat + 2.576 * std::sqrt(phat * (1.0 - phat) / static_cast<double>(n - 1)));
    r.min_entropy_per_byte = (pu >= 1.0) ? 0.0 : -std::log2(pu);

    // ── Repetition-Count Test (§4.4.1) ──────────────────────────────────────
    // Cutoff C = 1 + ceil(-log2(alpha) / H), alpha = 2^-30. Fail if a run reaches C.
    std::size_t run = 1, longest = 1;
    for (std::size_t i = 1; i < n; ++i) {
        run = (data[i] == data[i - 1]) ? run + 1 : 1;
        longest = std::max(longest, run);
    }
    r.longest_run = longest;
    const double H = std::max(r.min_entropy_per_byte, 0.05);
    const std::size_t rct_cutoff = 1 + static_cast<std::size_t>(std::ceil(30.0 / H));
    r.rct_passed = longest < rct_cutoff;

    // ── Adaptive-Proportion Test (§4.4.2), window W = 512 ───────────────────
    // Normal-approximation cutoff at alpha = 2^-30 (z ≈ 6.0). Fail if any window
    // has more matches to its first sample than the cutoff.
    constexpr std::size_t W = 512;
    const double p = std::pow(2.0, -r.min_entropy_per_byte); // per-sample collision prob
    const double mean = W * p;
    const double sd = std::sqrt(W * p * (1.0 - p));
    const std::size_t apt_cutoff = static_cast<std::size_t>(std::ceil(mean + 6.0 * sd)) + 1;
    std::size_t peak = 0;
    for (std::size_t w = 0; w + W <= n; w += W) {
        uint8_t first = data[w];
        std::size_t count = 0;
        for (std::size_t i = 0; i < W; ++i) if (data[w + i] == first) ++count;
        peak = std::max(peak, count);
    }
    r.max_window_count = peak;
    r.apt_passed = peak < apt_cutoff;

    return r;
}

} // namespace crypto::entropy
