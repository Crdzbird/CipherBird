#pragma once

/**
 * crypto::entropy — Entropy health tests (NIST SP 800-90B)
 *
 * A source-quality check over a raw byte stream, used to flag a low-entropy
 * media file BEFORE trusting it (especially in deterministic "the file IS the
 * key" mode). Three signals, all from SP 800-90B:
 *
 *   min_entropy_per_byte — the smaller of the Most-Common-Value estimate
 *                          (§6.3.1) and the Markov estimate over the bit
 *                          expansion (§6.3.3): a conservative lower bound
 *                          (0..8 bits/byte) from two of the 90B estimators.
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

/// Two decimals of a double, for the messages below.
[[nodiscard]] inline std::string two_decimals(double v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.2f", v);
    return buf;
}

/// Repetition-Count Test cutoff (SP 800-90B 4.4.1) for a claimed min-entropy
/// of `floor_bits` per byte at alpha = 2^-30: C = 1 + ceil(30 / H). The
/// cutoff is calibrated against the entropy the caller requires rather than
/// the entropy measured, so a run of padding bytes in a container header
/// trips the test only when it is implausible under the claim.
[[nodiscard]] inline std::size_t rct_cutoff_for(double floor_bits) noexcept {
    const double H = std::max(floor_bits, 0.05);
    return 1 + static_cast<std::size_t>(std::ceil(30.0 / H));
}

/// Adaptive-Proportion Test cutoff (SP 800-90B 4.4.2) for the same claim,
/// window `window`, normal approximation at alpha = 2^-30 (z = 6).
[[nodiscard]] inline std::size_t apt_cutoff_for(double floor_bits, std::size_t window = 512) noexcept {
    const double p = std::pow(2.0, -std::max(floor_bits, 0.05));
    const double mean = static_cast<double>(window) * p;
    const double sd = std::sqrt(static_cast<double>(window) * p * (1.0 - p));
    return static_cast<std::size_t>(std::ceil(mean + 6.0 * sd)) + 1;
}

struct HealthReport {
    double      min_entropy_per_byte = 0.0; // min of the estimates below, 0..8 bits/byte
    double      mcv_bits_per_byte    = 0.0; // Most-Common-Value estimate (6.3.1)
    double      markov_bits_per_byte = 0.0; // Markov estimate over the bit expansion (6.3.3), per byte
    double      floor_bits_per_byte  = 1.0; // the claim the two cutoffs below are calibrated for
    std::size_t sample_bytes         = 0;   // bytes the estimates and tests looked at
    std::size_t longest_run          = 0;   // longest run of one identical byte
    std::size_t rct_cutoff           = 0;   // a run this long fails the repetition-count test
    std::size_t max_window_count     = 0;   // peak same-value count in any APT window
    std::size_t apt_cutoff           = 0;   // a window count this high fails the adaptive-proportion test
    std::size_t apt_window           = 512;
    bool        rct_passed           = true;
    bool        apt_passed           = true;

    /// A source is "healthy" if its estimated min-entropy clears `min_bits`
    /// per byte AND neither local test fired.
    [[nodiscard]] bool healthy(double min_bits = 1.0) const noexcept {
        return min_entropy_per_byte >= min_bits && rct_passed && apt_passed;
    }

    /// Every figure behind the verdict, one line per signal, so a refusal can
    /// be understood and the policy adjusted on purpose.
    [[nodiscard]] std::string explain() const {
        std::string out;
        out += "min-entropy " + two_decimals(min_entropy_per_byte) + " bits/byte over " +
               std::to_string(sample_bytes) + " bytes (most-common-value " +
               two_decimals(mcv_bits_per_byte) + ", markov " + two_decimals(markov_bits_per_byte) +
               "), policy floor " + two_decimals(floor_bits_per_byte) + "\n";
        out += "repetition-count: longest run of one byte " + std::to_string(longest_run) +
               ", cutoff " + std::to_string(rct_cutoff) + " for the floor: " +
               (rct_passed ? "passed" : "FAILED") + "\n";
        out += "adaptive-proportion: peak " + std::to_string(max_window_count) + " of " +
               std::to_string(apt_window) + " in a window, cutoff " + std::to_string(apt_cutoff) +
               ": " + (apt_passed ? "passed" : "failed");
        return out;
    }
};

/// What a harvest requires of its source before trusting it. The strict
/// default refuses a file below one bit of min-entropy per byte or one that
/// fails the repetition-count test; the adaptive-proportion test is reported
/// and only required on request, because the smooth regions of ordinary
/// photographs trip it. Both cutoffs are calibrated against
/// `min_bits_per_byte`, the entropy the caller is claiming, so the tests ask
/// "is this run or this skew plausible if the source really has that much
/// entropy" rather than measuring the file against itself. The permissive
/// policy keeps the assessment but never refuses.
struct SourcePolicy {
    double min_bits_per_byte = 1.0;
    bool   require_rct       = true;
    bool   require_apt       = false;

    [[nodiscard]] static constexpr SourcePolicy strict() noexcept { return {}; }
    [[nodiscard]] static constexpr SourcePolicy permissive() noexcept { return {0.0, false, false}; }

    /// Empty when the report satisfies the policy; otherwise the reason, with
    /// every number behind it and the knob that would relax it.
    [[nodiscard]] std::string reject(const HealthReport& h) const {
        if (h.min_entropy_per_byte < min_bits_per_byte)
            return "MediaEntropy: refused, min-entropy " + two_decimals(h.min_entropy_per_byte) +
                   " bits/byte is below the policy floor of " + two_decimals(min_bits_per_byte) +
                   " (most-common-value " + two_decimals(h.mcv_bits_per_byte) + ", markov " +
                   two_decimals(h.markov_bits_per_byte) + " over " + std::to_string(h.sample_bytes) +
                   " bytes); lower min_bits_per_byte or use SourcePolicy::permissive() to accept a weak source";
        if (require_rct && !h.rct_passed)
            return "MediaEntropy: refused by the repetition-count test, a run of " +
                   std::to_string(h.longest_run) + " identical bytes where the cutoff for the " +
                   two_decimals(floor_for(h)) + " bits/byte floor is " + std::to_string(h.rct_cutoff) +
                   "; a run this long usually means a blank region or an empty file rather than padding, "
                   "set require_rct=false to report it instead of refusing";
        if (require_apt && !h.apt_passed)
            return "MediaEntropy: refused by the adaptive-proportion test, one byte value filled " +
                   std::to_string(h.max_window_count) + " of " + std::to_string(h.apt_window) +
                   " positions in a window where the cutoff for the " + two_decimals(floor_for(h)) +
                   " bits/byte floor is " + std::to_string(h.apt_cutoff) +
                   "; set require_apt=false to report it instead of refusing";
        return {};
    }

private:
    [[nodiscard]] double floor_for(const HealthReport& h) const noexcept {
        return h.floor_bits_per_byte > 0.0 ? h.floor_bits_per_byte : min_bits_per_byte;
    }
};

/// SP 800-90B 6.3.3, the Markov estimate, over the bit expansion of the
/// bytes (most significant bit first). Returns min-entropy per bit. The
/// estimate takes the most likely 128-bit sequence under a first-order
/// Markov model fitted to the data and is the second estimator the library
/// applies; the full 90B non-IID suite has more, so the result is still a
/// lower bound on nothing more than what these two estimators see.
[[nodiscard]] inline double markov_min_entropy_per_bit(std::span<const uint8_t> data) {
    const std::uint64_t n = static_cast<std::uint64_t>(data.size()) * 8;
    if (n < 128) return 0.0;
    std::uint64_t c0 = 0, c1 = 0, c00 = 0, c01 = 0, c10 = 0, c11 = 0;
    int prev = -1;
    for (uint8_t byte : data) {
        for (int bit = 7; bit >= 0; --bit) {
            const int b = (byte >> bit) & 1;
            (b ? c1 : c0)++;
            if (prev == 0) (b ? c01 : c00)++;
            if (prev == 1) (b ? c11 : c10)++;
            prev = b;
        }
    }
    auto lg = [](std::uint64_t num, std::uint64_t den) {
        return (num == 0 || den == 0) ? -1e9 : std::log2(static_cast<double>(num) / static_cast<double>(den));
    };
    const double p0 = lg(c0, n), p1 = lg(c1, n);
    const double p00 = lg(c00, c00 + c01), p01 = lg(c01, c00 + c01);
    const double p10 = lg(c10, c10 + c11), p11 = lg(c11, c10 + c11);
    const double candidates[6] = {
        p0 + 127 * p00,
        p0 + 64 * p01 + 63 * p10,
        p0 + p01 + 126 * p11,
        p1 + 127 * p11,
        p1 + p10 + 126 * p00,
        p1 + 64 * p10 + 63 * p01,
    };
    double best = -1e9;
    for (double c : candidates) best = std::max(best, c);
    if (best <= -1e8) return 0.0;
    return std::min(1.0, -best / 128.0);
}

/// Assess a byte buffer against the SP 800-90B tests. `floor_bits_per_byte`
/// is the min-entropy the caller intends to claim; it calibrates the two
/// local tests (see `rct_cutoff_for`) and is echoed in the report.
[[nodiscard]] inline HealthReport assess_health(std::span<const uint8_t> data,
                                                double floor_bits_per_byte = 1.0) {
    HealthReport r;
    r.floor_bits_per_byte = floor_bits_per_byte;
    r.rct_cutoff = rct_cutoff_for(floor_bits_per_byte);
    r.apt_cutoff = apt_cutoff_for(floor_bits_per_byte, r.apt_window);
    const std::size_t n = data.size();
    r.sample_bytes = n;
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
    r.mcv_bits_per_byte = (pu >= 1.0) ? 0.0 : -std::log2(pu);
    r.markov_bits_per_byte = 8.0 * markov_min_entropy_per_bit(data);
    r.min_entropy_per_byte = std::min(r.mcv_bits_per_byte, r.markov_bits_per_byte);

    // ── Repetition-Count Test (§4.4.1) ──────────────────────────────────────
    // The cutoff comes from the claimed floor (rct_cutoff_for). Fail if a run reaches it.
    std::size_t run = 1, longest = 1;
    for (std::size_t i = 1; i < n; ++i) {
        run = (data[i] == data[i - 1]) ? run + 1 : 1;
        longest = std::max(longest, run);
    }
    r.longest_run = longest;
    r.rct_passed = longest < r.rct_cutoff;

    // ── Adaptive-Proportion Test (§4.4.2), window W = 512 ───────────────────
    // Fail if any window has more matches to its first sample than the cutoff
    // (apt_cutoff_for, calibrated against the claimed floor).
    const std::size_t W = r.apt_window;
    std::size_t peak = 0;
    for (std::size_t w = 0; w + W <= n; w += W) {
        uint8_t first = data[w];
        std::size_t count = 0;
        for (std::size_t i = 0; i < W; ++i) if (data[w + i] == first) ++count;
        peak = std::max(peak, count);
    }
    r.max_window_count = peak;
    r.apt_passed = peak < r.apt_cutoff;

    return r;
}

} // namespace crypto::entropy
