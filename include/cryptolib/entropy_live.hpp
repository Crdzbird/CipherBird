#pragma once
/**
 * crypto::entropy::LiveEntropy, a continuous entropy source for a stream.
 *
 * Feed it chunks as they arrive (camera frames, audio buffers, video
 * packets, anything) and draw randomness at any time. Every chunk is
 * assessed with the SP 800-90B tests under a SourcePolicy, calibrated to
 * the floor the policy claims, with the repetition-count run carried across
 * chunk boundaries so a blank stretch spanning two frames is still seen.
 * A chunk that passes is credited with min_entropy_per_byte * size bits;
 * one that fails is mixed in all the same (mixing never hurts) but credited
 * nothing, and the report says why.
 *
 * Output comes from an SP 800-90A HMAC-DRBG (SHA-512) that is instantiated
 * once at least `min_credited_bits` (256 by default) of credited entropy
 * have been fed, with a nonce from the operating system so the output is
 * never weaker than the system generator, and reseeded from the accumulator
 * every time another `min_credited_bits` arrive. `generate` fails closed
 * until the source has earned its first seed.
 *
 * Honest limits: the estimators are two of the 90B suite over whatever the
 * stream carries; a stream of identical or highly compressible frames earns
 * little credit and the status says so. Not thread-safe; one feeder, one
 * consumer, or an external lock.
 */
#include "entropy_drbg.hpp"
#include "entropy_health.hpp"
#include "types.hpp"
#include <sodium.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace crypto::entropy {

struct LiveFeedReport {
    bool         accepted            = false;  // credited under the policy
    double       credited_bits       = 0.0;    // this chunk's credit
    double       credited_bits_total = 0.0;    // since construction
    bool         ready               = false;  // generate() would succeed
    HealthReport health;                       // the assessment of this chunk
    std::string  reason;                       // empty when accepted
};

struct LiveStatus {
    std::uint64_t chunks_fed                 = 0;
    std::uint64_t chunks_accepted            = 0;
    std::uint64_t chunks_rejected            = 0;
    std::uint64_t bytes_fed                  = 0;
    std::uint64_t reseeds                    = 0;  // DRBG seedings so far
    double        credited_bits_total        = 0.0;
    double        credited_bits_since_reseed = 0.0;
    double        min_credited_bits          = 0.0;
    bool          ready                      = false;
    HealthReport  last_health;
    std::string   last_reason;
};

class LiveEntropy {
public:
    static constexpr std::size_t MIN_CHUNK_BYTES = 1024;
    static constexpr std::size_t ACC_BYTES       = 64;

    explicit LiveEntropy(SourcePolicy policy = {}, double min_credited_bits = 256.0)
        : policy_(policy), min_credited_(min_credited_bits < 1.0 ? 1.0 : min_credited_bits) {
        reset_accumulator();
    }
    LiveEntropy(const LiveEntropy&)            = delete;
    LiveEntropy& operator=(const LiveEntropy&) = delete;
    LiveEntropy(LiveEntropy&&) noexcept            = default;
    LiveEntropy& operator=(LiveEntropy&&) noexcept = default;
    ~LiveEntropy() { sodium_memzero(&acc_, sizeof acc_); }

    /// Assess, mix and (when the policy allows) credit one chunk.
    [[nodiscard]] LiveFeedReport feed(std::span<const uint8_t> chunk, uint8_t source_id = 0) {
        LiveFeedReport r;
        ++chunks_fed_;
        bytes_fed_ += chunk.size();
        mix(source_id, chunk);
        if (chunk.size() < MIN_CHUNK_BYTES) {
            r.reason = "LiveEntropy: a chunk of " + std::to_string(chunk.size()) +
                       " bytes is below the " + std::to_string(MIN_CHUNK_BYTES) +
                       "-byte minimum for an assessment; it was mixed in but not credited";
            return finish(r, false);
        }
        r.health = assess_health(chunk, policy_.min_bits_per_byte);
        carry_run(chunk, r.health);
        if (auto why = policy_.reject(r.health); !why.empty()) {
            r.reason = why + " (the chunk was mixed in but not credited)";
            return finish(r, false);
        }
        r.credited_bits = r.health.min_entropy_per_byte * static_cast<double>(chunk.size());
        credited_total_ += r.credited_bits;
        credited_since_reseed_ += r.credited_bits;
        return finish(r, true);
    }

    [[nodiscard]] bool ready() const noexcept {
        return drbg_.has_value() || credited_total_ >= min_credited_;
    }

    /// Draw `n` bytes. Fails closed until the first seed has been earned;
    /// reseeds first whenever another `min_credited_bits` have arrived.
    [[nodiscard]] Result<SecureBuffer> generate(std::size_t n) {
        if (!drbg_.has_value()) {
            if (credited_total_ < min_credited_)
                return Result<SecureBuffer>::err(
                    "LiveEntropy: not ready, " + two_decimals(credited_total_) + " of " +
                    two_decimals(min_credited_) + " credited bits of min-entropy have been fed (" +
                    std::to_string(chunks_accepted_) + " chunks credited, " +
                    std::to_string(chunks_rejected_) + " mixed in without credit" +
                    (last_reason_.empty() ? "" : "; last: " + last_reason_) + ")");
            uint8_t nonce[32];
            randombytes_buf(nonce, sizeof nonce);
            auto seed = take_accumulator();
            static constexpr char kPers[] = "cryptolib-live-entropy-v1";
            auto d = HmacDrbg::instantiate(
                { seed.data(), seed.size() }, { nonce, sizeof nonce },
                { reinterpret_cast<const uint8_t*>(kPers), sizeof kPers - 1 });
            sodium_memzero(nonce, sizeof nonce);
            sodium_memzero(seed.data(), seed.size());
            if (d.is_err()) return Result<SecureBuffer>::err(d.error().message);
            drbg_.emplace(std::move(d.value()));
            ++reseeds_;
            credited_since_reseed_ = 0.0;
        } else if (credited_since_reseed_ >= min_credited_) {
            auto seed = take_accumulator();
            drbg_->reseed({ seed.data(), seed.size() });
            sodium_memzero(seed.data(), seed.size());
            ++reseeds_;
            credited_since_reseed_ = 0.0;
        }
        return drbg_->generate(n);
    }

    [[nodiscard]] LiveStatus status() const {
        LiveStatus s;
        s.chunks_fed = chunks_fed_;
        s.chunks_accepted = chunks_accepted_;
        s.chunks_rejected = chunks_rejected_;
        s.bytes_fed = bytes_fed_;
        s.reseeds = reseeds_;
        s.credited_bits_total = credited_total_;
        s.credited_bits_since_reseed = credited_since_reseed_;
        s.min_credited_bits = min_credited_;
        s.ready = ready();
        s.last_health = last_health_;
        s.last_reason = last_reason_;
        return s;
    }

    [[nodiscard]] const SourcePolicy& policy() const noexcept { return policy_; }

private:
    void reset_accumulator() {
        static constexpr char kLabel[] = "cryptolib-live-entropy-acc-v1";
        crypto_generichash_init(&acc_, reinterpret_cast<const unsigned char*>(kLabel),
                                sizeof kLabel - 1, ACC_BYTES);
    }

    void mix(uint8_t source_id, std::span<const uint8_t> chunk) {
        const std::uint64_t len = chunk.size();
        uint8_t hdr[9];
        hdr[0] = source_id;
        for (int i = 0; i < 8; ++i) hdr[1 + i] = static_cast<uint8_t>(len >> (8 * i));
        crypto_generichash_update(&acc_, hdr, sizeof hdr);
        crypto_generichash_update(&acc_, chunk.data(), chunk.size());
    }

    [[nodiscard]] SecureBuffer take_accumulator() {
        SecureBuffer out(ACC_BYTES);
        crypto_generichash_final(&acc_, out.data(), ACC_BYTES);
        reset_accumulator();
        return out;
    }

    /// Carry the run of identical bytes across chunk boundaries so the
    /// repetition-count test sees a blank stretch that spans two chunks.
    void carry_run(std::span<const uint8_t> chunk, HealthReport& h) {
        const std::size_t n = chunk.size();
        std::size_t lead = 1;
        while (lead < n && chunk[lead] == chunk[0]) ++lead;
        const std::size_t carry = (have_last_ && chunk[0] == last_byte_) ? run_ : 0;
        h.longest_run = std::max(h.longest_run, carry + lead);
        h.rct_passed = h.longest_run < h.rct_cutoff;
        std::size_t trail = 1;
        while (trail < n && chunk[n - 1 - trail] == chunk[n - 1]) ++trail;
        run_ = (trail == n) ? carry + n : trail;
        last_byte_ = chunk[n - 1];
        have_last_ = true;
    }

    LiveFeedReport finish(LiveFeedReport& r, bool accepted) {
        r.accepted = accepted;
        (accepted ? chunks_accepted_ : chunks_rejected_)++;
        r.credited_bits_total = credited_total_;
        r.ready = ready();
        last_health_ = r.health;
        last_reason_ = r.reason;
        return r;
    }

    SourcePolicy              policy_;
    double                    min_credited_;
    crypto_generichash_state  acc_{};
    std::optional<HmacDrbg>   drbg_;
    HealthReport              last_health_;
    std::string               last_reason_;
    std::uint64_t chunks_fed_ = 0, chunks_accepted_ = 0, chunks_rejected_ = 0, bytes_fed_ = 0, reseeds_ = 0;
    double        credited_total_ = 0.0, credited_since_reseed_ = 0.0;
    std::size_t   run_ = 0;
    uint8_t       last_byte_ = 0;
    bool          have_last_ = false;
};

} // namespace crypto::entropy
