#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::entropy::FortunaPool — Fortuna-style entropy accumulator             ║
 * ║                                                                            ║
 * ║  A pooled accumulator + generator after Ferguson & Schneier's Fortuna. Where ║
 * ║  the HMAC-DRBG beacon (SP 800-90A) turns ONE conditioned pull into a          ║
 * ║  keystream, Fortuna keeps accumulating from many independent, possibly        ║
 * ║  low-quality sources and *recovers* from a state compromise once enough        ║
 * ║  fresh entropy has flowed in.                                                 ║
 * ║                                                                            ║
 * ║  Design (composition only — BLAKE2b pools + ChaCha20 generator):              ║
 * ║    • 32 pools, each a running BLAKE2b hash. Successive entropy events are      ║
 * ║      spread round-robin across the pools.                                     ║
 * ║    • Reseed r folds in pool i iff (r mod 2^i)==0 — the "catch-up" schedule:    ║
 * ║      pool 0 every reseed, pool 1 every 2nd, … pool 31 rarely — so an attacker  ║
 * ║      who cannot starve every pool eventually loses control of the state.       ║
 * ║    • Generator: ChaCha20 keystream under the running key; the key is rekeyed   ║
 * ║      from its own output after every request (forward secrecy).               ║
 * ║                                                                            ║
 * ║  Deliberate simplification vs the book: the ~100 ms inter-reseed wall-clock    ║
 * ║  throttle is omitted so the accumulator is fully deterministic and testable —  ║
 * ║  reseed gates on pool-0 fill (MIN_RESEED_BYTES). Callers wanting the throttle  ║
 * ║  rate-limit generate() themselves. No new cryptography.                       ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace crypto::entropy {

class FortunaPool {
public:
    static constexpr std::size_t NUM_POOLS       = 32;
    static constexpr std::size_t KEY_BYTES       = 32;
    static constexpr std::size_t MIN_RESEED_BYTES = 64;  // pool-0 fill before an automatic reseed

    FortunaPool() {
        std::memset(key_.data(), 0, KEY_BYTES);
        for (auto& st : pools_) crypto_generichash_init(&st, nullptr, 0, POOL_OUT);
    }

    /// Add an entropy event from logical source `source_id`. Events are spread
    /// round-robin across the pools; each is bound to its source id and length so
    /// concatenation is unambiguous.
    void add_entropy(uint8_t source_id, std::span<const uint8_t> data) {
        std::size_t idx = event_counter_++ % NUM_POOLS;
        uint8_t hdr[2] = { source_id, static_cast<uint8_t>(data.size() & 0xFF) };
        crypto_generichash_update(&pools_[idx], hdr, sizeof hdr);
        crypto_generichash_update(&pools_[idx], data.data(), data.size());
        if (idx == 0) pool0_bytes_ += data.size();
    }

    /// Generate `n` pseudo-random bytes. Automatically reseeds first if pool 0 has
    /// accumulated enough entropy. Errs if the pool has never been seeded.
    [[nodiscard]] Result<SecureBuffer> generate(std::size_t n) {
        if (pool0_bytes_ >= MIN_RESEED_BYTES) reseed_now();
        if (reseed_count_ == 0)
            return Result<SecureBuffer>::err("FortunaPool: not yet seeded (add entropy first)");

        SecureBuffer out(n);
        if (n > 0) {
            uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
            counter_to_nonce(nonce);
            crypto_stream_chacha20(out.data(), n, nonce, key_.data());
            ++counter_;
        }
        rekey();  // forward secrecy: derive a fresh key from the generator
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Force a reseed now, folding in every pool that the catch-up schedule
    /// selects for the next reseed counter. Safe to call with a partially-filled
    /// pool 0 (used for deterministic seeding in tests / explicit control).
    void reseed_now() {
        ++reseed_count_;
        std::vector<uint8_t> seed;
        seed.insert(seed.end(), key_.begin(), key_.end());
        for (std::size_t i = 0; i < NUM_POOLS; ++i) {
            // Pool i is folded iff (r mod 2^i)==0. 2^i grows monotonically, so the
            // first pool that isn't due ends the run (pool 0 is always due: r%1==0).
            if (reseed_count_ % (1ull << i) != 0) break;
            std::array<uint8_t, POOL_OUT> ph{};
            crypto_generichash_final(&pools_[i], ph.data(), ph.size());
            seed.insert(seed.end(), ph.begin(), ph.end());
            crypto_generichash_init(&pools_[i], nullptr, 0, POOL_OUT);  // reset the folded pool
            sodium_memzero(ph.data(), ph.size());
        }
        crypto_generichash(key_.data(), KEY_BYTES, seed.data(), seed.size(), nullptr, 0);
        sodium_memzero(seed.data(), seed.size());
        pool0_bytes_ = 0;
        counter_ = 0;
    }

    [[nodiscard]] std::uint64_t reseed_count() const noexcept { return reseed_count_; }
    [[nodiscard]] bool seeded() const noexcept { return reseed_count_ > 0; }

private:
    static constexpr std::size_t POOL_OUT = 32;  // BLAKE2b-256 per pool

    std::array<uint8_t, KEY_BYTES>                    key_{};
    std::array<crypto_generichash_state, NUM_POOLS>   pools_{};
    std::uint64_t event_counter_ = 0;
    std::uint64_t pool0_bytes_   = 0;
    std::uint64_t reseed_count_  = 0;
    std::uint64_t counter_       = 0;   // generator block counter (reset each reseed)

    void counter_to_nonce(uint8_t nonce[crypto_stream_chacha20_NONCEBYTES]) const {
        std::memset(nonce, 0, crypto_stream_chacha20_NONCEBYTES);
        for (int i = 0; i < 8; ++i) nonce[i] = static_cast<uint8_t>((counter_ >> (8 * i)) & 0xFF);
    }

    // Rekey from two fresh generator blocks (Fortuna's post-request rekey).
    void rekey() {
        uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
        counter_to_nonce(nonce);
        std::array<uint8_t, KEY_BYTES> newkey{};
        crypto_stream_chacha20(newkey.data(), KEY_BYTES, nonce, key_.data());
        ++counter_;
        std::memcpy(key_.data(), newkey.data(), KEY_BYTES);
        sodium_memzero(newkey.data(), newkey.size());
    }
};

} // namespace crypto::entropy
