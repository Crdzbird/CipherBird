#pragma once

/**
 * crypto::stego::fec — Forward error correction for the stego robustness knob.
 *
 * Steganographic carriers can pick up bit errors (lossy re-save, resampling,
 * transmission). FEC trades capacity for the ability to *recover* the embedded
 * bytes after a bounded number of bit flips, instead of failing the CRC outright.
 *
 * Two schemes (composition only — classic codes, no cryptography):
 *   Repetition-N (N odd) — each bit written N times; majority vote on decode.
 *                          Corrects up to (N-1)/2 flips per bit. N× overhead.
 *   Hamming(7,4)         — every 4 data bits → 7-bit codeword; corrects exactly
 *                          one flip per 7-bit block via syndrome decoding. 1.75×.
 *
 * All operations are bit-exact and deterministic, so correction capability is
 * validated by injecting known bit-error patterns (see test_stego_fec.cpp) — the
 * honest analogue of a KAT for an error-correcting code.
 */

#include "types.hpp"

#include <cstdint>
#include <span>

namespace crypto::stego::fec {

enum class Scheme : uint8_t {
    None        = 0,
    Repetition3 = 1,   // corrects 1 flip / bit, 3× size
    Repetition5 = 2,   // corrects 2 flips / bit, 5× size
    Hamming74   = 3,   // corrects 1 flip / 7-bit block, 1.75× size
};

namespace detail {

// MSB-first bit writer/reader over a byte buffer.
class BitWriter {
public:
    void put(uint8_t bit) {
        if (nbits_ % 8 == 0) buf_.push_back(0);
        if (bit & 1) buf_.back() |= static_cast<uint8_t>(0x80u >> (nbits_ % 8));
        ++nbits_;
    }
    [[nodiscard]] Bytes take() { return std::move(buf_); }
    [[nodiscard]] std::size_t bit_count() const noexcept { return nbits_; }
private:
    Bytes       buf_;
    std::size_t nbits_ = 0;
};

class BitReader {
public:
    explicit BitReader(std::span<const uint8_t> data) : data_(data) {}
    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() * 8 - pos_; }
    [[nodiscard]] uint8_t get() {
        uint8_t bit = (data_[pos_ / 8] >> (7 - (pos_ % 8))) & 1u;
        ++pos_;
        return bit;
    }
private:
    std::span<const uint8_t> data_;
    std::size_t              pos_ = 0;
};

[[nodiscard]] inline int rep_factor(Scheme s) noexcept {
    return s == Scheme::Repetition3 ? 3 : s == Scheme::Repetition5 ? 5 : 0;
}

// Hamming(7,4): data bits d1..d4 → codeword positions (1-indexed)
//   pos3=d1 pos5=d2 pos6=d3 pos7=d4 ; parity pos1,pos2,pos4.
inline void hamming_encode_nibble(uint8_t d1, uint8_t d2, uint8_t d3, uint8_t d4, BitWriter& w) {
    uint8_t p1 = d1 ^ d2 ^ d4;   // covers 1,3,5,7
    uint8_t p2 = d1 ^ d3 ^ d4;   // covers 2,3,6,7
    uint8_t p4 = d2 ^ d3 ^ d4;   // covers 4,5,6,7
    w.put(p1); w.put(p2); w.put(d1); w.put(p4); w.put(d2); w.put(d3); w.put(d4);
}

// Read a 7-bit codeword, correct a single-bit error, return the 4 data bits
// packed as the low nibble (d1 d2 d3 d4 → bits 3..0).
[[nodiscard]] inline uint8_t hamming_decode_block(BitReader& r) {
    uint8_t c[8];
    for (int i = 1; i <= 7; ++i) c[i] = r.get();
    uint8_t s1 = c[1] ^ c[3] ^ c[5] ^ c[7];
    uint8_t s2 = c[2] ^ c[3] ^ c[6] ^ c[7];
    uint8_t s4 = c[4] ^ c[5] ^ c[6] ^ c[7];
    int err = s1 * 1 + s2 * 2 + s4 * 4;
    if (err >= 1 && err <= 7) c[err] ^= 1;
    uint8_t d1 = c[3], d2 = c[5], d3 = c[6], d4 = c[7];
    return static_cast<uint8_t>((d1 << 3) | (d2 << 2) | (d3 << 1) | d4);
}

} // namespace detail

/// Encode `data` under `scheme`. None returns a plain copy.
[[nodiscard]] inline Bytes encode(std::span<const uint8_t> data, Scheme scheme) {
    using namespace detail;
    if (scheme == Scheme::None) return Bytes(data.begin(), data.end());

    BitWriter w;
    if (int n = rep_factor(scheme)) {
        for (uint8_t byte : data)
            for (int b = 7; b >= 0; --b) {
                uint8_t bit = (byte >> b) & 1u;
                for (int i = 0; i < n; ++i) w.put(bit);
            }
    } else { // Hamming74
        for (uint8_t byte : data) {
            hamming_encode_nibble((byte >> 7) & 1, (byte >> 6) & 1, (byte >> 5) & 1, (byte >> 4) & 1, w);
            hamming_encode_nibble((byte >> 3) & 1, (byte >> 2) & 1, (byte >> 1) & 1, (byte >> 0) & 1, w);
        }
    }
    return w.take();
}

/// Decode exactly `original_len` bytes from `encoded` under `scheme`, correcting
/// bit errors within each scheme's capability. Errs if `encoded` is too short.
[[nodiscard]] inline Result<Bytes>
decode(std::span<const uint8_t> encoded, Scheme scheme, std::size_t original_len) {
    using namespace detail;
    if (scheme == Scheme::None) {
        if (encoded.size() < original_len)
            return Result<Bytes>::err("FEC: buffer too short");
        return Result<Bytes>::ok(Bytes(encoded.begin(), encoded.begin() + original_len));
    }

    BitReader r(encoded);
    BitWriter out;
    if (int n = rep_factor(scheme)) {
        const std::size_t need_bits = original_len * 8 * static_cast<std::size_t>(n);
        if (encoded.size() * 8 < need_bits)
            return Result<Bytes>::err("FEC: buffer too short for repetition decode");
        for (std::size_t i = 0; i < original_len * 8; ++i) {
            int ones = 0;
            for (int k = 0; k < n; ++k) ones += r.get();
            out.put(ones * 2 > n ? 1 : 0);   // majority
        }
    } else { // Hamming74 — two 7-bit blocks per output byte
        const std::size_t need_bits = original_len * 2 * 7;
        if (encoded.size() * 8 < need_bits)
            return Result<Bytes>::err("FEC: buffer too short for Hamming decode");
        for (std::size_t i = 0; i < original_len; ++i) {
            uint8_t hi = hamming_decode_block(r);
            uint8_t lo = hamming_decode_block(r);
            for (int b = 3; b >= 0; --b) out.put((hi >> b) & 1u);
            for (int b = 3; b >= 0; --b) out.put((lo >> b) & 1u);
        }
    }
    return Result<Bytes>::ok(out.take());
}

/// Overhead multiplier for capacity planning (encoded_bits / data_bits).
[[nodiscard]] inline double overhead(Scheme scheme) noexcept {
    switch (scheme) {
        case Scheme::Repetition3: return 3.0;
        case Scheme::Repetition5: return 5.0;
        case Scheme::Hamming74:   return 7.0 / 4.0;
        default:                  return 1.0;
    }
}

} // namespace crypto::stego::fec
