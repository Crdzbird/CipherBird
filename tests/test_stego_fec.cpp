// crypto::stego::fec — forward error correction codec. Correction capability is
// validated by injecting KNOWN bit-error patterns (the honest analogue of a KAT
// for an error-correcting code): each scheme must recover within its bound and
// (for the repetition codes) fail beyond it.
#include "test_framework.hpp"
using namespace test;

namespace fec = crypto::stego::fec;

namespace {
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }
void flip(std::vector<uint8_t>& v, std::size_t bit) { v[bit / 8] ^= static_cast<uint8_t>(0x80u >> (bit % 8)); }
std::vector<uint8_t> msg() { return { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x5A, 0xA5 }; }
}

TEST("fec/roundtrip-no-errors") {
    auto data = msg();
    for (auto s : { fec::Scheme::None, fec::Scheme::Repetition3, fec::Scheme::Repetition5, fec::Scheme::Hamming74 }) {
        auto enc = fec::encode(sp(data), s);
        auto dec = fec::decode(sp(enc), s, data.size());
        REQUIRE(dec.is_ok());
        CHECK(dec.value() == data);
    }
}

TEST("fec/repetition3-corrects-one-flip-per-bit") {
    auto data = msg();
    auto enc = fec::encode(sp(data), fec::Scheme::Repetition3);
    // Flip one bit in each 3-bit group (positions 0,3,6,...): majority survives.
    for (std::size_t g = 0; g * 3 < enc.size() * 8; ++g) flip(enc, g * 3);
    auto dec = fec::decode(sp(enc), fec::Scheme::Repetition3, data.size());
    REQUIRE(dec.is_ok());
    CHECK(dec.value() == data);
}

TEST("fec/repetition3-fails-beyond-bound") {
    auto data = msg();
    auto enc = fec::encode(sp(data), fec::Scheme::Repetition3);
    // Flip TWO of three copies of the very first bit → majority now wrong.
    flip(enc, 0); flip(enc, 1);
    auto dec = fec::decode(sp(enc), fec::Scheme::Repetition3, data.size());
    REQUIRE(dec.is_ok());
    CHECK(dec.value() != data);      // honest limit: 2 flips/group exceeds capability
}

TEST("fec/repetition5-corrects-two-flips-per-bit") {
    auto data = msg();
    auto enc = fec::encode(sp(data), fec::Scheme::Repetition5);
    // Flip two bits in each 5-bit group (positions 0,1 of each group): 3/5 survive.
    for (std::size_t g = 0; g * 5 + 1 < enc.size() * 8; ++g) { flip(enc, g * 5); flip(enc, g * 5 + 1); }
    auto dec = fec::decode(sp(enc), fec::Scheme::Repetition5, data.size());
    REQUIRE(dec.is_ok());
    CHECK(dec.value() == data);
}

TEST("fec/hamming74-corrects-one-flip-per-block") {
    auto data = msg();
    auto enc = fec::encode(sp(data), fec::Scheme::Hamming74);
    // One flip in every 7-bit codeword (position 2 of each block) — all corrected.
    for (std::size_t blk = 0; blk * 7 + 2 < enc.size() * 8; ++blk) flip(enc, blk * 7 + 2);
    auto dec = fec::decode(sp(enc), fec::Scheme::Hamming74, data.size());
    REQUIRE(dec.is_ok());
    CHECK(dec.value() == data);
}

TEST("fec/hamming74-single-error-every-position") {
    // For a single byte, exhaustively flip each of the 14 encoded bits (two
    // codewords) one at a time — Hamming must correct every single-bit error.
    std::vector<uint8_t> data = { 0x9C };
    auto base = fec::encode(sp(data), fec::Scheme::Hamming74);
    for (std::size_t pos = 0; pos < base.size() * 8; ++pos) {
        auto enc = base;
        flip(enc, pos);
        auto dec = fec::decode(sp(enc), fec::Scheme::Hamming74, data.size());
        REQUIRE(dec.is_ok());
        CHECK(dec.value() == data);
    }
}

TEST("fec/overhead-and-short-buffer") {
    CHECK(fec::overhead(fec::Scheme::Repetition3) == 3.0);
    CHECK(fec::overhead(fec::Scheme::Hamming74)   == 7.0 / 4.0);
    // Too-short buffers are rejected, not read out of bounds.
    std::vector<uint8_t> tiny = { 0x01 };
    CHECK(fec::decode(sp(tiny), fec::Scheme::Repetition5, 4).is_err());
    CHECK(fec::decode(sp(tiny), fec::Scheme::Hamming74, 4).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_stego_fec() {
    RUN("fec/roundtrip-no-errors");
    RUN("fec/repetition3-corrects-one-flip-per-bit");
    RUN("fec/repetition3-fails-beyond-bound");
    RUN("fec/repetition5-corrects-two-flips-per-bit");
    RUN("fec/hamming74-corrects-one-flip-per-block");
    RUN("fec/hamming74-single-error-every-position");
    RUN("fec/overhead-and-short-buffer");
}
