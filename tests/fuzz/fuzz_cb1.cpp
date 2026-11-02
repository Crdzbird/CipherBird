/**
 * fuzz_cb1.cpp - libFuzzer target for the cb1 tokens.
 *
 * Feeds the input to cb1.local decrypt and cb1.public verify as untrusted
 * tokens under fixed keys and requires a fail-closed result with a wiped
 * output region, then round-trips the input as a message through both and
 * requires that replacing the byte the input selects with any other byte
 * value is rejected.
 *
 * Build with -DCRYPTOLIB_FUZZ=ON (clang); run: ./fuzz_cb1 -max_total_time=60
 */

#include <cryptolib/cryptolib.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <span>
#include <vector>

using crypto::cb1::Local;
using crypto::cb1::Public;
using crypto::cb1::Status;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

const crypto::pq::HybridSig::KeyPair& keys() {
    static const crypto::pq::HybridSig::KeyPair kp = [] {
        auto r = crypto::pq::HybridSig::generate_keypair();
        require(r.is_ok());
        return std::move(r.value());
    }();
    return kp;
}

template <class T, class Open>
void fail_closed(std::size_t size, Open open) {
    std::vector<uint8_t> out(T::open_capacity(size) + 1, 0xA5);
    std::size_t n = 1;
    const Status s = open(out, n);
    require(s == Status::ok || s == Status::invalid);
    if (s != Status::ok) {
        require(n == 0);
        for (std::size_t i = 0; i + 1 < out.size(); ++i) require(out[i] == 0);
    }
    require(out.back() == 0xA5);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (sodium_init() < 0) return 0;
    static const uint8_t key[32] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    static const uint8_t footer[] = {'k', 'i', 'd'};
    static const uint8_t implicit[] = {'a', 'u', 'd'};
    const std::span<const uint8_t> in(data, size);
    const auto& kp = keys();

    fail_closed<Local>(size, [&](std::span<uint8_t> out, std::size_t& n) {
        return Local::open(out, n, in, key, footer, implicit);
    });
    fail_closed<Public>(size, [&](std::span<uint8_t> out, std::size_t& n) {
        return Public::verify(out, n, in, kp.public_key.span(), footer, implicit);
    });

    if (size > 4096) return 0;
    std::vector<uint8_t> tok(Local::token_len(size, sizeof footer));
    std::size_t tl = 0;
    require(Local::seal(tok, tl, key, in, footer, implicit) == Status::ok);
    require(tl == tok.size());
    std::vector<uint8_t> back(Local::open_capacity(tl));
    std::size_t bl = 0;
    require(Local::open(back, bl, tok, key, footer, implicit) == Status::ok);
    require(bl == size && std::equal(back.begin(), back.begin() + bl, in.begin()));

    std::vector<uint8_t> ptok(Public::token_len(size, sizeof footer));
    std::size_t pl = 0;
    require(Public::sign(ptok, pl, kp.secret_key.span(), in, footer, implicit) == Status::ok);
    require(pl == ptok.size());
    std::vector<uint8_t> pback(Public::open_capacity(pl));
    std::size_t pbl = 0;
    require(Public::verify(pback, pbl, ptok, kp.public_key.span(), footer, implicit) == Status::ok);
    require(pbl == size && std::equal(pback.begin(), pback.begin() + pbl, in.begin()));

    if (size == 0) return 0;
    const uint8_t sub = data[size / 2];
    const std::size_t pos = (static_cast<std::size_t>(data[0]) << 8 | data[size - 1]) % tl;
    tok[pos] = sub != tok[pos] ? sub : static_cast<uint8_t>(tok[pos] ^ 1u);
    require(Local::open(back, bl, tok, key, footer, implicit) == Status::invalid);
    const std::size_t ppos = (static_cast<std::size_t>(data[0]) << 8 | data[size - 1]) % pl;
    ptok[ppos] = sub != ptok[ppos] ? sub : static_cast<uint8_t>(ptok[ppos] ^ 1u);
    require(Public::verify(pback, pbl, ptok, kp.public_key.span(), footer, implicit) == Status::invalid);
    return 0;
}
