/**
 * fuzz_paseto_v4.cpp - libFuzzer target for PASETO v4.local.
 *
 * Feeds the fuzz input to decrypt as an untrusted token under a fixed key,
 * expected footer and implicit assertion, and requires a fail-closed result
 * with a wiped output region. It requires the token codec to accept exactly
 * what libsodium's URL-safe unpadded decoder accepts, with the same bytes,
 * and to encode exactly as libsodium does. It also round-trips the input as
 * a message and requires that replacing the byte the input selects with any
 * other byte value is rejected.
 *
 * Build with -DCRYPTOLIB_FUZZ=ON (clang); run: ./fuzz_paseto_v4 -max_total_time=60
 */

#include <cryptolib/cryptolib.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <span>
#include <vector>

using crypto::paseto::V4Local;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (sodium_init() < 0) return 0;
    static const uint8_t key[32] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    static const uint8_t footer[] = {'k', 'i', 'd'};
    static const uint8_t implicit[] = {'a', 'u', 'd'};
    const std::span<const uint8_t> in(data, size);

    std::vector<uint8_t> out(V4Local::open_capacity(size) + 1, 0xA5);
    std::size_t n = 1;
    const auto s = V4Local::open(out, n, in, key, footer, implicit);
    require(s == V4Local::Status::ok || s == V4Local::Status::invalid);
    if (s != V4Local::Status::ok) {
        require(n == 0);
        for (std::size_t i = 0; i + 1 < out.size(); ++i) require(out[i] == 0);
    }
    require(out.back() == 0xA5);

    {
        std::vector<uint8_t> a(size + 1), b(size + 1);
        std::size_t na = 0, nb = 0;
        const char* text = reinterpret_cast<const char*>(data);
        const bool oa = crypto::paseto::codec::decode(a.data(), a.size(), text, size, na);
        const bool ob = sodium_base642bin(b.data(), b.size(), text, size, nullptr, &nb, nullptr,
                                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0;
        require(oa == ob);
        require(!oa || (na == nb && std::equal(a.begin(), a.begin() + na, b.begin())));
        std::vector<uint8_t> e(crypto::paseto::codec::encoded_len(size) + 1);
        const std::size_t w = crypto::paseto::codec::encode(e.data(), data, size);
        std::vector<char> ref(sodium_base64_ENCODED_LEN(size, sodium_base64_VARIANT_URLSAFE_NO_PADDING));
        sodium_bin2base64(ref.data(), ref.size(), data, size, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        require(w + 1 == ref.size() && std::equal(e.begin(), e.begin() + w, ref.begin()));
    }
    if (size > 4096) return 0;
    std::vector<uint8_t> tok(V4Local::token_len(size, sizeof footer));
    std::size_t tl = 0;
    require(V4Local::seal(tok, tl, key, in, footer, implicit) == V4Local::Status::ok);
    require(tl == tok.size());
    std::vector<uint8_t> back(V4Local::open_capacity(tl));
    std::size_t bl = 0;
    require(V4Local::open(back, bl, tok, key, footer, implicit) == V4Local::Status::ok);
    require(bl == size && std::equal(back.begin(), back.begin() + bl, in.begin()));
    if (size == 0) return 0;
    const std::size_t pos = (static_cast<std::size_t>(data[0]) << 8 | data[size - 1]) % tl;
    const uint8_t sub = data[size / 2];
    tok[pos] = sub != tok[pos] ? sub : static_cast<uint8_t>(tok[pos] ^ 1u);
    require(V4Local::open(back, bl, tok, key, footer, implicit) == V4Local::Status::invalid);
    return 0;
}
