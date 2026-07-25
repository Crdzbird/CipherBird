#pragma once

/**
 * crypto::stego — Keyed steganography primitives (Phase 1 hardening)
 *
 * Two key-derived transforms that turn the otherwise fingerprint-able embedding
 * into a keyed operation:
 *
 *   stego_whiten()      — XOR the whole embedded stream (header + payload) with a
 *                         ChaCha20 keystream, so the fixed 'CSTG' magic (and the
 *                         length/CRC fields) never appear in the extracted bits.
 *                         Without the key the carrier is indistinguishable from a
 *                         payload-free one at the bit-stream level.
 *
 *   block_permutation() — a key-seeded Fisher–Yates permutation of carrier slot
 *                         indices, so the payload is scattered across the carrier
 *                         instead of filling a contiguous, location-predictable
 *                         region.
 *
 * Both derive a domain-separated subkey from the caller's embedding key via
 * keyed BLAKE2b, then use libsodium's ChaCha20 keystream. No new cryptography —
 * a stream cipher and a shuffle over vetted primitives.
 *
 * NOTE: whitening is NOT authentication and NOT confidentiality — the payload
 * must still be AEAD-encrypted (as seal_into does). Whitening only removes the
 * steganographic *signature*; the wrong key yields garbage that fails the CRC
 * (fast-fail) and, underneath, the AEAD tag.
 */

#include "types.hpp"

#include <sodium.h>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::stego {

// Domain-separated 32-byte subkey = BLAKE2b(label, key=embedding_key).
[[nodiscard]] inline std::array<uint8_t, 32>
stego_subkey(std::span<const uint8_t> key, std::string_view label) {
    std::array<uint8_t, 32> out{};
    crypto_generichash(out.data(), out.size(),
                       reinterpret_cast<const uint8_t*>(label.data()), label.size(),
                       key.data(), key.size());
    return out;
}

// XOR `data` in place with a ChaCha20 keystream keyed by (key, whiten-label).
// Symmetric — calling it again with the same key restores the original bytes.
// The subkey is domain-separated and single-purpose, so a fixed zero nonce is
// safe; identical (key, data) → identical output, which is fine because embedded
// payloads carry their own AEAD nonce and are never byte-identical in practice.
inline void stego_whiten(std::span<uint8_t> data, std::span<const uint8_t> key) {
    if (key.empty() || data.empty()) return;
    auto sk = stego_subkey(key, "cryptolib-stego-whiten-v1");
    static const uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    crypto_stream_chacha20_xor(data.data(), data.data(), data.size(), nonce, sk.data());
    sodium_memzero(sk.data(), sk.size());
}

// Key-seeded permutation of [0, n) via Fisher–Yates driven by a ChaCha20
// keystream. Returns the identity permutation when the key is empty or n < 2.
// The modulo reduction has negligible bias — acceptable here since this only
// spreads carrier positions, it is not a source of cryptographic randomness.
[[nodiscard]] inline std::vector<uint32_t>
block_permutation(std::size_t n, std::span<const uint8_t> key) {
    std::vector<uint32_t> perm(n);
    for (std::size_t i = 0; i < n; ++i) perm[i] = static_cast<uint32_t>(i);
    if (key.empty() || n < 2) return perm;

    auto sk = stego_subkey(key, "cryptolib-stego-perm-v1");
    std::vector<uint64_t> rnd(n);
    static const uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    crypto_stream_chacha20(reinterpret_cast<uint8_t*>(rnd.data()),
                           n * sizeof(uint64_t), nonce, sk.data());
    for (std::size_t i = n - 1; i > 0; --i) {
        std::size_t j = static_cast<std::size_t>(rnd[i] % (i + 1));
        std::swap(perm[i], perm[j]);
    }
    sodium_memzero(sk.data(), sk.size());
    sodium_memzero(rnd.data(), rnd.size() * sizeof(uint64_t));
    return perm;
}

} // namespace crypto::stego
