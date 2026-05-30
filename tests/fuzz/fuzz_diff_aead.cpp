/**
 * fuzz_diff_aead.cpp — differential fuzz target.
 *
 * Asserts CryptoLib's XChaCha20-Poly1305 *wrapper* and the raw libsodium
 * primitive interoperate byte-for-byte. The wrapper adds framing (nonce prefix,
 * length handling) — exactly where an AI-assisted attacker hunts for a deviation
 * the underlying primitive doesn't have. Any mismatch aborts the run.
 *
 * Build with -DCRYPTOLIB_FUZZ=ON (clang); run: ./fuzz_diff_aead -max_total_time=60
 */

#include <cryptolib/cryptolib.hpp>
#include <sodium.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using crypto::symmetric::XChaCha20Poly1305;

static constexpr std::size_t KEY = 32, NONCE = 24, MAC = 16;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (sodium_init() < 0) return 0;
    // Layout the fuzz input: key(32) | aad_len(1) | aad | msg
    if (size < KEY + 1) return 0;
    std::span<const uint8_t> key{data, KEY};
    std::size_t aad_len = data[KEY] % 64;
    if (size < KEY + 1 + aad_len) return 0;
    std::span<const uint8_t> aad{data + KEY + 1, aad_len};
    std::span<const uint8_t> msg{data + KEY + 1 + aad_len,
                                 size - (KEY + 1 + aad_len)};

    // (A) CryptoLib encrypt → raw libsodium must decrypt to the same plaintext.
    auto wrapped = XChaCha20Poly1305::encrypt(msg, key, aad);
    assert(wrapped.is_ok());
    auto w = wrapped.value().span();               // [nonce | ct | mac]
    assert(w.size() == NONCE + msg.size() + MAC);

    std::vector<uint8_t> ref(msg.size());
    unsigned long long ref_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ref.data(), &ref_len, nullptr,
        w.data() + NONCE, w.size() - NONCE,
        aad.empty() ? nullptr : aad.data(), aad.size(),
        w.data() /*nonce*/, key.data());
    assert(rc == 0 && "wrapper ciphertext rejected by raw libsodium");
    assert(ref_len == msg.size());
    assert(std::equal(ref.begin(), ref.end(), msg.begin()) &&
           "wrapper/primitive plaintext mismatch");

    // (B) Raw libsodium encrypt (fixed nonce) → CryptoLib wrapper must decrypt it.
    std::vector<uint8_t> framed(NONCE + msg.size() + MAC, 0);
    // deterministic nonce derived from input so the run is reproducible
    for (std::size_t i = 0; i < NONCE; ++i) framed[i] = data[i % KEY];
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        framed.data() + NONCE, &ct_len,
        msg.data(), msg.size(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        nullptr, framed.data(), key.data());
    framed.resize(NONCE + static_cast<std::size_t>(ct_len));
    auto back = XChaCha20Poly1305::decrypt(framed, key, aad);
    assert(back.is_ok() && "wrapper rejected raw-libsodium ciphertext");
    assert(back.value().size() == msg.size());
    assert(std::equal(back.value().span().begin(), back.value().span().end(), msg.begin()));

    return 0;
}
