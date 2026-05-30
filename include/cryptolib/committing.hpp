#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::symmetric::CommittingAead — key/context-committing AEAD            ║
 * ║                                                                            ║
 * ║  Plain AES-GCM and (X)ChaCha20-Poly1305 are NOT key-committing: a single    ║
 * ║  ciphertext can decrypt under MORE THAN ONE key without an auth failure.    ║
 * ║  That enables partitioning-oracle / "Invisible Salamanders" attacks. This   ║
 * ║  wrapper makes decryption commit to (key, AAD): a ciphertext authenticates  ║
 * ║  under exactly the key+context that produced it.                            ║
 * ║                                                                            ║
 * ║  Construction — UtC (UNAE-then-Commit, Bellare–Hoang 2022), key-splitting:  ║
 * ║                                                                            ║
 * ║    (K_enc ‖ K_com) = HKDF-SHA256(IKM=K, salt=LABEL, info=AAD, 64 bytes)      ║
 * ║    wire            = K_com(32) ‖ XChaCha20Poly1305(K_enc, P, AAD)           ║
 * ║    decrypt: rederive; constant-time-compare K_com; then AEAD-decrypt.       ║
 * ║                                                                            ║
 * ║  • Commitment to (K, AAD) rests on HKDF preimage/collision resistance.      ║
 * ║  • The AEAD's 192-bit random nonce makes reusing K_enc across messages      ║
 * ║    with the same (K, AAD) safe (XChaCha nonce space — no rekey needed).     ║
 * ║  • Built only from already-vetted primitives (HKDF + XChaCha20-Poly1305).   ║
 * ║                                                                            ║
 * ║  REVIEW STATUS: new composition — KAT- and differential-fuzz-covered,        ║
 * ║  pending external review. See docs/THREAT_MODEL.md §5.4.                     ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"        // crypto::hash::HkdfSha256
#include "symmetric.hpp"   // crypto::symmetric::XChaCha20Poly1305

#include <sodium.h>        // sodium_memcmp (constant-time)
#include <cstring>
#include <span>
#include <string_view>

namespace crypto::symmetric {

class CommittingAead {
public:
    static constexpr std::size_t KEY_BYTES    = 32;
    static constexpr std::size_t COMMIT_BYTES = 32;
    static constexpr std::string_view LABEL   = "cryptolib/cmt-aead/v1";

    [[nodiscard]] static SecureBuffer generate_key() {
        return XChaCha20Poly1305::generate_key();
    }

    /// Encrypt → wire = K_com(32) ‖ nonce ‖ ciphertext ‖ tag.
    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("CommittingAead: key must be 32 bytes");

        auto okm = derive(key, aad);
        if (okm.is_err()) return Result<SecureBuffer>::err(okm.error().message);
        auto k_enc = okm.value().span().subspan(0, 32);
        auto k_com = okm.value().span().subspan(32, 32);

        auto body = XChaCha20Poly1305::encrypt(plaintext, k_enc, aad);
        if (body.is_err()) return Result<SecureBuffer>::err(body.error().message);

        SecureBuffer out(COMMIT_BYTES + body.value().size());
        std::memcpy(out.data(), k_com.data(), COMMIT_BYTES);
        std::memcpy(out.data() + COMMIT_BYTES, body.value().data(), body.value().size());
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /// Decrypt. Fails closed on commitment mismatch OR AEAD auth failure —
    /// indistinguishably (no oracle).
    [[nodiscard]] static Result<SecureBuffer>
    decrypt(std::span<const uint8_t> wire,
            std::span<const uint8_t> key,
            std::span<const uint8_t> aad = {}) {
        if (key.size() != KEY_BYTES)
            return Result<SecureBuffer>::err("CommittingAead: key must be 32 bytes");
        if (wire.size() < COMMIT_BYTES)
            return Result<SecureBuffer>::err("CommittingAead: ciphertext too short");

        auto okm = derive(key, aad);
        if (okm.is_err()) return Result<SecureBuffer>::err(okm.error().message);
        auto k_enc = okm.value().span().subspan(0, 32);
        auto k_com = okm.value().span().subspan(32, 32);

        // CONST-TIME: commitment check must not branch on secret-dependent data.
        if (sodium_memcmp(wire.data(), k_com.data(), COMMIT_BYTES) != 0)
            return Result<SecureBuffer>::err("CommittingAead: authentication failed");

        return XChaCha20Poly1305::decrypt(wire.subspan(COMMIT_BYTES), k_enc, aad);
    }

    // string_view conveniences
    [[nodiscard]] static Result<SecureBuffer>
    encrypt(std::string_view plaintext, std::span<const uint8_t> key, std::string_view aad = {}) {
        return encrypt({reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()},
                       key,
                       {reinterpret_cast<const uint8_t*>(aad.data()), aad.size()});
    }

private:
    [[nodiscard]] static Result<SecureBuffer>
    derive(std::span<const uint8_t> key, std::span<const uint8_t> aad) {
        const std::span<const uint8_t> label{
            reinterpret_cast<const uint8_t*>(LABEL.data()), LABEL.size()};
        auto prk = hash::HkdfSha256::extract(label, key);
        if (prk.is_err()) return prk;
        return hash::HkdfSha256::expand(prk.value().span(), aad, 64);
    }
};

} // namespace crypto::symmetric
