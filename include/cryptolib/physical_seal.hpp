#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::PhysicalSeal — two-factor "the photo is the key, the message        ║
 * ║  hides in another photo" seal                                               ║
 * ║                                                                            ║
 * ║  A composed feature (no new cryptography) combining three vetted pieces:     ║
 * ║    1. crypto::entropy::MediaEntropy (deterministic) — a *key media* file     ║
 * ║       (a photo, an audio clip) is conditioned into a reproducible master.    ║
 * ║    2. XChaCha20-Poly1305 — the plaintext is AEAD-sealed under a key derived   ║
 * ║       from that master (HKDF-SHA-512 labeled derive), binding the caller AAD. ║
 * ║    3. The keyed stego path (whitened + block-permuted) — the ciphertext is    ║
 * ║       hidden inside a *separate cover carrier*, keyed by an independent        ║
 * ║       subkey derived from the same master.                                    ║
 * ║                                                                            ║
 * ║  The result is a genuine two-factor scheme by media possession:               ║
 * ║    • the key media alone  → no ciphertext to open;                            ║
 * ║    • the stego carrier alone → no key, and (because the stego stream is        ║
 * ║      whitened) no 'CSTG' signature — it is indistinguishable from a           ║
 * ║      payload-free image at the bit-stream level.                              ║
 * ║  Both files are required to recover the message.                              ║
 * ║                                                                            ║
 * ║  This differs from MediaEntropy::seal_into (single media file, *plain*        ║
 * ║  fingerprint-able stego): PhysicalSeal splits key media from cover and hides  ║
 * ║  through the keyed path, so neither artefact is individually incriminating.   ║
 * ║                                                                            ║
 * ║  HONESTY: stego is concealment, not confidentiality — confidentiality here    ║
 * ║  comes entirely from the AEAD layer. The scheme is only as strong as the      ║
 * ║  secrecy of the key-media file; treat it like any other key.                  ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "symmetric.hpp"
#include "media_entropy.hpp"
#include "steganography.hpp"

#include <filesystem>
#include <span>
#include <string_view>

namespace crypto {

class PhysicalSeal {
public:
    // Domain-separation labels — the AEAD key and the stego master key are
    // independent derivations from the same conditioned media entropy.
    static constexpr std::string_view AEAD_LABEL  = "cryptolib-physicalseal-aead-v1";
    static constexpr std::string_view STEGO_LABEL = "cryptolib-physicalseal-stego-v1";

    /// Seal `plaintext` (binding `aad`) using entropy derived deterministically
    /// from `key_media`, then hide the ciphertext inside `cover`, writing the
    /// stego carrier to `out_stego`. `cover` must have enough stego capacity for
    /// the sealed packet (nonce+ciphertext+tag); .ppm carriers are supported.
    [[nodiscard]] static Result<void>
    seal(const std::filesystem::path& key_media,
         std::span<const uint8_t>     plaintext,
         std::span<const uint8_t>     aad,
         const std::filesystem::path& cover,
         const std::filesystem::path& out_stego)
    {
        auto keys = derive_keys(key_media);
        if (keys.is_err()) return Result<void>::err(keys.error().message);
        auto& [aead_key, stego_key] = keys.value();

        auto ct = symmetric::XChaCha20Poly1305::encrypt(
            plaintext, aead_key.span(), aad);
        if (ct.is_err()) return Result<void>::err(ct.error().message);

        stego::StegoParams params;
        params.key.assign(stego_key.span().begin(), stego_key.span().end());
        const auto& blob = ct.value();
        auto r = stego::StegoEngine::embed(
            cover.string(), { blob.data(), blob.size() }, out_stego.string(), params);
        sodium_memzero(params.key.data(), params.key.size());
        return r;
    }

    /// Recover the plaintext: reconstruct the entropy from `key_media`, extract
    /// the hidden ciphertext from `stego`, and AEAD-open it under `aad`.
    /// Fails closed if either file is wrong, the key media differs, or the
    /// carrier was tampered with (CRC fast-fail, then the Poly1305 tag).
    [[nodiscard]] static Result<Bytes>
    open(const std::filesystem::path& key_media,
         std::span<const uint8_t>     aad,
         const std::filesystem::path& stego)
    {
        auto keys = derive_keys(key_media);
        if (keys.is_err()) return Result<Bytes>::err(keys.error().message);
        auto& [aead_key, stego_key] = keys.value();

        stego::StegoParams params;
        params.key.assign(stego_key.span().begin(), stego_key.span().end());
        auto ct = stego::StegoEngine::extract(stego.string(), params);
        sodium_memzero(params.key.data(), params.key.size());
        if (ct.is_err()) return Result<Bytes>::err(ct.error().message);

        auto& blob = ct.value();
        auto pt = symmetric::XChaCha20Poly1305::decrypt(
            { blob.data(), blob.size() }, aead_key.span(), aad);
        if (pt.is_err()) return Result<Bytes>::err(pt.error().message);

        const auto& sb = pt.value();
        return Result<Bytes>::ok(Bytes(sb.data(), sb.data() + sb.size()));
    }

    /// String-view convenience for text plaintext / AAD.
    [[nodiscard]] static Result<void>
    seal(const std::filesystem::path& key_media,
         std::string_view             plaintext,
         std::string_view             aad,
         const std::filesystem::path& cover,
         const std::filesystem::path& out_stego)
    {
        return seal(key_media,
            { reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size() },
            { reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
            cover, out_stego);
    }

    [[nodiscard]] static Result<Bytes>
    open(const std::filesystem::path& key_media,
         std::string_view             aad,
         const std::filesystem::path& stego)
    {
        return open(key_media,
            { reinterpret_cast<const uint8_t*>(aad.data()), aad.size() }, stego);
    }

private:
    // Derive the two independent 32-byte keys from the key-media entropy.
    [[nodiscard]] static Result<std::pair<SecureBuffer, SecureBuffer>>
    derive_keys(const std::filesystem::path& key_media) {
        auto me = entropy::MediaEntropy::from_file_deterministic(key_media);
        if (me.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(me.error().message);
        auto aead_key  = me.value().derive(AEAD_LABEL,
                             symmetric::XChaCha20Poly1305::KEY_BYTES);
        auto stego_key = me.value().derive(STEGO_LABEL, 32);
        return Result<std::pair<SecureBuffer, SecureBuffer>>::ok(
            { std::move(aead_key), std::move(stego_key) });
    }
};

} // namespace crypto
