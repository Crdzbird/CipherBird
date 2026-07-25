#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::ImageFactorSeal — a shared image as an OPRF-gated second factor      ║
 * ║                                                                            ║
 * ║  Composition only (no new cryptography). Combines:                            ║
 * ║    • crypto::Oprf (RFC 9497, ristretto255-SHA-512) — an oblivious PRF keyed   ║
 * ║      by a long-term secret, evaluated over a *reference image*'s content.     ║
 * ║    • XChaCha20-Poly1305 — seals the plaintext under a key derived from the    ║
 * ║      OPRF output (HKDF-SHA-512 labeled).                                       ║
 * ║    • the keyed stego path (whitened + block-permuted) — hides the ciphertext  ║
 * ║      in a cover carrier under an independent OPRF-derived subkey.             ║
 * ║                                                                            ║
 * ║  Two factors are required to open: the OPRF secret (something you know) AND   ║
 * ║  the exact reference image (something you have). Change one pixel of the      ║
 * ║  reference and the OPRF input — and every derived key — changes.              ║
 * ║                                                                            ║
 * ║  The OPRF (vs a plain HKDF(secret‖image)) buys the *oblivious* mode: an image ║
 * ║  holder can obtain the seal keys from a REMOTE server that holds the OPRF      ║
 * ║  secret, without revealing which image they hold and without the server        ║
 * ║  learning the resulting key. Local one-shot and oblivious both converge on     ║
 * ║  the same 64-byte PRF via *_with_prf().                                        ║
 * ║                                                                            ║
 * ║  HONESTY: stego is concealment, confidentiality is the AEAD's. The scheme is  ║
 * ║  only as strong as the secrecy of the OPRF key and the reference image.       ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"
#include "symmetric.hpp"
#include "oprf.hpp"
#include "media_entropy.hpp"
#include "steganography.hpp"

#include <cstring>
#include <filesystem>
#include <span>
#include <string_view>

namespace crypto {

class ImageFactorSeal {
public:
    static constexpr std::string_view AEAD_LABEL  = "cryptolib-imagefactor-aead-v1";
    static constexpr std::string_view STEGO_LABEL = "cryptolib-imagefactor-stego-v1";

    // ── OPRF input: a deterministic 64-byte digest of the reference image ──────
    /// The image content (not its path) is conditioned into a stable 64-byte
    /// value used as the OPRF input. Streams large files safely.
    [[nodiscard]] static Result<SecureBuffer>
    image_input(const std::filesystem::path& reference_image) {
        auto me = entropy::MediaEntropy::from_file_deterministic(reference_image);
        if (me.is_err()) return Result<SecureBuffer>::err(me.error().message);
        const auto& raw = me.value().raw();               // 64B, content-deterministic
        SecureBuffer out(raw.span().size());
        std::memcpy(out.data(), raw.span().data(), raw.span().size());
        return Result<SecureBuffer>::ok(std::move(out));
    }

    // ── Local one-shot: holder has both the OPRF secret and the image ──────────
    [[nodiscard]] static Result<void>
    seal(std::span<const uint8_t>     oprf_secret_seed,
         const std::filesystem::path& reference_image,
         std::span<const uint8_t>     plaintext,
         std::span<const uint8_t>     aad,
         const std::filesystem::path& cover,
         const std::filesystem::path& out_stego)
    {
        auto prf = local_prf(oprf_secret_seed, reference_image);
        if (prf.is_err()) return Result<void>::err(prf.error().message);
        return seal_with_prf(prf.value().span(), plaintext, aad, cover, out_stego);
    }

    [[nodiscard]] static Result<Bytes>
    open(std::span<const uint8_t>     oprf_secret_seed,
         const std::filesystem::path& reference_image,
         std::span<const uint8_t>     aad,
         const std::filesystem::path& stego)
    {
        auto prf = local_prf(oprf_secret_seed, reference_image);
        if (prf.is_err()) return Result<Bytes>::err(prf.error().message);
        return open_with_prf(prf.value().span(), aad, stego);
    }

    // ── Oblivious building blocks (OPRF secret lives on a remote server) ───────
    // Client blinds the image; server runs Oprf::blind_evaluate(sk, blinded);
    // client finalizes to the same 64-byte PRF — without revealing the image and
    // without the server learning the PRF.
    [[nodiscard]] static Result<Oprf::BlindResult>
    blind_image(const std::filesystem::path& reference_image) {
        auto input = image_input(reference_image);
        if (input.is_err()) return Result<Oprf::BlindResult>::err(input.error().message);
        return Oprf::blind(input.value().span());
    }

    [[nodiscard]] static Result<SecureBuffer>
    finalize_prf(const std::filesystem::path& reference_image,
                 std::span<const uint8_t>     blind_scalar,
                 std::span<const uint8_t>     evaluated_element) {
        auto input = image_input(reference_image);
        if (input.is_err()) return Result<SecureBuffer>::err(input.error().message);
        return Oprf::finalize(input.value().span(), blind_scalar, evaluated_element);
    }

    // ── Seal/open from a precomputed 64-byte PRF (both paths converge here) ────
    [[nodiscard]] static Result<void>
    seal_with_prf(std::span<const uint8_t>     prf,
                  std::span<const uint8_t>     plaintext,
                  std::span<const uint8_t>     aad,
                  const std::filesystem::path& cover,
                  const std::filesystem::path& out_stego)
    {
        auto keys = keys_from_prf(prf);
        if (keys.is_err()) return Result<void>::err(keys.error().message);
        auto& [aead_key, stego_key] = keys.value();

        auto ct = symmetric::XChaCha20Poly1305::encrypt(plaintext, aead_key.span(), aad);
        if (ct.is_err()) return Result<void>::err(ct.error().message);

        stego::StegoParams params;
        params.key.assign(stego_key.span().begin(), stego_key.span().end());
        const auto& blob = ct.value();
        auto r = stego::StegoEngine::embed(
            cover.string(), { blob.data(), blob.size() }, out_stego.string(), params);
        sodium_memzero(params.key.data(), params.key.size());
        return r;
    }

    [[nodiscard]] static Result<Bytes>
    open_with_prf(std::span<const uint8_t>     prf,
                  std::span<const uint8_t>     aad,
                  const std::filesystem::path& stego)
    {
        auto keys = keys_from_prf(prf);
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

private:
    // Local PRF: derive a valid OPRF secret key from the caller's seed, then
    // evaluate the OPRF over the image digest. Deterministic → reproducible.
    [[nodiscard]] static Result<SecureBuffer>
    local_prf(std::span<const uint8_t> oprf_secret_seed,
              const std::filesystem::path& reference_image) {
        auto kp = Oprf::derive_keypair(oprf_secret_seed);
        if (kp.is_err()) return Result<SecureBuffer>::err(kp.error().message);
        auto input = image_input(reference_image);
        if (input.is_err()) return Result<SecureBuffer>::err(input.error().message);
        return Oprf::evaluate(kp.value().secret_key.span(), input.value().span());
    }

    // Expand the 64-byte OPRF output into two independent 32-byte keys.
    [[nodiscard]] static Result<std::pair<SecureBuffer, SecureBuffer>>
    keys_from_prf(std::span<const uint8_t> prf) {
        auto aead = hash::HkdfSha512::derive(prf, {}, AEAD_LABEL,
                        symmetric::XChaCha20Poly1305::KEY_BYTES);
        if (aead.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(aead.error().message);
        auto stego = hash::HkdfSha512::derive(prf, {}, STEGO_LABEL, 32);
        if (stego.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(stego.error().message);
        return Result<std::pair<SecureBuffer, SecureBuffer>>::ok(
            { std::move(aead.value()), std::move(stego.value()) });
    }
};

} // namespace crypto
