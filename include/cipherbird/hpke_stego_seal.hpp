#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::HpkeStegoSeal — keyed stego bound to an HPKE session                 ║
 * ║                                                                            ║
 * ║  The public-key analogue of StegoEngine::embed_encrypted (which binds        ║
 * ║  concealment to a *symmetric* key). Here one HPKE session (RFC 9180,          ║
 * ║  DHKEM-X25519 + HKDF-SHA-256 + ChaCha20-Poly1305) governs BOTH:              ║
 * ║    • the AEAD ciphertext (the HPKE context seals the plaintext), and          ║
 * ║    • the stego concealment key — derived from the SAME session via the        ║
 * ║      HPKE *exporter interface* (RFC 9180 §5.3), so no separate key is needed. ║
 * ║                                                                            ║
 * ║  Composition only — no new cryptography.                                      ║
 * ║                                                                            ║
 * ║  The KEM encapsulation `enc` is public by design (HPKE always transmits it    ║
 * ║  in the clear); seal() returns it to send alongside the carrier. Because the  ║
 * ║  receiver needs `enc` to reconstruct the session (and thus the exporter-        ║
 * ║  derived stego key), only the AEAD ciphertext is hidden in the carrier —      ║
 * ║  which is exactly what must stay secret. Whitening removes the 'CSTG'          ║
 * ║  signature, so the carrier looks payload-free without the session.            ║
 * ║                                                                            ║
 * ║  HONESTY: stego is concealment, confidentiality is HPKE's AEAD. Only the       ║
 * ║  holder of the recipient secret key skR can derive the stego key and open.    ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hpke.hpp"
#include "steganography.hpp"

#include <filesystem>
#include <span>
#include <string_view>

namespace crypto {

class HpkeStegoSeal {
public:
    static constexpr std::string_view EXPORT_LABEL = "cryptolib-hpke-stego-v1";
    static constexpr Hpke::Kdf  KDF  = Hpke::Kdf::HkdfSha256;
    static constexpr Hpke::Aead AEAD = Hpke::Aead::ChaCha20Poly1305; // always available

    /// Seal `plaintext` to recipient public key `pkR`, hiding the HPKE ciphertext
    /// in `cover` (keyed by the session's exporter secret). Returns the public
    /// KEM encapsulation `enc` — transmit it alongside `out_stego`; the receiver
    /// needs it to reconstruct the session.
    [[nodiscard]] static Result<SecureBuffer>
    seal(std::span<const uint8_t>     pkR,
         std::span<const uint8_t>     plaintext,
         std::span<const uint8_t>     aad,
         std::span<const uint8_t>     info,
         const std::filesystem::path& cover,
         const std::filesystem::path& out_stego)
    {
        auto sc = Hpke::setup_base_s(KDF, AEAD, pkR, info);
        if (sc.is_err()) return Result<SecureBuffer>::err(sc.error().message);
        auto& ctx = sc.value().ctx;

        auto stego_key = ctx.export_secret(label_bytes(), 32);   // const — session-bound
        if (stego_key.is_err()) return Result<SecureBuffer>::err(stego_key.error().message);

        auto ct = ctx.seal(aad, plaintext);
        if (ct.is_err()) return Result<SecureBuffer>::err(ct.error().message);

        stego::StegoParams params;
        params.key.assign(stego_key.value().span().begin(), stego_key.value().span().end());
        const auto& blob = ct.value();
        auto r = stego::StegoEngine::embed(
            cover.string(), { blob.data(), blob.size() }, out_stego.string(), params);
        sodium_memzero(params.key.data(), params.key.size());
        if (r.is_err()) return Result<SecureBuffer>::err(r.error().message);

        return Result<SecureBuffer>::ok(std::move(sc.value().enc)); // public encapsulation
    }

    /// Open: reconstruct the session from `enc` + recipient secret `skR`, derive
    /// the same stego key, extract the ciphertext, and AEAD-open it. Fails closed
    /// for the wrong skR/enc/info/aad or a tampered carrier.
    [[nodiscard]] static Result<Bytes>
    open(std::span<const uint8_t>     skR,
         std::span<const uint8_t>     enc,
         std::span<const uint8_t>     aad,
         std::span<const uint8_t>     info,
         const std::filesystem::path& stego)
    {
        auto ctx_res = Hpke::setup_base_r(KDF, AEAD, enc, skR, info);
        if (ctx_res.is_err()) return Result<Bytes>::err(ctx_res.error().message);
        auto& ctx = ctx_res.value();

        auto stego_key = ctx.export_secret(label_bytes(), 32);
        if (stego_key.is_err()) return Result<Bytes>::err(stego_key.error().message);

        stego::StegoParams params;
        params.key.assign(stego_key.value().span().begin(), stego_key.value().span().end());
        auto ct = stego::StegoEngine::extract(stego.string(), params);
        sodium_memzero(params.key.data(), params.key.size());
        if (ct.is_err()) return Result<Bytes>::err(ct.error().message);

        auto& blob = ct.value();
        auto pt = ctx.open(aad, { blob.data(), blob.size() });
        if (pt.is_err()) return Result<Bytes>::err(pt.error().message);
        const auto& sb = pt.value();
        return Result<Bytes>::ok(Bytes(sb.data(), sb.data() + sb.size()));
    }

private:
    [[nodiscard]] static std::span<const uint8_t> label_bytes() {
        return { reinterpret_cast<const uint8_t*>(EXPORT_LABEL.data()), EXPORT_LABEL.size() };
    }
};

} // namespace crypto
