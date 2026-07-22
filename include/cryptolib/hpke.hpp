#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Hpke — Hybrid Public Key Encryption (RFC 9180)                       ║
 * ║                                                                            ║
 * ║  THE standardized single-shot / streaming public-key encryption used by      ║
 * ║  TLS ECH, MLS, Oblivious HTTP, and ODoH. Where Flagship/Fortress are          ║
 * ║  deliberately library-native, HPKE is a wire standard: an envelope sealed     ║
 * ║  here opens in any conformant HPKE implementation and vice-versa.            ║
 * ║                                                                            ║
 * ║  KEM  : DHKEM(X25519, HKDF-SHA256)              (kem_id 0x0020)             ║
 * ║  KDF  : HKDF-SHA256 / HKDF-SHA512               (0x0001 / 0x0003)           ║
 * ║  AEAD : AES-128-GCM / AES-256-GCM† / ChaCha20Poly1305 / Export-only          ║
 * ║           († AES-GCM needs OpenSSL; ChaCha20 is always available)            ║
 * ║  Modes: Base · PSK · Auth · AuthPSK                                          ║
 * ║                                                                            ║
 * ║  Composition only — no new cryptography. Every primitive (X25519, HKDF,      ║
 * ║  ChaCha20-Poly1305-IETF, AES-GCM) is a vetted library call. Validated        ║
 * ║  byte-for-byte against the RFC 9180 test vectors.                           ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"          // HkdfSha256 / HkdfSha512
#include "asymmetric.hpp"    // X25519

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#ifdef CRYPTOLIB_HAS_OPENSSL
#include <openssl/evp.h>
#endif

namespace crypto {

class Hpke {
public:
    // ── Ciphersuite identifiers (RFC 9180 §7) ─────────────────────────────────
    static constexpr uint16_t KEM_ID = 0x0020;   // DHKEM(X25519, HKDF-SHA256)

    enum class Kdf : uint16_t { HkdfSha256 = 0x0001, HkdfSha512 = 0x0003 };
    enum class Aead : uint16_t {
        Aes128Gcm = 0x0001, Aes256Gcm = 0x0002, ChaCha20Poly1305 = 0x0003, ExportOnly = 0xFFFF
    };
    enum class Mode : uint8_t { Base = 0x00, Psk = 0x01, Auth = 0x02, AuthPsk = 0x03 };

    static constexpr std::size_t NSECRET = 32; // DHKEM(X25519) shared secret
    static constexpr std::size_t NPK = 32, NSK = 32, NENC = 32; // X25519 sizes

    struct KeyPair { SecureBuffer public_key; SecureBuffer secret_key; };

    // ── An established HPKE context (one direction) ───────────────────────────
    // Holds the derived AEAD key, base nonce, sequence counter and exporter
    // secret. `seal` (sender) / `open` (receiver) advance the same counter; a
    // context is single-direction and move-only.
    class Context {
    public:
        Context(Context&&) = default;
        Context& operator=(Context&&) = default;
        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;

        /// Sender: AEAD-seal the next message (advances the sequence number).
        [[nodiscard]] Result<SecureBuffer> seal(std::span<const uint8_t> aad,
                                                std::span<const uint8_t> pt) {
            if (aead_ == Aead::ExportOnly)
                return Result<SecureBuffer>::err("HPKE: export-only context cannot seal");
            auto nonce = compute_nonce();
            if (nonce.is_err()) return Result<SecureBuffer>::err(nonce.error().message);
            auto ct = aead_seal(aead_, key_.span(), nonce.value().span(), aad, pt);
            if (ct.is_err()) return ct;
            ++seq_;
            return ct;
        }

        /// Receiver: AEAD-open the next message (advances the sequence number).
        [[nodiscard]] Result<SecureBuffer> open(std::span<const uint8_t> aad,
                                                std::span<const uint8_t> ct) {
            if (aead_ == Aead::ExportOnly)
                return Result<SecureBuffer>::err("HPKE: export-only context cannot open");
            auto nonce = compute_nonce();
            if (nonce.is_err()) return Result<SecureBuffer>::err(nonce.error().message);
            auto pt = aead_open(aead_, key_.span(), nonce.value().span(), aad, ct);
            if (pt.is_err()) return pt; // do NOT advance seq on failure
            ++seq_;
            return pt;
        }

        /// Derive a secret bound to this context (RFC 9180 §5.3 secret export).
        [[nodiscard]] Result<SecureBuffer> export_secret(std::span<const uint8_t> exporter_context,
                                                         std::size_t length) const {
            return labeled_expand(kdf_, suite_id_, exporter_secret_.span(), "sec",
                                  exporter_context, length);
        }

    private:
        friend class Hpke;
        Context(Kdf kdf, Aead aead, std::vector<uint8_t> suite_id,
                SecureBuffer key, SecureBuffer base_nonce, SecureBuffer exporter_secret)
            : kdf_(kdf), aead_(aead), suite_id_(std::move(suite_id)),
              key_(std::move(key)), base_nonce_(std::move(base_nonce)),
              exporter_secret_(std::move(exporter_secret)) {}

        [[nodiscard]] Result<SecureBuffer> compute_nonce() const {
            const std::size_t Nn = base_nonce_.size(); // 12
            if (seq_ == UINT64_MAX)
                return Result<SecureBuffer>::err("HPKE: message limit reached (sequence overflow)");
            SecureBuffer nonce(Nn);
            std::memcpy(nonce.data(), base_nonce_.data(), Nn);
            // XOR big-endian I2OSP(seq, Nn) into the trailing 8 bytes.
            for (std::size_t i = 0; i < 8; ++i)
                nonce.data()[Nn - 1 - i] ^= static_cast<uint8_t>((seq_ >> (8 * i)) & 0xff);
            return Result<SecureBuffer>::ok(std::move(nonce));
        }

        Kdf kdf_;
        Aead aead_;
        std::vector<uint8_t> suite_id_;
        SecureBuffer key_;
        SecureBuffer base_nonce_;
        SecureBuffer exporter_secret_;
        uint64_t seq_ = 0;
    };

    struct SenderContext { SecureBuffer enc; Context ctx; };
    struct Sealed { SecureBuffer enc; SecureBuffer ct; };

    // ── Key generation ────────────────────────────────────────────────────────
    [[nodiscard]] static KeyPair generate_keypair() {
        KeyPair kp;
        kp.secret_key = SecureBuffer(NSK);
        randombytes_buf(kp.secret_key.data(), NSK);
        kp.public_key = x25519_pk(kp.secret_key.span());
        return kp;
    }

    /// Deterministically derive a key pair from input keying material
    /// (DHKEM(X25519).DeriveKeyPair — used for reproducible/test keys).
    [[nodiscard]] static Result<KeyPair> derive_keypair(std::span<const uint8_t> ikm) {
        auto sid = kem_suite_id();
        auto dkp_prk = labeled_extract(Kdf::HkdfSha256, sid, {}, "dkp_prk", ikm);
        auto sk = labeled_expand(Kdf::HkdfSha256, sid, dkp_prk.span(), "sk", {}, NSK);
        if (sk.is_err()) return Result<KeyPair>::err(sk.error().message);
        KeyPair kp;
        kp.public_key = x25519_pk(sk.value().span());
        kp.secret_key = std::move(sk.value());
        return Result<KeyPair>::ok(std::move(kp));
    }

    // ── Sender setup (per mode) ───────────────────────────────────────────────
    [[nodiscard]] static Result<SenderContext>
    setup_base_s(Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info) {
        return setup_s(Mode::Base, kdf, aead, pkR, info, {}, {}, {}, {});
    }
    [[nodiscard]] static Result<SenderContext>
    setup_psk_s(Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info,
                std::span<const uint8_t> psk, std::span<const uint8_t> psk_id) {
        return setup_s(Mode::Psk, kdf, aead, pkR, info, psk, psk_id, {}, {});
    }
    [[nodiscard]] static Result<SenderContext>
    setup_auth_s(Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info,
                 std::span<const uint8_t> skS) {
        return setup_s(Mode::Auth, kdf, aead, pkR, info, {}, {}, skS, {});
    }
    [[nodiscard]] static Result<SenderContext>
    setup_auth_psk_s(Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info,
                     std::span<const uint8_t> psk, std::span<const uint8_t> psk_id,
                     std::span<const uint8_t> skS) {
        return setup_s(Mode::AuthPsk, kdf, aead, pkR, info, psk, psk_id, skS, {});
    }

    // ── Receiver setup (per mode) ─────────────────────────────────────────────
    [[nodiscard]] static Result<Context>
    setup_base_r(Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
                 std::span<const uint8_t> info) {
        return setup_r(Mode::Base, kdf, aead, enc, skR, info, {}, {}, {});
    }
    [[nodiscard]] static Result<Context>
    setup_psk_r(Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
                std::span<const uint8_t> info, std::span<const uint8_t> psk, std::span<const uint8_t> psk_id) {
        return setup_r(Mode::Psk, kdf, aead, enc, skR, info, psk, psk_id, {});
    }
    [[nodiscard]] static Result<Context>
    setup_auth_r(Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
                 std::span<const uint8_t> info, std::span<const uint8_t> pkS) {
        return setup_r(Mode::Auth, kdf, aead, enc, skR, info, {}, {}, pkS);
    }
    [[nodiscard]] static Result<Context>
    setup_auth_psk_r(Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
                     std::span<const uint8_t> info, std::span<const uint8_t> psk,
                     std::span<const uint8_t> psk_id, std::span<const uint8_t> pkS) {
        return setup_r(Mode::AuthPsk, kdf, aead, enc, skR, info, psk, psk_id, pkS);
    }

    // ── Single-shot convenience (base mode) ───────────────────────────────────
    [[nodiscard]] static Result<Sealed>
    seal_base(Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info,
              std::span<const uint8_t> aad, std::span<const uint8_t> pt) {
        auto s = setup_base_s(kdf, aead, pkR, info);
        if (s.is_err()) return Result<Sealed>::err(s.error().message);
        auto ct = s.value().ctx.seal(aad, pt);
        if (ct.is_err()) return Result<Sealed>::err(ct.error().message);
        return Result<Sealed>::ok(Sealed{ std::move(s.value().enc), std::move(ct.value()) });
    }
    [[nodiscard]] static Result<SecureBuffer>
    open_base(Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
              std::span<const uint8_t> info, std::span<const uint8_t> aad, std::span<const uint8_t> ct) {
        auto r = setup_base_r(kdf, aead, enc, skR, info);
        if (r.is_err()) return Result<SecureBuffer>::err(r.error().message);
        return r.value().open(aad, ct);
    }

    // ── Deterministic setup (test vectors): caller supplies the ephemeral sk ──
    [[nodiscard]] static Result<SenderContext>
    setup_s_deterministic(Mode mode, Kdf kdf, Aead aead, std::span<const uint8_t> pkR,
                          std::span<const uint8_t> info, std::span<const uint8_t> psk,
                          std::span<const uint8_t> psk_id, std::span<const uint8_t> skS,
                          std::span<const uint8_t> skE) {
        return setup_s(mode, kdf, aead, pkR, info, psk, psk_id, skS, skE);
    }

private:
    // ── byte helpers ──────────────────────────────────────────────────────────
    static void put(std::vector<uint8_t>& v, std::span<const uint8_t> s) {
        v.insert(v.end(), s.begin(), s.end());
    }
    static void put(std::vector<uint8_t>& v, std::string_view s) {
        v.insert(v.end(), s.begin(), s.end());
    }
    static std::span<const uint8_t> sv(std::string_view s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }

    static std::vector<uint8_t> kem_suite_id() {
        return { 'K', 'E', 'M', static_cast<uint8_t>(KEM_ID >> 8), static_cast<uint8_t>(KEM_ID & 0xff) };
    }
    static std::vector<uint8_t> hpke_suite_id(Kdf kdf, Aead aead) {
        auto k = static_cast<uint16_t>(kdf);
        auto a = static_cast<uint16_t>(aead);
        return { 'H', 'P', 'K', 'E',
                 static_cast<uint8_t>(KEM_ID >> 8), static_cast<uint8_t>(KEM_ID & 0xff),
                 static_cast<uint8_t>(k >> 8), static_cast<uint8_t>(k & 0xff),
                 static_cast<uint8_t>(a >> 8), static_cast<uint8_t>(a & 0xff) };
    }

    // ── HKDF dispatch on the chosen KDF ───────────────────────────────────────
    static SecureBuffer hkdf_extract(Kdf kdf, std::span<const uint8_t> salt, std::span<const uint8_t> ikm) {
        if (kdf == Kdf::HkdfSha512) return std::move(hash::HkdfSha512::extract(salt, ikm).value());
        return std::move(hash::HkdfSha256::extract(salt, ikm).value());
    }
    static Result<SecureBuffer> hkdf_expand(Kdf kdf, std::span<const uint8_t> prk,
                                            std::span<const uint8_t> info, std::size_t L) {
        return kdf == Kdf::HkdfSha512 ? hash::HkdfSha512::expand(prk, info, L)
                                      : hash::HkdfSha256::expand(prk, info, L);
    }
    static std::size_t kdf_Nh(Kdf kdf) { return kdf == Kdf::HkdfSha512 ? 64 : 32; }

    // ── HPKE labeled KDF (RFC 9180 §4) ────────────────────────────────────────
    static SecureBuffer labeled_extract(Kdf kdf, std::span<const uint8_t> suite_id,
                                        std::span<const uint8_t> salt, std::string_view label,
                                        std::span<const uint8_t> ikm) {
        std::vector<uint8_t> li;
        put(li, "HPKE-v1"); put(li, suite_id); put(li, label); put(li, ikm);
        return hkdf_extract(kdf, salt, li);
    }
    static Result<SecureBuffer> labeled_expand(Kdf kdf, std::span<const uint8_t> suite_id,
                                               std::span<const uint8_t> prk, std::string_view label,
                                               std::span<const uint8_t> info, std::size_t L) {
        std::vector<uint8_t> li;
        li.push_back(static_cast<uint8_t>((L >> 8) & 0xff));
        li.push_back(static_cast<uint8_t>(L & 0xff));
        put(li, "HPKE-v1"); put(li, suite_id); put(li, label); put(li, info);
        return hkdf_expand(kdf, prk, li, L);
    }

    // ── X25519 KEM primitives ─────────────────────────────────────────────────
    static SecureBuffer x25519_pk(std::span<const uint8_t> sk) {
        SecureBuffer pk(NPK);
        crypto_scalarmult_base(pk.data(), sk.data());
        return pk;
    }
    static Result<SecureBuffer> dh(std::span<const uint8_t> sk, std::span<const uint8_t> pk) {
        return asymmetric::X25519::shared_secret(sk, pk); // rejects low-order (all-zero) result
    }
    static SecureBuffer extract_and_expand(std::span<const uint8_t> dh_bytes,
                                           std::span<const uint8_t> kem_context) {
        auto sid = kem_suite_id();
        auto eae_prk = labeled_extract(Kdf::HkdfSha256, sid, {}, "eae_prk", dh_bytes);
        return std::move(labeled_expand(Kdf::HkdfSha256, sid, eae_prk.span(), "shared_secret",
                                        kem_context, NSECRET).value());
    }

    // Encap (mode Base/PSK) or AuthEncap (mode Auth/AuthPSK). enc = ephemeral pk.
    static Result<std::pair<SecureBuffer, SecureBuffer>>
    encap(std::span<const uint8_t> pkR, std::span<const uint8_t> skS_or_empty,
          std::span<const uint8_t> skE) {
        SecureBuffer pkE = x25519_pk(skE);
        auto dh1 = dh(skE, pkR);
        if (dh1.is_err()) return Result<std::pair<SecureBuffer, SecureBuffer>>::err(dh1.error().message);

        std::vector<uint8_t> dh_bytes(dh1.value().span().begin(), dh1.value().span().end());
        std::vector<uint8_t> kem_context(pkE.span().begin(), pkE.span().end());
        kem_context.insert(kem_context.end(), pkR.begin(), pkR.end());

        if (!skS_or_empty.empty()) { // AuthEncap
            auto dh2 = dh(skS_or_empty, pkR);
            if (dh2.is_err()) return Result<std::pair<SecureBuffer, SecureBuffer>>::err(dh2.error().message);
            dh_bytes.insert(dh_bytes.end(), dh2.value().span().begin(), dh2.value().span().end());
            SecureBuffer pkS = x25519_pk(skS_or_empty);
            kem_context.insert(kem_context.end(), pkS.span().begin(), pkS.span().end());
        }
        SecureBuffer shared = extract_and_expand(dh_bytes, kem_context);
        return Result<std::pair<SecureBuffer, SecureBuffer>>::ok({ std::move(shared), std::move(pkE) });
    }

    // Decap (Base/PSK) or AuthDecap (Auth/AuthPSK).
    static Result<SecureBuffer>
    decap(std::span<const uint8_t> enc, std::span<const uint8_t> skR,
          std::span<const uint8_t> pkS_or_empty) {
        auto dh1 = dh(skR, enc);
        if (dh1.is_err()) return Result<SecureBuffer>::err(dh1.error().message);
        std::vector<uint8_t> dh_bytes(dh1.value().span().begin(), dh1.value().span().end());
        SecureBuffer pkR = x25519_pk(skR);
        std::vector<uint8_t> kem_context(enc.begin(), enc.end());
        kem_context.insert(kem_context.end(), pkR.span().begin(), pkR.span().end());

        if (!pkS_or_empty.empty()) { // AuthDecap
            auto dh2 = dh(skR, pkS_or_empty);
            if (dh2.is_err()) return Result<SecureBuffer>::err(dh2.error().message);
            dh_bytes.insert(dh_bytes.end(), dh2.value().span().begin(), dh2.value().span().end());
            kem_context.insert(kem_context.end(), pkS_or_empty.begin(), pkS_or_empty.end());
        }
        return Result<SecureBuffer>::ok(extract_and_expand(dh_bytes, kem_context));
    }

    // ── Key schedule (RFC 9180 §5.1) → Context ────────────────────────────────
    static Result<Context> key_schedule(Mode mode, Kdf kdf, Aead aead,
                                        std::span<const uint8_t> shared_secret,
                                        std::span<const uint8_t> info,
                                        std::span<const uint8_t> psk,
                                        std::span<const uint8_t> psk_id) {
        // VerifyPSKInputs: PSK and PSK-id must be jointly present or absent.
        bool got_psk = !psk.empty(), got_id = !psk_id.empty();
        if (got_psk != got_id)
            return Result<Context>::err("HPKE: PSK and PSK-id must both be set or both empty");
        bool mode_needs_psk = (mode == Mode::Psk || mode == Mode::AuthPsk);
        if (mode_needs_psk != got_psk)
            return Result<Context>::err("HPKE: PSK presence does not match the mode");

        auto suite_id = hpke_suite_id(kdf, aead);
        auto psk_id_hash = labeled_extract(kdf, suite_id, {}, "psk_id_hash", psk_id);
        auto info_hash   = labeled_extract(kdf, suite_id, {}, "info_hash", info);

        std::vector<uint8_t> ksc;
        ksc.push_back(static_cast<uint8_t>(mode));
        put(ksc, psk_id_hash.span());
        put(ksc, info_hash.span());

        auto secret = labeled_extract(kdf, suite_id, shared_secret, "secret", psk);

        SecureBuffer key, base_nonce;
        std::size_t Nk = aead_Nk(aead), Nn = aead_Nn(aead);
        if (aead != Aead::ExportOnly) {
            auto k = labeled_expand(kdf, suite_id, secret.span(), "key", ksc, Nk);
            if (k.is_err()) return Result<Context>::err(k.error().message);
            auto bn = labeled_expand(kdf, suite_id, secret.span(), "base_nonce", ksc, Nn);
            if (bn.is_err()) return Result<Context>::err(bn.error().message);
            key = std::move(k.value());
            base_nonce = std::move(bn.value());
        }
        auto exp = labeled_expand(kdf, suite_id, secret.span(), "exp", ksc, kdf_Nh(kdf));
        if (exp.is_err()) return Result<Context>::err(exp.error().message);

        return Result<Context>::ok(Context(kdf, aead, std::move(suite_id),
                                           std::move(key), std::move(base_nonce), std::move(exp.value())));
    }

    static Result<SenderContext>
    setup_s(Mode mode, Kdf kdf, Aead aead, std::span<const uint8_t> pkR, std::span<const uint8_t> info,
            std::span<const uint8_t> psk, std::span<const uint8_t> psk_id,
            std::span<const uint8_t> skS, std::span<const uint8_t> skE_opt) {
        SecureBuffer skE_owned;
        std::span<const uint8_t> skE = skE_opt;
        if (skE.empty()) {
            skE_owned = SecureBuffer(NSK);
            randombytes_buf(skE_owned.data(), NSK);
            skE = skE_owned.span();
        }
        auto e = encap(pkR, skS, skE);
        if (e.is_err()) return Result<SenderContext>::err(e.error().message);
        auto& [shared, enc] = e.value();
        auto ctx = key_schedule(mode, kdf, aead, shared.span(), info, psk, psk_id);
        if (ctx.is_err()) return Result<SenderContext>::err(ctx.error().message);
        return Result<SenderContext>::ok(SenderContext{ std::move(enc), std::move(ctx.value()) });
    }

    static Result<Context>
    setup_r(Mode mode, Kdf kdf, Aead aead, std::span<const uint8_t> enc, std::span<const uint8_t> skR,
            std::span<const uint8_t> info, std::span<const uint8_t> psk, std::span<const uint8_t> psk_id,
            std::span<const uint8_t> pkS) {
        auto shared = decap(enc, skR, pkS);
        if (shared.is_err()) return Result<Context>::err(shared.error().message);
        return key_schedule(mode, kdf, aead, shared.value().span(), info, psk, psk_id);
    }

    // ── AEAD (RFC 9180 §7.3) ──────────────────────────────────────────────────
    static std::size_t aead_Nk(Aead a) {
        switch (a) {
            case Aead::Aes128Gcm: return 16;
            case Aead::Aes256Gcm: return 32;
            case Aead::ChaCha20Poly1305: return 32;
            default: return 0;
        }
    }
    static std::size_t aead_Nn(Aead a) { return a == Aead::ExportOnly ? 0 : 12; }
    static constexpr std::size_t AEAD_TAG = 16;

    static Result<SecureBuffer> aead_seal(Aead aead, std::span<const uint8_t> key,
                                          std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                          std::span<const uint8_t> pt) {
        if (aead == Aead::ChaCha20Poly1305) {
            SecureBuffer ct(pt.size() + AEAD_TAG);
            unsigned long long clen = 0;
            if (crypto_aead_chacha20poly1305_ietf_encrypt(
                    ct.data(), &clen, pt.data(), pt.size(),
                    aad.data(), aad.size(), nullptr, nonce.data(), key.data()) != 0)
                return Result<SecureBuffer>::err("HPKE: ChaCha20Poly1305 seal failed");
            return Result<SecureBuffer>::ok(std::move(ct));
        }
        return aes_gcm(aead, true, key, nonce, aad, pt);
    }

    static Result<SecureBuffer> aead_open(Aead aead, std::span<const uint8_t> key,
                                          std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                          std::span<const uint8_t> ct) {
        if (ct.size() < AEAD_TAG) return Result<SecureBuffer>::err("HPKE: ciphertext too short");
        if (aead == Aead::ChaCha20Poly1305) {
            SecureBuffer pt(ct.size() - AEAD_TAG);
            unsigned long long mlen = 0;
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    pt.data(), &mlen, nullptr, ct.data(), ct.size(),
                    aad.data(), aad.size(), nonce.data(), key.data()) != 0)
                return Result<SecureBuffer>::err("HPKE: ChaCha20Poly1305 open failed (auth)");
            return Result<SecureBuffer>::ok(std::move(pt));
        }
        return aes_gcm(aead, false, key, nonce, aad, ct);
    }

#ifdef CRYPTOLIB_HAS_OPENSSL
    static Result<SecureBuffer> aes_gcm(Aead aead, bool encrypt, std::span<const uint8_t> key,
                                        std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                        std::span<const uint8_t> in) {
        const char* alg = aead == Aead::Aes128Gcm ? "AES-128-GCM" : "AES-256-GCM";
        struct CipherFree { void operator()(EVP_CIPHER* c) const { if (c) EVP_CIPHER_free(c); } };
        struct CtxFree { void operator()(EVP_CIPHER_CTX* c) const { if (c) EVP_CIPHER_CTX_free(c); } };
        std::unique_ptr<EVP_CIPHER, CipherFree> cipher{ EVP_CIPHER_fetch(nullptr, alg, nullptr) };
        std::unique_ptr<EVP_CIPHER_CTX, CtxFree> ctx{ EVP_CIPHER_CTX_new() };
        if (!cipher || !ctx) return Result<SecureBuffer>::err("HPKE: OpenSSL AES-GCM init failed");

        int len = 0;
        if (encrypt) {
            SecureBuffer out(in.size() + AEAD_TAG);
            if (EVP_EncryptInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
                EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data(), nonce.data(), nullptr) != 1)
                return Result<SecureBuffer>::err("HPKE: AES-GCM encrypt init failed");
            if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
                return Result<SecureBuffer>::err("HPKE: AES-GCM aad failed");
            if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, in.data(), static_cast<int>(in.size())) != 1)
                return Result<SecureBuffer>::err("HPKE: AES-GCM encrypt failed");
            int final_len = 0;
            if (EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &final_len) != 1)
                return Result<SecureBuffer>::err("HPKE: AES-GCM encrypt final failed");
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, AEAD_TAG, out.data() + in.size()) != 1)
                return Result<SecureBuffer>::err("HPKE: AES-GCM get tag failed");
            return Result<SecureBuffer>::ok(std::move(out));
        }
        // decrypt: in = ciphertext || tag
        const std::size_t ct_len = in.size() - AEAD_TAG;
        SecureBuffer out(ct_len);
        if (EVP_DecryptInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex2(ctx.get(), nullptr, key.data(), nonce.data(), nullptr) != 1)
            return Result<SecureBuffer>::err("HPKE: AES-GCM decrypt init failed");
        if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            return Result<SecureBuffer>::err("HPKE: AES-GCM aad failed");
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, in.data(), static_cast<int>(ct_len)) != 1)
            return Result<SecureBuffer>::err("HPKE: AES-GCM decrypt failed");
        uint8_t tag[AEAD_TAG];
        std::memcpy(tag, in.data() + ct_len, AEAD_TAG);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, AEAD_TAG, tag) != 1)
            return Result<SecureBuffer>::err("HPKE: AES-GCM set tag failed");
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &final_len) != 1)
            return Result<SecureBuffer>::err("HPKE: AES-GCM open failed (auth)");
        return Result<SecureBuffer>::ok(std::move(out));
    }
#else
    static Result<SecureBuffer> aes_gcm(Aead, bool, std::span<const uint8_t>, std::span<const uint8_t>,
                                        std::span<const uint8_t>, std::span<const uint8_t>) {
        return Result<SecureBuffer>::err("HPKE: AES-GCM requires OpenSSL (build with CRYPTOLIB_HAS_OPENSSL)");
    }
#endif
};

} // namespace crypto
