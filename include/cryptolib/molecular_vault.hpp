#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// MolecularVault — maximum-assurance layered encryption.
//
// This is COMPOSITION of existing, individually-vetted primitives. It invents no
// new cryptography. It exists to raise the *practical* cost of decryption to the
// theoretical maximum this library can offer, defending against:
//
//   • password guessing        → Argon2id, memory-hard, caller-tunable to GiBs
//   • a single-cipher break     → cascade of two independent AEADs with
//                                 independent keys (AES-256-GCM-SIV ∘ XChaCha20)
//   • future quantum attackers  → keys may be agreed via the X25519+ML-KEM-768
//                                 hybrid KEM (harvest-now-decrypt-later defense)
//   • key/context confusion     → key-committing outer layer (UtC), so a
//                                 ciphertext binds to exactly one key
//   • tampering                 → every layer is authenticated (fails closed)
//
// Honest scope: none of this helps if the master key or passphrase leaks. Brute
// force against the *keys* is already infeasible (256-bit); the layers remove
// single points of failure and make password-derived keys expensive to attack.
//
// Wire format (self-describing, versioned):
//   magic "MVLT" | ver(1) | mode(1) | argon_ops(8 LE) | argon_mem(8 LE) |
//   salt(16) | inner_ciphertext
// where inner_ciphertext = CommittingAead( AesGcmSiv( XChaCha20( plaintext ) ) )
// bound to the AAD at every layer.
// ─────────────────────────────────────────────────────────────────────────────
#include "types.hpp"
#include "symmetric.hpp"
#include "committing.hpp"
#include "aead_siv.hpp"
#include "hash.hpp"

#include <array>
#include <cstring>
#include <sodium.h>

// The cascade's middle layer is AES-256-GCM-SIV, which requires OpenSSL. When
// OpenSSL is not compiled in, MolecularVault is simply absent (callers gate on
// its presence exactly as they do for the SIV AEAD).
#ifdef CRYPTOLIB_HAS_OPENSSL

namespace crypto {

// The composed primitives live in sub-namespaces; bring them into scope.
using hash::Argon2id;
using hash::HkdfSha256;
using symmetric::XChaCha20Poly1305;
using symmetric::Aes256GcmSiv;
using symmetric::CommittingAead;

class MolecularVault {
public:
    static constexpr std::array<uint8_t, 4> MAGIC = {'M', 'V', 'L', 'T'};
    static constexpr uint8_t  VERSION   = 1;
    static constexpr std::size_t SALT_BYTES = Argon2id::SALT_BYTES; // 16
    static constexpr std::string_view HKDF_INFO = "cryptolib/molecular-vault/v1";

    // Argon2id work factor. Defaults to libsodium's SENSITIVE preset; callers
    // handling high-value secrets should push mem toward 1–4 GiB. Higher = each
    // password guess costs more time AND memory, which is the only lever that
    // slows a well-funded brute-force attacker.
    struct KdfParams {
        unsigned long long ops = crypto_pwhash_OPSLIMIT_SENSITIVE;
        std::size_t        mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
    };

    // ── Passphrase mode ─────────────────────────────────────────────────────
    // Seal plaintext under a passphrase. The master key is derived with
    // Argon2id(params) over a fresh random salt, then split via HKDF into two
    // independent AEAD keys for the cascade. Everything needed to open (salt,
    // Argon2id params) travels in the header; only the passphrase is secret.
    [[nodiscard]] static Result<SecureBuffer>
    seal(std::span<const uint8_t> plaintext,
         std::string_view         passphrase,
         std::span<const uint8_t> aad     = {},
         KdfParams                params  = KdfParams{crypto_pwhash_OPSLIMIT_SENSITIVE,
                                                      crypto_pwhash_MEMLIMIT_SENSITIVE}) {
        if (passphrase.empty())
            return Result<SecureBuffer>::err("MolecularVault: passphrase must not be empty");

        // Fresh salt per seal — never reused.
        std::array<uint8_t, SALT_BYTES> salt{};
        randombytes_buf(salt.data(), salt.size());

        auto master = Argon2id::derive_key(passphrase, salt, 32, params.ops, params.mem);
        if (master.is_err()) return Result<SecureBuffer>::err(master.error().message);

        auto inner = seal_with_master(plaintext, master.value().span(), aad);
        if (inner.is_err()) return inner;

        return frame(salt, params, inner.value().span());
    }

    // Open a passphrase-sealed envelope. AAD must match exactly.
    [[nodiscard]] static Result<SecureBuffer>
    open(std::span<const uint8_t> envelope,
         std::string_view         passphrase,
         std::span<const uint8_t> aad = {}) {
        std::array<uint8_t, SALT_BYTES> salt{};
        KdfParams params;
        std::span<const uint8_t> inner;
        if (auto e = unframe(envelope, salt, params, inner); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);

        auto master = Argon2id::derive_key(passphrase, salt, 32, params.ops, params.mem);
        if (master.is_err()) return Result<SecureBuffer>::err(master.error().message);

        return open_with_master(inner, master.value().span(), aad);
    }

    // ── Raw-key mode ────────────────────────────────────────────────────────
    // Seal/open under a caller-supplied 32-byte master key (e.g. one agreed via
    // the hybrid KEM, or a high-entropy random key). No Argon2id is applied; the
    // key is expected to already be full-entropy. The header records ops=mem=0.
    [[nodiscard]] static Result<SecureBuffer>
    seal_with_key(std::span<const uint8_t> plaintext,
                  std::span<const uint8_t> master_key,
                  std::span<const uint8_t> aad = {}) {
        if (master_key.size() != 32)
            return Result<SecureBuffer>::err("MolecularVault: master key must be 32 bytes");
        std::array<uint8_t, SALT_BYTES> salt{}; // zero salt = raw-key marker
        auto inner = seal_with_master(plaintext, master_key, aad);
        if (inner.is_err()) return inner;
        return frame(salt, KdfParams{0, 0}, inner.value().span());
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_with_key(std::span<const uint8_t> envelope,
                  std::span<const uint8_t> master_key,
                  std::span<const uint8_t> aad = {}) {
        if (master_key.size() != 32)
            return Result<SecureBuffer>::err("MolecularVault: master key must be 32 bytes");
        std::array<uint8_t, SALT_BYTES> salt{};
        KdfParams params;
        std::span<const uint8_t> inner;
        if (auto e = unframe(envelope, salt, params, inner); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);
        return open_with_master(inner, master_key, aad);
    }

    // AES-256-GCM-SIV requires OpenSSL (CRYPTOLIB_HAS_OPENSSL). Callers can check
    // before choosing MolecularVault so failures are surfaced early, not at seal.
    [[nodiscard]] static bool is_available() noexcept {
        return Aes256GcmSiv::is_available();
    }

private:
    // Split a 32-byte master into two independent 32-byte AEAD keys via HKDF.
    // Distinct info labels domain-separate the cascade layers.
    [[nodiscard]] static Result<std::pair<SecureBuffer, SecureBuffer>>
    split_keys(std::span<const uint8_t> master) {
        // extract with an empty salt (master is already high-entropy / KDF'd)
        auto prk = HkdfSha256::extract({}, master);
        if (prk.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(prk.error().message);

        static constexpr std::string_view I1 = "cryptolib/mv/layer1-xchacha";
        static constexpr std::string_view I2 = "cryptolib/mv/layer2-gcmsiv";
        auto k1 = HkdfSha256::expand(prk.value().span(),
            {reinterpret_cast<const uint8_t*>(I1.data()), I1.size()}, 32);
        if (k1.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(k1.error().message);
        auto k2 = HkdfSha256::expand(prk.value().span(),
            {reinterpret_cast<const uint8_t*>(I2.data()), I2.size()}, 32);
        if (k2.is_err())
            return Result<std::pair<SecureBuffer, SecureBuffer>>::err(k2.error().message);

        return Result<std::pair<SecureBuffer, SecureBuffer>>::ok(
            std::make_pair(std::move(k1.value()), std::move(k2.value())));
    }

    // Cascade: XChaCha20-Poly1305 (inner) → AES-256-GCM-SIV (middle) →
    // key-committing AEAD (outer). Each layer authenticates the same AAD, so
    // tampering at any level fails closed. Independent keys mean a break of one
    // cipher does not expose the plaintext.
    [[nodiscard]] static Result<SecureBuffer>
    seal_with_master(std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> master,
                     std::span<const uint8_t> aad) {
        auto keys = split_keys(master);
        if (keys.is_err()) return Result<SecureBuffer>::err(keys.error().message);
        const auto& [k1, k2] = keys.value();

        auto l1 = XChaCha20Poly1305::encrypt(plaintext, k1.span(), aad);
        if (l1.is_err()) return l1;
        auto l2 = Aes256GcmSiv::encrypt(l1.value().span(), k2.span(), aad);
        if (l2.is_err()) return l2;
        // Outer committing layer keyed by the master itself (binds ciphertext to key).
        return CommittingAead::encrypt(l2.value().span(), master, aad);
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_with_master(std::span<const uint8_t> inner,
                     std::span<const uint8_t> master,
                     std::span<const uint8_t> aad) {
        auto keys = split_keys(master);
        if (keys.is_err()) return Result<SecureBuffer>::err(keys.error().message);
        const auto& [k1, k2] = keys.value();

        auto o = CommittingAead::decrypt(inner, master, aad);
        if (o.is_err()) return o;
        auto m = Aes256GcmSiv::decrypt(o.value().span(), k2.span(), aad);
        if (m.is_err()) return m;
        return XChaCha20Poly1305::decrypt(m.value().span(), k1.span(), aad);
    }

    // ── Framing ─────────────────────────────────────────────────────────────
    static void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
        for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
    static uint64_t get_u64_le(const uint8_t* p) {
        uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= static_cast<uint64_t>(p[i]) << (8 * i);
        return x;
    }

    [[nodiscard]] static Result<SecureBuffer>
    frame(const std::array<uint8_t, SALT_BYTES>& salt,
          KdfParams params, std::span<const uint8_t> inner) {
        std::vector<uint8_t> out;
        out.reserve(4 + 1 + 1 + 8 + 8 + SALT_BYTES + inner.size());
        out.insert(out.end(), MAGIC.begin(), MAGIC.end());
        out.push_back(VERSION);
        out.push_back(0); // reserved mode byte
        put_u64_le(out, params.ops);
        put_u64_le(out, static_cast<uint64_t>(params.mem));
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), inner.begin(), inner.end());
        return Result<SecureBuffer>::ok(SecureBuffer(std::move(out)));
    }

    [[nodiscard]] static Result<void>
    unframe(std::span<const uint8_t> env,
            std::array<uint8_t, SALT_BYTES>& salt,
            KdfParams& params, std::span<const uint8_t>& inner) {
        constexpr std::size_t HDR = 4 + 1 + 1 + 8 + 8 + SALT_BYTES;
        if (env.size() < HDR)
            return Result<void>::err("MolecularVault: envelope too short");
        if (std::memcmp(env.data(), MAGIC.data(), MAGIC.size()) != 0)
            return Result<void>::err("MolecularVault: bad magic");
        if (env[4] != VERSION)
            return Result<void>::err("MolecularVault: unsupported version");
        params.ops = get_u64_le(env.data() + 6);
        params.mem = static_cast<std::size_t>(get_u64_le(env.data() + 14));
        std::memcpy(salt.data(), env.data() + 22, SALT_BYTES);
        inner = env.subspan(HDR);
        return Result<void>::ok();
    }
};

} // namespace crypto

#endif // CRYPTOLIB_HAS_OPENSSL
