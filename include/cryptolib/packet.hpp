#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::EncryptedPacket  /  crypto::KdfParams                           ║
 * ║                                                                            ║
 * ║  Minimal types shared between vault.hpp and steganography.hpp.            ║
 * ║  Extracted to break the circular include chain so that vault.hpp can      ║
 * ║  include steganography.hpp (to add native stego methods) without          ║
 * ║  steganography.hpp needing to re-include vault.hpp.                       ║
 * ║                                                                            ║
 * ║  EncryptedPacket — the complete sealed output of any vault operation.     ║
 * ║    Fields:  ciphertext  (nonce + ciphertext + Poly1305 MAC)               ║
 * ║             signature   (Ed25519 over ciphertext, 64 bytes)               ║
 * ║             kdf_salt    (Argon2id salt, 16 bytes — not secret)            ║
 * ║                                                                            ║
 * ║  KdfParams — Argon2id memory-hardness tuning.                             ║
 * ║    INTERACTIVE: ~0.5s, 64 MiB   — file encryption, session keys          ║
 * ║    SENSITIVE  : ~2.0s, 256 MiB  — master key protection                  ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <span>

namespace crypto {

// ─────────────────────────────────────────────────────────────────────────────
// EncryptedPacket — the sealed output of every vault operation.
// All three fields must travel together; none can be reconstructed separately.
// Wire format (serialise / deserialise): [salt_len(1) | salt | sig_len(1) | sig | ct]
// ─────────────────────────────────────────────────────────────────────────────
struct EncryptedPacket {
    SecureBuffer ciphertext;   // nonce(24) + enc[plain ‖ tag] + MAC(16)
    SecureBuffer signature;    // Ed25519 signature over ciphertext (64 B)
    SecureBuffer kdf_salt;     // Argon2id salt (16 B) — not secret

    /// Serialise to a flat byte buffer for transport or embedding.
    [[nodiscard]] SecureBuffer serialise() const {
        const std::size_t total =
            1 + kdf_salt.size()  +
            1 + signature.size() +
            ciphertext.size();

        SecureBuffer out(total);
        uint8_t* p = out.data();

        *p++ = static_cast<uint8_t>(kdf_salt.size());
        std::memcpy(p, kdf_salt.data(), kdf_salt.size());
        p += kdf_salt.size();

        *p++ = static_cast<uint8_t>(signature.size());
        std::memcpy(p, signature.data(), signature.size());
        p += signature.size();

        std::memcpy(p, ciphertext.data(), ciphertext.size());
        return out;
    }

    /// Deserialise from a flat byte buffer.
    [[nodiscard]] static Result<EncryptedPacket>
    deserialise(std::span<const uint8_t> raw) {
        const uint8_t* p   = raw.data();
        const uint8_t* end = raw.data() + raw.size();

        // Check a byte is available before each length prefix and that the
        // declared field fits in the remaining bytes. Comparisons use the
        // remaining count (end - p) rather than p + len, which would be
        // undefined behaviour if the pointer arithmetic overflowed on a crafted
        // length. Untrusted input: this is the decrypt-path entry point.
        if (p >= end)
            return Result<EncryptedPacket>::err("Packet too short");
        std::size_t salt_len = *p++;
        if (static_cast<std::size_t>(end - p) < salt_len)
            return Result<EncryptedPacket>::err("Truncated salt");
        SecureBuffer salt(p, salt_len); p += salt_len;

        if (p >= end)
            return Result<EncryptedPacket>::err("Truncated signature length");
        std::size_t sig_len = *p++;
        if (static_cast<std::size_t>(end - p) < sig_len)
            return Result<EncryptedPacket>::err("Truncated signature");
        SecureBuffer sig(p, sig_len); p += sig_len;

        SecureBuffer ct(p, static_cast<std::size_t>(end - p));

        return Result<EncryptedPacket>::ok(
            EncryptedPacket{ std::move(ct), std::move(sig), std::move(salt) });
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// KdfParams — Argon2id memory-hardness tuning knobs.
// ─────────────────────────────────────────────────────────────────────────────
struct KdfParams {
    unsigned long long opslimit;
    std::size_t        memlimit;

    static KdfParams interactive() {
        return { crypto_pwhash_OPSLIMIT_INTERACTIVE,
                 crypto_pwhash_MEMLIMIT_INTERACTIVE };
    }
    static KdfParams sensitive() {
        return { crypto_pwhash_OPSLIMIT_SENSITIVE,
                 crypto_pwhash_MEMLIMIT_SENSITIVE };
    }
    static KdfParams custom(unsigned long long ops, std::size_t mem) {
        // Enforce Argon2id minimums (libsodium rejects anything below these anyway,
        // but failing at KDF time gives a cryptic OOM error instead of a clear message).
        if (ops < crypto_pwhash_OPSLIMIT_MIN)
            ops = crypto_pwhash_OPSLIMIT_MIN;
        if (mem < crypto_pwhash_MEMLIMIT_MIN)
            mem = crypto_pwhash_MEMLIMIT_MIN;
        return { ops, mem };
    }
};

} // namespace crypto
