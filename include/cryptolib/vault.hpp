#pragma once

/**
 * CryptoLib — Full Proof of Concept
 *
 * Sections:
 *   A) Standalone primitives        — hash, symmetric, asymmetric
 *   B) Layered vault pipeline       — SecureVault / AsymmetricVault
 *   C) Media entropy layer          — photo / video / audio → keys
 *   D) End-to-end integration       — media entropy feeds the vault pipeline
 */

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLib — SecureVault                                                ║
 * ║                                                                          ║
 * ║  A layered encryption pipeline that chains unidirectional primitives    ║
 * ║  (hashing, KDF, signing) with bidirectional ones (AEAD encryption) to   ║
 * ║  form a single high-grade "lock".                                        ║
 * ║                                                                          ║
 * ║  ENCRYPT PIPELINE                                                        ║
 * ║  ─────────────────────────────────────────────────────────────────────  ║
 * ║  plaintext                                                               ║
 * ║    → [L1] Argon2id KDF (unidirectional)                                 ║
 * ║           Derives cipher key + MAC key from master key + random salt.   ║
 * ║           Optional: mix in MediaEntropy for LavaRand-style boost.       ║
 * ║           Memory-hard: brute force is computationally infeasible.       ║
 * ║    → [L2] BLAKE2b integrity tag (unidirectional)                        ║
 * ║           Keyed hash of plaintext. Detects internal corruption          ║
 * ║           even before the AEAD layer is checked.                        ║
 * ║    → [L3] XChaCha20-Poly1305 AEAD (bidirectional)                      ║
 * ║           Encrypts [plaintext ‖ integrity_tag] with a 192-bit nonce.   ║
 * ║           Provides confidentiality + authentication in one step.        ║
 * ║    → [L4] Ed25519 signature (unidirectional)                            ║
 * ║           Signs the final ciphertext. Proves authorship and prevents    ║
 * ║           any third party from forging or substituting the packet.      ║
 * ║    → EncryptedPacket { ciphertext, signature, kdf_salt }                ║
 * ║                                                                          ║
 * ║  DECRYPT PIPELINE (strict order — fail fast at every layer)             ║
 * ║  ─────────────────────────────────────────────────────────────────────  ║
 * ║  EncryptedPacket                                                         ║
 * ║    → [L4] Ed25519 verify (unidirectional)  — reject forgeries first    ║
 * ║    → [L1] Argon2id re-derive key (unidirectional)                       ║
 * ║    → [L3] XChaCha20 decrypt (bidirectional)                             ║
 * ║    → [L2] BLAKE2b integrity verify (unidirectional)                     ║
 * ║    → plaintext                                                           ║
 * ║                                                                          ║
 * ║  Each layer defends against a different attack class:                   ║
 * ║    L1 → brute-force / dictionary attacks on the key                     ║
 * ║    L2 → internal data corruption / partial decryption attacks           ║
 * ║    L3 → confidentiality breach / ciphertext tampering                   ║
 * ║    L4 → impersonation / packet forgery / replay attacks                 ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "packet.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace crypto {

// Forward-declare MediaEntropy so SecureVault and AsymmetricVault can declare
// from_entropy() without including media_entropy.hpp (which already includes
// vault.hpp).  The inline definitions live in media_entropy.hpp, after
// MediaEntropy is fully defined — the same deferred-definition pattern used
// for seal_into() / open_from().
namespace entropy { class MediaEntropy; }

// ─────────────────────────────────────────────────────────────────────────────
// VaultKeyPair — holds the signing identity (Ed25519) for the vault owner.
// The encryption key is derived on-the-fly from the master_key via Argon2id,
// so it never needs to be stored.
// ─────────────────────────────────────────────────────────────────────────────
struct VaultKeyPair {
    SecureBuffer sign_public;   // 32 bytes — share this to allow signature verification
    SecureBuffer sign_secret;   // 64 bytes — never share, never store in plain text
};

// EncryptedPacket and KdfParams are defined in packet.hpp (included above).

// ─────────────────────────────────────────────────────────────────────────────
// SecureVault — the unified pipeline.
//
// Usage pattern:
//
//   auto kp = SecureVault::generate_keypair();
//   SecureVault vault(master_key, kp);
//
//   auto packet = vault.seal("sensitive data", "optional context");
//   auto plain  = vault.open(packet.value(), "optional context");
//
// ─────────────────────────────────────────────────────────────────────────────
class SecureVault {
public:
    // Internal size constants (not part of the public API)
    static constexpr std::size_t KDF_SALT_BYTES    = crypto_pwhash_SALTBYTES;           // 16
    static constexpr std::size_t CIPHER_KEY_BYTES  = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
    static constexpr std::size_t MAC_KEY_BYTES     = crypto_generichash_KEYBYTES;       // 32
    static constexpr std::size_t INTEGRITY_BYTES   = crypto_generichash_BYTES_MAX;      // 64
    static constexpr std::size_t NONCE_BYTES       = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    static constexpr std::size_t AEAD_MAC_BYTES    = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16
    static constexpr std::size_t SIG_BYTES         = crypto_sign_BYTES;                 // 64

    // The KDF derives two keys at once: cipher key + MAC key for the integrity tag
    static constexpr std::size_t DERIVED_MATERIAL  = CIPHER_KEY_BYTES + MAC_KEY_BYTES;  // 64

    // ── Constructor ──────────────────────────────────────────────────────────
    // master_key: any secret bytes (password hash, device secret, HSM output…)
    // kp:         Ed25519 keypair for signing sealed packets
    // params:     Argon2id tuning (default: INTERACTIVE)
    explicit SecureVault(std::span<const uint8_t> master_key,
                         VaultKeyPair              kp,
                         KdfParams                 params = KdfParams::interactive())
        : master_key_(master_key.data(), master_key.size())
        , keypair_(std::move(kp))
        , kdf_params_(params)
    {}

    // ── Key generation ───────────────────────────────────────────────────────
    [[nodiscard]] static VaultKeyPair generate_keypair() {
        VaultKeyPair kp;
        kp.sign_public.resize(crypto_sign_PUBLICKEYBYTES);
        kp.sign_secret.resize(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(kp.sign_public.data(), kp.sign_secret.data());
        return kp;
    }

    // Deterministic keypair from a seed (useful for key backup / derivation)
    [[nodiscard]] static Result<VaultKeyPair>
    keypair_from_seed(std::span<const uint8_t> seed) {
        if (seed.size() != crypto_sign_SEEDBYTES)
            return Result<VaultKeyPair>::err("Seed must be 32 bytes");
        VaultKeyPair kp;
        kp.sign_public.resize(crypto_sign_PUBLICKEYBYTES);
        kp.sign_secret.resize(crypto_sign_SECRETKEYBYTES);
        crypto_sign_seed_keypair(kp.sign_public.data(), kp.sign_secret.data(), seed.data());
        return Result<VaultKeyPair>::ok(std::move(kp));
    }

    // ────────────────────────────────────────────────────────────────────────
    // seal() — encrypt + sign a message through all four layers.
    //
    // aad: optional associated data (e.g. user ID, session ID, file path).
    //      It is cryptographically bound to the packet — decryption will
    //      fail if a different aad is presented, preventing context-swap attacks.
    // ────────────────────────────────────────────────────────────────────────
    // ── seal ─────────────────────────────────────────────────────────────────
    // extra_entropy — optional LavaRand-style entropy boost (e.g. from
    //   MediaEntropy::entropy_boost()).  When supplied, it is mixed into the
    //   Argon2id password material so the derived key depends on BOTH the
    //   master key AND the external entropy source.  The same value must be
    //   passed to open() for decryption to succeed.
    //
    //   Use the MediaEntropy overload (declared below; defined in
    //   media_entropy.hpp) for ergonomic boost injection:
    //     vault.seal(plaintext, aad, media_entropy_object);
    [[nodiscard]] Result<EncryptedPacket>
    seal(std::span<const uint8_t> plaintext,
         std::span<const uint8_t> aad           = {},
         std::span<const uint8_t> extra_entropy  = {}) const {

        // ── L1: Argon2id — derive cipher key + MAC key ───────────────────
        SecureBuffer kdf_salt(KDF_SALT_BYTES);
        randombytes_buf(kdf_salt.data(), KDF_SALT_BYTES);

        auto derived = derive_keys(kdf_salt.span(), extra_entropy);
        if (derived.is_err()) return Result<EncryptedPacket>::err(derived.error().message);

        auto [cipher_key, mac_key] = split_derived(derived.value());

        // ── L2: BLAKE2b — keyed integrity tag over (plaintext ‖ aad) ──────
        SecureBuffer integrity_tag(INTEGRITY_BYTES);
        {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, mac_key.data(), mac_key.size(), INTEGRITY_BYTES);
            crypto_generichash_update(&gh, plaintext.data(), plaintext.size());
            if (!aad.empty())
                crypto_generichash_update(&gh, aad.data(), aad.size());
            crypto_generichash_final(&gh, integrity_tag.data(), INTEGRITY_BYTES);
        }

        // ── L3: XChaCha20-Poly1305 — encrypt [plaintext ‖ integrity_tag] ─
        // Build the message: plaintext concatenated with the integrity tag.
        // Use SecureBuffer so plaintext is zeroed when inner goes out of scope.
        SecureBuffer inner(plaintext.size() + INTEGRITY_BYTES);
        std::memcpy(inner.data(), plaintext.data(), plaintext.size());
        std::memcpy(inner.data() + plaintext.size(),
                    integrity_tag.data(), INTEGRITY_BYTES);

        SecureBuffer ciphertext(NONCE_BYTES + inner.size() + AEAD_MAC_BYTES);
        uint8_t* nonce_ptr = ciphertext.data();
        randombytes_buf(nonce_ptr, NONCE_BYTES);

        unsigned long long ct_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.data() + NONCE_BYTES, &ct_len,
                inner.data(), inner.size(),
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nullptr, nonce_ptr, cipher_key.data()) != 0)
            return Result<EncryptedPacket>::err("AEAD encryption failed");

        ciphertext.resize(NONCE_BYTES + static_cast<std::size_t>(ct_len));

        // ── L4: Ed25519 — sign the ciphertext (sign-then-encrypt output) ─
        SecureBuffer signature(SIG_BYTES);
        unsigned long long sig_len = 0;
        crypto_sign_detached(
            signature.data(), &sig_len,
            ciphertext.data(), ciphertext.size(),
            keypair_.sign_secret.data());
        signature.resize(static_cast<std::size_t>(sig_len));

        return Result<EncryptedPacket>::ok(
            EncryptedPacket{ std::move(ciphertext), std::move(signature), std::move(kdf_salt) });
    }

    // Convenience: string / string_view overload (no entropy boost)
    [[nodiscard]] Result<EncryptedPacket>
    seal(std::string_view plaintext, std::string_view aad = {}) const {
        return seal(
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size() },
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
            std::span<const uint8_t>{});
    }

    // MediaEntropy boost overload — declared here, defined in media_entropy.hpp
    // after MediaEntropy is fully visible.
    [[nodiscard]] Result<EncryptedPacket>
    seal(std::span<const uint8_t>        plaintext,
         std::span<const uint8_t>        aad,
         const entropy::MediaEntropy&    boost) const;

    [[nodiscard]] Result<EncryptedPacket>
    seal(std::string_view                plaintext,
         std::string_view               aad,
         const entropy::MediaEntropy&    boost) const;

    // ────────────────────────────────────────────────────────────────────────
    // open() — verify + decrypt through all four layers (strict fail-fast).
    //
    // verifier_public_key: the signer's Ed25519 public key.
    //   If you are opening your own packets, pass keypair_.sign_public.span().
    //   If opening packets from another party, pass their public key.
    // ────────────────────────────────────────────────────────────────────────
    // extra_entropy must be identical to the value passed to seal().
    // If seal() was called without extra_entropy, open() must also omit it (or
    // pass {}).  Mismatch produces a wrong key — decryption will fail at L3.
    [[nodiscard]] Result<SecureBuffer>
    open(const EncryptedPacket&      packet,
         std::span<const uint8_t>    verifier_public_key,
         std::span<const uint8_t>    aad            = {},
         std::span<const uint8_t>    extra_entropy  = {}) const {

        // ── L4: Ed25519 verify — reject forgeries immediately ────────────
        if (verifier_public_key.size() != crypto_sign_PUBLICKEYBYTES)
            return Result<SecureBuffer>::err("Invalid public key length");

        if (crypto_sign_verify_detached(
                packet.signature.data(),
                packet.ciphertext.data(), packet.ciphertext.size(),
                verifier_public_key.data()) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        // ── L1: Argon2id — re-derive the same cipher key + MAC key ───────
        auto derived = derive_keys(packet.kdf_salt.span(), extra_entropy);
        if (derived.is_err()) return Result<SecureBuffer>::err(derived.error().message);

        auto [cipher_key, mac_key] = split_derived(derived.value());

        // ── L3: XChaCha20 — decrypt [plaintext ‖ integrity_tag] ──────────
        if (packet.ciphertext.size() <= NONCE_BYTES + AEAD_MAC_BYTES)
            return Result<SecureBuffer>::err("Vault: decryption failed — invalid packet");

        const uint8_t* nonce_ptr = packet.ciphertext.data();
        const uint8_t* ct_ptr    = packet.ciphertext.data() + NONCE_BYTES;
        std::size_t    ct_len    = packet.ciphertext.size() - NONCE_BYTES;

        SecureBuffer inner(ct_len - AEAD_MAC_BYTES);
        unsigned long long pt_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                inner.data(), &pt_len,
                nullptr,
                ct_ptr, ct_len,
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nonce_ptr, cipher_key.data()) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        inner.resize(static_cast<std::size_t>(pt_len));

        // Split inner back into plaintext and integrity tag
        if (inner.size() < INTEGRITY_BYTES)
            return Result<SecureBuffer>::err("Vault: decryption failed — invalid packet");

        const std::size_t pt_size = inner.size() - INTEGRITY_BYTES;
        const uint8_t*    pt_data = inner.data();
        const uint8_t*    tag_data = inner.data() + pt_size;

        // ── L2: BLAKE2b — verify integrity tag ───────────────────────────
        SecureBuffer expected_tag(INTEGRITY_BYTES);
        {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, mac_key.data(), mac_key.size(), INTEGRITY_BYTES);
            crypto_generichash_update(&gh, pt_data, pt_size);
            if (!aad.empty())
                crypto_generichash_update(&gh, aad.data(), aad.size());
            crypto_generichash_final(&gh, expected_tag.data(), INTEGRITY_BYTES);
        }

        if (sodium_memcmp(expected_tag.data(), tag_data, INTEGRITY_BYTES) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        // All layers passed — return the plaintext
        SecureBuffer plaintext(pt_data, pt_size);
        return Result<SecureBuffer>::ok(std::move(plaintext));
    }

    // Convenience: open your own packets (self-verification, no entropy boost)
    [[nodiscard]] Result<SecureBuffer>
    open(const EncryptedPacket& packet, std::string_view aad = {}) const {
        return open(
            packet,
            keypair_.sign_public.span(),
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
            std::span<const uint8_t>{});
    }

    // MediaEntropy boost overload — declared here, defined in media_entropy.hpp
    [[nodiscard]] Result<SecureBuffer>
    open(const EncryptedPacket&         packet,
         std::span<const uint8_t>       verifier_public_key,
         std::span<const uint8_t>       aad,
         const entropy::MediaEntropy&   boost) const;

    [[nodiscard]] Result<SecureBuffer>
    open(const EncryptedPacket&         packet,
         std::string_view               aad,
         const entropy::MediaEntropy&   boost) const;

    // ─────────────────────────────────────────────────────────────────────────
    // Steganography integration — native seal-into-media and open-from-media.
    //
    // Fuses the 4-layer vault pipeline with steganographic embedding:
    //   encrypt (content hidden) → embed in carrier (existence hidden).
    //
    // seal_into — seal plaintext and hide the packet inside a carrier file.
    //   cover_path   source media (.ppm / .wav / .crvf)
    //   plaintext    message to encrypt
    //   output_path  stego output file (same format as cover)
    //   aad          optional additional authenticated data
    //
    // open_from — extract the hidden packet and decrypt it.
    //   stego_path   stego media file produced by seal_into()
    //   aad          must match the aad used in seal_into()
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] Result<void>
    seal_into(std::string_view cover_path,
              std::string_view plaintext,
              std::string_view output_path,
              std::string_view aad = {}) const;

    [[nodiscard]] Result<SecureBuffer>
    open_from(std::string_view stego_path,
              std::string_view aad = {}) const;

    // ─────────────────────────────────────────────────────────────────────────
    // Media entropy integration — construct a vault seeded by physical entropy.
    //
    // from_entropy() is the named construction path for entropy-seeded vaults.
    // It is the symmetric counterpart to the random-key constructor:
    //
    //   // random key (default path)
    //   auto vault = SecureVault(crypto::random_bytes(32), kp);
    //
    //   // entropy-seeded (LavaRand path)
    //   auto vault = SecureVault::from_entropy(me).value();
    //
    // The key material (master key + Ed25519 keypair) is derived deterministically
    // from the MediaEntropy object.  System entropy is mixed at from_file() time,
    // not here — see MediaEntropy for the LavaRand defence-in-depth guarantee.
    //
    // Definition is in media_entropy.hpp (after MediaEntropy is fully defined).
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<SecureVault>
    from_entropy(const entropy::MediaEntropy& source,
                 KdfParams params = KdfParams::interactive());

    // ── Accessors ────────────────────────────────────────────────────────────
    [[nodiscard]] std::span<const uint8_t> public_key() const noexcept {
        return keypair_.sign_public.span();
    }

private:
    // ── Internal: derive 64 bytes of key material via Argon2id ─────────────
    //
    // extra_entropy: optional LavaRand-style boost mixed into the password
    //   material before Argon2id.  When provided:
    //     effective_pw = BLAKE2b( master_key ‖ extra_entropy )
    //   This makes the derived key depend on BOTH the master key AND the media
    //   source — a compromised master key alone is not sufficient if the caller
    //   also supplied entropy boost.  The same extra_entropy must be passed to
    //   open() for the round-trip to succeed.
    [[nodiscard]] Result<SecureBuffer>
    derive_keys(std::span<const uint8_t> salt,
                std::span<const uint8_t> extra_entropy = {}) const {
        if (salt.size() != KDF_SALT_BYTES)
            return Result<SecureBuffer>::err("KDF salt wrong size");

        // Mix extra entropy into password material when provided.
        // We hash into a fixed 32-byte buffer so Argon2id always sees the same
        // input size regardless of how large the entropy source is.
        SecureBuffer pw_buf;
        const char*   pw_ptr;
        std::size_t   pw_len;

        if (!extra_entropy.empty()) {
            pw_buf.resize(CIPHER_KEY_BYTES);   // 32 bytes
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, nullptr, 0, CIPHER_KEY_BYTES);
            crypto_generichash_update(&gh, master_key_.data(), master_key_.size());
            crypto_generichash_update(&gh, extra_entropy.data(), extra_entropy.size());
            crypto_generichash_final(&gh, pw_buf.data(), CIPHER_KEY_BYTES);
            pw_ptr = reinterpret_cast<const char*>(pw_buf.data());
            pw_len = CIPHER_KEY_BYTES;
        } else {
            pw_ptr = reinterpret_cast<const char*>(master_key_.data());
            pw_len = master_key_.size();
        }

        SecureBuffer material(DERIVED_MATERIAL);
        if (crypto_pwhash(
                material.data(), DERIVED_MATERIAL,
                pw_ptr, pw_len,
                salt.data(),
                kdf_params_.opslimit,
                kdf_params_.memlimit,
                crypto_pwhash_ALG_ARGON2ID13) != 0)
            return Result<SecureBuffer>::err("Argon2id key derivation failed (OOM?)");

        return Result<SecureBuffer>::ok(std::move(material));
    }

    // Split 64-byte derived material into [cipher_key(32) | mac_key(32)]
    struct DerivedKeys { SecureBuffer cipher; SecureBuffer mac; };

    [[nodiscard]] static DerivedKeys split_derived(const SecureBuffer& mat) {
        SecureBuffer cipher(mat.data(),                   CIPHER_KEY_BYTES);
        SecureBuffer mac   (mat.data() + CIPHER_KEY_BYTES, MAC_KEY_BYTES);
        return { std::move(cipher), std::move(mac) };
    }

    SecureBuffer  master_key_;
    VaultKeyPair  keypair_;
    KdfParams     kdf_params_;
};

// ─────────────────────────────────────────────────────────────────────────────
// AsymmetricVault — same layered pipeline, but uses X25519 Box for the
// bidirectional layer instead of a symmetric key.
// Useful when sender and receiver have different identities.
//
// PIPELINE:
//   plaintext
//     → [L1] BLAKE2b integrity tag (unidirectional)
//     → [L2] X25519 + XChaCha20-Poly1305 Box (bidirectional)
//             — encrypts [plaintext ‖ integrity_tag]
//     → [L3] Ed25519 sign ciphertext (unidirectional)
//     → EncryptedPacket
// ─────────────────────────────────────────────────────────────────────────────
struct AsymKeyBundle {
    SecureBuffer box_public;    // X25519  public key (32 B) — share for receiving
    SecureBuffer box_secret;    // X25519  secret key (32 B) — keep private
    SecureBuffer sign_public;   // Ed25519 public key (32 B) — share for verification
    SecureBuffer sign_secret;   // Ed25519 secret key (64 B) — keep private
};

class AsymmetricVault {
public:
    static constexpr std::size_t INTEGRITY_BYTES = crypto_generichash_BYTES_MAX;
    static constexpr std::size_t BOX_MAC_BYTES   = crypto_box_MACBYTES;
    static constexpr std::size_t BOX_NONCE_BYTES = crypto_box_NONCEBYTES;
    static constexpr std::size_t SIG_BYTES       = crypto_sign_BYTES;
    // MAC key for BLAKE2b: derived from the shared X25519 secret via HKDF-like step
    static constexpr std::size_t MAC_KEY_BYTES   = crypto_generichash_KEYBYTES;

    [[nodiscard]] static AsymKeyBundle generate_bundle() {
        AsymKeyBundle b;
        b.box_public.resize(crypto_box_PUBLICKEYBYTES);
        b.box_secret.resize(crypto_box_SECRETKEYBYTES);
        crypto_box_keypair(b.box_public.data(), b.box_secret.data());

        b.sign_public.resize(crypto_sign_PUBLICKEYBYTES);
        b.sign_secret.resize(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(b.sign_public.data(), b.sign_secret.data());
        return b;
    }

    // ── seal: sender → recipient ─────────────────────────────────────────────
    //
    // extra_entropy — optional LavaRand-style boost mixed into the MAC key
    //   derivation step.  When provided, the MAC key becomes:
    //     BLAKE2b( X25519_shared ‖ extra_entropy )
    //   instead of simply BLAKE2b(X25519_shared), making the integrity tag
    //   depend on both the key exchange AND the external entropy source.
    [[nodiscard]] static Result<EncryptedPacket>
    seal(std::span<const uint8_t>  plaintext,
         const AsymKeyBundle&      sender,
         std::span<const uint8_t>  recipient_box_public,
         std::span<const uint8_t>  aad            = {},
         std::span<const uint8_t>  extra_entropy  = {}) {

        // ── L1: Derive a MAC key from the X25519 shared secret ────────────
        //   shared_secret = X25519(sender_secret, recipient_public)
        //   mac_key       = BLAKE2b(shared_secret [‖ extra_entropy])
        SecureBuffer shared(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(
                shared.data(),
                sender.box_secret.data(),
                recipient_box_public.data()) != 0)
            return Result<EncryptedPacket>::err("X25519: low-order point rejected");

        SecureBuffer mac_key(MAC_KEY_BYTES);
        if (!extra_entropy.empty()) {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, nullptr, 0, MAC_KEY_BYTES);
            crypto_generichash_update(&gh, shared.data(), shared.size());
            crypto_generichash_update(&gh, extra_entropy.data(), extra_entropy.size());
            crypto_generichash_final(&gh, mac_key.data(), MAC_KEY_BYTES);
        } else {
            crypto_generichash(mac_key.data(), MAC_KEY_BYTES,
                               shared.data(), shared.size(),
                               nullptr, 0);
        }

        // ── L1: BLAKE2b integrity tag — binds plaintext AND aad ─────────
        SecureBuffer integrity_tag(INTEGRITY_BYTES);
        {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, mac_key.data(), mac_key.size(), INTEGRITY_BYTES);
            crypto_generichash_update(&gh, plaintext.data(), plaintext.size());
            if (!aad.empty())
                crypto_generichash_update(&gh, aad.data(), aad.size());
            crypto_generichash_final(&gh, integrity_tag.data(), INTEGRITY_BYTES);
        }

        // ── L2: Box-encrypt [plaintext ‖ integrity_tag] ───────────────────
        // Use SecureBuffer so plaintext is zeroed when inner goes out of scope.
        SecureBuffer inner(plaintext.size() + INTEGRITY_BYTES);
        std::memcpy(inner.data(), plaintext.data(), plaintext.size());
        std::memcpy(inner.data() + plaintext.size(),
                    integrity_tag.data(), INTEGRITY_BYTES);

        SecureBuffer ciphertext(BOX_NONCE_BYTES + BOX_MAC_BYTES + inner.size());
        uint8_t* nonce_ptr = ciphertext.data();
        randombytes_buf(nonce_ptr, BOX_NONCE_BYTES);

        if (crypto_box_easy(
                ciphertext.data() + BOX_NONCE_BYTES,
                inner.data(), inner.size(),
                nonce_ptr,
                recipient_box_public.data(),
                sender.box_secret.data()) != 0)
            return Result<EncryptedPacket>::err("Box: encryption failed");

        // ── L3: Ed25519 sign over (ciphertext ‖ sender_box_public) ────────
        // The sender's X25519 box public key travels in the kdf_salt field and
        // is used by the recipient for the ECDH. Binding it into the signature
        // ties the box identity to the signing identity, preventing an
        // unknown-key-share / key-substitution attack where an attacker swaps
        // the transported box key.
        SecureBuffer signed_msg(ciphertext.size() + sender.box_public.size());
        std::memcpy(signed_msg.data(), ciphertext.data(), ciphertext.size());
        std::memcpy(signed_msg.data() + ciphertext.size(),
                    sender.box_public.data(), sender.box_public.size());

        SecureBuffer signature(SIG_BYTES);
        unsigned long long sig_len = 0;
        crypto_sign_detached(
            signature.data(), &sig_len,
            signed_msg.data(), signed_msg.size(),
            sender.sign_secret.data());
        signature.resize(static_cast<std::size_t>(sig_len));

        // kdf_salt is unused here; we reuse the field to carry the sender's box public key
        SecureBuffer sender_pk(sender.box_public.data(), sender.box_public.size());

        return Result<EncryptedPacket>::ok(
            EncryptedPacket{
                std::move(ciphertext),
                std::move(signature),
                std::move(sender_pk)   // kdf_salt field repurposed as sender_box_public
            });
    }

    // ── open: recipient opens a packet from sender ────────────────────────────
    // extra_entropy must match the value used in seal() exactly.
    [[nodiscard]] static Result<SecureBuffer>
    open(const EncryptedPacket&    packet,
         const AsymKeyBundle&      recipient,
         std::span<const uint8_t>  sender_sign_public,
         std::span<const uint8_t>  aad            = {},
         std::span<const uint8_t>  extra_entropy  = {}) {

        // sender box public key is stored in kdf_salt field
        std::span<const uint8_t> sender_box_public = packet.kdf_salt.span();

        // ── L3: Verify signature over (ciphertext ‖ sender_box_public) ────
        // Must mirror seal(): the transported box public key is bound into the
        // signature, so tampering with it now fails here rather than silently
        // changing the ECDH input.
        if (sender_sign_public.size() != crypto_sign_PUBLICKEYBYTES)
            return Result<SecureBuffer>::err("Invalid sign public key");

        SecureBuffer signed_msg(packet.ciphertext.size() + sender_box_public.size());
        std::memcpy(signed_msg.data(), packet.ciphertext.data(), packet.ciphertext.size());
        std::memcpy(signed_msg.data() + packet.ciphertext.size(),
                    sender_box_public.data(), sender_box_public.size());

        if (crypto_sign_verify_detached(
                packet.signature.data(),
                signed_msg.data(), signed_msg.size(),
                sender_sign_public.data()) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        // ── L1: Re-derive MAC key (must mirror seal()) ────────────────────
        SecureBuffer shared(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(
                shared.data(),
                recipient.box_secret.data(),
                sender_box_public.data()) != 0)
            return Result<SecureBuffer>::err("X25519: invalid sender key");

        SecureBuffer mac_key(MAC_KEY_BYTES);
        if (!extra_entropy.empty()) {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, nullptr, 0, MAC_KEY_BYTES);
            crypto_generichash_update(&gh, shared.data(), shared.size());
            crypto_generichash_update(&gh, extra_entropy.data(), extra_entropy.size());
            crypto_generichash_final(&gh, mac_key.data(), MAC_KEY_BYTES);
        } else {
            crypto_generichash(mac_key.data(), MAC_KEY_BYTES,
                               shared.data(), shared.size(),
                               nullptr, 0);
        }

        // ── L2: Box decrypt ───────────────────────────────────────────────
        if (packet.ciphertext.size() <= BOX_NONCE_BYTES + BOX_MAC_BYTES)
            return Result<SecureBuffer>::err("Vault: decryption failed — invalid packet");

        const uint8_t* nonce_ptr = packet.ciphertext.data();
        const uint8_t* ct_ptr    = packet.ciphertext.data() + BOX_NONCE_BYTES;
        std::size_t    ct_len    = packet.ciphertext.size() - BOX_NONCE_BYTES;

        SecureBuffer inner(ct_len - BOX_MAC_BYTES);
        if (crypto_box_open_easy(
                inner.data(),
                ct_ptr, ct_len,
                nonce_ptr,
                sender_box_public.data(),
                recipient.box_secret.data()) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        // ── L1: Verify BLAKE2b integrity tag ──────────────────────────────
        if (inner.size() < INTEGRITY_BYTES)
            return Result<SecureBuffer>::err("Vault: decryption failed — invalid packet");

        const std::size_t pt_size = inner.size() - INTEGRITY_BYTES;
        const uint8_t*    pt_data = inner.data();
        const uint8_t*    tag_data = inner.data() + pt_size;

        SecureBuffer expected_tag(INTEGRITY_BYTES);
        {
            crypto_generichash_state gh{};
            crypto_generichash_init(&gh, mac_key.data(), mac_key.size(), INTEGRITY_BYTES);
            crypto_generichash_update(&gh, pt_data, pt_size);
            if (!aad.empty())
                crypto_generichash_update(&gh, aad.data(), aad.size());
            crypto_generichash_final(&gh, expected_tag.data(), INTEGRITY_BYTES);
        }

        if (sodium_memcmp(expected_tag.data(), tag_data, INTEGRITY_BYTES) != 0)
            return Result<SecureBuffer>::err(
                "Vault: decryption failed — invalid packet");

        SecureBuffer plaintext(pt_data, pt_size);
        return Result<SecureBuffer>::ok(std::move(plaintext));
    }

    // Convenience: string overloads (no entropy boost)
    [[nodiscard]] static Result<EncryptedPacket>
    seal(std::string_view plaintext,
         const AsymKeyBundle& sender,
         std::span<const uint8_t> recipient_box_public,
         std::string_view aad = {}) {
        return seal(
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size() },
            sender, recipient_box_public,
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
            std::span<const uint8_t>{});
    }

    [[nodiscard]] static Result<SecureBuffer>
    open(const EncryptedPacket&   packet,
         const AsymKeyBundle&     recipient,
         std::span<const uint8_t> sender_sign_public,
         std::string_view         aad) {
        return open(packet, recipient, sender_sign_public,
            std::span<const uint8_t>{ reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
            std::span<const uint8_t>{});
    }

    // MediaEntropy boost overloads — declared here, defined in media_entropy.hpp
    [[nodiscard]] static Result<EncryptedPacket>
    seal(std::span<const uint8_t>       plaintext,
         const AsymKeyBundle&           sender,
         std::span<const uint8_t>       recipient_box_public,
         std::span<const uint8_t>       aad,
         const entropy::MediaEntropy&   boost);

    [[nodiscard]] static Result<SecureBuffer>
    open(const EncryptedPacket&         packet,
         const AsymKeyBundle&           recipient,
         std::span<const uint8_t>       sender_sign_public,
         std::span<const uint8_t>       aad,
         const entropy::MediaEntropy&   boost);

    // ─────────────────────────────────────────────────────────────────────────
    // Steganography integration — seal_into / open_from for AsymmetricVault.
    //
    // seal_into — encrypt for recipient and hide the packet in a carrier file.
    //   sender           caller's full AsymKeyBundle (for signing)
    //   recipient_pub    recipient's box public key (for X25519 ECDH)
    //   plaintext        message to encrypt
    //   cover_path       source media (.ppm / .wav / .crvf)
    //   output_path      stego output file
    //   aad              optional additional authenticated data
    //
    // open_from — extract the hidden packet, verify sender, and decrypt.
    //   recipient        caller's full AsymKeyBundle (for decryption)
    //   sender_sign_pub  sender's Ed25519 public key (for verification)
    //   stego_path       stego media file produced by seal_into()
    //   aad              must match the aad used in seal_into()
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void>
    seal_into(const AsymKeyBundle&      sender,
              std::span<const uint8_t>  recipient_box_public,
              std::string_view          plaintext,
              std::string_view          cover_path,
              std::string_view          output_path,
              std::string_view          aad = {});

    [[nodiscard]] static Result<SecureBuffer>
    open_from(const AsymKeyBundle&      recipient,
              std::span<const uint8_t>  sender_sign_public,
              std::string_view          stego_path,
              std::string_view          aad = {});

    // ─────────────────────────────────────────────────────────────────────────
    // Media entropy integration — derive an AsymKeyBundle from a MediaEntropy
    // source.  This is the entropy-seeded construction path for asymmetric
    // operations:
    //
    //   // random bundle (default path)
    //   auto bundle = AsymmetricVault::generate_bundle();
    //
    //   // entropy-seeded (LavaRand path) — same file = same identity
    //   auto bundle = AsymmetricVault::from_entropy(me).value();
    //
    // The derived bundle has stable identity as long as the entropy source
    // (media file) is unchanged.  Useful for long-lived pseudonymous identities
    // anchored to a physical artefact (e.g., a master photograph).
    //
    // Definition is in media_entropy.hpp (after MediaEntropy is fully defined).
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<AsymKeyBundle>
    from_entropy(const entropy::MediaEntropy& source);
};

} // namespace crypto

// ─────────────────────────────────────────────────────────────────────────────
// Steganography engine — included after vault class definitions.
// steganography.hpp now includes packet.hpp (not vault.hpp), so there is no
// circular dependency: vault.hpp → steganography.hpp → packet.hpp  ✓
// ─────────────────────────────────────────────────────────────────────────────
#include "steganography.hpp"

namespace crypto {

// ── SecureVault::seal_into / open_from implementations ───────────────────────

inline Result<void>
SecureVault::seal_into(std::string_view cover_path,
                       std::string_view plaintext,
                       std::string_view output_path,
                       std::string_view aad) const
{
    auto pkt = seal(plaintext, aad);
    if (pkt.is_err()) return Result<void>::err(pkt.error().message);
    return stego::StegoEngine::embed_packet(cover_path, pkt.value(), output_path);
}

inline Result<SecureBuffer>
SecureVault::open_from(std::string_view stego_path,
                       std::string_view aad) const
{
    auto pkt = stego::StegoEngine::extract_packet(stego_path);
    if (pkt.is_err()) return Result<SecureBuffer>::err(pkt.error().message);
    return open(pkt.value(), aad);
}

// ── AsymmetricVault::seal_into / open_from implementations ───────────────────

inline Result<void>
AsymmetricVault::seal_into(const AsymKeyBundle&      sender,
                           std::span<const uint8_t>  recipient_box_public,
                           std::string_view           plaintext,
                           std::string_view           cover_path,
                           std::string_view           output_path,
                           std::string_view           aad)
{
    auto pkt = AsymmetricVault::seal(plaintext, sender, recipient_box_public, aad);
    if (pkt.is_err()) return Result<void>::err(pkt.error().message);
    return stego::StegoEngine::embed_packet(cover_path, pkt.value(), output_path);
}

inline Result<SecureBuffer>
AsymmetricVault::open_from(const AsymKeyBundle&      recipient,
                           std::span<const uint8_t>  sender_sign_public,
                           std::string_view           stego_path,
                           std::string_view           aad)
{
    auto pkt = stego::StegoEngine::extract_packet(stego_path);
    if (pkt.is_err()) return Result<SecureBuffer>::err(pkt.error().message);
    return AsymmetricVault::open(pkt.value(), recipient, sender_sign_public, aad);
}

// ── from_entropy — definitions deferred until after MediaEntropy is complete ──
// These are declared here in vault.hpp but defined in media_entropy.hpp,
// which is #included after this file and contains the full MediaEntropy type.
// This follows the same deferred-definition pattern as seal_into/open_from above.
//
// SecureVault::from_entropy(me, params)
// AsymmetricVault::from_entropy(me)
//
// See media_entropy.hpp for the inline implementations.

} // namespace crypto
