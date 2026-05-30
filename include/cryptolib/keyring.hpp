#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Keyring — envelope encryption with key-slots                      ║
 * ║                                                                            ║
 * ║  One random 256-bit MASTER KEY encrypts the user's data (via SecureVault).  ║
 * ║  The master key is never stored in plaintext — it is wrapped in one or more ║
 * ║  SLOTS, each holding the master key AEAD-encrypted under a different        ║
 * ║  "unlock factor":                                                          ║
 * ║                                                                            ║
 * ║    • Device slot     slot_key = HKDF-SHA256(device_factor_key)             ║
 * ║                      The 32-byte factor key comes from the platform's      ║
 * ║                      secure hardware (iOS Secure Enclave / Android         ║
 * ║                      Keystore / WebAuthn) and is non-exportable. This is   ║
 * ║                      the DEFAULT single-device path.                       ║
 * ║                                                                            ║
 * ║    • Passphrase slot slot_key = Argon2id(passphrase)                       ║
 * ║                      Memory-hard; the OPT-IN cross-device path — the same  ║
 * ║                      envelope blob + passphrase reconstructs the master    ║
 * ║                      key on any device.                                    ║
 * ║                                                                            ║
 * ║  A "unique input" (voice / gesture / biometric) integrates by PRODUCING a  ║
 * ║  32-byte factor key (platform biometric-unlock today; a fuzzy extractor    ║
 * ║  later). This module stays agnostic about where factor keys come from.     ║
 * ║                                                                            ║
 * ║  REVOCATION: remove a slot and re-serialise → that factor no longer opens  ║
 * ║  the master key. (You can't revoke a biometric, but you can revoke the     ║
 * ║  slot it gated.)                                                            ║
 * ║                                                                            ║
 * ║  ANTI-DOWNGRADE: each slot binds its type, salt and KDF params into the     ║
 * ║  AEAD associated data, so a tampered envelope can't weaken Argon2id params  ║
 * ║  or swap a strong slot for a weak one without failing authentication.      ║
 * ║                                                                            ║
 * ║  Typical flow                                                              ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║    Enroll (device 1):                                                      ║
 * ║      auto kr = Keyring::create();                  // random master key    ║
 * ║      kr.add_device_slot(enclave_key.span());       // default, 1 device    ║
 * ║      kr.add_passphrase_slot("…", KdfParams::sensitive()); // opt cross-dev ║
 * ║      store(kr.serialise());                        // no plaintext key     ║
 * ║                                                                            ║
 * ║    Use (device 1):                                                         ║
 * ║      auto kr = Keyring::deserialise(blob).value();                         ║
 * ║      auto master = kr.unlock_with_device(enclave_key.span()).value();      ║
 * ║                                                                            ║
 * ║    Use (device 2, cross-device opt-in):                                    ║
 * ║      auto kr = Keyring::deserialise(blob).value();                         ║
 * ║      auto master = kr.unlock_with_passphrase("…").value();                 ║
 * ║      kr.add_device_slot(device2_enclave_key.span());  // bind new device   ║
 * ║      store(kr.serialise());                                                ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"
#include "symmetric.hpp"
#include "packet.hpp"   // KdfParams
#include "vault.hpp"    // SecureVault convenience

#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

class Keyring {
public:
    static constexpr std::size_t MASTER_KEY_BYTES = 32;
    static constexpr std::size_t SLOT_KEY_BYTES   = 32;
    static constexpr std::size_t SALT_BYTES       = crypto_pwhash_SALTBYTES; // 16
    static constexpr std::size_t ENVELOPE_ID_BYTES = 16;
    static constexpr std::size_t MAX_SLOTS        = 16;   // bound untrusted input
    static constexpr uint8_t     VERSION          = 1;

    enum class SlotType : uint8_t { Passphrase = 0, DeviceKey = 1 };

    // ── Construction ──────────────────────────────────────────────────────────

    /// New keyring with a fresh random master key (held in memory until wrapped).
    [[nodiscard]] static Keyring create() {
        Keyring kr;
        kr.envelope_id_ = rand_buf(ENVELOPE_ID_BYTES);
        kr.master_      = rand_buf(MASTER_KEY_BYTES);
        return kr;
    }

    /// Adopt an existing 32-byte master key (e.g. derived from MediaEntropy).
    [[nodiscard]] static Result<Keyring> from_master_key(std::span<const uint8_t> master) {
        if (master.size() != MASTER_KEY_BYTES)
            return Result<Keyring>::err("Keyring: master key must be 32 bytes");
        Keyring kr;
        kr.envelope_id_ = rand_buf(ENVELOPE_ID_BYTES);
        kr.master_      = SecureBuffer(master.data(), master.size());
        return Result<Keyring>::ok(std::move(kr));
    }

    // ── Slot management (require an unlocked/created master key) ───────────────

    /// Add a passphrase slot (cross-device path). Default to SENSITIVE params:
    /// this guards the master key, so memory-hardness matters.
    [[nodiscard]] Result<void>
    add_passphrase_slot(std::string_view passphrase,
                        KdfParams params = KdfParams::sensitive()) {
        if (master_.empty())
            return Result<void>::err("Keyring: locked — create or unlock first");
        if (slots_.size() >= MAX_SLOTS)
            return Result<void>::err("Keyring: too many slots");

        Slot s;
        s.type = SlotType::Passphrase;
        s.salt = rand_buf(SALT_BYTES);
        s.ops  = params.opslimit;
        s.mem  = params.memlimit;

        auto slot_key = derive_passphrase_key(passphrase, s.salt.span(), s.ops, s.mem);
        if (slot_key.is_err()) return Result<void>::err(slot_key.error().message);
        auto wrapped = wrap(slot_key.value().span(), aad_for(s));
        if (wrapped.is_err()) return Result<void>::err(wrapped.error().message);
        s.wrapped = std::move(wrapped.value());
        slots_.push_back(std::move(s));
        return Result<void>::ok();
    }

    /// Add a device slot. `factor_key` is a 32-byte key from secure hardware
    /// (Secure Enclave / Keystore / WebAuthn) — opaque to this module.
    [[nodiscard]] Result<void>
    add_device_slot(std::span<const uint8_t> factor_key) {
        if (master_.empty())
            return Result<void>::err("Keyring: locked — create or unlock first");
        if (factor_key.size() < SLOT_KEY_BYTES)
            return Result<void>::err("Keyring: device factor key must be >= 32 bytes");
        if (slots_.size() >= MAX_SLOTS)
            return Result<void>::err("Keyring: too many slots");

        Slot s;
        s.type = SlotType::DeviceKey;
        s.salt = rand_buf(SALT_BYTES);
        s.ops  = 0;
        s.mem  = 0;

        auto slot_key = derive_device_key(factor_key, s.salt.span());
        if (slot_key.is_err()) return Result<void>::err(slot_key.error().message);
        auto wrapped = wrap(slot_key.value().span(), aad_for(s));
        if (wrapped.is_err()) return Result<void>::err(wrapped.error().message);
        s.wrapped = std::move(wrapped.value());
        slots_.push_back(std::move(s));
        return Result<void>::ok();
    }

    [[nodiscard]] std::size_t slot_count() const noexcept { return slots_.size(); }

    /// Revoke a slot. The master key is unchanged; that factor can no longer
    /// open it once the new envelope is persisted.
    [[nodiscard]] Result<void> remove_slot(std::size_t index) {
        if (index >= slots_.size())
            return Result<void>::err("Keyring: slot index out of range");
        slots_.erase(slots_.begin() + static_cast<std::ptrdiff_t>(index));
        return Result<void>::ok();
    }

    // ── Rotation ────────────────────────────────────────────────────────────────
    //
    // rewrap: change credentials (passphrase/device) while KEEPING the master
    //   key, so existing data stays decryptable. A fresh envelope_id makes the
    //   new envelope unlinkable to the old one. Requires the keyring unlocked.
    //
    // rekey: rotate the MASTER key itself (e.g. on suspected compromise).
    //   Returns the OLD master so the caller can decrypt-then-re-encrypt data
    //   under the new master. Requires the keyring unlocked.
    //
    // Both re-wrap under the SUPPLIED factors (re-deriving slot keys needs the
    // factors, which the keyring never stores), and roll back on any failure.

    [[nodiscard]] Result<void>
    rewrap(std::vector<std::span<const uint8_t>> device_factors,
           std::vector<std::string_view> passphrases,
           KdfParams pp_params = KdfParams::sensitive()) {
        if (master_.empty())
            return Result<void>::err("Keyring: locked — unlock before rewrap");
        SecureBuffer keep_master(master_.data(), master_.size());
        return rebuild(std::move(keep_master), device_factors, passphrases, pp_params)
                   ? Result<void>::ok()
                   : Result<void>::err("Keyring: rewrap failed (bad factor?)");
    }

    [[nodiscard]] Result<SecureBuffer>
    rekey(std::vector<std::span<const uint8_t>> device_factors,
          std::vector<std::string_view> passphrases,
          KdfParams pp_params = KdfParams::sensitive()) {
        if (master_.empty())
            return Result<SecureBuffer>::err("Keyring: locked — unlock before rekey");
        SecureBuffer old_master(master_.data(), master_.size());
        SecureBuffer new_master = rand_buf(MASTER_KEY_BYTES);
        if (!rebuild(std::move(new_master), device_factors, passphrases, pp_params))
            return Result<SecureBuffer>::err("Keyring: rekey failed (bad factor?)");
        return Result<SecureBuffer>::ok(std::move(old_master));
    }

    // ── Unlock ────────────────────────────────────────────────────────────────

    /// Recover the master key with a passphrase. On success the keyring becomes
    /// "unlocked" (you may then add more slots, e.g. to bind a new device).
    [[nodiscard]] Result<SecureBuffer>
    unlock_with_passphrase(std::string_view passphrase) {
        for (const auto& s : slots_) {
            if (s.type != SlotType::Passphrase) continue;
            auto slot_key = derive_passphrase_key(passphrase, s.salt.span(), s.ops, s.mem);
            if (slot_key.is_err()) continue;
            auto m = unwrap(s, slot_key.value().span());
            if (m.is_ok()) { master_ = SecureBuffer(m.value().data(), m.value().size());
                             return m; }
        }
        return Result<SecureBuffer>::err("Keyring: unlock failed");
    }

    /// Recover the master key with a device factor key.
    [[nodiscard]] Result<SecureBuffer>
    unlock_with_device(std::span<const uint8_t> factor_key) {
        for (const auto& s : slots_) {
            if (s.type != SlotType::DeviceKey) continue;
            auto slot_key = derive_device_key(factor_key, s.salt.span());
            if (slot_key.is_err()) continue;
            auto m = unwrap(s, slot_key.value().span());
            if (m.is_ok()) { master_ = SecureBuffer(m.value().data(), m.value().size());
                             return m; }
        }
        return Result<SecureBuffer>::err("Keyring: unlock failed");
    }

    // ── Convenience: unlock straight into a ready-to-use SecureVault ──────────
    [[nodiscard]] Result<SecureVault>
    open_vault_with_passphrase(std::string_view passphrase, VaultKeyPair kp,
                               KdfParams params = KdfParams::interactive()) {
        auto m = unlock_with_passphrase(passphrase);
        if (m.is_err()) return Result<SecureVault>::err(m.error().message);
        return Result<SecureVault>::ok(SecureVault(m.value().span(), std::move(kp), params));
    }

    [[nodiscard]] Result<SecureVault>
    open_vault_with_device(std::span<const uint8_t> factor_key, VaultKeyPair kp,
                           KdfParams params = KdfParams::interactive()) {
        auto m = unlock_with_device(factor_key);
        if (m.is_err()) return Result<SecureVault>::err(m.error().message);
        return Result<SecureVault>::ok(SecureVault(m.value().span(), std::move(kp), params));
    }

    // ── Serialisation (envelope blob — safe to store/transport) ───────────────
    //
    // Layout (little-endian):
    //   'C''K''R''1' | version(1) | envelope_id(16) | slot_count(1)
    //   per slot: type(1) | salt_len(1) | salt | ops(8) | mem(8)
    //             | wrapped_len(2) | wrapped
    [[nodiscard]] SecureBuffer serialise() const {
        std::vector<uint8_t> out;
        auto put8  = [&](uint8_t v){ out.push_back(v); };
        auto put16 = [&](uint16_t v){ out.push_back(uint8_t(v)); out.push_back(uint8_t(v >> 8)); };
        auto put64 = [&](uint64_t v){ for (int i = 0; i < 8; ++i) out.push_back(uint8_t(v >> (8*i))); };
        auto putb  = [&](std::span<const uint8_t> b){ out.insert(out.end(), b.begin(), b.end()); };

        out.push_back('C'); out.push_back('K'); out.push_back('R'); out.push_back('1');
        put8(VERSION);
        putb(envelope_id_.span());
        put8(static_cast<uint8_t>(slots_.size()));
        for (const auto& s : slots_) {
            put8(static_cast<uint8_t>(s.type));
            put8(static_cast<uint8_t>(s.salt.size()));
            putb(s.salt.span());
            put64(s.ops);
            put64(static_cast<uint64_t>(s.mem));
            put16(static_cast<uint16_t>(s.wrapped.size()));
            putb(s.wrapped.span());
        }
        return SecureBuffer(std::move(out));
    }

    /// Parse an envelope blob. Untrusted input: every read is bounds-checked.
    [[nodiscard]] static Result<Keyring> deserialise(std::span<const uint8_t> raw) {
        const uint8_t* p   = raw.data();
        const uint8_t* end = raw.data() + raw.size();
        auto need = [&](std::size_t n) { return static_cast<std::size_t>(end - p) >= n; };

        if (!need(4) || p[0] != 'C' || p[1] != 'K' || p[2] != 'R' || p[3] != '1')
            return Result<Keyring>::err("Keyring: bad magic");
        p += 4;
        if (!need(1) || *p != VERSION) return Result<Keyring>::err("Keyring: bad version");
        ++p;
        if (!need(ENVELOPE_ID_BYTES)) return Result<Keyring>::err("Keyring: truncated id");

        Keyring kr;
        kr.envelope_id_ = SecureBuffer(p, ENVELOPE_ID_BYTES); p += ENVELOPE_ID_BYTES;

        if (!need(1)) return Result<Keyring>::err("Keyring: truncated slot count");
        std::size_t count = *p++;
        if (count > MAX_SLOTS) return Result<Keyring>::err("Keyring: too many slots");

        auto get16 = [&](uint16_t& v) -> bool {
            if (!need(2)) return false;
            v = static_cast<uint16_t>(p[0]) | static_cast<uint16_t>(p[1]) << 8; p += 2; return true;
        };
        auto get64 = [&](uint64_t& v) -> bool {
            if (!need(8)) return false;
            v = 0; for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8*i);
            p += 8; return true;
        };

        for (std::size_t i = 0; i < count; ++i) {
            Slot s;
            if (!need(1)) return Result<Keyring>::err("Keyring: truncated slot type");
            uint8_t t = *p++;
            if (t > static_cast<uint8_t>(SlotType::DeviceKey))
                return Result<Keyring>::err("Keyring: unknown slot type");
            s.type = static_cast<SlotType>(t);

            if (!need(1)) return Result<Keyring>::err("Keyring: truncated salt len");
            std::size_t salt_len = *p++;
            if (!need(salt_len)) return Result<Keyring>::err("Keyring: truncated salt");
            s.salt = SecureBuffer(p, salt_len); p += salt_len;

            uint64_t ops = 0, mem = 0;
            if (!get64(ops) || !get64(mem)) return Result<Keyring>::err("Keyring: truncated kdf params");
            s.ops = ops; s.mem = static_cast<std::size_t>(mem);

            uint16_t wlen = 0;
            if (!get16(wlen)) return Result<Keyring>::err("Keyring: truncated wrapped len");
            if (!need(wlen)) return Result<Keyring>::err("Keyring: truncated wrapped");
            s.wrapped = SecureBuffer(p, wlen); p += wlen;

            kr.slots_.push_back(std::move(s));
        }
        return Result<Keyring>::ok(std::move(kr));
    }

private:
    struct Slot {
        SlotType           type = SlotType::DeviceKey;
        SecureBuffer       salt;
        unsigned long long ops = 0;   // Argon2id opslimit (passphrase slots)
        std::size_t        mem = 0;   // Argon2id memlimit (passphrase slots)
        SecureBuffer       wrapped;   // XChaCha20Poly1305(master): nonce|ct|tag
    };

    SecureBuffer       envelope_id_;
    std::vector<Slot>  slots_;
    SecureBuffer       master_;       // present only after create()/unlock_*()

    // Local CSPRNG helper (crypto::random_bytes lives in the umbrella header,
    // which includes this one — so we use libsodium directly to avoid the cycle).
    [[nodiscard]] static SecureBuffer rand_buf(std::size_t n) {
        SecureBuffer b(n);
        randombytes_buf(b.data(), n);
        return b;
    }

    // Replace the master + envelope with `new_master` under a fresh envelope_id,
    // re-wrapping under the supplied factors. Atomic: rolls back on any failure.
    [[nodiscard]] bool rebuild(SecureBuffer new_master,
                               const std::vector<std::span<const uint8_t>>& dfs,
                               const std::vector<std::string_view>& pps,
                               KdfParams params) {
        if (dfs.empty() && pps.empty()) return false;
        SecureBuffer      save_master(master_.data(), master_.size());
        std::vector<Slot> save_slots = std::move(slots_);
        SecureBuffer      save_id(envelope_id_.data(), envelope_id_.size());

        master_      = std::move(new_master);
        envelope_id_ = rand_buf(ENVELOPE_ID_BYTES);
        slots_.clear();

        bool good = true;
        for (auto f : dfs) if (add_device_slot(f).is_err()) { good = false; break; }
        if (good) for (auto p : pps) if (add_passphrase_slot(p, params).is_err()) { good = false; break; }

        if (!good) {  // roll back to the pre-rotation state
            master_      = std::move(save_master);
            slots_       = std::move(save_slots);
            envelope_id_ = std::move(save_id);
            return false;
        }
        return true;
    }

    // Bind slot metadata (incl. KDF params) into the AEAD AAD so an attacker
    // cannot downgrade params, change slot type, or move a slot between envelopes.
    [[nodiscard]] std::vector<uint8_t> aad_for(const Slot& s) const {
        std::vector<uint8_t> aad;
        aad.push_back('C'); aad.push_back('K'); aad.push_back('R'); aad.push_back('1');
        aad.push_back(VERSION);
        aad.insert(aad.end(), envelope_id_.span().begin(), envelope_id_.span().end());
        aad.push_back(static_cast<uint8_t>(s.type));
        aad.insert(aad.end(), s.salt.span().begin(), s.salt.span().end());
        for (int i = 0; i < 8; ++i) aad.push_back(uint8_t(s.ops >> (8*i)));
        for (int i = 0; i < 8; ++i) aad.push_back(uint8_t(static_cast<uint64_t>(s.mem) >> (8*i)));
        return aad;
    }

    [[nodiscard]] static Result<SecureBuffer>
    derive_passphrase_key(std::string_view pw, std::span<const uint8_t> salt,
                          unsigned long long ops, std::size_t mem) {
        return hash::Argon2id::derive_key(pw, salt, SLOT_KEY_BYTES, ops, mem);
    }

    [[nodiscard]] static Result<SecureBuffer>
    derive_device_key(std::span<const uint8_t> factor_key, std::span<const uint8_t> salt) {
        return hash::HkdfSha256::derive(factor_key, salt,
                   std::string_view("cryptolib:keyring:v1:device"), SLOT_KEY_BYTES);
    }

    [[nodiscard]] Result<SecureBuffer>
    wrap(std::span<const uint8_t> slot_key, const std::vector<uint8_t>& aad) const {
        return symmetric::XChaCha20Poly1305::encrypt(master_.span(), slot_key, aad);
    }

    // Rebuilds the AAD from envelope context, so it must be a member.
    [[nodiscard]] Result<SecureBuffer>
    unwrap(const Slot& s, std::span<const uint8_t> slot_key) const {
        return symmetric::XChaCha20Poly1305::decrypt(s.wrapped.span(), slot_key, aad_for(s));
    }
};

} // namespace crypto
