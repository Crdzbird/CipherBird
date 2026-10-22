#pragma once
/**
 * crypto::fips::Envelope: key wrapping with approved operations only. A
 * 32-byte master from the module's DRBG is wrapped once per slot under
 * AES-256-GCM; a passphrase slot derives its wrapping key with PBKDF2
 * (SP 800-132), a key slot with HKDF (SP 800-56C) from a caller-held
 * 32-byte factor such as a hardware-unwrapped keyring factor.
 *
 * Wire: "FKR1" | version(1) | id(16) | slot_count(1) | slots, each
 * type(1) | salt_len(1) | salt | iterations(4 LE) | wrapped_len(2 LE) | wrapped
 * where wrapped is the AES-256-GCM output (iv | ct | tag) with the slot
 * header as AAD. Nothing in this file touches libsodium.
 */
#ifdef CRYPTOLIB_HAS_FIPS_PROVIDER
#include "primitives.hpp"
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::fips {

class Envelope {
public:
    static constexpr std::size_t MASTER_BYTES = 32;
    static constexpr std::size_t SALT_BYTES = 16;
    static constexpr std::size_t ID_BYTES = 16;
    static constexpr std::size_t MAX_SLOTS = 16;
    static constexpr uint8_t VERSION = 1;
    static constexpr unsigned MAX_ITERATIONS = 10000000;
    enum class SlotType : uint8_t { Passphrase = 0, Key = 1 };

    [[nodiscard]] static Result<Envelope> create() {
        auto id = Random::bytes(ID_BYTES);
        if (id.is_err()) return Result<Envelope>::err(id.error().message);
        auto master = Random::bytes(MASTER_BYTES);
        if (master.is_err()) return Result<Envelope>::err(master.error().message);
        Envelope e;
        e.id_ = PublicBuffer(id.value().data(), id.value().size());
        e.master_ = std::move(master.value());
        return Result<Envelope>::ok(std::move(e));
    }

    [[nodiscard]] Result<void> add_passphrase_slot(std::span<const uint8_t> passphrase,
                                                   unsigned iterations = Pbkdf2::DEFAULT_ITERATIONS) {
        if (master_.empty()) return Result<void>::err("fips envelope: locked");
        if (slots_.size() >= MAX_SLOTS) return Result<void>::err("fips envelope: too many slots");
        if (iterations < Pbkdf2::MIN_ITERATIONS || iterations > MAX_ITERATIONS)
            return Result<void>::err("fips envelope: iterations outside policy");
        Slot s;
        s.type = SlotType::Passphrase;
        s.iterations = iterations;
        auto salt = Random::bytes(SALT_BYTES);
        if (salt.is_err()) return Result<void>::err(salt.error().message);
        s.salt = PublicBuffer(salt.value().data(), salt.value().size());
        auto key = Pbkdf2::derive(Hash::Sha256, passphrase, s.salt.span(), iterations, 32);
        if (key.is_err()) return Result<void>::err(key.error().message);
        return wrap_into(s, key.value().span());
    }

    [[nodiscard]] Result<void> add_key_slot(std::span<const uint8_t> factor) {
        if (master_.empty()) return Result<void>::err("fips envelope: locked");
        if (slots_.size() >= MAX_SLOTS) return Result<void>::err("fips envelope: too many slots");
        if (factor.size() < 32) return Result<void>::err("fips envelope: factor must be at least 32 bytes");
        Slot s;
        s.type = SlotType::Key;
        auto salt = Random::bytes(SALT_BYTES);
        if (salt.is_err()) return Result<void>::err(salt.error().message);
        s.salt = PublicBuffer(salt.value().data(), salt.value().size());
        auto key = Hkdf::derive(Hash::Sha256, factor, s.salt.span(), info_bytes("cryptolib:fips:envelope:key"), 32);
        if (key.is_err()) return Result<void>::err(key.error().message);
        return wrap_into(s, key.value().span());
    }

    [[nodiscard]] Result<SecureBuffer> unlock_with_passphrase(std::span<const uint8_t> passphrase) {
        for (const auto& s : slots_) {
            if (s.type != SlotType::Passphrase) continue;
            auto key = Pbkdf2::derive(Hash::Sha256, passphrase, s.salt.span(), s.iterations, 32);
            if (key.is_err()) continue;
            auto m = Aes256Gcm::decrypt(key.value().span(), s.wrapped.span(), aad_for(s));
            if (m.is_ok()) { master_ = SecureBuffer(m.value().data(), m.value().size()); return m; }
        }
        return Result<SecureBuffer>::err("fips envelope: unlock failed");
    }

    [[nodiscard]] Result<SecureBuffer> unlock_with_key(std::span<const uint8_t> factor) {
        for (const auto& s : slots_) {
            if (s.type != SlotType::Key) continue;
            auto key = Hkdf::derive(Hash::Sha256, factor, s.salt.span(), info_bytes("cryptolib:fips:envelope:key"), 32);
            if (key.is_err()) continue;
            auto m = Aes256Gcm::decrypt(key.value().span(), s.wrapped.span(), aad_for(s));
            if (m.is_ok()) { master_ = SecureBuffer(m.value().data(), m.value().size()); return m; }
        }
        return Result<SecureBuffer>::err("fips envelope: unlock failed");
    }

    [[nodiscard]] std::size_t slot_count() const noexcept { return slots_.size(); }

    [[nodiscard]] Result<void> remove_slot(std::size_t index) {
        if (index >= slots_.size()) return Result<void>::err("fips envelope: bad slot index");
        slots_.erase(slots_.begin() + static_cast<std::ptrdiff_t>(index));
        return Result<void>::ok();
    }

    [[nodiscard]] PublicBuffer serialise() const {
        std::vector<uint8_t> out = { 'F', 'K', 'R', '1', VERSION };
        out.insert(out.end(), id_.span().begin(), id_.span().end());
        out.push_back(static_cast<uint8_t>(slots_.size()));
        for (const auto& s : slots_) {
            auto head = slot_header(s);
            out.insert(out.end(), head.begin(), head.end());
            out.push_back(static_cast<uint8_t>(s.wrapped.size() & 0xff));
            out.push_back(static_cast<uint8_t>(s.wrapped.size() >> 8));
            out.insert(out.end(), s.wrapped.span().begin(), s.wrapped.span().end());
        }
        return PublicBuffer(std::move(out));
    }

    [[nodiscard]] static Result<Envelope> deserialise(std::span<const uint8_t> raw) {
        const uint8_t* p = raw.data();
        const uint8_t* end = raw.data() + raw.size();
        auto need = [&](std::size_t n) { return static_cast<std::size_t>(end - p) >= n; };
        if (!need(5) || p[0] != 'F' || p[1] != 'K' || p[2] != 'R' || p[3] != '1') return Result<Envelope>::err("fips envelope: bad magic");
        if (p[4] != VERSION) return Result<Envelope>::err("fips envelope: bad version");
        p += 5;
        if (!need(ID_BYTES + 1)) return Result<Envelope>::err("fips envelope: truncated");
        Envelope e;
        e.id_ = PublicBuffer(p, ID_BYTES); p += ID_BYTES;
        std::size_t count = *p++;
        if (count > MAX_SLOTS) return Result<Envelope>::err("fips envelope: too many slots");
        for (std::size_t i = 0; i < count; ++i) {
            Slot s;
            if (!need(2)) return Result<Envelope>::err("fips envelope: truncated slot");
            uint8_t t = *p++;
            if (t > static_cast<uint8_t>(SlotType::Key)) return Result<Envelope>::err("fips envelope: unknown slot type");
            s.type = static_cast<SlotType>(t);
            std::size_t salt_len = *p++;
            if (salt_len < SALT_BYTES || !need(salt_len)) return Result<Envelope>::err("fips envelope: bad salt");
            s.salt = PublicBuffer(p, salt_len); p += salt_len;
            if (!need(4)) return Result<Envelope>::err("fips envelope: truncated iterations");
            s.iterations = static_cast<unsigned>(p[0]) | static_cast<unsigned>(p[1]) << 8 | static_cast<unsigned>(p[2]) << 16 | static_cast<unsigned>(p[3]) << 24;
            p += 4;
            if (s.type == SlotType::Passphrase && (s.iterations < Pbkdf2::MIN_ITERATIONS || s.iterations > MAX_ITERATIONS))
                return Result<Envelope>::err("fips envelope: iterations outside policy");
            if (!need(2)) return Result<Envelope>::err("fips envelope: truncated wrapped length");
            std::size_t wlen = static_cast<std::size_t>(p[0]) | static_cast<std::size_t>(p[1]) << 8; p += 2;
            if (!need(wlen)) return Result<Envelope>::err("fips envelope: truncated wrapped");
            s.wrapped = PublicBuffer(p, wlen); p += wlen;
            e.slots_.push_back(std::move(s));
        }
        return Result<Envelope>::ok(std::move(e));
    }

private:
    struct Slot {
        SlotType type = SlotType::Key;
        PublicBuffer salt;
        unsigned iterations = 0;
        PublicBuffer wrapped;
    };

    PublicBuffer id_;
    std::vector<Slot> slots_;
    SecureBuffer master_;

    static std::span<const uint8_t> info_bytes(std::string_view s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }

    std::vector<uint8_t> slot_header(const Slot& s) const {
        std::vector<uint8_t> h;
        h.push_back(static_cast<uint8_t>(s.type));
        h.push_back(static_cast<uint8_t>(s.salt.size()));
        h.insert(h.end(), s.salt.span().begin(), s.salt.span().end());
        for (int i = 0; i < 4; ++i) h.push_back(static_cast<uint8_t>(s.iterations >> (8 * i)));
        return h;
    }

    std::vector<uint8_t> aad_for(const Slot& s) const {
        std::vector<uint8_t> aad = { 'F', 'K', 'R', '1', VERSION };
        aad.insert(aad.end(), id_.span().begin(), id_.span().end());
        auto h = slot_header(s);
        aad.insert(aad.end(), h.begin(), h.end());
        return aad;
    }

    Result<void> wrap_into(Slot& s, std::span<const uint8_t> key) {
        auto wrapped = Aes256Gcm::encrypt(key, master_.span(), aad_for(s));
        if (wrapped.is_err()) return Result<void>::err(wrapped.error().message);
        s.wrapped = std::move(wrapped.value());
        slots_.push_back(std::move(s));
        return Result<void>::ok();
    }
};

}
#endif
