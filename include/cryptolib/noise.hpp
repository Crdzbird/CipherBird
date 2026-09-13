#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::NoiseXX — Noise_XX_25519_ChaChaPoly_SHA256 secure channel          ║
 * ║                                                                            ║
 * ║  A mutually-authenticated, forward-secret handshake built from CryptoLib's   ║
 * ║  vetted primitives (X25519 DH, ChaCha20-Poly1305 IETF AEAD, SHA-256/HKDF)   ║
 * ║  following the Noise Protocol Framework (https://noiseprotocol.org). The XX  ║
 * ║  pattern authenticates BOTH parties' static keys and yields forward secrecy  ║
 * ║  via per-session ephemerals.                                                ║
 * ║                                                                            ║
 * ║    -> e                                                                     ║
 * ║    <- e, ee, s, es                                                          ║
 * ║    -> s, se                                                                 ║
 * ║                                                                            ║
 * ║  After the 3 handshake messages, into_session() yields two transport        ║
 * ║  CipherStates (send/recv) for AEAD record exchange.                          ║
 * ║                                                                            ║
 * ║  ⚠ INTEROP: round-trip and security-property tested, but NOT yet validated   ║
 * ║  against the official Noise test vectors — wire-compatibility with other     ║
 * ║  Noise implementations must be confirmed against those vectors before        ║
 * ║  cross-implementation use. See docs/THREAT_MODEL.md.                         ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"        // HkdfSha256, Sha256
#include "asymmetric.hpp"  // X25519

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace crypto {

class NoiseXX {
public:
    static constexpr std::size_t DHLEN   = 32;
    static constexpr std::size_t HASHLEN = 32;
    static constexpr std::size_t TAGLEN  = 16;
    static constexpr const char* PROTOCOL = "Noise_XX_25519_ChaChaPoly_SHA256";

    /// A directional transport cipher (post-handshake).
    struct CipherState {
        SecureBuffer k;       // 32 bytes (empty ⇒ no key)
        uint64_t     n = 0;

        [[nodiscard]] Result<SecureBuffer> encrypt(std::span<const uint8_t> pt,
                                                   std::span<const uint8_t> ad = {}) {
            SecureBuffer out(pt.size() + TAGLEN);
            unsigned long long olen = 0;
            std::array<uint8_t, 12> nonce = make_nonce(n);
            if (crypto_aead_chacha20poly1305_ietf_encrypt(
                    out.data(), &olen, pt.data(), pt.size(),
                    ad.empty() ? nullptr : ad.data(), ad.size(),
                    nullptr, nonce.data(), k.data()) != 0)
                return Result<SecureBuffer>::err("Noise: transport encrypt failed");
            ++n;
            out.resize(static_cast<std::size_t>(olen));
            return Result<SecureBuffer>::ok(std::move(out));
        }
        [[nodiscard]] Result<SecureBuffer> decrypt(std::span<const uint8_t> ct,
                                                   std::span<const uint8_t> ad = {}) {
            if (ct.size() < TAGLEN) return Result<SecureBuffer>::err("Noise: transport ciphertext too short");
            SecureBuffer out(ct.size() - TAGLEN);
            unsigned long long olen = 0;
            std::array<uint8_t, 12> nonce = make_nonce(n);
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    out.data(), &olen, nullptr, ct.data(), ct.size(),
                    ad.empty() ? nullptr : ad.data(), ad.size(),
                    nonce.data(), k.data()) != 0)
                return Result<SecureBuffer>::err("Noise: transport authentication failed");
            ++n;
            out.resize(static_cast<std::size_t>(olen));
            return Result<SecureBuffer>::ok(std::move(out));
        }

        /// Decrypt the record that was sent at counter `at`, without
        /// touching this state.
        ///
        /// Transport records are sealed under (k, counter), so any record
        /// can be opened independently once its counter is known. That is
        /// what lets a receiver decrypt several records at once instead of
        /// walking them one at a time — the sequential `decrypt` above is
        /// a serial bottleneck purely because it owns `n`.
        ///
        /// CONST-TIME: the AEAD tag check is libsodium's, which is
        /// constant-time; nothing here branches on plaintext.
        ///
        /// Deliberately `const`: not advancing `n` is the property that
        /// makes this re-entrant, so several threads may call it on one
        /// state concurrently. The compiler enforces it rather than a
        /// comment. CALLER'S DUTY: a counter must be opened at most once
        /// and the plaintexts reassembled in order — this cannot tell a
        /// replayed record from a fresh one, because statelessly it is
        /// the same record.
        ///
        /// There is deliberately NO explicit-nonce `encrypt` counterpart.
        /// Sealing twice under one (k, n) leaks the XOR of both plaintexts
        /// AND the Poly1305 one-time key, which yields forgery — so nonce
        /// choice stays with `n` above, where it cannot repeat. Opening
        /// carries no such risk: the tag binds the counter, so a record
        /// only authenticates under the one its sender used.
        [[nodiscard]] Result<SecureBuffer> decrypt_at(uint64_t at,
                                                      std::span<const uint8_t> ct,
                                                      std::span<const uint8_t> ad = {}) const {
            if (k.size() != 32) return Result<SecureBuffer>::err("Noise: transport not keyed");
            // Noise reserves the maximum counter; a sender must rekey
            // before reaching it, so a record claiming it is malformed.
            // VERIFY: Noise spec rev 34 §5.1 reserves n = 2^64-1.
            if (at == UINT64_MAX) return Result<SecureBuffer>::err("Noise: reserved nonce");
            if (ct.size() < TAGLEN) return Result<SecureBuffer>::err("Noise: transport ciphertext too short");
            SecureBuffer out(ct.size() - TAGLEN);
            unsigned long long olen = 0;
            std::array<uint8_t, 12> nonce = make_nonce(at);
            // AUTH-FIRST: libsodium writes no plaintext unless the tag verifies.
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    out.data(), &olen, nullptr, ct.data(), ct.size(),
                    ad.empty() ? nullptr : ad.data(), ad.size(),
                    nonce.data(), k.data()) != 0)
                return Result<SecureBuffer>::err("Noise: transport authentication failed");
            out.resize(static_cast<std::size_t>(olen));
            return Result<SecureBuffer>::ok(std::move(out));
        }
    };

    struct Session { CipherState send, recv; };

    [[nodiscard]] static NoiseXX initiator(const asymmetric::EncryptionKeyPair& static_kp,
                                           std::span<const uint8_t> prologue = {}) {
        return NoiseXX(true, static_kp, prologue);
    }
    [[nodiscard]] static NoiseXX responder(const asymmetric::EncryptionKeyPair& static_kp,
                                           std::span<const uint8_t> prologue = {}) {
        return NoiseXX(false, static_kp, prologue);
    }

    /// TEST-ONLY: force the ephemeral keypair used by the next `e` token so that
    /// handshakes become deterministic for known-answer (vector) validation.
    /// Production code must never call this — ephemerals must be random.
    void test_set_ephemeral(const asymmetric::EncryptionKeyPair& e) {
        e_.public_key = SecureBuffer(e.public_key.data(), e.public_key.size());
        e_.secret_key = SecureBuffer(e.secret_key.data(), e.secret_key.size());
        have_fixed_e_ = true;
    }

    [[nodiscard]] bool handshake_finished() const { return msg_index_ >= 3; }

    /// The peer's static public key learned during the handshake (XX exchanges
    /// statics in-band). Apps should pin/verify this to prevent MITM.
    [[nodiscard]] const SecureBuffer& remote_static() const { return rs_; }

    /// The Noise handshake hash `h` (32 bytes). After completion both parties
    /// agree on it; useful as a channel binding and for vector validation.
    [[nodiscard]] std::span<const uint8_t> handshake_hash() const { return h_; }

    /// Produce the next handshake message (your turn), embedding `payload`.
    [[nodiscard]] Result<SecureBuffer> write_message(std::span<const uint8_t> payload = {}) {
        if (handshake_finished()) return Result<SecureBuffer>::err("Noise: handshake already finished");
        if (!my_turn()) return Result<SecureBuffer>::err("Noise: not this party's turn to write");

        std::vector<uint8_t> out;
        for (Token t : pattern(msg_index_)) {
            switch (t) {
                case Token::E: {
                    if (!have_fixed_e_) e_ = asymmetric::X25519::generate_keypair();
                    append(out, e_.public_key.span());
                    mix_hash(e_.public_key.span());
                    break;
                }
                case Token::S: {
                    auto enc = encrypt_and_hash(s_.public_key.span());
                    if (enc.is_err()) return Result<SecureBuffer>::err(enc.error().message);
                    append(out, enc.value().span());
                    break;
                }
                default:
                    if (auto r = mix_dh(t); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
            }
        }
        auto tail = encrypt_and_hash(payload);
        if (tail.is_err()) return Result<SecureBuffer>::err(tail.error().message);
        append(out, tail.value().span());
        ++msg_index_;
        return Result<SecureBuffer>::ok(SecureBuffer(std::move(out)));
    }

    /// Consume a peer handshake message (peer's turn), returning the payload.
    [[nodiscard]] Result<SecureBuffer> read_message(std::span<const uint8_t> message) {
        if (handshake_finished()) return Result<SecureBuffer>::err("Noise: handshake already finished");
        if (my_turn()) return Result<SecureBuffer>::err("Noise: not peer's turn to read");

        std::size_t off = 0;
        for (Token t : pattern(msg_index_)) {
            switch (t) {
                case Token::E: {
                    if (message.size() - off < DHLEN) return Result<SecureBuffer>::err("Noise: truncated (e)");
                    re_ = SecureBuffer(message.data() + off, DHLEN); off += DHLEN;
                    mix_hash(re_.span());
                    break;
                }
                case Token::S: {
                    std::size_t need = has_key_ ? DHLEN + TAGLEN : DHLEN;
                    if (message.size() - off < need) return Result<SecureBuffer>::err("Noise: truncated (s)");
                    auto dec = decrypt_and_hash({message.data() + off, need}); off += need;
                    if (dec.is_err()) return Result<SecureBuffer>::err(dec.error().message);
                    rs_ = std::move(dec.value());
                    break;
                }
                default:
                    if (auto r = mix_dh(t); r.is_err()) return Result<SecureBuffer>::err(r.error().message);
            }
        }
        auto payload = decrypt_and_hash({message.data() + off, message.size() - off});
        if (payload.is_err()) return Result<SecureBuffer>::err(payload.error().message);
        ++msg_index_;
        return payload;
    }

    /// Valid once handshake_finished(): the two transport CipherStates.
    [[nodiscard]] Result<Session> into_session() {
        if (!handshake_finished()) return Result<Session>::err("Noise: handshake not finished");
        auto out = hkdf2(ck_, {});  // Split(): HKDF(ck, empty, 2)
        Session s;
        // Initiator sends with the first output, receives with the second.
        if (initiator_) { s.send.k = std::move(out.first); s.recv.k = std::move(out.second); }
        else            { s.send.k = std::move(out.second); s.recv.k = std::move(out.first); }
        return Result<Session>::ok(std::move(s));
    }

private:
    enum class Token { E, S, EE, ES, SE };

    bool initiator_;
    int  msg_index_ = 0;
    asymmetric::EncryptionKeyPair s_;   // local static
    asymmetric::EncryptionKeyPair e_;   // local ephemeral
    SecureBuffer rs_;                   // remote static
    SecureBuffer re_;                   // remote ephemeral
    // SymmetricState
    std::array<uint8_t, HASHLEN> ck_{};
    std::array<uint8_t, HASHLEN> h_{};
    SecureBuffer k_;                    // current handshake cipher key (empty ⇒ none)
    uint64_t     nk_ = 0;
    bool         has_key_ = false;
    bool         have_fixed_e_ = false; // test seam

    NoiseXX(bool initiator, const asymmetric::EncryptionKeyPair& static_kp,
            std::span<const uint8_t> prologue)
        : initiator_(initiator) {
        s_.public_key = SecureBuffer(static_kp.public_key.data(), static_kp.public_key.size());
        s_.secret_key = SecureBuffer(static_kp.secret_key.data(), static_kp.secret_key.size());
        // InitializeSymmetric(PROTOCOL): the name is exactly HASHLEN (32) bytes,
        // so h = name (no padding, no hashing).
        std::string_view name{PROTOCOL};
        std::memset(h_.data(), 0, HASHLEN);
        std::memcpy(h_.data(), name.data(), name.size());
        ck_ = h_;
        // HandshakeState init: MixHash(prologue) — required even when empty
        // (MixHash({}) = SHA256(h)). XX has no pre-messages.
        mix_hash(prologue);
    }

    [[nodiscard]] bool my_turn() const {
        // initiator writes even messages (0,2); responder writes odd (1).
        return initiator_ == ((msg_index_ % 2) == 0);
    }

    static std::span<const Token> pattern(int idx) {
        static const Token m0[] = {Token::E};
        static const Token m1[] = {Token::E, Token::EE, Token::S, Token::ES};
        static const Token m2[] = {Token::S, Token::SE};
        switch (idx) {
            case 0: return {m0, 1};
            case 1: return {m1, 4};
            default: return {m2, 2};
        }
    }

    static void append(std::vector<uint8_t>& v, std::span<const uint8_t> d) {
        v.insert(v.end(), d.begin(), d.end());
    }

    static std::array<uint8_t, 12> make_nonce(uint64_t n) {
        std::array<uint8_t, 12> nonce{};
        for (int i = 0; i < 8; ++i) nonce[4 + i] = static_cast<uint8_t>(n >> (8 * i));
        return nonce;
    }

    void mix_hash(std::span<const uint8_t> data) {
        std::vector<uint8_t> buf(h_.begin(), h_.end());
        buf.insert(buf.end(), data.begin(), data.end());
        auto d = hash::Sha256::digest(std::span<const uint8_t>{buf});
        std::memcpy(h_.data(), d.value().data(), HASHLEN);
    }

    // Noise HKDF(chaining_key, ikm, 2) → (out1, out2).
    struct Two { SecureBuffer first, second; };
    [[nodiscard]] static Two hkdf2(std::span<const uint8_t> ck, std::span<const uint8_t> ikm) {
        auto prk = hash::HkdfSha256::extract(ck, ikm);
        auto okm = hash::HkdfSha256::expand(prk.value().span(), std::span<const uint8_t>{}, 2 * HASHLEN);
        Two t{SecureBuffer(okm.value().data(), HASHLEN),
              SecureBuffer(okm.value().data() + HASHLEN, HASHLEN)};
        return t;
    }

    void mix_key(std::span<const uint8_t> ikm) {
        auto two = hkdf2(ck_, ikm);
        std::memcpy(ck_.data(), two.first.data(), HASHLEN);
        k_ = std::move(two.second);
        nk_ = 0;
        has_key_ = true;
    }

    [[nodiscard]] Result<void> mix_dh(Token t) {
        // DH peer/local selection per Noise token semantics.
        Result<SecureBuffer> dh = [&]() -> Result<SecureBuffer> {
            switch (t) {
                case Token::EE: return asymmetric::X25519::shared_secret(e_.secret_key.span(), re_.span());
                case Token::ES: return initiator_
                    ? asymmetric::X25519::shared_secret(e_.secret_key.span(), rs_.span())
                    : asymmetric::X25519::shared_secret(s_.secret_key.span(), re_.span());
                case Token::SE: return initiator_
                    ? asymmetric::X25519::shared_secret(s_.secret_key.span(), re_.span())
                    : asymmetric::X25519::shared_secret(e_.secret_key.span(), rs_.span());
                default: return Result<SecureBuffer>::err("Noise: bad DH token");
            }
        }();
        if (dh.is_err()) return Result<void>::err(dh.error().message);
        mix_key(dh.value().span());
        return Result<void>::ok();
    }

    [[nodiscard]] Result<SecureBuffer> encrypt_and_hash(std::span<const uint8_t> pt) {
        SecureBuffer ct;
        if (has_key_) {
            ct = SecureBuffer(pt.size() + TAGLEN);
            unsigned long long olen = 0;
            auto nonce = make_nonce(nk_);
            if (crypto_aead_chacha20poly1305_ietf_encrypt(
                    ct.data(), &olen, pt.data(), pt.size(),
                    h_.data(), HASHLEN, nullptr, nonce.data(), k_.data()) != 0)
                return Result<SecureBuffer>::err("Noise: handshake encrypt failed");
            ++nk_;
            ct.resize(static_cast<std::size_t>(olen));
        } else {
            ct = SecureBuffer(pt.data(), pt.size());
        }
        mix_hash(ct.span());
        return Result<SecureBuffer>::ok(std::move(ct));
    }

    [[nodiscard]] Result<SecureBuffer> decrypt_and_hash(std::span<const uint8_t> ct) {
        SecureBuffer pt;
        if (has_key_) {
            if (ct.size() < TAGLEN) return Result<SecureBuffer>::err("Noise: handshake ciphertext too short");
            pt = SecureBuffer(ct.size() - TAGLEN);
            unsigned long long olen = 0;
            auto nonce = make_nonce(nk_);
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    pt.data(), &olen, nullptr, ct.data(), ct.size(),
                    h_.data(), HASHLEN, nonce.data(), k_.data()) != 0)
                return Result<SecureBuffer>::err("Noise: handshake authentication failed");
            ++nk_;
            pt.resize(static_cast<std::size_t>(olen));
        } else {
            pt = SecureBuffer(ct.data(), ct.size());
        }
        mix_hash(ct);
        return Result<SecureBuffer>::ok(std::move(pt));
    }
};

} // namespace crypto
