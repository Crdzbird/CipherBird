#pragma once

/**
 * crypto::cb1 - CipherBird tokens, version 1: the PASETO v4 token shape
 * carried by this library's own primitives. A PASETO parser rejects a cb1
 * token by its header, and these classes reject PASETO tokens the same way;
 * the two formats never pass for each other.
 *
 * cb1.local is PASETO v4.local with BLAKE3 in place of BLAKE2b. A random
 * 32-byte nonce n; Ek || n2 = BLAKE3 keyed with K over "cb1-encryption-key"
 * || n, 56 bytes of extendable output; Ak = BLAKE3 keyed with K over
 * "cb1-auth-key" || n, 32 bytes; c = XChaCha20(Ek, n2) XOR m; t = BLAKE3
 * keyed with Ak over PAE("cb1.local.", n, c, f, i), 32 bytes; token =
 * "cb1.local." || base64url(n || c || t) and, when f is not empty, "." ||
 * base64url(f). The authentication key is derived from K, so the tag commits
 * the token to the key: a ciphertext cannot open under a second key.
 *
 * cb1.public is PASETO v4.public with the Ed25519 + ML-DSA-65 hybrid
 * signature in place of Ed25519: sig = HybridSig(sk, PAE("cb1.public.", m,
 * f, i)); token = "cb1.public." || base64url(m || sig) and the same footer
 * rule. A token verifies only if both signature halves verify, so it stays
 * unforgeable while either Ed25519 or ML-DSA-65 is unbroken.
 *
 * The local functions write into caller-provided buffers, allocate nothing
 * and lock no memory; derived keys live on the stack and are wiped on every
 * path, and the tag is verified in constant time before anything is
 * decrypted. The public functions build the pre-authentication encoding in
 * plain memory, because every byte of it is public.
 */

#include "paseto.hpp"
#include "hash.hpp"
#ifdef CRYPTOLIB_HAS_PQ
#include "hybrid_sig.hpp"
#endif
#include <vector>

namespace crypto::cb1 {

namespace codec = paseto::codec;

/// ok; invalid (any token, footer, tag or signature failure, one verdict);
/// argument (a caller error that does not depend on token content);
/// internal (the backend failed).
enum class Status { ok, invalid, argument, internal };

inline constexpr std::size_t MAX_INPUT_BYTES = std::size_t{1} << 26;

namespace detail {

[[nodiscard]] constexpr std::size_t b64_len(std::size_t n) noexcept { return codec::encoded_len(n); }

/// Token length for a header, a raw body and a footer, or 0 when an input
/// exceeds MAX_INPUT_BYTES.
[[nodiscard]] constexpr std::size_t
token_len(std::size_t header, std::size_t raw_len, std::size_t footer_len) noexcept {
    const std::size_t f = footer_len == 0 ? 0 : 1 + b64_len(footer_len);
    return header + b64_len(raw_len) + f;
}

/// Splits a token after its header into the body text and the optional
/// footer text. Returns false when the header does not match, a dot is
/// followed by nothing, or the presence of a footer disagrees with
/// expected_footer being empty.
struct Split { const char* body; std::size_t body_len; const char* footer; std::size_t footer_len; };

[[nodiscard]] inline bool split(std::span<const uint8_t> token, std::string_view header,
                                bool expect_footer, Split& out) noexcept {
    if (token.size() <= header.size() ||
        std::memcmp(token.data(), header.data(), header.size()) != 0)
        return false;
    const char* rest = reinterpret_cast<const char*>(token.data()) + header.size();
    const std::size_t rest_len = token.size() - header.size();
    const char* dot = static_cast<const char*>(std::memchr(rest, '.', rest_len));
    out.body = rest;
    out.body_len = dot ? static_cast<std::size_t>(dot - rest) : rest_len;
    out.footer = dot ? dot + 1 : nullptr;
    out.footer_len = dot ? rest_len - out.body_len - 1 : 0;
    if (dot != nullptr && out.footer_len == 0) return false;
    return (dot != nullptr) == expect_footer;
}

/// Decodes the footer text into work and compares it with the expected one.
[[nodiscard]] inline bool footer_matches(uint8_t* work, std::size_t cap, const Split& s,
                                         std::span<const uint8_t> expected) noexcept {
    std::size_t flen = 0;
    if (s.footer && !codec::decode(work, cap, s.footer, s.footer_len, flen)) return false;
    return flen == expected.size() && (flen == 0 || std::memcmp(work, expected.data(), flen) == 0);
}

/// Writes the token text: header, the base64url of raw (already placed at
/// the end of the body region), and the footer.
inline std::size_t finish(std::span<uint8_t> out, std::string_view header, const uint8_t* raw,
                          std::size_t raw_len, std::span<const uint8_t> footer) noexcept {
    std::memcpy(out.data(), header.data(), header.size());
    std::size_t pos = header.size() + codec::encode(out.data() + header.size(), raw, raw_len);
    if (!footer.empty()) {
        out[pos++] = '.';
        pos += codec::encode(out.data() + pos, footer.data(), footer.size());
    }
    return pos;
}

}

#ifdef CRYPTOLIB_HAS_BLAKE3

/// cb1.local encrypt and decrypt into caller-provided buffers.
class Local {
public:
    static constexpr std::size_t KEY_BYTES = 32;
    static constexpr std::size_t NONCE_BYTES = 32;
    static constexpr std::size_t TAG_BYTES = 32;
    static constexpr std::string_view HEADER = "cb1.local.";

    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        if (msg_len > MAX_INPUT_BYTES || footer_len > MAX_INPUT_BYTES) return 0;
        return detail::token_len(HEADER.size(), NONCE_BYTES + msg_len + TAG_BYTES, footer_len);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return token_len(MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    /// Output capacity decrypt requires for a token of token_len bytes; 0 for
    /// a length no valid token has.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        if (token_len <= HEADER.size() || token_len > max_token_len()) return 0;
        return (token_len - HEADER.size()) * 3 / 4;
    }

    /// Encrypts msg with a fresh nonce. out must hold token_len(msg.size(),
    /// footer.size()) bytes and overlap no input; on success out_len is that
    /// length, otherwise 0.
    [[nodiscard]] static Status
    seal(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> key,
         std::span<const uint8_t> msg, std::span<const uint8_t> footer,
         std::span<const uint8_t> implicit) noexcept {
        uint8_t n[NONCE_BYTES];
        paseto::detail::NonceSource::fresh(n, NONCE_BYTES);
        return seal_impl(out, out_len, key, msg, footer, implicit, n);
    }

#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    /// Test builds only: seal with a caller-chosen nonce, for pinned vectors.
    [[nodiscard]] static Status
    seal_with_nonce_for_testing(std::span<uint8_t> out, std::size_t& out_len,
                                std::span<const uint8_t> key, std::span<const uint8_t> msg,
                                std::span<const uint8_t> footer, std::span<const uint8_t> implicit,
                                std::span<const uint8_t> nonce) noexcept {
        out_len = 0;
        if (nonce.size() != NONCE_BYTES) return Status::argument;
        return seal_impl(out, out_len, key, msg, footer, implicit, nonce.data());
    }
#endif

    /// Authenticates and decrypts token; the tag is verified in constant time
    /// before anything is decrypted. out must hold open_capacity(token.size())
    /// bytes and overlap no input; on success the message is out[0, out_len)
    /// and the rest of that region is zero, on failure the whole region is
    /// zero and out_len is 0.
    [[nodiscard]] static Status
    open(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> token,
         std::span<const uint8_t> key, std::span<const uint8_t> expected_footer,
         std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t cap = open_capacity(token.size());
        if (key.size() != KEY_BYTES || expected_footer.size() > MAX_INPUT_BYTES ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < cap)
            return Status::argument;
        if (paseto::detail::overlaps(out, token) || paseto::detail::overlaps(out, key) ||
            paseto::detail::overlaps(out, expected_footer) || paseto::detail::overlaps(out, implicit))
            return Status::argument;
        const Status s = open_impl(out.first(cap), out_len, token, key, expected_footer, implicit);
        if (s == Status::ok) return s;
        if (cap != 0) sodium_memzero(out.data(), cap);
        out_len = 0;
        return s;
    }

private:
    static constexpr std::string_view ENC_DOMAIN = "cb1-encryption-key";
    static constexpr std::string_view AUTH_DOMAIN = "cb1-auth-key";

    struct Keys {
        uint8_t split[56];
        uint8_t ak[KEY_BYTES];
        uint8_t tag[TAG_BYTES];
        hash::blake3_hasher h;
        const uint8_t* ek() const noexcept { return split; }
        const uint8_t* n2() const noexcept { return split + 32; }
        Keys() noexcept = default;
        Keys(const Keys&) = delete;
        Keys& operator=(const Keys&) = delete;
        ~Keys() { sodium_memzero(this, sizeof *this); }
    };

    static void derive(Keys& k, const uint8_t* key, const uint8_t* n) noexcept {
        blake3_hasher_init_keyed(&k.h, key);
        blake3_hasher_update(&k.h, ENC_DOMAIN.data(), ENC_DOMAIN.size());
        blake3_hasher_update(&k.h, n, NONCE_BYTES);
        blake3_hasher_finalize(&k.h, k.split, sizeof k.split);
        blake3_hasher_init_keyed(&k.h, key);
        blake3_hasher_update(&k.h, AUTH_DOMAIN.data(), AUTH_DOMAIN.size());
        blake3_hasher_update(&k.h, n, NONCE_BYTES);
        blake3_hasher_finalize(&k.h, k.ak, sizeof k.ak);
    }

    static void pae_piece(hash::blake3_hasher& h, const uint8_t* p, std::size_t n) noexcept {
        uint8_t le[8];
        paseto::detail::put_le(le, n);
        blake3_hasher_update(&h, le, sizeof le);
        if (n != 0) blake3_hasher_update(&h, p, n);
    }

    static void mac(Keys& k, uint8_t* tag, const uint8_t* n, std::span<const uint8_t> c,
                    std::span<const uint8_t> f, std::span<const uint8_t> i) noexcept {
        uint8_t le[8];
        blake3_hasher_init_keyed(&k.h, k.ak);
        paseto::detail::put_le(le, 5);
        blake3_hasher_update(&k.h, le, sizeof le);
        pae_piece(k.h, reinterpret_cast<const uint8_t*>(HEADER.data()), HEADER.size());
        pae_piece(k.h, n, NONCE_BYTES);
        pae_piece(k.h, c.data(), c.size());
        pae_piece(k.h, f.data(), f.size());
        pae_piece(k.h, i.data(), i.size());
        blake3_hasher_finalize(&k.h, tag, TAG_BYTES);
    }

    static Status seal_impl(std::span<uint8_t> out, std::size_t& out_len,
                            std::span<const uint8_t> key, std::span<const uint8_t> msg,
                            std::span<const uint8_t> footer, std::span<const uint8_t> implicit,
                            const uint8_t* n) noexcept {
        out_len = 0;
        const std::size_t need = token_len(msg.size(), footer.size());
        if (key.size() != KEY_BYTES || need == 0 || implicit.size() > MAX_INPUT_BYTES ||
            out.size() < need)
            return Status::argument;
        if (paseto::detail::overlaps(out, key) || paseto::detail::overlaps(out, msg) ||
            paseto::detail::overlaps(out, footer) || paseto::detail::overlaps(out, implicit))
            return Status::argument;
        const std::size_t raw_len = NONCE_BYTES + msg.size() + TAG_BYTES;
        uint8_t* raw = out.data() + HEADER.size() + detail::b64_len(raw_len) - raw_len;
        uint8_t* c = raw + NONCE_BYTES;
        Keys k;
        derive(k, key.data(), n);
        std::memcpy(raw, n, NONCE_BYTES);
        if (!msg.empty() &&
            crypto_stream_xchacha20_xor(c, msg.data(), msg.size(), k.n2(), k.ek()) != 0) {
            sodium_memzero(out.data(), need);
            return Status::internal;
        }
        mac(k, c + msg.size(), n, {c, msg.size()}, footer, implicit);
        out_len = detail::finish(out, HEADER, raw, raw_len, footer);
        return Status::ok;
    }

    static Status open_impl(std::span<uint8_t> work, std::size_t& out_len,
                            std::span<const uint8_t> token, std::span<const uint8_t> key,
                            std::span<const uint8_t> expected_footer,
                            std::span<const uint8_t> implicit) noexcept {
        detail::Split s{};
        if (work.empty() || !detail::split(token, HEADER, !expected_footer.empty(), s))
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!codec::decode(work.data(), work.size(), s.body, s.body_len, raw_len) ||
            raw_len < NONCE_BYTES + TAG_BYTES)
            return Status::invalid;
        if (!detail::footer_matches(work.data() + raw_len, work.size() - raw_len, s, expected_footer))
            return Status::invalid;
        uint8_t n[NONCE_BYTES];
        uint8_t t[TAG_BYTES];
        std::memcpy(n, work.data(), NONCE_BYTES);
        std::memcpy(t, work.data() + raw_len - TAG_BYTES, TAG_BYTES);
        const std::size_t clen = raw_len - NONCE_BYTES - TAG_BYTES;
        uint8_t* c = work.data() + NONCE_BYTES;
        Keys k;
        derive(k, key.data(), n);
        mac(k, k.tag, n, {c, clen}, expected_footer, implicit);
        int verdict = crypto_verify_32(t, k.tag);
        crypto::detail::ct_declassify(&verdict, sizeof verdict);
        if (verdict != 0) return Status::invalid;
        std::memmove(work.data(), c, clen);
        if (clen != 0 &&
            crypto_stream_xchacha20_xor(work.data(), work.data(), clen, k.n2(), k.ek()) != 0)
            return Status::internal;
        sodium_memzero(work.data() + clen, work.size() - clen);
        out_len = clen;
        return Status::ok;
    }
};

#endif

#ifdef CRYPTOLIB_HAS_PQ

/// cb1.public sign and verify into caller-provided buffers. Keys are the
/// Ed25519 + ML-DSA-65 hybrid pairs of pq::HybridSig: public key 1984 bytes,
/// secret key 4096 bytes, signature 3373 bytes.
class Public {
public:
    static constexpr std::size_t PUBLIC_KEY_BYTES = 32 + 1952;
    static constexpr std::size_t SECRET_KEY_BYTES = 64 + 4032;
    static constexpr std::size_t SIG_BYTES = 64 + 3309;
    static constexpr std::string_view HEADER = "cb1.public.";

    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        if (msg_len > MAX_INPUT_BYTES || footer_len > MAX_INPUT_BYTES) return 0;
        return detail::token_len(HEADER.size(), msg_len + SIG_BYTES, footer_len);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return token_len(MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    /// Output capacity verify requires for a token of token_len bytes; 0 for
    /// a length no valid token has.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        if (token_len <= HEADER.size() || token_len > max_token_len()) return 0;
        return (token_len - HEADER.size()) * 3 / 4;
    }

    /// Signs msg. out must hold token_len(msg.size(), footer.size()) bytes and
    /// overlap no input; on success out_len is that length, otherwise 0.
    [[nodiscard]] static Status
    sign(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> secret_key,
         std::span<const uint8_t> msg, std::span<const uint8_t> footer,
         std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t need = token_len(msg.size(), footer.size());
        if (secret_key.size() != SECRET_KEY_BYTES || need == 0 ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < need)
            return Status::argument;
        if (paseto::detail::overlaps(out, secret_key) || paseto::detail::overlaps(out, msg) ||
            paseto::detail::overlaps(out, footer) || paseto::detail::overlaps(out, implicit))
            return Status::argument;
        try {
            const std::vector<uint8_t> m2 = pae(msg, footer, implicit);
            auto sig = pq::HybridSig::sign(m2, secret_key);
            if (sig.is_err() || sig.value().size() != SIG_BYTES) return Status::internal;
            const std::size_t raw_len = msg.size() + SIG_BYTES;
            uint8_t* raw = out.data() + HEADER.size() + detail::b64_len(raw_len) - raw_len;
            if (!msg.empty()) std::memmove(raw, msg.data(), msg.size());
            std::memcpy(raw + msg.size(), sig.value().data(), SIG_BYTES);
            out_len = detail::finish(out, HEADER, raw, raw_len, footer);
            return Status::ok;
        } catch (...) {
            return Status::internal;
        }
    }

    /// Verifies token under public_key. out must hold
    /// open_capacity(token.size()) bytes and overlap no input; on success the
    /// message is out[0, out_len) and the rest of that region is zero, on
    /// failure the whole region is zero and out_len is 0.
    [[nodiscard]] static Status
    verify(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> token,
           std::span<const uint8_t> public_key, std::span<const uint8_t> expected_footer,
           std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t cap = open_capacity(token.size());
        if (public_key.size() != PUBLIC_KEY_BYTES || expected_footer.size() > MAX_INPUT_BYTES ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < cap)
            return Status::argument;
        if (paseto::detail::overlaps(out, token) || paseto::detail::overlaps(out, public_key) ||
            paseto::detail::overlaps(out, expected_footer) || paseto::detail::overlaps(out, implicit))
            return Status::argument;
        Status s = Status::internal;
        try {
            s = verify_impl(out.first(cap), out_len, token, public_key, expected_footer, implicit);
        } catch (...) {
            s = Status::internal;
        }
        if (s == Status::ok) return s;
        if (cap != 0) sodium_memzero(out.data(), cap);
        out_len = 0;
        return s;
    }

private:
    static void piece(std::vector<uint8_t>& v, const uint8_t* p, std::size_t n) {
        uint8_t le[8];
        paseto::detail::put_le(le, n);
        v.insert(v.end(), le, le + 8);
        if (n != 0) v.insert(v.end(), p, p + n);
    }

    /// PAE("cb1.public.", m, f, i), in plain memory: every piece is public.
    [[nodiscard]] static std::vector<uint8_t>
    pae(std::span<const uint8_t> m, std::span<const uint8_t> f, std::span<const uint8_t> i) {
        std::vector<uint8_t> v;
        v.reserve(8 * 5 + HEADER.size() + m.size() + f.size() + i.size());
        uint8_t le[8];
        paseto::detail::put_le(le, 4);
        v.insert(v.end(), le, le + 8);
        piece(v, reinterpret_cast<const uint8_t*>(HEADER.data()), HEADER.size());
        piece(v, m.data(), m.size());
        piece(v, f.data(), f.size());
        piece(v, i.data(), i.size());
        return v;
    }

    static Status verify_impl(std::span<uint8_t> work, std::size_t& out_len,
                              std::span<const uint8_t> token, std::span<const uint8_t> public_key,
                              std::span<const uint8_t> expected_footer,
                              std::span<const uint8_t> implicit) {
        detail::Split s{};
        if (work.empty() || !detail::split(token, HEADER, !expected_footer.empty(), s))
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!codec::decode(work.data(), work.size(), s.body, s.body_len, raw_len) ||
            raw_len < SIG_BYTES)
            return Status::invalid;
        if (!detail::footer_matches(work.data() + raw_len, work.size() - raw_len, s, expected_footer))
            return Status::invalid;
        const std::size_t mlen = raw_len - SIG_BYTES;
        const std::span<const uint8_t> m(work.data(), mlen);
        const std::span<const uint8_t> sig(work.data() + mlen, SIG_BYTES);
        const std::vector<uint8_t> m2 = pae(m, expected_footer, implicit);
        if (pq::HybridSig::verify(m2, sig, public_key).is_err()) return Status::invalid;
        sodium_memzero(work.data() + mlen, work.size() - mlen);
        out_len = mlen;
        return Status::ok;
    }
};

#endif

}
