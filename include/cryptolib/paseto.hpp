#pragma once

/**
 * crypto::paseto - PASETO version 4 local tokens (v4.local).
 *
 * The construction of the PASETO v4 specification: a random 32-byte nonce n;
 * Ek || n2 = BLAKE2b-448 keyed with K over "paseto-encryption-key" || n;
 * Ak = BLAKE2b-256 keyed with K over "paseto-auth-key-for-aead" || n;
 * c = XChaCha20(Ek, n2) XOR m; t = BLAKE2b-256 keyed with Ak over
 * PAE("v4.local.", n, c, f, i); token = "v4.local." || base64url(n || c || t)
 * and, when f is not empty, "." || base64url(f). Base64url is unpadded.
 *
 * Every function writes into a buffer the caller provides, allocates nothing
 * and locks no memory. Derived keys live on the stack and are wiped with
 * sodium_memzero on every path. The raw XChaCha20 stream is used only here,
 * after the tag has been verified in constant time.
 *
 * The token text is encoded and decoded by the table-driven base64url codec
 * in crypto::paseto::codec instead of libsodium's constant-time codec, which
 * cost about 0.8 us per token each way. Everything it touches is public: the nonce, the
 * ciphertext and the tag are the token itself, and the footer is sent in
 * clear. The decoder is as strict as libsodium's with the URL-safe unpadded
 * variant: only the 64 URL-safe characters, no padding, no length of 1 mod
 * 4, and the unused low bits of the last character must be zero, so every
 * byte string has exactly one accepted encoding. The footer is public too,
 * so it is compared with memcmp; the tag is compared with crypto_verify_32.
 * The PAE header, the nonce and the ciphertext length are fed to BLAKE2b as
 * one block of 73 bytes instead of six updates.
 *
 * Nonces come from the batched CSPRNG source in detail::NonceSource, shared
 * with the cb1 tokens.
 */

#include "detail/ct.hpp"
#include <sodium.h>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#if defined(__unix__) || defined(__APPLE__)
#include <pthread.h>
#endif

namespace crypto::paseto {

/// Base64url (RFC 4648 section 5, unpadded) for PASETO token text. Not
/// constant time: use it only for public bytes such as token bodies and
/// footers, never for keys.
namespace codec {

inline constexpr char B64URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
inline constexpr uint8_t B64URL_BAD = 0x80;

struct B64UrlDecodeTable {
    uint8_t v[256];
    constexpr B64UrlDecodeTable() noexcept : v{} {
        for (auto& x : v) x = B64URL_BAD;
        for (uint8_t k = 0; k < 64; ++k) v[static_cast<unsigned char>(B64URL_ALPHABET[k])] = k;
    }
};

inline constexpr B64UrlDecodeTable B64URL_DECODE{};

/// Number of characters encode writes for len bytes.
[[nodiscard]] constexpr std::size_t encoded_len(std::size_t len) noexcept {
    return len / 3 * 4 + (len % 3 == 0 ? 0 : len % 3 + 1);
}

/// Writes the unpadded base64url of src[0, len) to dst and returns
/// encoded_len(len). The two must not overlap, except that src may begin
/// encoded_len(len) - len or more bytes after dst, as when the input sits at
/// the end of the output region: each input group is read before its output
/// is written, and the output never catches up with unread input.
inline std::size_t encode(uint8_t* dst, const uint8_t* src, std::size_t len) noexcept {
    std::size_t i = 0, w = 0;
    for (; len - i >= 3; i += 3, w += 4) {
        const uint32_t v = uint32_t{src[i]} << 16 | uint32_t{src[i + 1]} << 8 | src[i + 2];
        dst[w] = static_cast<uint8_t>(B64URL_ALPHABET[v >> 18]);
        dst[w + 1] = static_cast<uint8_t>(B64URL_ALPHABET[(v >> 12) & 63]);
        dst[w + 2] = static_cast<uint8_t>(B64URL_ALPHABET[(v >> 6) & 63]);
        dst[w + 3] = static_cast<uint8_t>(B64URL_ALPHABET[v & 63]);
    }
    const std::size_t rem = len - i;
    if (rem == 0) return w;
    const uint32_t v = uint32_t{src[i]} << 16 | (rem == 2 ? uint32_t{src[i + 1]} << 8 : 0);
    dst[w] = static_cast<uint8_t>(B64URL_ALPHABET[v >> 18]);
    dst[w + 1] = static_cast<uint8_t>(B64URL_ALPHABET[(v >> 12) & 63]);
    if (rem == 2) dst[w + 2] = static_cast<uint8_t>(B64URL_ALPHABET[(v >> 6) & 63]);
    return w + rem + 1;
}

/// Decodes src[0, len) into dst (capacity cap) and sets n to the decoded
/// length. It accepts exactly the strings libsodium's sodium_base642bin
/// accepts with sodium_base64_VARIANT_URLSAFE_NO_PADDING and no ignored
/// characters: only the 64 URL-safe characters, no padding, a length that
/// is not 1 mod 4, and zero unused bits in the last character, so each byte
/// string has one accepted encoding. Returns false, with n set to 0, on any
/// other input or when the result would exceed cap; dst may then hold
/// partial output.
inline bool decode(uint8_t* dst, std::size_t cap, const char* src, std::size_t len,
                   std::size_t& n) noexcept {
    n = 0;
    const std::size_t rem = len % 4;
    const std::size_t need = len / 4 * 3 + (rem == 0 ? 0 : rem - 1);
    if (rem == 1 || need > cap) return false;
    const auto* s = reinterpret_cast<const unsigned char*>(src);
    uint32_t bad = 0;
    std::size_t i = 0, w = 0;
    for (; len - i >= 4; i += 4, w += 3) {
        const uint32_t a = B64URL_DECODE.v[s[i]], b = B64URL_DECODE.v[s[i + 1]];
        const uint32_t c = B64URL_DECODE.v[s[i + 2]], d = B64URL_DECODE.v[s[i + 3]];
        bad |= a | b | c | d;
        const uint32_t v = (a & 63) << 18 | (b & 63) << 12 | (c & 63) << 6 | (d & 63);
        dst[w] = static_cast<uint8_t>(v >> 16);
        dst[w + 1] = static_cast<uint8_t>(v >> 8);
        dst[w + 2] = static_cast<uint8_t>(v);
    }
    if (rem != 0) {
        const uint32_t a = B64URL_DECODE.v[s[i]], b = B64URL_DECODE.v[s[i + 1]];
        const uint32_t c = rem == 3 ? B64URL_DECODE.v[s[i + 2]] : 0;
        bad |= a | b | c;
        const uint32_t v = (a & 63) << 18 | (b & 63) << 12 | (c & 63) << 6;
        const uint32_t spare = rem == 2 ? (v >> 8) & 0xFF : v & 0xFF;
        bad |= spare == 0 ? 0 : B64URL_BAD;
        dst[w] = static_cast<uint8_t>(v >> 16);
        if (rem == 3) dst[w + 1] = static_cast<uint8_t>(v >> 8);
    }
    if ((bad & B64URL_BAD) != 0) return false;
    n = need;
    return true;
}

}

/// Helpers every token class shares: little-endian lengths for PAE, overlap
/// checks, and the nonce source.
namespace detail {

inline void put_le(uint8_t* p, std::size_t n) noexcept {
    const uint64_t v = static_cast<uint64_t>(n) & 0x7FFFFFFFFFFFFFFFULL;
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

inline bool overlaps(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept {
    if (a.empty() || b.empty()) return false;
    const auto a0 = reinterpret_cast<std::uintptr_t>(a.data());
    const auto b0 = reinterpret_cast<std::uintptr_t>(b.data());
    return a0 < b0 + b.size() && b0 < a0 + a.size();
}

/// Nonces come from libsodium's CSPRNG (randombytes_buf), drawn 1 KiB at a
/// time into a per-thread batch because each operating-system call costs
/// microseconds and is serialised across threads. A nonce is public and only
/// has to be unique, so the batch is not secret; each nonce is zeroed in the
/// batch as it is taken, and a fork handler discards every batch in the child
/// so a parent and child never emit the same nonce.
class NonceSource {
public:
    static constexpr std::size_t BATCH_BYTES = 1024;

    /// Writes len fresh bytes (at most BATCH_BYTES) to n.
    static void fresh(uint8_t* n, std::size_t len) noexcept {
        struct Batch {
            uint8_t buf[BATCH_BYTES];
            std::size_t pos = sizeof buf;
            unsigned gen = 0;
        };
        static const bool hooked = fork_hook();
        static thread_local Batch batch;
        const unsigned g = fork_generation().load(std::memory_order_relaxed);
        if (!hooked || len > sizeof batch.buf) {
            randombytes_buf(n, len);
            return;
        }
        if (batch.pos + len > sizeof batch.buf || batch.gen != g) {
            randombytes_buf(batch.buf, sizeof batch.buf);
            batch.pos = 0;
            batch.gen = g;
        }
        std::memcpy(n, batch.buf + batch.pos, len);
        sodium_memzero(batch.buf + batch.pos, len);
        batch.pos += len;
    }

private:
    static std::atomic<unsigned>& fork_generation() noexcept {
        static std::atomic<unsigned> g{0};
        return g;
    }

    static void on_fork_child() noexcept {
        fork_generation().fetch_add(1, std::memory_order_relaxed);
    }

    static bool fork_hook() noexcept {
#if defined(__unix__) || defined(__APPLE__)
        return pthread_atfork(nullptr, nullptr, &NonceSource::on_fork_child) == 0;
#else
        return true;
#endif
    }
};

}

/// PASETO v4.local encrypt and decrypt into caller-provided buffers.
class V4Local {
public:
    static constexpr std::size_t KEY_BYTES = 32;
    static constexpr std::size_t NONCE_BYTES = 32;
    static constexpr std::size_t TAG_BYTES = 32;
    static constexpr std::size_t MAX_INPUT_BYTES = std::size_t{1} << 26;
    static constexpr std::string_view HEADER = "v4.local.";

    /// ok; invalid (decrypt: any token, footer or tag failure, one verdict);
    /// argument (a caller error that does not depend on token content);
    /// internal (the backend failed).
    enum class Status { ok, invalid, argument, internal };

    /// Exact token length for a message and footer, or 0 when either
    /// exceeds MAX_INPUT_BYTES.
    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        if (msg_len > MAX_INPUT_BYTES || footer_len > MAX_INPUT_BYTES) return 0;
        const std::size_t f = footer_len == 0 ? 0 : 1 + b64_len(footer_len);
        return HEADER.size() + b64_len(NONCE_BYTES + msg_len + TAG_BYTES) + f;
    }

    /// Length of the longest token decrypt accepts.
    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return token_len(MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    /// Output capacity decrypt requires for a token of token_len bytes. It
    /// depends only on the length, and is 0 for a length no valid token has.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        if (token_len <= HEADER.size() || token_len > max_token_len()) return 0;
        return (token_len - HEADER.size()) * 3 / 4;
    }

    /// Encrypts msg with a fresh nonce from libsodium's CSPRNG. out must hold
    /// token_len(msg.size(), footer.size()) bytes and overlap no input; on
    /// success out_len is that length, otherwise 0.
    [[nodiscard]] static Status
    seal(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> key,
         std::span<const uint8_t> msg, std::span<const uint8_t> footer,
         std::span<const uint8_t> implicit) noexcept {
        uint8_t n[NONCE_BYTES];
        detail::NonceSource::fresh(n, NONCE_BYTES);
        return seal_impl(out, out_len, key, msg, footer, implicit, n);
    }

#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    /// Test builds only: seal with a caller-chosen nonce, for the official
    /// test vectors. A repeated nonce under one key reuses the keystream.
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

    /// Authenticates and decrypts token. expected_footer must equal the
    /// token's footer exactly; empty means the token must carry none. The tag
    /// is verified in constant time before anything is decrypted. out must
    /// hold open_capacity(token.size()) bytes and overlap no input; on success
    /// the message is out[0, out_len) and the rest of that region is zero, on
    /// failure the whole region is zero and out_len is 0.
    [[nodiscard]] static Status
    open(std::span<uint8_t> out, std::size_t& out_len, std::span<const uint8_t> token,
         std::span<const uint8_t> key, std::span<const uint8_t> expected_footer,
         std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t cap = open_capacity(token.size());
        if (key.size() != KEY_BYTES || expected_footer.size() > MAX_INPUT_BYTES ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < cap)
            return Status::argument;
        if (detail::overlaps(out, token) || detail::overlaps(out, key) || detail::overlaps(out, expected_footer) ||
            detail::overlaps(out, implicit))
            return Status::argument;
        const Status s = open_impl(out.first(cap), out_len, token, key, expected_footer, implicit);
        if (s == Status::ok) return s;
        if (cap != 0) sodium_memzero(out.data(), cap);
        out_len = 0;
        return s;
    }

private:
    static constexpr std::string_view ENC_DOMAIN = "paseto-encryption-key";
    static constexpr std::string_view AUTH_DOMAIN = "paseto-auth-key-for-aead";

    struct Keys {
        uint8_t split[56];
        uint8_t ak[KEY_BYTES];
        uint8_t tag[TAG_BYTES];
        const uint8_t* ek() const noexcept { return split; }
        const uint8_t* n2() const noexcept { return split + 32; }
        Keys() noexcept = default;
        Keys(const Keys&) = delete;
        Keys& operator=(const Keys&) = delete;
        ~Keys() { sodium_memzero(this, sizeof *this); }
    };

    static constexpr std::size_t b64_len(std::size_t n) noexcept { return codec::encoded_len(n); }

    static int derive(Keys& k, const uint8_t* key, const uint8_t* n) noexcept {
        uint8_t m[AUTH_DOMAIN.size() + NONCE_BYTES];
        std::memcpy(m, ENC_DOMAIN.data(), ENC_DOMAIN.size());
        std::memcpy(m + ENC_DOMAIN.size(), n, NONCE_BYTES);
        int rc = crypto_generichash(k.split, sizeof k.split, m, ENC_DOMAIN.size() + NONCE_BYTES,
                                    key, KEY_BYTES);
        std::memcpy(m, AUTH_DOMAIN.data(), AUTH_DOMAIN.size());
        std::memcpy(m + AUTH_DOMAIN.size(), n, NONCE_BYTES);
        rc |= crypto_generichash(k.ak, sizeof k.ak, m, sizeof m, key, KEY_BYTES);
        return rc;
    }

    static constexpr std::size_t PAE_HEAD = 8 + 8 + HEADER.size() + 8 + NONCE_BYTES + 8;

    static int pae_piece(crypto_generichash_state& st, const uint8_t* p, std::size_t n) noexcept {
        uint8_t le[8];
        detail::put_le(le, n);
        int rc = crypto_generichash_update(&st, le, sizeof le);
        if (n != 0) rc |= crypto_generichash_update(&st, p, n);
        return rc;
    }

    static int mac(uint8_t* tag, const uint8_t* ak, const uint8_t* n,
                   std::span<const uint8_t> c, std::span<const uint8_t> f,
                   std::span<const uint8_t> i) noexcept {
        uint8_t head[PAE_HEAD];
        detail::put_le(head, 5);
        detail::put_le(head + 8, HEADER.size());
        std::memcpy(head + 16, HEADER.data(), HEADER.size());
        detail::put_le(head + 16 + HEADER.size(), NONCE_BYTES);
        std::memcpy(head + 24 + HEADER.size(), n, NONCE_BYTES);
        detail::put_le(head + 24 + HEADER.size() + NONCE_BYTES, c.size());
        crypto_generichash_state st;
        int rc = crypto_generichash_init(&st, ak, KEY_BYTES, TAG_BYTES);
        rc |= crypto_generichash_update(&st, head, sizeof head);
        if (!c.empty()) rc |= crypto_generichash_update(&st, c.data(), c.size());
        rc |= pae_piece(st, f.data(), f.size());
        rc |= pae_piece(st, i.data(), i.size());
        rc |= crypto_generichash_final(&st, tag, TAG_BYTES);
        sodium_memzero(&st, sizeof st);
        return rc;
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
        if (detail::overlaps(out, key) || detail::overlaps(out, msg) || detail::overlaps(out, footer) ||
            detail::overlaps(out, implicit))
            return Status::argument;
        const std::size_t raw_len = NONCE_BYTES + msg.size() + TAG_BYTES;
        uint8_t* raw = out.data() + HEADER.size() + b64_len(raw_len) - raw_len;
        uint8_t* c = raw + NONCE_BYTES;
        Keys k;
        int rc = derive(k, key.data(), n);
        std::memcpy(raw, n, NONCE_BYTES);
        if (!msg.empty())
            rc |= crypto_stream_xchacha20_xor(c, msg.data(), msg.size(), k.n2(), k.ek());
        rc |= mac(c + msg.size(), k.ak, n, {c, msg.size()}, footer, implicit);
        if (rc != 0) {
            sodium_memzero(out.data(), need);
            return Status::internal;
        }
        std::memcpy(out.data(), HEADER.data(), HEADER.size());
        std::size_t pos = HEADER.size() + codec::encode(out.data() + HEADER.size(), raw, raw_len);
        if (!footer.empty()) {
            out[pos++] = '.';
            pos += codec::encode(out.data() + pos, footer.data(), footer.size());
        }
        out_len = pos;
        return Status::ok;
    }

    static Status open_impl(std::span<uint8_t> work, std::size_t& out_len,
                            std::span<const uint8_t> token, std::span<const uint8_t> key,
                            std::span<const uint8_t> expected_footer,
                            std::span<const uint8_t> implicit) noexcept {
        if (work.empty() || std::memcmp(token.data(), HEADER.data(), HEADER.size()) != 0)
            return Status::invalid;
        const char* rest = reinterpret_cast<const char*>(token.data()) + HEADER.size();
        const std::size_t rest_len = token.size() - HEADER.size();
        const char* dot = static_cast<const char*>(std::memchr(rest, '.', rest_len));
        const std::size_t body_len = dot ? static_cast<std::size_t>(dot - rest) : rest_len;
        const std::size_t ftxt_len = dot ? rest_len - body_len - 1 : 0;
        if ((dot != nullptr && ftxt_len == 0) || (dot != nullptr) == expected_footer.empty())
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!codec::decode(work.data(), work.size(), rest, body_len, raw_len) ||
            raw_len < NONCE_BYTES + TAG_BYTES)
            return Status::invalid;
        std::size_t flen = 0;
        if (dot && !codec::decode(work.data() + raw_len, work.size() - raw_len, dot + 1, ftxt_len, flen))
            return Status::invalid;
        const uint8_t* f = work.data() + raw_len;
        if (flen != expected_footer.size() ||
            (flen != 0 && std::memcmp(f, expected_footer.data(), flen) != 0))
            return Status::invalid;
        uint8_t n[NONCE_BYTES];
        uint8_t t[TAG_BYTES];
        std::memcpy(n, work.data(), NONCE_BYTES);
        std::memcpy(t, work.data() + raw_len - TAG_BYTES, TAG_BYTES);
        const std::size_t clen = raw_len - NONCE_BYTES - TAG_BYTES;
        uint8_t* c = work.data() + NONCE_BYTES;
        Keys k;
        int rc = derive(k, key.data(), n);
        rc |= mac(k.tag, k.ak, n, {c, clen}, {f, flen}, implicit);
        int verdict = crypto_verify_32(t, k.tag);
        crypto::detail::ct_declassify(&verdict, sizeof verdict);
        if (rc != 0) return Status::internal;
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

}
