#pragma once
/// Tokens: one API for every format (docs/TOKEN_API.md).
///
/// A format is named by its token header without the trailing dot
/// ("v4.local", "cb1.local", "cb1.public"). The table below describes each
/// format the engine knows, whether it is available in this build, and how
/// to issue (encrypt or sign), accept (decrypt or verify) and generate keys
/// for it. Adding a format is one entry here and nothing in the C ABI or
/// the bindings. Formats that are compiled out keep their entry, marked
/// unavailable, so a client can tell "unknown format" from "not in this
/// profile".

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
#include "paseto.hpp"
#include "cb1_token.hpp"
#endif

#if defined(CRYPTOLIB_HAS_SODIUM_CRYPTO) && defined(CRYPTOLIB_HAS_BLAKE3) && defined(CRYPTOLIB_HAS_NATIVE_COMBINERS)
#define CRYPTOLIB_TOKEN_HAS_CB1_LOCAL 1
#if defined(CRYPTOLIB_HAS_PQ)
#define CRYPTOLIB_TOKEN_HAS_CB1_PUBLIC 1
#endif
#endif

namespace crypto::token {

enum class Purpose { local, pub };

/// ok; invalid (any token, footer, tag or signature failure, one verdict);
/// argument (a caller error independent of token content); internal (the
/// backend failed); unavailable (the format is not in this profile); format
/// (the name matches no format this engine knows).
enum class Status { ok, invalid, argument, internal, unavailable, format };

using Out = std::span<uint8_t>;
using In = std::span<const uint8_t>;

struct Format {
    std::string_view name;
    Purpose purpose;
    std::string_view standard;
    std::size_t key_bytes;
    std::size_t public_key_bytes;
    std::size_t secret_key_bytes;
    std::size_t signature_bytes;
    std::size_t max_input_bytes;
    bool available;
    std::size_t (*issue_len)(std::size_t payload_len, std::size_t footer_len);
    std::size_t (*accept_cap)(std::size_t token_len);
    Status (*keygen)(Out secret, std::size_t& secret_len, Out pub, std::size_t& pub_len);
    Status (*issue)(Out out, std::size_t& out_len, In key, In payload, In footer, In implicit);
    Status (*accept)(Out out, std::size_t& out_len, In token, In key, In expected_footer, In implicit);
};

namespace detail {

inline constexpr std::size_t MAX_INPUT_BYTES = std::size_t{1} << 26;

inline std::size_t unavailable_len(std::size_t, std::size_t) noexcept { return 0; }
inline std::size_t unavailable_cap(std::size_t) noexcept { return 0; }
inline Status unavailable_keygen(Out, std::size_t& a, Out, std::size_t& b) noexcept {
    a = 0;
    b = 0;
    return Status::unavailable;
}
inline Status unavailable_issue(Out, std::size_t& out_len, In, In, In, In) noexcept {
    out_len = 0;
    return Status::unavailable;
}
inline Status unavailable_accept(Out, std::size_t& out_len, In, In, In, In) noexcept {
    out_len = 0;
    return Status::unavailable;
}

template <class S>
Status map(S s) noexcept {
    if (s == S::ok) return Status::ok;
    if (s == S::invalid) return Status::invalid;
    if (s == S::argument) return Status::argument;
    return Status::internal;
}

#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
template <class C>
struct LocalAdapter {
    static std::size_t issue_len(std::size_t p, std::size_t f) noexcept { return C::token_len(p, f); }
    static std::size_t accept_cap(std::size_t t) noexcept { return C::open_capacity(t); }
    static Status keygen(Out secret, std::size_t& secret_len, Out, std::size_t& pub_len) noexcept {
        secret_len = 0;
        pub_len = 0;
        if (secret.size() < C::KEY_BYTES) return Status::argument;
        randombytes_buf(secret.data(), C::KEY_BYTES);
        secret_len = C::KEY_BYTES;
        return Status::ok;
    }
    static Status issue(Out out, std::size_t& out_len, In key, In payload, In footer, In implicit) noexcept {
        return map(C::seal(out, out_len, key, payload, footer, implicit));
    }
    static Status accept(Out out, std::size_t& out_len, In token, In key, In footer, In implicit) noexcept {
        return map(C::open(out, out_len, token, key, footer, implicit));
    }
};
#endif

#ifdef CRYPTOLIB_TOKEN_HAS_CB1_PUBLIC
struct Cb1PublicAdapter {
    using C = crypto::cb1::Public;
    static std::size_t issue_len(std::size_t p, std::size_t f) noexcept { return C::token_len(p, f); }
    static std::size_t accept_cap(std::size_t t) noexcept { return C::open_capacity(t); }
    static Status keygen(Out secret, std::size_t& secret_len, Out pub, std::size_t& pub_len) noexcept {
        secret_len = 0;
        pub_len = 0;
        if (secret.size() < C::SECRET_KEY_BYTES || pub.size() < C::PUBLIC_KEY_BYTES) return Status::argument;
        try {
            auto r = crypto::pq::HybridSig::generate_keypair();
            if (r.is_err() || r.value().public_key.size() != C::PUBLIC_KEY_BYTES ||
                r.value().secret_key.size() != C::SECRET_KEY_BYTES)
                return Status::internal;
            std::memcpy(secret.data(), r.value().secret_key.data(), C::SECRET_KEY_BYTES);
            std::memcpy(pub.data(), r.value().public_key.data(), C::PUBLIC_KEY_BYTES);
        } catch (...) {
            return Status::internal;
        }
        secret_len = C::SECRET_KEY_BYTES;
        pub_len = C::PUBLIC_KEY_BYTES;
        return Status::ok;
    }
    static Status issue(Out out, std::size_t& out_len, In key, In payload, In footer, In implicit) noexcept {
        return map(C::sign(out, out_len, key, payload, footer, implicit));
    }
    static Status accept(Out out, std::size_t& out_len, In token, In key, In footer, In implicit) noexcept {
        return map(C::verify(out, out_len, token, key, footer, implicit));
    }
};
#endif

template <class A>
constexpr Format local_format(std::string_view name, std::string_view standard, std::size_t key_bytes) noexcept {
    return Format{name, Purpose::local, standard, key_bytes, 0, 0, 0, MAX_INPUT_BYTES, true,
                  &A::issue_len, &A::accept_cap, &A::keygen, &A::issue, &A::accept};
}

template <class A>
constexpr Format public_format(std::string_view name, std::string_view standard, std::size_t pk, std::size_t sk,
                               std::size_t sig) noexcept {
    return Format{name, Purpose::pub, standard, 0, pk, sk, sig, MAX_INPUT_BYTES, true,
                  &A::issue_len, &A::accept_cap, &A::keygen, &A::issue, &A::accept};
}

constexpr Format unavailable_format(std::string_view name, Purpose purpose, std::string_view standard,
                                    std::size_t key_bytes, std::size_t pk, std::size_t sk,
                                    std::size_t sig) noexcept {
    return Format{name, purpose, standard, key_bytes, pk, sk, sig, MAX_INPUT_BYTES, false,
                  &unavailable_len, &unavailable_cap, &unavailable_keygen, &unavailable_issue,
                  &unavailable_accept};
}

inline constexpr std::string_view PASETO_V4 = "PASETO v4";
inline constexpr std::string_view LIBRARY_NATIVE = "library-native";
inline constexpr std::size_t CB1_PUBLIC_KEY_BYTES = 32 + 1952;
inline constexpr std::size_t CB1_SECRET_KEY_BYTES = 64 + 4032;
inline constexpr std::size_t CB1_SIGNATURE_BYTES = 64 + 3309;

/// Strict unpadded base64url: returns false on any character outside the
/// alphabet, a length of 1 mod 4, or non-zero trailing bits.
inline bool b64url_decode(uint8_t* dst, std::size_t cap, const uint8_t* src, std::size_t len,
                          std::size_t& n) noexcept {
    n = 0;
    const std::size_t rem = len % 4;
    if (rem == 1) return false;
    const std::size_t need = len / 4 * 3 + (rem == 0 ? 0 : rem - 1);
    if (need > cap) return false;
    uint32_t acc = 0;
    int bits = 0;
    std::size_t o = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const uint8_t c = src[i];
        uint32_t v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '-') v = 62;
        else if (c == '_') v = 63;
        else return false;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[o++] = static_cast<uint8_t>((acc >> bits) & 0xff);
        }
    }
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return false;
    n = o;
    return true;
}

inline bool version_char(uint8_t c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

/// The header of token as a format name ("cb1.local"), or empty when the
/// text does not start with <version>.<local|public>. where the version is
/// one to eight of [a-z0-9].
inline std::string_view header_of(In token) noexcept {
    const char* s = reinterpret_cast<const char*>(token.data());
    std::size_t i = 0;
    while (i < token.size() && i < 8 && version_char(token[i])) ++i;
    if (i == 0 || i >= token.size() || token[i] != '.') return {};
    const std::string_view rest(s + i + 1, token.size() - i - 1);
    for (std::string_view purpose : {std::string_view("local"), std::string_view("public")}) {
        if (rest.size() > purpose.size() && rest.substr(0, purpose.size()) == purpose &&
            rest[purpose.size()] == '.')
            return std::string_view(s, i + 1 + purpose.size());
    }
    return {};
}

}

/// Every format this engine knows, available or not.
inline constexpr std::array<Format, 3> FORMATS = {
#ifdef CRYPTOLIB_HAS_SODIUM_CRYPTO
    detail::local_format<detail::LocalAdapter<crypto::paseto::V4Local>>("v4.local", detail::PASETO_V4, 32),
#else
    detail::unavailable_format("v4.local", Purpose::local, detail::PASETO_V4, 32, 0, 0, 0),
#endif
#ifdef CRYPTOLIB_TOKEN_HAS_CB1_LOCAL
    detail::local_format<detail::LocalAdapter<crypto::cb1::Local>>("cb1.local", detail::LIBRARY_NATIVE, 32),
#else
    detail::unavailable_format("cb1.local", Purpose::local, detail::LIBRARY_NATIVE, 32, 0, 0, 0),
#endif
#ifdef CRYPTOLIB_TOKEN_HAS_CB1_PUBLIC
    detail::public_format<detail::Cb1PublicAdapter>("cb1.public", detail::LIBRARY_NATIVE,
                                                   detail::CB1_PUBLIC_KEY_BYTES, detail::CB1_SECRET_KEY_BYTES,
                                                   detail::CB1_SIGNATURE_BYTES),
#else
    detail::unavailable_format("cb1.public", Purpose::pub, detail::LIBRARY_NATIVE, 0, detail::CB1_PUBLIC_KEY_BYTES,
                               detail::CB1_SECRET_KEY_BYTES, detail::CB1_SIGNATURE_BYTES),
#endif
};

/// The format named name, or nullptr.
[[nodiscard]] inline const Format* find(std::string_view name) noexcept {
    for (const Format& f : FORMATS) {
        if (f.name == name) return &f;
    }
    return nullptr;
}

/// Exact token length for a payload and footer; 0 for an unknown or
/// unavailable format or an input over the maximum.
[[nodiscard]] inline std::size_t issue_len(std::string_view format, std::size_t payload_len,
                                           std::size_t footer_len) noexcept {
    const Format* f = find(format);
    return f ? f->issue_len(payload_len, footer_len) : 0;
}

/// Output capacity accept needs for a token of token_len bytes; 0 for an
/// unknown or unavailable format or a length no valid token has.
[[nodiscard]] inline std::size_t accept_cap(std::string_view format, std::size_t token_len) noexcept {
    const Format* f = find(format);
    return f ? f->accept_cap(token_len) : 0;
}

/// A fresh key (local: key_bytes of CSPRNG output in secret, pub_len 0) or
/// pair (public: both halves) for the format.
[[nodiscard]] inline Status keygen(std::string_view format, Out secret, std::size_t& secret_len, Out pub,
                                   std::size_t& pub_len) noexcept {
    secret_len = 0;
    pub_len = 0;
    const Format* f = find(format);
    if (!f) return Status::format;
    return f->keygen(secret, secret_len, pub, pub_len);
}

/// Encrypts (local) or signs (public, key is the secret half) payload into
/// a token written to out.
[[nodiscard]] inline Status issue(std::string_view format, Out out, std::size_t& out_len, In key, In payload,
                                  In footer, In implicit) noexcept {
    out_len = 0;
    const Format* f = find(format);
    if (!f) return Status::format;
    return f->issue(out, out_len, key, payload, footer, implicit);
}

/// Decrypts (local) or verifies (public, key is the public half) token into
/// out. The token's header must equal format; a mismatch is invalid and is
/// decided before the key is touched.
[[nodiscard]] inline Status accept(std::string_view format, Out out, std::size_t& out_len, In token, In key,
                                   In expected_footer, In implicit) noexcept {
    out_len = 0;
    const Format* f = find(format);
    if (!f) return Status::format;
    if (!f->available) return Status::unavailable;
    if (detail::header_of(token) != f->name) return Status::invalid;
    return f->accept(out, out_len, token, key, expected_footer, implicit);
}

/// The header of token as a format name, unverified; empty when the text
/// has no header of the known shape. The name need not be a known format.
[[nodiscard]] inline std::string_view peek_format(In token) noexcept { return detail::header_of(token); }

/// The decoded footer of token, unverified: ok with out_len 0 when the token
/// has no footer, invalid when the text has no header of the known shape or
/// the footer is not base64url, argument when out is too small.
[[nodiscard]] inline Status peek_footer(In token, Out out, std::size_t& out_len) noexcept {
    out_len = 0;
    const std::string_view h = detail::header_of(token);
    if (h.empty()) return Status::invalid;
    const std::size_t start = h.size() + 1;
    const uint8_t* rest = token.data() + start;
    const std::size_t rest_len = token.size() - start;
    const void* dot = rest_len ? std::memchr(rest, '.', rest_len) : nullptr;
    if (!dot) return Status::ok;
    const uint8_t* f = static_cast<const uint8_t*>(dot) + 1;
    const std::size_t f_len = static_cast<std::size_t>(token.data() + token.size() - f);
    if (f_len == 0 || std::memchr(f, '.', f_len)) return Status::invalid;
    const std::size_t rem = f_len % 4;
    if (rem == 1) return Status::invalid;
    const std::size_t need = f_len / 4 * 3 + (rem == 0 ? 0 : rem - 1);
    if (out.size() < need) return Status::argument;
    if (!detail::b64url_decode(out.data(), out.size(), f, f_len, out_len)) {
        out_len = 0;
        return Status::invalid;
    }
    return Status::ok;
}

/// The format table as a JSON array (docs/TOKEN_API.md).
[[nodiscard]] inline std::string formats_json() {
    std::string s = "[";
    bool first = true;
    for (const Format& f : FORMATS) {
        if (!first) s += ",";
        first = false;
        s += "{\"format\":\"";
        s += f.name;
        s += "\",\"purpose\":\"";
        s += f.purpose == Purpose::local ? "local" : "public";
        s += "\",\"standard\":\"";
        s += f.standard;
        s += "\",\"key_bytes\":" + std::to_string(f.key_bytes);
        s += ",\"public_key_bytes\":" + std::to_string(f.public_key_bytes);
        s += ",\"secret_key_bytes\":" + std::to_string(f.secret_key_bytes);
        s += ",\"signature_bytes\":" + std::to_string(f.signature_bytes);
        s += ",\"max_input_bytes\":" + std::to_string(f.max_input_bytes);
        s += ",\"available\":";
        s += f.available ? "true" : "false";
        s += "}";
    }
    s += "]";
    return s;
}

}
