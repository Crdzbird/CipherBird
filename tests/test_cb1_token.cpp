#include "test_framework.hpp"
#include "json_lite.hpp"
#include "../bridge/cryptolib_c.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
using namespace test;

using L = crypto::cb1::Local;
using P = crypto::cb1::Public;
using crypto::cb1::Status;
using Bytes = std::vector<uint8_t>;
using Span = std::span<const uint8_t>;

namespace {

constexpr int B64 = sodium_base64_VARIANT_URLSAFE_NO_PADDING;

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

Bytes fixed(size_t n, uint8_t start) {
    Bytes v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(start + 7 * i);
    return v;
}

Bytes unhex(std::string_view h) {
    Bytes out(h.size() / 2);
    size_t n = 0;
    if (sodium_hex2bin(out.data(), out.size(), h.data(), h.size(), nullptr, &n, nullptr) != 0) return {};
    out.resize(n);
    return out;
}

std::string hex(Span b) {
    std::string s(b.size() * 2 + 1, '\0');
    sodium_bin2hex(s.data(), s.size(), b.data(), b.size());
    s.resize(b.size() * 2);
    return s;
}

std::string b64e(Span in) {
    std::string s(sodium_base64_ENCODED_LEN(in.size(), B64), '\0');
    sodium_bin2base64(s.data(), s.size(), in.data(), in.size(), B64);
    s.resize(std::strlen(s.c_str()));
    return s;
}

bool b64d(std::string_view in, Bytes& out) {
    out.assign(in.size(), 0);
    size_t n = 0;
    if (sodium_base642bin(out.data(), out.size(), in.data(), in.size(), nullptr, &n, nullptr, B64) != 0)
        return false;
    out.resize(n);
    return true;
}

const Bytes kKey = fixed(32, 0x70);
const Bytes kOther = fixed(32, 0x90);

struct Tok { int rc; std::string s; };
struct Msg { int rc; Bytes m; };

const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }

Tok lenc(Span key, Span msg, Span footer, Span implicit) {
    std::string out(cryptolib_cb1_local_encrypt_len(msg.size(), footer.size()), '\0');
    size_t n = 12345;
    const int rc = cryptolib_cb1_local_encrypt(
        reinterpret_cast<uint8_t*>(out.data()), out.size(), &n, key.data(), key.size(),
        msg.data(), msg.size(), footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

Msg ldec(std::string_view token, Span key, Span footer, Span implicit) {
    Bytes out(cryptolib_cb1_local_decrypt_cap(token.size()));
    size_t n = 12345;
    const int rc = cryptolib_cb1_local_decrypt(
        out.empty() ? nullptr : out.data(), out.size(), &n, u8(token), token.size(), key.data(), key.size(),
        footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

Tok psign(Span sk, Span msg, Span footer, Span implicit) {
    std::string out(cryptolib_cb1_public_sign_len(msg.size(), footer.size()), '\0');
    size_t n = 12345;
    const int rc = cryptolib_cb1_public_sign(
        reinterpret_cast<uint8_t*>(out.data()), out.size(), &n, sk.data(), sk.size(),
        msg.data(), msg.size(), footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

Msg pverify(std::string_view token, Span pk, Span footer, Span implicit) {
    Bytes out(cryptolib_cb1_public_verify_cap(token.size()));
    size_t n = 12345;
    const int rc = cryptolib_cb1_public_verify(
        out.empty() ? nullptr : out.data(), out.size(), &n, u8(token), token.size(), pk.data(), pk.size(),
        footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

Bytes pae(const std::vector<Span>& pieces) {
    Bytes out;
    auto le = [&](uint64_t v) { for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i))); };
    le(pieces.size());
    for (const auto& p : pieces) { le(p.size()); out.insert(out.end(), p.begin(), p.end()); }
    return out;
}

/* An independent cb1.local, written from the format description with the
 * BLAKE3 and libsodium primitives directly. */
std::string ref_local_seal(Span key, Span m, Span f, Span i, Span n) {
    uint8_t split[56], ak[32], tag[32];
    crypto::hash::blake3_hasher h;
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, "cb1-encryption-key", 18);
    blake3_hasher_update(&h, n.data(), 32);
    blake3_hasher_finalize(&h, split, 56);
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, "cb1-auth-key", 12);
    blake3_hasher_update(&h, n.data(), 32);
    blake3_hasher_finalize(&h, ak, 32);
    Bytes c(m.size());
    if (!m.empty()) crypto_stream_xchacha20_xor(c.data(), m.data(), m.size(), split + 32, split);
    const std::string hdr = "cb1.local.";
    const Bytes pre = pae({Span(u8(hdr), hdr.size()), n, c, f, i});
    blake3_hasher_init_keyed(&h, ak);
    blake3_hasher_update(&h, pre.data(), pre.size());
    blake3_hasher_finalize(&h, tag, 32);
    Bytes raw(n.begin(), n.end());
    raw.insert(raw.end(), c.begin(), c.end());
    raw.insert(raw.end(), tag, tag + 32);
    std::string t = hdr + b64e(raw);
    if (!f.empty()) t += "." + b64e(f);
    return t;
}

bool ref_local_open(std::string_view token, Span key, Span f, Span i, Bytes& m) {
    const std::string hdr = "cb1.local.";
    if (token.substr(0, hdr.size()) != hdr) return false;
    std::string_view rest = token.substr(hdr.size());
    const size_t dot = rest.find('.');
    Bytes raw, footer;
    if (!b64d(rest.substr(0, dot), raw) || raw.size() < 64) return false;
    if (dot != std::string_view::npos && !b64d(rest.substr(dot + 1), footer)) return false;
    if (Span(footer) .size() != f.size() || !std::equal(footer.begin(), footer.end(), f.begin())) return false;
    const Span n(raw.data(), 32), c(raw.data() + 32, raw.size() - 64), t(raw.data() + raw.size() - 32, 32);
    uint8_t split[56], ak[32], tag[32];
    crypto::hash::blake3_hasher h;
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, "cb1-encryption-key", 18);
    blake3_hasher_update(&h, n.data(), 32);
    blake3_hasher_finalize(&h, split, 56);
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, "cb1-auth-key", 12);
    blake3_hasher_update(&h, n.data(), 32);
    blake3_hasher_finalize(&h, ak, 32);
    const Bytes pre = pae({Span(u8(hdr), hdr.size()), n, c, f, i});
    blake3_hasher_init_keyed(&h, ak);
    blake3_hasher_update(&h, pre.data(), pre.size());
    blake3_hasher_finalize(&h, tag, 32);
    if (sodium_memcmp(tag, t.data(), 32) != 0) return false;
    m.assign(c.begin(), c.end());
    if (!m.empty()) crypto_stream_xchacha20_xor(m.data(), m.data(), m.size(), split + 32, split);
    return true;
}

Bytes pub_pae(Span m, Span f, Span i) {
    const std::string hdr = "cb1.public.";
    return pae({Span(u8(hdr), hdr.size()), m, f, i});
}

std::string ref_public_sign(Span sk, Span m, Span f, Span i) {
    const Bytes m2 = pub_pae(m, f, i);
    auto r = cryptolib_hybrid_sig_sign(m2.data(), m2.size(), sk.data(), sk.size());
    if (r.error) { cryptolib_str_free(r.error); return {}; }
    Bytes raw(m.begin(), m.end());
    raw.insert(raw.end(), r.buf.data, r.buf.data + r.buf.len);
    cryptolib_buffer_free(&r.buf);
    std::string t = "cb1.public." + b64e(raw);
    if (!f.empty()) t += "." + b64e(f);
    return t;
}

bool ref_public_verify(std::string_view token, Span pk, Span f, Span i, Bytes& m) {
    const std::string hdr = "cb1.public.";
    if (token.substr(0, hdr.size()) != hdr) return false;
    std::string_view rest = token.substr(hdr.size());
    const size_t dot = rest.find('.');
    Bytes raw, footer;
    if (!b64d(rest.substr(0, dot), raw) || raw.size() < 3373) return false;
    if (dot != std::string_view::npos && !b64d(rest.substr(dot + 1), footer)) return false;
    if (footer.size() != f.size() || !std::equal(footer.begin(), footer.end(), f.begin())) return false;
    m.assign(raw.begin(), raw.end() - 3373);
    const Bytes m2 = pub_pae(m, f, i);
    return cryptolib_hybrid_sig_verify(m2.data(), m2.size(), raw.data() + m.size(), 3373, pk.data(), pk.size()) == 1;
}

struct KeyPair { Bytes pk, sk; };

const KeyPair& signer() {
    static const KeyPair kp = [] {
        auto r = cryptolib_hybrid_sig_keygen();
        KeyPair k{Bytes(r.public_key.data, r.public_key.data + r.public_key.len),
                  Bytes(r.secret_key.data, r.secret_key.data + r.secret_key.len)};
        cryptolib_keypair_free(&r);
        return k;
    }();
    return kp;
}

const KeyPair& stranger() {
    static const KeyPair kp = [] {
        auto r = cryptolib_hybrid_sig_keygen();
        KeyPair k{Bytes(r.public_key.data, r.public_key.data + r.public_key.len),
                  Bytes(r.secret_key.data, r.secret_key.data + r.secret_key.len)};
        cryptolib_keypair_free(&r);
        return k;
    }();
    return kp;
}

std::string json_escape(std::string_view s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (static_cast<unsigned char>(c) < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
        else o += c;
    }
    return o;
}

Bytes ascii_run(size_t n) {
    Bytes v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>('a' + (i * 7) % 26);
    return v;
}

const char* const kVectorsRel = "/tests/vectors/cb1/vectors.json";

}

TEST("cb1/sizes-match-the-hybrid-signature") {
    REQUIRE(cryptolib_init() == 0);
    auto sz = crypto::pq::HybridSig::sizes();
    REQUIRE(sz.is_ok());
    CHECK(sz.value().public_key == P::PUBLIC_KEY_BYTES);
    CHECK(sz.value().secret_key == P::SECRET_KEY_BYTES);
    CHECK(sz.value().signature == P::SIG_BYTES);
    CHECK(signer().pk.size() == CRYPTOLIB_CB1_PUBLIC_KEY_BYTES);
    CHECK(signer().sk.size() == CRYPTOLIB_CB1_SECRET_KEY_BYTES);
    CHECK(P::SIG_BYTES == CRYPTOLIB_CB1_SIGNATURE_BYTES);
}

TEST("cb1/local/round-trip-shape-and-exact-length") {
    struct Case { const char* name; Bytes m, f, i; };
    const Case cases[] = {
        {"empty", {}, {}, {}},
        {"payload", bytes_of("{\"data\":\"x\"}"), {}, {}},
        {"footer", bytes_of("{\"data\":\"x\"}"), bytes_of("{\"kid\":\"a\"}"), {}},
        {"implicit", bytes_of("{\"data\":\"x\"}"), {}, bytes_of("ctx")},
        {"all", Bytes(1000, 0xff), bytes_of("f"), bytes_of("i")},
        {"large", Bytes(1 << 20, 0x5a), Bytes(3000, 1), bytes_of("i")},
    };
    for (const auto& c : cases) {
        const auto t = lenc(kKey, c.m, c.f, c.i);
        REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
        CHECK(t.s.size() == cryptolib_cb1_local_encrypt_len(c.m.size(), c.f.size()));
        CHECK(t.s.rfind("cb1.local.", 0) == 0);
        CHECK(std::count(t.s.begin(), t.s.end(), '.') == (c.f.empty() ? 2 : 3));
        CHECK(t.s.find('=') == std::string::npos);
        const auto d = ldec(t.s, kKey, c.f, c.i);
        CHECK(d.rc == CRYPTOLIB_PASETO_OK);
        CHECK(d.m == c.m);
        CHECK(cryptolib_cb1_local_decrypt_cap(t.s.size()) == L::open_capacity(t.s.size()));
        CHECK(cryptolib_cb1_local_decrypt_cap(t.s.size()) >= c.m.size());
    }
    CHECK(cryptolib_cb1_local_encrypt_len(CRYPTOLIB_CB1_MAX_INPUT_BYTES + 1, 0) == 0);
    CHECK(cryptolib_cb1_local_encrypt_len(0, CRYPTOLIB_CB1_MAX_INPUT_BYTES + 1) == 0);
    CHECK(cryptolib_cb1_local_decrypt_cap(10) == 0);
    CHECK(cryptolib_cb1_local_decrypt_cap(11) == 0);
    CHECK(cryptolib_cb1_local_decrypt_cap(14) == 3);
}

TEST("cb1/local/independent-reference-interoperates-both-ways") {
    const Bytes m = bytes_of("{\"sub\":\"alice\",\"exp\":\"2030-01-01T00:00:00Z\"}");
    const Bytes f = bytes_of("{\"kid\":\"k1\"}"), i = bytes_of("audience");
    Bytes n(32);
    randombytes_buf(n.data(), n.size());
    const std::string ref = ref_local_seal(kKey, m, f, i, n);
    const auto d = ldec(ref, kKey, f, i);
    CHECK(d.rc == CRYPTOLIB_PASETO_OK);
    CHECK(d.m == m);
    const auto t = lenc(kKey, m, f, i);
    REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
    Bytes back;
    CHECK(ref_local_open(t.s, kKey, f, i, back));
    CHECK(back == m);
    CHECK(!ref_local_open(t.s, kOther, f, i, back));
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    std::string a(cryptolib_cb1_local_encrypt_len(m.size(), f.size()), '\0');
    size_t na = 0;
    REQUIRE(cryptolib_cb1_local_encrypt_with_nonce_for_testing(
                reinterpret_cast<uint8_t*>(a.data()), a.size(), &na, kKey.data(), 32, m.data(), m.size(),
                f.data(), f.size(), i.data(), i.size(), n.data(), 32) == CRYPTOLIB_PASETO_OK);
    a.resize(na);
    CHECK(a == ref);
    CHECK(cryptolib_cb1_local_encrypt_with_nonce_for_testing(
              reinterpret_cast<uint8_t*>(a.data()), a.size(), &na, kKey.data(), 32, m.data(), m.size(),
              f.data(), f.size(), i.data(), i.size(), n.data(), 31) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
#else
    std::printf("      note: CRYPTOLIB_PASETO_TEST_NONCE is OFF, the fixed-nonce equality is not checked\n");
#endif
}

TEST("cb1/local/nonce-is-fresh") {
    const Bytes m = bytes_of("m");
    const auto a = lenc(kKey, m, {}, {}), b = lenc(kKey, m, {}, {});
    REQUIRE(a.rc == 0 && b.rc == 0);
    CHECK(a.s != b.s);
    CHECK(a.s.size() == b.s.size());
}

TEST("cb1/local/every-token-byte-tampered-fails") {
    const Bytes m = bytes_of("{\"data\":\"x\"}"), f = bytes_of("{\"kid\":\"k\"}"), i = bytes_of("bind");
    const auto t = lenc(kKey, m, f, i);
    REQUIRE(t.rc == 0);
    int rejected = 0;
    for (size_t pos = 0; pos < t.s.size(); ++pos) {
        for (char sub : {'A', 'z', '-', '.'}) {
            if (sub == t.s[pos]) continue;
            std::string x = t.s;
            x[pos] = sub;
            if (ldec(x, kKey, f, i).rc == CRYPTOLIB_PASETO_ERR_INVALID) ++rejected;
            else { std::printf("      position %zu accepted '%c'\n", pos, sub); CHECK(false); }
        }
    }
    CHECK(rejected > 0);
    for (size_t len = 0; len < t.s.size(); ++len)
        CHECK(ldec(t.s.substr(0, len), kKey, f, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(t.s + "A", kKey, f, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("cb1/local/wrong-key-footer-and-implicit-fail") {
    const Bytes m = bytes_of("m"), f = bytes_of("f"), i = bytes_of("i");
    const auto t = lenc(kKey, m, f, i);
    REQUIRE(t.rc == 0);
    CHECK(ldec(t.s, kOther, f, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(t.s, kKey, bytes_of("g"), i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(t.s, kKey, {}, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(t.s, kKey, f, bytes_of("j")).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(t.s, kKey, f, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    const auto nf = lenc(kKey, m, {}, {});
    REQUIRE(nf.rc == 0);
    CHECK(ldec(nf.s, kKey, f, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(nf.s + ".", kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec(nf.s, kKey, {}, {}).rc == CRYPTOLIB_PASETO_OK);
}

TEST("cb1/local/rejects-paseto-and-non-canonical-encodings") {
    const Bytes m = bytes_of("m");
    std::string v4(cryptolib_paseto_v4_local_encrypt_len(m.size(), 0), '\0');
    size_t n = 0;
    REQUIRE(cryptolib_paseto_v4_local_encrypt(reinterpret_cast<uint8_t*>(v4.data()), v4.size(), &n,
                                              kKey.data(), 32, m.data(), m.size(), nullptr, 0, nullptr, 0) == 0);
    CHECK(ldec(v4, kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    const auto cb = lenc(kKey, m, {}, {});
    REQUIRE(cb.rc == 0);
    Bytes o(cryptolib_paseto_v4_local_decrypt_cap(cb.s.size()));
    CHECK(cryptolib_paseto_v4_local_decrypt(o.data(), o.size(), &n, u8(cb.s), cb.s.size(), kKey.data(), 32,
                                            nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_INVALID);
    const auto pub = psign(signer().sk, m, {}, {});
    REQUIRE(pub.rc == 0);
    CHECK(ldec(pub.s, kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    std::string body = cb.s.substr(10);
    CHECK(ldec("cb1.local." + body + "=", kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec("cb1.local." + body + "==", kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    std::string plus = body;
    plus[5] = '+';
    CHECK(ldec("cb1.local." + plus, kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec("CB1.local." + body, kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec("cb1.local.", kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(ldec("", kKey, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("cb1/local/abi-rejects-bad-arguments-and-wipes") {
    const Bytes m = bytes_of("secret claims");
    const auto t = lenc(kKey, m, {}, {});
    REQUIRE(t.rc == 0);
    const size_t cap = cryptolib_cb1_local_decrypt_cap(t.s.size());
    Bytes o(cap + 4, 0xAA);
    size_t n = 0;
    const uint8_t* tp = u8(t.s);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), cap - 1, &n, tp, t.s.size(), kKey.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_decrypt(nullptr, cap, &n, tp, t.s.size(), kKey.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), cap, nullptr, tp, t.s.size(), kKey.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), cap, &n, tp, t.s.size(), kKey.data(), 31, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), cap, &n, tp, t.s.size(), nullptr, 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), cap, &n, tp, t.s.size(), kKey.data(), 32, nullptr, 2, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    Bytes inplace(t.s.begin(), t.s.end());
    CHECK(cryptolib_cb1_local_decrypt(inplace.data(), cap, &n, inplace.data(), inplace.size(), kKey.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    REQUIRE(cryptolib_cb1_local_decrypt(o.data(), o.size(), &n, tp, t.s.size(), kKey.data(), 32, nullptr, 0, nullptr, 0) == 0);
    CHECK(std::string(o.begin(), o.begin() + n) == "secret claims");
    CHECK(sodium_is_zero(o.data() + n, cap - n) == 1);
    CHECK(o[cap] == 0xAA);
    std::fill(o.begin(), o.end(), 0xAA);
    CHECK(cryptolib_cb1_local_decrypt(o.data(), o.size(), &n, tp, t.s.size(), kOther.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(n == 0);
    CHECK(sodium_is_zero(o.data(), cap) == 1);
    std::string small(4, '\0');
    CHECK(cryptolib_cb1_local_encrypt(reinterpret_cast<uint8_t*>(small.data()), small.size(), &n, kKey.data(), 32, m.data(), m.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(n == 0);
    CHECK(cryptolib_cb1_local_encrypt(nullptr, 0, &n, kKey.data(), 32, m.data(), m.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_local_encrypt(o.data(), o.size(), &n, kKey.data(), 32, nullptr, 1, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
}

TEST("cb1/public/sign-verify-round-trip-and-exact-length") {
    const auto& kp = signer();
    struct Case { const char* name; Bytes m, f, i; };
    const Case cases[] = {
        {"empty", {}, {}, {}},
        {"payload", bytes_of("{\"data\":\"x\"}"), {}, {}},
        {"footer", bytes_of("{\"data\":\"x\"}"), bytes_of("{\"kid\":\"a\"}"), {}},
        {"implicit", bytes_of("{\"data\":\"x\"}"), {}, bytes_of("ctx")},
        {"all", Bytes(1000, 0xff), bytes_of("f"), bytes_of("i")},
        {"large", Bytes(1 << 18, 0x5a), Bytes(300, 1), bytes_of("i")},
    };
    for (const auto& c : cases) {
        const auto t = psign(kp.sk, c.m, c.f, c.i);
        REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
        CHECK(t.s.size() == cryptolib_cb1_public_sign_len(c.m.size(), c.f.size()));
        CHECK(t.s.rfind("cb1.public.", 0) == 0);
        CHECK(std::count(t.s.begin(), t.s.end(), '.') == (c.f.empty() ? 2 : 3));
        const auto v = pverify(t.s, kp.pk, c.f, c.i);
        CHECK(v.rc == CRYPTOLIB_PASETO_OK);
        CHECK(v.m == c.m);
        CHECK(cryptolib_cb1_public_verify_cap(t.s.size()) == P::open_capacity(t.s.size()));
    }
    CHECK(cryptolib_cb1_public_sign_len(CRYPTOLIB_CB1_MAX_INPUT_BYTES + 1, 0) == 0);
    CHECK(cryptolib_cb1_public_verify_cap(11) == 0);
}

TEST("cb1/public/independent-reference-interoperates-both-ways") {
    const auto& kp = signer();
    const Bytes m = bytes_of("{\"sub\":\"alice\"}"), f = bytes_of("{\"kid\":\"k1\"}"), i = bytes_of("aud");
    const std::string ref = ref_public_sign(kp.sk, m, f, i);
    REQUIRE(!ref.empty());
    const auto v = pverify(ref, kp.pk, f, i);
    CHECK(v.rc == CRYPTOLIB_PASETO_OK);
    CHECK(v.m == m);
    const auto t = psign(kp.sk, m, f, i);
    REQUIRE(t.rc == 0);
    Bytes back;
    CHECK(ref_public_verify(t.s, kp.pk, f, i, back));
    CHECK(back == m);
    CHECK(!ref_public_verify(t.s, stranger().pk, f, i, back));
}

TEST("cb1/public/both-signature-halves-are-required") {
    const auto& kp = signer();
    const Bytes m = bytes_of("{\"data\":\"x\"}");
    const auto t = psign(kp.sk, m, {}, {});
    REQUIRE(t.rc == 0);
    Bytes raw;
    REQUIRE(b64d(t.s.substr(11), raw));
    REQUIRE(raw.size() == m.size() + 3373);
    for (size_t pos : {m.size(), m.size() + 63, m.size() + 64, raw.size() - 1}) {
        Bytes x = raw;
        x[pos] ^= 0x01;
        CHECK(pverify("cb1.public." + b64e(x), kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    }
    for (size_t pos = 0; pos < m.size(); ++pos) {
        Bytes x = raw;
        x[pos] ^= 0x80;
        CHECK(pverify("cb1.public." + b64e(x), kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    }
    int rejected = 0;
    for (size_t pos = 0; pos < t.s.size(); pos += 7) {
        std::string x = t.s;
        x[pos] = x[pos] == 'A' ? 'B' : 'A';
        if (pverify(x, kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID) ++rejected;
        else { std::printf("      position %zu accepted\n", pos); CHECK(false); }
    }
    CHECK(rejected > 0);
    Bytes shorter(raw.begin(), raw.end() - 1);
    CHECK(pverify("cb1.public." + b64e(shorter), kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    Bytes sig_only(raw.begin() + m.size(), raw.end());
    CHECK(pverify("cb1.public." + b64e(sig_only), kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("cb1/public/wrong-key-footer-and-implicit-fail") {
    const auto& kp = signer();
    const Bytes m = bytes_of("m"), f = bytes_of("f"), i = bytes_of("i");
    const auto t = psign(kp.sk, m, f, i);
    REQUIRE(t.rc == 0);
    CHECK(pverify(t.s, stranger().pk, f, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(pverify(t.s, kp.pk, bytes_of("g"), i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(pverify(t.s, kp.pk, {}, i).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(pverify(t.s, kp.pk, f, bytes_of("j")).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(pverify(t.s, kp.pk, f, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(psign(stranger().sk, m, f, i).rc == CRYPTOLIB_PASETO_OK);
    const auto local = lenc(kKey, m, {}, {});
    REQUIRE(local.rc == 0);
    CHECK(pverify(local.s, kp.pk, {}, {}).rc == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("cb1/public/abi-rejects-bad-arguments-and-wipes") {
    const auto& kp = signer();
    const Bytes m = bytes_of("claims");
    const auto t = psign(kp.sk, m, {}, {});
    REQUIRE(t.rc == 0);
    const size_t cap = cryptolib_cb1_public_verify_cap(t.s.size());
    Bytes o(cap + 4, 0xAA);
    size_t n = 0;
    const uint8_t* tp = u8(t.s);
    CHECK(cryptolib_cb1_public_verify(o.data(), cap - 1, &n, tp, t.s.size(), kp.pk.data(), kp.pk.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_public_verify(o.data(), cap, &n, tp, t.s.size(), kp.pk.data(), 31, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_public_verify(o.data(), cap, nullptr, tp, t.s.size(), kp.pk.data(), kp.pk.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    REQUIRE(cryptolib_cb1_public_verify(o.data(), o.size(), &n, tp, t.s.size(), kp.pk.data(), kp.pk.size(), nullptr, 0, nullptr, 0) == 0);
    CHECK(std::string(o.begin(), o.begin() + n) == "claims");
    CHECK(sodium_is_zero(o.data() + n, cap - n) == 1);
    CHECK(o[cap] == 0xAA);
    std::fill(o.begin(), o.end(), 0xAA);
    CHECK(cryptolib_cb1_public_verify(o.data(), o.size(), &n, tp, t.s.size(), stranger().pk.data(), stranger().pk.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(n == 0);
    CHECK(sodium_is_zero(o.data(), cap) == 1);
    std::string small(4, '\0');
    CHECK(cryptolib_cb1_public_sign(reinterpret_cast<uint8_t*>(small.data()), small.size(), &n, kp.sk.data(), kp.sk.size(), m.data(), m.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_public_sign(o.data(), o.size(), &n, kp.sk.data(), 64, m.data(), m.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_cb1_public_sign(o.data(), o.size(), &n, nullptr, kp.sk.size(), m.data(), m.size(), nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
}

TEST("cb1/pinned-vectors") {
    const std::string path = std::string(CRYPTOLIB_SOURCE_DIR) + kVectorsRel;
    const char* write = std::getenv("CRYPTOLIB_CB1_WRITE_VECTORS");
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    if (write && *write) {
        const auto& kp = signer();
        std::string out = "{\n  \"name\": \"CipherBird cb1 token vectors\",\n";
        out += "  \"note\": \"Generated by cryptolib_tests (CRYPTOLIB_CB1_WRITE_VECTORS) from the cb1 format description; every binding decrypts and verifies these.\",\n";
        out += "  \"local\": [\n";
        struct LC { const char* name; Bytes m, f, i; uint8_t nonce_start; bool fail; const char* how; };
        const LC lcs[] = {
            {"cb1-L-1", bytes_of("{\"data\":\"this is a secret message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), {}, {}, 0x00, false, ""},
            {"cb1-L-2", bytes_of("{\"data\":\"this is a secret message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), bytes_of("{\"kid\":\"zVhMiRdm\"}"), {}, 0x10, false, ""},
            {"cb1-L-3", bytes_of("{\"data\":\"this is a secret message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), {}, bytes_of("{\"test-vector\":\"cb1-L-3\"}"), 0x20, false, ""},
            {"cb1-L-4", bytes_of("{\"data\":\"this is a secret message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), bytes_of("{\"kid\":\"zVhMiRdm\"}"), bytes_of("{\"test-vector\":\"cb1-L-4\"}"), 0x30, false, ""},
            {"cb1-L-5", {}, {}, {}, 0x40, false, ""},
            {"cb1-L-6", ascii_run(2000), bytes_of("f"), bytes_of("i"), 0x50, false, ""},
            {"cb1-F-1", bytes_of("{\"data\":\"x\"}"), {}, {}, 0x60, true, "tag"},
            {"cb1-F-2", bytes_of("{\"data\":\"x\"}"), bytes_of("{\"kid\":\"a\"}"), {}, 0x70, true, "footer"},
            {"cb1-F-3", bytes_of("{\"data\":\"x\"}"), {}, {}, 0x80, true, "padding"},
            {"cb1-F-4", bytes_of("{\"data\":\"x\"}"), {}, {}, 0x90, true, "paseto"},
        };
        bool first = true;
        for (const auto& c : lcs) {
            const Bytes n = fixed(32, c.nonce_start);
            std::string tok(cryptolib_cb1_local_encrypt_len(c.m.size(), c.f.size()), '\0');
            size_t tl = 0;
            REQUIRE(cryptolib_cb1_local_encrypt_with_nonce_for_testing(
                        reinterpret_cast<uint8_t*>(tok.data()), tok.size(), &tl, kKey.data(), 32, c.m.data(), c.m.size(),
                        c.f.data(), c.f.size(), c.i.data(), c.i.size(), n.data(), 32) == 0);
            tok.resize(tl);
            Bytes expect_f = c.f;
            std::string how = c.how;
            if (how == "tag") tok[tok.size() - 1] = tok[tok.size() - 1] == 'A' ? 'B' : 'A';
            if (how == "footer") expect_f = bytes_of("{\"kid\":\"b\"}");
            if (how == "padding") tok += "=";
            if (how == "paseto") {
                std::string v4(cryptolib_paseto_v4_local_encrypt_len(c.m.size(), 0), '\0');
                REQUIRE(cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
                            reinterpret_cast<uint8_t*>(v4.data()), v4.size(), &tl, kKey.data(), 32, c.m.data(), c.m.size(),
                            nullptr, 0, nullptr, 0, n.data(), 32) == 0);
                tok = v4;
            }
            out += std::string(first ? "" : ",\n") + "    {\"name\": \"" + c.name + "\", \"expect-fail\": " + (c.fail ? "true" : "false") +
                   ", \"key\": \"" + hex(kKey) + "\", \"nonce\": \"" + hex(n) + "\", \"token\": \"" + tok +
                   "\", \"payload\": \"" + json_escape(std::string(c.m.begin(), c.m.end())) +
                   "\", \"footer\": \"" + json_escape(std::string(expect_f.begin(), expect_f.end())) +
                   "\", \"implicit-assertion\": \"" + json_escape(std::string(c.i.begin(), c.i.end())) + "\"}";
            first = false;
        }
        out += "\n  ],\n  \"public\": [\n";
        struct PC { const char* name; Bytes m, f, i; bool fail; const char* how; };
        const PC pcs[] = {
            {"cb1-P-1", bytes_of("{\"data\":\"this is a signed message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), {}, {}, false, ""},
            {"cb1-P-2", bytes_of("{\"data\":\"this is a signed message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), bytes_of("{\"kid\":\"zVhMiRdm\"}"), {}, false, ""},
            {"cb1-P-3", bytes_of("{\"data\":\"this is a signed message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), {}, bytes_of("{\"test-vector\":\"cb1-P-3\"}"), false, ""},
            {"cb1-P-4", bytes_of("{\"data\":\"this is a signed message\",\"exp\":\"2030-01-01T00:00:00Z\"}"), bytes_of("{\"kid\":\"zVhMiRdm\"}"), bytes_of("{\"test-vector\":\"cb1-P-4\"}"), false, ""},
            {"cb1-P-5", {}, {}, {}, false, ""},
            {"cb1-PF-1", bytes_of("{\"data\":\"x\"}"), {}, {}, true, "signature"},
            {"cb1-PF-2", bytes_of("{\"data\":\"x\"}"), bytes_of("{\"kid\":\"a\"}"), {}, true, "footer"},
            {"cb1-PF-3", bytes_of("{\"data\":\"x\"}"), {}, {}, true, "message"},
        };
        first = true;
        for (const auto& c : pcs) {
            auto t = psign(kp.sk, c.m, c.f, c.i);
            REQUIRE(t.rc == 0);
            std::string tok = t.s;
            Bytes expect_f = c.f;
            std::string how = c.how;
            if (how == "signature") tok[tok.size() - 1] = tok[tok.size() - 1] == 'A' ? 'B' : 'A';
            if (how == "footer") expect_f = bytes_of("{\"kid\":\"b\"}");
            if (how == "message") tok[11] = tok[11] == 'A' ? 'B' : 'A';
            out += std::string(first ? "" : ",\n") + "    {\"name\": \"" + c.name + "\", \"expect-fail\": " + (c.fail ? "true" : "false") +
                   ", \"public-key\": \"" + hex(kp.pk) + "\", \"secret-key\": \"" + hex(kp.sk) + "\", \"token\": \"" + tok +
                   "\", \"payload\": \"" + json_escape(std::string(c.m.begin(), c.m.end())) +
                   "\", \"footer\": \"" + json_escape(std::string(expect_f.begin(), expect_f.end())) +
                   "\", \"implicit-assertion\": \"" + json_escape(std::string(c.i.begin(), c.i.end())) + "\"}";
            first = false;
        }
        out += "\n  ]\n}\n";
        std::ofstream o(path, std::ios::binary);
        REQUIRE(static_cast<bool>(o));
        o << out;
        std::printf("      wrote %s\n", path.c_str());
    }
#else
    (void)write;
#endif
    std::ifstream in(path, std::ios::binary);
    if (!in) std::printf("      %s is missing; generate it with a CRYPTOLIB_PASETO_TEST_NONCE build and CRYPTOLIB_CB1_WRITE_VECTORS=1\n", path.c_str());
    REQUIRE(static_cast<bool>(in));
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    JsonParser p{text};
    const Json root = p.value();
    REQUIRE(p.ok);
    const Json* local = root.get("local");
    const Json* pub = root.get("public");
    REQUIRE(local && local->kind == Json::Arr && pub && pub->kind == Json::Arr);
    int lpass = 0, lfail = 0, ppass = 0, pfail = 0, reencrypted = 0;
    for (const Json& t : local->arr) {
        const std::string name = jstr(t, "name"), token = jstr(t, "token");
        const Bytes key = unhex(jstr(t, "key")), nonce = unhex(jstr(t, "nonce"));
        const Bytes payload = bytes_of(jstr(t, "payload")), f = bytes_of(jstr(t, "footer")), i = bytes_of(jstr(t, "implicit-assertion"));
        const Json* ef = t.get("expect-fail");
        const bool fail = ef && ef->kind == Json::Bool && ef->b;
        REQUIRE(key.size() == 32 && nonce.size() == 32);
        const auto d = ldec(token, key, f, i);
        if (fail) { CHECK(d.rc == CRYPTOLIB_PASETO_ERR_INVALID); CHECK(d.m.empty()); ++lfail; continue; }
        if (d.rc != 0) std::printf("      vector %s gave %d\n", name.c_str(), d.rc);
        CHECK(d.rc == CRYPTOLIB_PASETO_OK);
        CHECK(d.m == payload);
        ++lpass;
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
        std::string again(cryptolib_cb1_local_encrypt_len(payload.size(), f.size()), '\0');
        size_t n = 0;
        REQUIRE(cryptolib_cb1_local_encrypt_with_nonce_for_testing(
                    reinterpret_cast<uint8_t*>(again.data()), again.size(), &n, key.data(), 32, payload.data(), payload.size(),
                    f.data(), f.size(), i.data(), i.size(), nonce.data(), 32) == 0);
        again.resize(n);
        CHECK(again == token);
        ++reencrypted;
#endif
    }
    for (const Json& t : pub->arr) {
        const std::string name = jstr(t, "name"), token = jstr(t, "token");
        const Bytes pk = unhex(jstr(t, "public-key")), sk = unhex(jstr(t, "secret-key"));
        const Bytes payload = bytes_of(jstr(t, "payload")), f = bytes_of(jstr(t, "footer")), i = bytes_of(jstr(t, "implicit-assertion"));
        const Json* ef = t.get("expect-fail");
        const bool fail = ef && ef->kind == Json::Bool && ef->b;
        REQUIRE(pk.size() == P::PUBLIC_KEY_BYTES && sk.size() == P::SECRET_KEY_BYTES);
        const auto v = pverify(token, pk, f, i);
        if (fail) { CHECK(v.rc == CRYPTOLIB_PASETO_ERR_INVALID); CHECK(v.m.empty()); ++pfail; continue; }
        if (v.rc != 0) std::printf("      vector %s gave %d\n", name.c_str(), v.rc);
        CHECK(v.rc == CRYPTOLIB_PASETO_OK);
        CHECK(v.m == payload);
        const auto again = psign(sk, payload, f, i);
        CHECK(again.rc == 0);
        CHECK(pverify(again.s, pk, f, i).m == payload);
        ++ppass;
    }
    std::printf("      local: %d decrypted, %d rejected, %d re-encrypted with the pinned nonce; public: %d verified, %d rejected\n",
                lpass, lfail, reencrypted, ppass, pfail);
    CHECK(lpass >= 6 && lfail >= 4 && ppass >= 5 && pfail >= 3);
}

void run_tests_cb1_token() {
    RUN("cb1/sizes-match-the-hybrid-signature");
    RUN("cb1/local/round-trip-shape-and-exact-length");
    RUN("cb1/local/independent-reference-interoperates-both-ways");
    RUN("cb1/local/nonce-is-fresh");
    RUN("cb1/local/every-token-byte-tampered-fails");
    RUN("cb1/local/wrong-key-footer-and-implicit-fail");
    RUN("cb1/local/rejects-paseto-and-non-canonical-encodings");
    RUN("cb1/local/abi-rejects-bad-arguments-and-wipes");
    RUN("cb1/public/sign-verify-round-trip-and-exact-length");
    RUN("cb1/public/independent-reference-interoperates-both-ways");
    RUN("cb1/public/both-signature-halves-are-required");
    RUN("cb1/public/wrong-key-footer-and-implicit-fail");
    RUN("cb1/public/abi-rejects-bad-arguments-and-wipes");
    RUN("cb1/pinned-vectors");
}
