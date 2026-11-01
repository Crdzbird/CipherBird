#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <set>
#include <utility>
#include <vector>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#endif
using namespace test;

using V4 = crypto::paseto::V4Local;
using Bytes = std::vector<uint8_t>;
using Span = std::span<const uint8_t>;

namespace {

constexpr int B64 = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
constexpr const char* kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

Bytes fixed(size_t n, uint8_t start) {
    Bytes v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(start + 7 * i);
    return v;
}

Bytes unhex(std::string_view h) {
    Bytes out(h.size() / 2);
    size_t n = 0;
    if (sodium_hex2bin(out.data(), out.size(), h.data(), h.size(), nullptr, &n, nullptr) != 0)
        return {};
    out.resize(n);
    return out;
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

struct Tok { int rc; std::string s; };
struct Msg { int rc; Bytes m; };

Tok enc(Span key, Span msg, Span footer, Span implicit) {
    std::string out(cryptolib_paseto_v4_local_encrypt_len(msg.size(), footer.size()), '\0');
    size_t n = 12345;
    const int rc = cryptolib_paseto_v4_local_encrypt(
        reinterpret_cast<uint8_t*>(out.data()), out.size(), &n, key.data(), key.size(),
        msg.data(), msg.size(), footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

Msg dec(std::string_view token, Span key, Span footer, Span implicit) {
    Bytes out(cryptolib_paseto_v4_local_decrypt_cap(token.size()));
    size_t n = 12345;
    const int rc = cryptolib_paseto_v4_local_decrypt(
        out.empty() ? nullptr : out.data(), out.size(), &n,
        reinterpret_cast<const uint8_t*>(token.data()), token.size(), key.data(), key.size(),
        footer.data(), footer.size(), implicit.data(), implicit.size());
    out.resize(n);
    return {rc, out};
}

int dec_rc(std::string_view token, Span key, Span footer, Span implicit) {
    return dec(token, key, footer, implicit).rc;
}

Bytes pae(const std::vector<Span>& pieces) {
    Bytes out;
    auto le = [&out](uint64_t v) {
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    le(pieces.size());
    for (const auto& p : pieces) {
        le(p.size());
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

struct RefKeys { Bytes ek, n2, ak; };

RefKeys ref_keys(Span key, Span n) {
    Bytes m1 = bytes_of("paseto-encryption-key"), m2 = bytes_of("paseto-auth-key-for-aead");
    m1.insert(m1.end(), n.begin(), n.end());
    m2.insert(m2.end(), n.begin(), n.end());
    Bytes tmp(56), ak(32);
    crypto_generichash(tmp.data(), 56, m1.data(), m1.size(), key.data(), key.size());
    crypto_generichash(ak.data(), 32, m2.data(), m2.size(), key.data(), key.size());
    return {Bytes(tmp.begin(), tmp.begin() + 32), Bytes(tmp.begin() + 32, tmp.end()), ak};
}

std::string ref_seal(Span key, Span msg, Span footer, Span implicit, Span n) {
    const auto k = ref_keys(key, n);
    Bytes c(msg.size());
    if (!msg.empty())
        crypto_stream_xchacha20_xor(c.data(), msg.data(), msg.size(), k.n2.data(), k.ek.data());
    const Bytes h = bytes_of("v4.local.");
    const Bytes pre = pae({h, n, c, footer, implicit});
    Bytes t(32);
    crypto_generichash(t.data(), 32, pre.data(), pre.size(), k.ak.data(), k.ak.size());
    Bytes raw(n.begin(), n.end());
    raw.insert(raw.end(), c.begin(), c.end());
    raw.insert(raw.end(), t.begin(), t.end());
    std::string tok = "v4.local." + b64e(raw);
    if (!footer.empty()) tok += "." + b64e(footer);
    return tok;
}

bool ref_open(std::string_view tok, Span key, Span footer, Span implicit, Bytes& msg) {
    if (tok.substr(0, 9) != "v4.local.") return false;
    tok.remove_prefix(9);
    const size_t dot = tok.find('.');
    Bytes raw, f;
    if (!b64d(tok.substr(0, dot), raw) || raw.size() < 64) return false;
    if (dot != std::string_view::npos && !b64d(tok.substr(dot + 1), f)) return false;
    if (f != Bytes(footer.begin(), footer.end())) return false;
    const Span n(raw.data(), 32), c(raw.data() + 32, raw.size() - 64);
    const auto k = ref_keys(key, n);
    const Bytes pre = pae({sv2sp("v4.local."), n, c, f, implicit});
    Bytes t(32);
    crypto_generichash(t.data(), 32, pre.data(), pre.size(), k.ak.data(), k.ak.size());
    if (sodium_memcmp(t.data(), raw.data() + raw.size() - 32, 32) != 0) return false;
    msg.assign(c.size(), 0);
    if (!c.empty())
        crypto_stream_xchacha20_xor(msg.data(), c.data(), c.size(), k.n2.data(), k.ek.data());
    return true;
}

const Bytes kKey = fixed(32, 0x70);
const Bytes kOther = fixed(32, 0x71);

struct Json {
    enum Kind { Null, Bool, Num, Str, Arr, Obj } kind = Null;
    bool b = false;
    std::string s;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;
    const Json* get(std::string_view k) const {
        for (const auto& [key, v] : obj) if (key == k) return &v;
        return nullptr;
    }
};

struct JsonParser {
    std::string_view in;
    size_t i = 0;
    bool ok = true;
    void ws() { while (i < in.size() && std::strchr(" \t\r\n", in[i]) && in[i]) ++i; }
    bool eat(char c) { ws(); if (i < in.size() && in[i] == c) { ++i; return true; } return false; }
    static void utf8(std::string& o, unsigned cp) {
        if (cp < 0x80) { o += static_cast<char>(cp); return; }
        if (cp < 0x800) { o += static_cast<char>(0xC0 | (cp >> 6)); o += static_cast<char>(0x80 | (cp & 0x3F)); return; }
        if (cp < 0x10000) { o += static_cast<char>(0xE0 | (cp >> 12)); o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); o += static_cast<char>(0x80 | (cp & 0x3F)); return; }
        o += static_cast<char>(0xF0 | (cp >> 18)); o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); o += static_cast<char>(0x80 | (cp & 0x3F));
    }
    unsigned hex4() {
        if (i + 4 > in.size()) { ok = false; return 0; }
        unsigned v = std::stoul(std::string(in.substr(i, 4)), nullptr, 16);
        i += 4;
        return v;
    }
    std::string str() {
        std::string o;
        if (!eat('"')) { ok = false; return o; }
        while (ok && i < in.size() && in[i] != '"') {
            char c = in[i++];
            if (c != '\\') { o += c; continue; }
            if (i >= in.size()) { ok = false; break; }
            const char e = in[i++];
            static constexpr const char* kEsc = "\"\\/bfnrt";
            const char* m = std::strchr(kEsc, e);
            if (e == 'u') {
                unsigned cp = hex4();
                if (cp >= 0xD800 && cp < 0xDC00 && in.substr(i, 2) == "\\u") { i += 2; cp = 0x10000 + ((cp - 0xD800) << 10) + (hex4() - 0xDC00); }
                utf8(o, cp);
                continue;
            }
            if (!m || !e) { ok = false; break; }
            o += "\"\\/\b\f\n\r\t"[m - kEsc];
        }
        if (!eat('"')) ok = false;
        return o;
    }
    Json value() {
        Json j;
        ws();
        if (i >= in.size()) { ok = false; return j; }
        const char c = in[i];
        if (c == '"') { j.kind = Json::Str; j.s = str(); return j; }
        if (c == '{') {
            ++i; j.kind = Json::Obj;
            if (eat('}')) return j;
            do { std::string k = str(); if (!eat(':')) ok = false; j.obj.emplace_back(k, value()); } while (ok && eat(','));
            if (!eat('}')) ok = false;
            return j;
        }
        if (c == '[') {
            ++i; j.kind = Json::Arr;
            if (eat(']')) return j;
            do { j.arr.push_back(value()); } while (ok && eat(','));
            if (!eat(']')) ok = false;
            return j;
        }
        if (in.substr(i, 4) == "true") { i += 4; j.kind = Json::Bool; j.b = true; return j; }
        if (in.substr(i, 5) == "false") { i += 5; j.kind = Json::Bool; return j; }
        if (in.substr(i, 4) == "null") { i += 4; return j; }
        while (i < in.size() && std::strchr("+-0123456789.eE", in[i]) && in[i]) ++i;
        j.kind = Json::Num;
        return j;
    }
};

std::string jstr(const Json& t, std::string_view k) {
    const Json* v = t.get(k);
    return v && v->kind == Json::Str ? v->s : std::string();
}

}

TEST("paseto_v4/round-trip-shape-and-exact-length") {
    REQUIRE(cryptolib_init() == 0);
    for (size_t ml : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{31}, size_t{200}, size_t{1000}}) {
        for (size_t fl : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{60}}) {
            for (size_t il : {size_t{0}, size_t{5}}) {
                const Bytes m = fixed(ml, 1), f = fixed(fl, 2), i = fixed(il, 3);
                const auto t = enc(kKey, m, f, i);
                REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
                CHECK(t.s.size() == cryptolib_paseto_v4_local_encrypt_len(ml, fl));
                CHECK(t.s.rfind("v4.local.", 0) == 0);
                CHECK(std::count(t.s.begin(), t.s.end(), '.') == (fl ? 3 : 2));
                const auto d = dec(t.s, kKey, f, i);
                CHECK(d.rc == CRYPTOLIB_PASETO_OK);
                CHECK(d.m == m);
            }
        }
    }
}

TEST("paseto_v4/large-message-crosses-encoder-chunks") {
    const Bytes m = fixed(1 << 20, 9), f = fixed(5000, 4);
    const auto t = enc(kKey, m, f, sv2sp("ctx"));
    REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
    Bytes back;
    CHECK(ref_open(t.s, kKey, f, sv2sp("ctx"), back));
    CHECK(back == m);
    CHECK(dec(t.s, kKey, f, sv2sp("ctx")).m == m);
}

TEST("paseto_v4/independent-reference-interoperates-both-ways") {
    for (size_t ml : {size_t{0}, size_t{1}, size_t{2}, size_t{200}}) {
        const Bytes m = fixed(ml, 5), f = bytes_of("{\"kid\":\"k4.lid.x\"}"), i = bytes_of("aud");
        const auto t = enc(kKey, m, f, i);
        REQUIRE(t.rc == CRYPTOLIB_PASETO_OK);
        Bytes back;
        CHECK(ref_open(t.s, kKey, f, i, back));
        CHECK(back == m);
        Bytes n(32);
        randombytes_buf(n.data(), n.size());
        const std::string r = ref_seal(kKey, m, f, i, n);
        const auto d = dec(r, kKey, f, i);
        CHECK(d.rc == CRYPTOLIB_PASETO_OK);
        CHECK(d.m == m);
    }
}

TEST("paseto_v4/nonce-is-fresh") {
    const auto a = enc(kKey, sv2sp("m"), {}, {});
    const auto b = enc(kKey, sv2sp("m"), {}, {});
    CHECK(a.rc == 0);
    CHECK(b.rc == 0);
    CHECK(a.s != b.s);
    CHECK(a.s.substr(0, 9 + 43) != b.s.substr(0, 9 + 43));
}

std::string nonce_of(const std::string& tok) {
    Bytes raw;
    if (!b64d(std::string_view(tok).substr(9), raw) || raw.size() < 32) return {};
    return std::string(raw.begin(), raw.begin() + 32);
}

TEST("paseto_v4/nonces-unique-across-batch-refills-and-threads") {
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        const auto t = enc(kKey, {}, {}, {});
        REQUIRE(t.rc == 0);
        CHECK(seen.insert(nonce_of(t.s)).second);
    }
    std::vector<std::vector<std::string>> per(4);
    std::vector<std::thread> threads;
    for (auto& v : per)
        threads.emplace_back([&v] { for (int i = 0; i < 300; ++i) v.push_back(nonce_of(enc(kKey, {}, {}, {}).s)); });
    for (auto& th : threads) th.join();
    for (const auto& v : per)
        for (const auto& n : v) CHECK(n.size() == 32 && seen.insert(n).second);
}

TEST("paseto_v4/fork-child-never-repeats-parent-nonce") {
#if defined(__unix__) || defined(__APPLE__)
    REQUIRE(enc(kKey, {}, {}, {}).rc == 0);
    int fds[2];
    REQUIRE(pipe(fds) == 0);
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        const std::string n = nonce_of(enc(kKey, {}, {}, {}).s);
        const ssize_t w = write(fds[1], n.data(), n.size());
        _exit(w == 32 ? 0 : 1);
    }
    close(fds[1]);
    const std::string mine = nonce_of(enc(kKey, {}, {}, {}).s);
    char buf[32];
    size_t got = 0;
    while (got < sizeof buf) {
        const ssize_t r = read(fds[0], buf + got, sizeof buf - got);
        if (r <= 0) break;
        got += static_cast<size_t>(r);
    }
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    REQUIRE(got == 32);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(std::string(buf, 32) != mine);
#endif
}

TEST("paseto_v4/every-token-byte-tampered-fails") {
    const Bytes f = bytes_of("{\"kid\":\"k\"}"), i = bytes_of("bind");
    const auto t = enc(kKey, sv2sp("{\"exp\":\"2026-11-02T00:00:00Z\"}"), f, i);
    REQUIRE(t.rc == 0);
    REQUIRE(dec_rc(t.s, kKey, f, i) == CRYPTOLIB_PASETO_OK);
    for (size_t p = 0; p < t.s.size(); ++p) {
        for (char bit : {char(0x01), char(0x02), char(0x80)}) {
            std::string x = t.s;
            x[p] = static_cast<char>(x[p] ^ bit);
            CHECK(dec_rc(x, kKey, f, i) == CRYPTOLIB_PASETO_ERR_INVALID);
        }
    }
    for (size_t len = 0; len < t.s.size(); ++len)
        CHECK(dec_rc(std::string_view(t.s).substr(0, len), kKey, f, i) == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("paseto_v4/every-decoded-byte-tampered-fails") {
    const Bytes f = bytes_of("{\"kid\":\"k\"}"), i = bytes_of("bind");
    const auto t = enc(kKey, sv2sp("payload-bytes"), f, i);
    REQUIRE(t.rc == 0);
    const std::string body = t.s.substr(9, t.s.find('.', 9) - 9);
    const std::string ftxt = t.s.substr(t.s.find('.', 9) + 1);
    Bytes raw;
    REQUIRE(b64d(body, raw));
    for (size_t p = 0; p < raw.size(); ++p) {
        for (uint8_t bit : {uint8_t{0x01}, uint8_t{0x80}}) {
            Bytes r = raw;
            r[p] ^= bit;
            CHECK(dec_rc("v4.local." + b64e(r) + "." + ftxt, kKey, f, i) == CRYPTOLIB_PASETO_ERR_INVALID);
        }
    }
    for (size_t p = 0; p < f.size(); ++p) {
        Bytes ff = f;
        ff[p] ^= 0x01;
        const std::string forged = "v4.local." + body + "." + b64e(ff);
        CHECK(dec_rc(forged, kKey, f, i) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(forged, kKey, ff, i) == CRYPTOLIB_PASETO_ERR_INVALID);
    }
}

TEST("paseto_v4/wrong-key-footer-and-implicit-fail") {
    const Bytes f = bytes_of("f"), i = bytes_of("class=1");
    const auto t = enc(kKey, sv2sp("m"), f, i);
    REQUIRE(t.rc == 0);
    CHECK(dec_rc(t.s, kOther, f, i) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s, kKey, sv2sp("g"), i) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s, kKey, sv2sp("ff"), i) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s, kKey, {}, i) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s, kKey, f, sv2sp("class=2")) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s, kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    const auto bare = enc(kKey, sv2sp("m"), {}, {});
    CHECK(dec_rc(bare.s, kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(bare.s, kKey, {}, i) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(bare.s, kKey, {}, {}) == CRYPTOLIB_PASETO_OK);
}

TEST("paseto_v4/non-canonical-and-malformed-encodings-fail") {
    for (size_t ml : {size_t{0}, size_t{1}}) {
        const Bytes m = fixed(ml, 3);
        const auto t = enc(kKey, m, {}, {});
        REQUIRE(t.rc == 0);
        std::string x = t.s;
        const char* pos = std::strchr(kAlphabet, x.back());
        REQUIRE(pos != nullptr);
        x.back() = kAlphabet[(pos - kAlphabet) | 1];
        CHECK(x != t.s);
        CHECK(dec_rc(x, kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(t.s + "=", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(t.s + "==", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(t.s + "A", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(t.s + ".", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        CHECK(dec_rc(t.s + "\n", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        std::string sp = t.s;
        sp.insert(20, " ");
        CHECK(dec_rc(sp, kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        for (char bad : {'+', '/', '=', '\0'}) {
            std::string y = t.s;
            y[30] = bad;
            CHECK(dec_rc(y, kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
        }
    }
    const Bytes f = bytes_of("f");
    const auto t = enc(kKey, sv2sp("m"), f, {});
    REQUIRE(t.rc == 0);
    CHECK(t.s.substr(t.s.size() - 3) == ".Zg");
    CHECK(dec_rc(t.s.substr(0, t.s.size() - 1) + "h", kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(t.s + "==", kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    const std::string body = t.s.substr(0, t.s.size() - 3);
    CHECK(dec_rc(body + "..Zg", kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(body + ".Zg.", kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc(body + ".Zg.Zg", kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    const std::string rest = t.s.substr(9);
    for (const char* h : {"v4.public.", "v3.local.", "V4.local.", "v4.locaL.", "v4.local", " v4.local.", "v2.local."})
        CHECK(dec_rc(std::string(h) + rest, kKey, f, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc("v4.local." + b64e(fixed(63, 0)), kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc("v4.local." + b64e(fixed(64, 0)), kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("paseto_v4/codec-matches-libsodium-exactly") {
    namespace codec = crypto::paseto::codec;
    long mismatches = 0;
    auto cmp = [&](const char* in, size_t len) {
        uint8_t a[96], b[96];
        size_t na = 7, nb = 0;
        const bool oa = codec::decode(a, sizeof a, in, len, na);
        const bool ob = sodium_base642bin(b, sizeof b, in, len, nullptr, &nb, nullptr, B64) == 0;
        if (oa != ob || (oa && (na != nb || std::memcmp(a, b, na) != 0)) || (!oa && na != 0)) ++mismatches;
    };
    char in[72];
    for (int x = 0; x < 256; ++x) {
        in[0] = static_cast<char>(x);
        cmp(in, 1);
        for (int y = 0; y < 256; ++y) {
            in[1] = static_cast<char>(y);
            cmp(in, 2);
            for (int z = 0; z < 256; z += 5) {
                in[2] = static_cast<char>(z);
                cmp(in, 3);
            }
        }
    }
    for (int r = 0; r < 200000; ++r) {
        const size_t len = randombytes_uniform(sizeof in);
        randombytes_buf(in, len);
        for (size_t i = 0; i < len; ++i)
            if (randombytes_uniform(64) != 0) in[i] = kAlphabet[static_cast<uint8_t>(in[i]) % 64];
        cmp(in, len);
    }
    CHECK(mismatches == 0);
    for (size_t len = 0; len <= 300; ++len) {
        const Bytes src = fixed(len, static_cast<uint8_t>(len));
        Bytes inplace(codec::encoded_len(len) + 1, 0xEE);
        std::copy(src.begin(), src.end(), inplace.end() - 1 - static_cast<std::ptrdiff_t>(len));
        const size_t w = codec::encode(inplace.data(), inplace.data() + inplace.size() - 1 - len, len);
        CHECK(w == codec::encoded_len(len));
        CHECK(std::string(inplace.begin(), inplace.begin() + static_cast<std::ptrdiff_t>(w)) == b64e(src));
        CHECK(inplace.back() == 0xEE);
        Bytes back(len + 1);
        size_t n = 0;
        CHECK(codec::decode(back.data(), len, reinterpret_cast<const char*>(inplace.data()), w, n));
        CHECK(n == len && std::equal(src.begin(), src.end(), back.begin()));
        if (len > 0) CHECK(!codec::decode(back.data(), len - 1, reinterpret_cast<const char*>(inplace.data()), w, n));
    }
}

TEST("paseto_v4/empty-and-oversize-inputs") {
    const size_t max = CRYPTOLIB_PASETO_V4_MAX_INPUT_BYTES;
    CHECK(cryptolib_paseto_v4_local_encrypt_len(0, 0) == 9 + 86);
    CHECK(cryptolib_paseto_v4_local_encrypt_len(max + 1, 0) == 0);
    CHECK(cryptolib_paseto_v4_local_encrypt_len(0, max + 1) == 0);
    CHECK(cryptolib_paseto_v4_local_encrypt_len(SIZE_MAX, SIZE_MAX) == 0);
    for (size_t n = 0; n <= 10; ++n) CHECK(cryptolib_paseto_v4_local_decrypt_cap(n) == 0);
    CHECK(cryptolib_paseto_v4_local_decrypt_cap(V4::max_token_len()) > 0);
    CHECK(cryptolib_paseto_v4_local_decrypt_cap(V4::max_token_len() + 1) == 0);
    CHECK(cryptolib_paseto_v4_local_decrypt_cap(SIZE_MAX) == 0);
    CHECK(dec_rc("", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc("v4.local.", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(dec_rc("v4.local.A", kKey, {}, {}) == CRYPTOLIB_PASETO_ERR_INVALID);
    uint8_t small[16] = {};
    uint8_t out[256];
    size_t n = 7;
    CHECK(cryptolib_paseto_v4_local_encrypt(out, sizeof out, &n, kKey.data(), 32, small, max + 1,
                                            nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(n == 0);
    CHECK(cryptolib_paseto_v4_local_encrypt(out, sizeof out, &n, kKey.data(), 32, small, 1,
                                            small, max + 1, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_encrypt(out, sizeof out, &n, kKey.data(), 32, small, 1,
                                            nullptr, 0, small, max + 1) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_decrypt(nullptr, 0, &n, small, V4::max_token_len() + 1,
                                            kKey.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_INVALID);
    const auto t = enc(kKey, {}, {}, {});
    Bytes o(cryptolib_paseto_v4_local_decrypt_cap(t.s.size()));
    CHECK(cryptolib_paseto_v4_local_decrypt(o.data(), o.size(), &n,
                                            reinterpret_cast<const uint8_t*>(t.s.data()), t.s.size(),
                                            kKey.data(), 32, small, max + 1, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_decrypt(o.data(), o.size(), &n,
                                            reinterpret_cast<const uint8_t*>(t.s.data()), t.s.size(),
                                            kKey.data(), 32, nullptr, 0, small, max + 1) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    const auto d = dec(t.s, kKey, {}, {});
    CHECK(d.rc == CRYPTOLIB_PASETO_OK);
    CHECK(d.m.empty());
}

TEST("paseto_v4/abi-rejects-bad-arguments") {
    const Bytes m = bytes_of("message");
    const size_t need = cryptolib_paseto_v4_local_encrypt_len(m.size(), 0);
    Bytes out(need + 8);
    size_t n = 99;
    auto e = [&](uint8_t* o, size_t cap, size_t* nl, const uint8_t* k, size_t kl,
                 const uint8_t* mp, size_t mlen) {
        return cryptolib_paseto_v4_local_encrypt(o, cap, nl, k, kl, mp, mlen, nullptr, 0, nullptr, 0);
    };
    const Bytes k33 = fixed(33, 1);
    CHECK(e(out.data(), out.size(), &n, k33.data(), 31, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(n == 0);
    CHECK(e(out.data(), out.size(), &n, k33.data(), 33, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), &n, k33.data(), 0, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), &n, nullptr, 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(nullptr, out.size(), &n, kKey.data(), 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), nullptr, kKey.data(), 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), &n, kKey.data(), 32, nullptr, 1) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), need - 1, &n, kKey.data(), 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), 0, &n, kKey.data(), 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), &n, out.data() + 40, 32, m.data(), m.size()) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), out.size(), &n, kKey.data(), 32, out.data() + 100, 7) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_encrypt(out.data(), out.size(), &n, kKey.data(), 32, m.data(), m.size(),
                                            nullptr, 3, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_encrypt(out.data(), out.size(), &n, kKey.data(), 32, m.data(), m.size(),
                                            nullptr, 0, nullptr, 3) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(e(out.data(), need, &n, kKey.data(), 32, m.data(), m.size()) == CRYPTOLIB_PASETO_OK);
    CHECK(n == need);
    std::string tok(reinterpret_cast<const char*>(out.data()), n);
    const auto* tp = reinterpret_cast<const uint8_t*>(tok.data());
    const size_t cap = cryptolib_paseto_v4_local_decrypt_cap(tok.size());
    Bytes o(cap);
    auto d = [&](uint8_t* op, size_t ocap, size_t* nl, const uint8_t* t, size_t tl, const uint8_t* k, size_t kl) {
        return cryptolib_paseto_v4_local_decrypt(op, ocap, nl, t, tl, k, kl, nullptr, 0, nullptr, 0);
    };
    CHECK(d(o.data(), cap - 1, &n, tp, tok.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(nullptr, cap, &n, tp, tok.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, nullptr, tp, tok.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, &n, nullptr, tok.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, &n, tp, tok.size(), nullptr, 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, &n, tp, tok.size(), kKey.data(), 31) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, &n, tp, tok.size(), k33.data(), 33) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(cryptolib_paseto_v4_local_decrypt(o.data(), cap, &n, tp, tok.size(), kKey.data(), 32,
                                            nullptr, 2, nullptr, 0) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    Bytes inplace(tok.begin(), tok.end());
    CHECK(d(inplace.data(), cap, &n, inplace.data(), inplace.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
    CHECK(d(o.data(), cap, &n, tp, tok.size(), kKey.data(), 32) == CRYPTOLIB_PASETO_OK);
    CHECK(n == m.size());
    CHECK(std::equal(m.begin(), m.end(), o.begin()));
    CHECK(d(nullptr, 0, &n, nullptr, 0, kKey.data(), 32) == CRYPTOLIB_PASETO_ERR_INVALID);
}

TEST("paseto_v4/decrypt-output-region-is-wiped") {
    const auto t = enc(kKey, sv2sp("secret claims"), {}, {});
    REQUIRE(t.rc == 0);
    const size_t cap = cryptolib_paseto_v4_local_decrypt_cap(t.s.size());
    Bytes o(cap + 4, 0xAA);
    size_t n = 0;
    REQUIRE(cryptolib_paseto_v4_local_decrypt(o.data(), o.size(), &n,
                                              reinterpret_cast<const uint8_t*>(t.s.data()), t.s.size(),
                                              kKey.data(), 32, nullptr, 0, nullptr, 0) == 0);
    CHECK(std::string(o.begin(), o.begin() + n) == "secret claims");
    CHECK(sodium_is_zero(o.data() + n, cap - n) == 1);
    CHECK(o[cap] == 0xAA);
    std::fill(o.begin(), o.end(), 0xAA);
    CHECK(cryptolib_paseto_v4_local_decrypt(o.data(), o.size(), &n,
                                            reinterpret_cast<const uint8_t*>(t.s.data()), t.s.size(),
                                            kOther.data(), 32, nullptr, 0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_INVALID);
    CHECK(n == 0);
    CHECK(sodium_is_zero(o.data(), cap) == 1);
}

TEST("paseto_v4/deterministic-nonce-entry-point") {
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    const Bytes n = fixed(32, 0x40), m = bytes_of("{\"data\":\"x\"}"), f = bytes_of("ft"), i = bytes_of("ia");
    std::string a(cryptolib_paseto_v4_local_encrypt_len(m.size(), f.size()), '\0');
    std::string b = a;
    size_t na = 0, nb = 0;
    REQUIRE(cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
                reinterpret_cast<uint8_t*>(a.data()), a.size(), &na, kKey.data(), 32, m.data(), m.size(),
                f.data(), f.size(), i.data(), i.size(), n.data(), 32) == 0);
    REQUIRE(cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
                reinterpret_cast<uint8_t*>(b.data()), b.size(), &nb, kKey.data(), 32, m.data(), m.size(),
                f.data(), f.size(), i.data(), i.size(), n.data(), 32) == 0);
    CHECK(a == b);
    CHECK(a == ref_seal(kKey, m, f, i, n));
    CHECK(cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
              reinterpret_cast<uint8_t*>(a.data()), a.size(), &na, kKey.data(), 32, m.data(), m.size(),
              f.data(), f.size(), i.data(), i.size(), n.data(), 31) == CRYPTOLIB_PASETO_ERR_ARGUMENT);
#else
    std::printf("      note: CRYPTOLIB_PASETO_TEST_NONCE is OFF, deterministic entry point not compiled\n");
#endif
}

TEST("paseto_v4/official-vectors") {
    static const char* const kNames[] = {"4-E-1", "4-E-2", "4-E-3", "4-E-4", "4-E-5", "4-E-6", "4-E-7",
                                         "4-E-8", "4-E-9", "4-F-1", "4-F-2", "4-F-3", "4-F-4", "4-F-5"};
    static constexpr const char* kSha256 = "0b72948b65d1f73f574c9ad2aa3481ec27bf8c632f5f6e1596cd41f5b9703387";
    const std::string path = std::string(CRYPTOLIB_SOURCE_DIR) + "/tests/vectors/paseto/v4.json";
    std::ifstream in(path, std::ios::binary);
    if (!in) std::printf("      %s is vendored and must be present\n", path.c_str());
    REQUIRE(static_cast<bool>(in));
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    uint8_t sum[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(sum, reinterpret_cast<const uint8_t*>(text.data()), text.size());
    char hex[2 * sizeof sum + 1];
    sodium_bin2hex(hex, sizeof hex, sum, sizeof sum);
    CHECK(std::string(hex) == kSha256);
    JsonParser p{text};
    const Json root = p.value();
    REQUIRE(p.ok);
    const Json* tests = root.get("tests");
    REQUIRE(tests != nullptr && tests->kind == Json::Arr);
    std::vector<std::string> seen;
    int decrypted = 0, rejected = 0, enc_checked = 0;
    for (const Json& t : tests->arr) {
        const std::string name = jstr(t, "name"), token = jstr(t, "token");
        if (name.rfind("4-E-", 0) != 0 && name.rfind("4-F-", 0) != 0) continue;
        seen.push_back(name);
        const Json* ef = t.get("expect-fail");
        const bool fail = ef && ef->kind == Json::Bool && ef->b;
        CHECK(fail == (name.rfind("4-F-", 0) == 0));
        const std::string footer = jstr(t, "footer"), implicit = jstr(t, "implicit-assertion");
        if (name == "4-F-1") {
            CHECK(jstr(t, "key").empty());
            CHECK(unhex(jstr(t, "public-key")).size() == 32);
            std::printf("      4-F-1 checks key typing (a v4.public key used for v4.local); a raw-byte ABI cannot "
                        "tell key types apart, so callers enforce it (PASERK k4.local parsing)\n");
            continue;
        }
        const Bytes key = unhex(jstr(t, "key"));
        REQUIRE(key.size() == 32);
        const auto d = dec(token, key, sv2sp(footer), sv2sp(implicit));
        if (fail) {
            if (d.rc != CRYPTOLIB_PASETO_ERR_INVALID) std::printf("      vector %s gave %d, want invalid\n", name.c_str(), d.rc);
            CHECK(d.rc == CRYPTOLIB_PASETO_ERR_INVALID);
            CHECK(d.m.empty());
            Bytes ignored;
            CHECK(!ref_open(token, key, sv2sp(footer), sv2sp(implicit), ignored));
            ++rejected;
            continue;
        }
        const Json* pl = t.get("payload");
        REQUIRE(pl != nullptr && pl->kind == Json::Str);
        if (d.rc != 0 || std::string(d.m.begin(), d.m.end()) != pl->s)
            std::printf("      vector %s failed to decrypt\n", name.c_str());
        CHECK(d.rc == CRYPTOLIB_PASETO_OK);
        CHECK(std::string(d.m.begin(), d.m.end()) == pl->s);
        const Bytes nonce = unhex(jstr(t, "nonce"));
        CHECK(nonce.size() == 32);
        CHECK(ref_seal(key, sv2sp(pl->s), sv2sp(footer), sv2sp(implicit), nonce) == token);
        ++decrypted;
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
        std::string out(cryptolib_paseto_v4_local_encrypt_len(pl->s.size(), footer.size()), '\0');
        size_t n = 0;
        const auto* msg = reinterpret_cast<const uint8_t*>(pl->s.data());
        CHECK(cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
                  reinterpret_cast<uint8_t*>(out.data()), out.size(), &n, key.data(), 32, msg, pl->s.size(),
                  sv2sp(footer).data(), footer.size(), sv2sp(implicit).data(), implicit.size(),
                  nonce.data(), nonce.size()) == 0);
        CHECK(n == token.size());
        CHECK(out == token);
        ++enc_checked;
#endif
    }
    CHECK(seen == std::vector<std::string>(std::begin(kNames), std::end(kNames)));
    CHECK(decrypted == 9);
    CHECK(rejected == 4);
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
    CHECK(enc_checked == 9);
#else
    CHECK(enc_checked == 0);
#endif
    std::printf("      %zu vectors: %d decrypted, %d rejected as invalid, 1 key-typing (4-F-1), %d re-encrypted%s\n",
                seen.size(), decrypted, rejected, enc_checked,
                enc_checked ? " byte for byte with the test nonce" : " (CRYPTOLIB_PASETO_TEST_NONCE is OFF)");
}

void run_tests_paseto_v4() {
    RUN("paseto_v4/round-trip-shape-and-exact-length");
    RUN("paseto_v4/large-message-crosses-encoder-chunks");
    RUN("paseto_v4/independent-reference-interoperates-both-ways");
    RUN("paseto_v4/nonce-is-fresh");
    RUN("paseto_v4/nonces-unique-across-batch-refills-and-threads");
    RUN("paseto_v4/fork-child-never-repeats-parent-nonce");
    RUN("paseto_v4/every-token-byte-tampered-fails");
    RUN("paseto_v4/every-decoded-byte-tampered-fails");
    RUN("paseto_v4/wrong-key-footer-and-implicit-fail");
    RUN("paseto_v4/non-canonical-and-malformed-encodings-fail");
    RUN("paseto_v4/codec-matches-libsodium-exactly");
    RUN("paseto_v4/empty-and-oversize-inputs");
    RUN("paseto_v4/abi-rejects-bad-arguments");
    RUN("paseto_v4/decrypt-output-region-is-wiped");
    RUN("paseto_v4/deterministic-nonce-entry-point");
    RUN("paseto_v4/official-vectors");
}
