/// The generic token API (docs/TOKEN_API.md): the format table, issue and
/// accept for every available format, the header rule, the peek functions,
/// the per-format functions as forwarders, and the common-schema vectors
/// under tests/vectors/tokens/ accepted through the generic calls.
#include "test_framework.hpp"
#include "json_lite.hpp"
#include "cryptolib_c.h"
#include <cryptolib/cryptolib.hpp>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace test;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

Bytes unhex(std::string_view h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(std::string(h.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

const char* const kFormats[] = {"v4.local", "cb1.local", "cb1.public"};

bool available(const char* format) { return cryptolib_token_issue_len(format, 1, 0) != 0; }

bool is_public(const char* format) {
    const std::string_view f(format);
    return f.size() > 7 && f.substr(f.size() - 7) == ".public";
}

struct Keys { Bytes secret, pub; };

Keys keygen(const char* format) {
    Keys k;
    k.secret.resize(4096);
    k.pub.resize(1984);
    size_t a = 0, b = 0;
    const int rc = cryptolib_token_keygen(format, k.secret.data(), k.secret.size(), &a, k.pub.data(), k.pub.size(), &b);
    CHECK(rc == CRYPTOLIB_TOKEN_OK);
    if (rc != CRYPTOLIB_TOKEN_OK) {
        a = 0;
        b = 0;
    }
    k.secret.resize(a);
    k.pub.resize(b);
    return k;
}

struct Issued { int rc; std::string token; };

Issued issue(const char* format, const Bytes& key, const Bytes& m, const Bytes& f, const Bytes& i) {
    std::string t(cryptolib_token_issue_len(format, m.size(), f.size()), '\0');
    size_t n = 0;
    const int rc = cryptolib_token_issue(format, reinterpret_cast<uint8_t*>(t.data()), t.size(), &n, key.data(),
                                         key.size(), m.data(), m.size(), f.data(), f.size(), i.data(), i.size());
    t.resize(n);
    return {rc, t};
}

struct Accepted { int rc; Bytes m; };

Accepted accept(const char* format, const std::string& token, const Bytes& key, const Bytes& f, const Bytes& i) {
    Bytes out(cryptolib_token_accept_cap(format, token.size()));
    size_t n = 0;
    const int rc = cryptolib_token_accept(format, out.data(), out.size(), &n,
                                          reinterpret_cast<const uint8_t*>(token.data()), token.size(), key.data(),
                                          key.size(), f.data(), f.size(), i.data(), i.size());
    out.resize(n);
    return {rc, out};
}

std::string formats_json() {
    const size_t n = cryptolib_token_formats(nullptr, 0);
    std::string j(n, '\0');
    const size_t again = cryptolib_token_formats(j.data(), j.size());
    if (again != n) return "";
    return j;
}

std::string entry(const char* format, const char* purpose, const char* standard, size_t key, size_t pk, size_t sk,
                  size_t sig, bool avail) {
    return std::string("{\"format\":\"") + format + "\",\"purpose\":\"" + purpose + "\",\"standard\":\"" + standard +
           "\",\"key_bytes\":" + std::to_string(key) + ",\"public_key_bytes\":" + std::to_string(pk) +
           ",\"secret_key_bytes\":" + std::to_string(sk) + ",\"signature_bytes\":" + std::to_string(sig) +
           ",\"max_input_bytes\":67108864,\"available\":" + (avail ? "true" : "false") + "}";
}

std::string peek_format(const std::string& token) {
    const auto* p = reinterpret_cast<const uint8_t*>(token.data());
    const size_t n = cryptolib_token_peek_format(p, token.size(), nullptr, 0);
    std::string s(n, '\0');
    if (n) cryptolib_token_peek_format(p, token.size(), s.data(), s.size());
    return s;
}

struct Footer { int rc; Bytes f; };

Footer peek_footer(const std::string& token) {
    Bytes out(token.size());
    size_t n = 0;
    const int rc = cryptolib_token_peek_footer(reinterpret_cast<const uint8_t*>(token.data()), token.size(),
                                               out.data(), out.size(), &n);
    out.resize(n);
    return {rc, out};
}

}

TEST("token_api/table-lists-every-format-with-its-sizes") {
    REQUIRE(cryptolib_init() == 0);
    const std::string j = formats_json();
    REQUIRE(!j.empty());
    CHECK(j.front() == '[' && j.back() == ']');
    CHECK(j.find(entry("v4.local", "local", "PASETO v4", 32, 0, 0, 0, available("v4.local"))) != std::string::npos);
    CHECK(j.find(entry("cb1.local", "local", "library-native", 32, 0, 0, 0, available("cb1.local"))) != std::string::npos);
    CHECK(j.find(entry("cb1.public", "public", "library-native", 0, 1984, 4096, 3373, available("cb1.public"))) !=
          std::string::npos);
    CHECK(available("v4.local"));
    char small[8];
    CHECK(cryptolib_token_formats(small, sizeof small) == j.size());
    JsonParser p{j};
    const Json root = p.value();
    CHECK(p.ok && root.kind == Json::Arr && root.arr.size() == 3);
}

TEST("token_api/unknown-format-and-unavailable-format-are-told-apart") {
    uint8_t out[64];
    size_t n = 7;
    CHECK(cryptolib_token_issue_len("v9.local", 1, 0) == 0);
    CHECK(cryptolib_token_accept_cap("v9.local", 100) == 0);
    CHECK(cryptolib_token_issue("v9.local", out, sizeof out, &n, out, 32, nullptr, 0, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_FORMAT);
    CHECK(n == 0);
    CHECK(cryptolib_token_accept("v4.secret", out, sizeof out, &n, out, 10, out, 32, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_FORMAT);
    CHECK(cryptolib_token_keygen("", out, sizeof out, &n, nullptr, 0, nullptr) == CRYPTOLIB_TOKEN_ERR_FORMAT);
    CHECK(cryptolib_token_keygen(nullptr, out, sizeof out, &n, nullptr, 0, nullptr) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    for (const char* f : kFormats) {
        if (available(f)) continue;
        CHECK(cryptolib_token_issue(f, out, sizeof out, &n, out, 32, nullptr, 0, nullptr, 0, nullptr, 0) ==
              CRYPTOLIB_TOKEN_ERR_UNAVAILABLE);
        CHECK(cryptolib_token_accept(f, out, sizeof out, &n, out, 10, out, 32, nullptr, 0, nullptr, 0) ==
              CRYPTOLIB_TOKEN_ERR_UNAVAILABLE);
        CHECK(cryptolib_token_keygen(f, out, sizeof out, &n, nullptr, 0, nullptr) == CRYPTOLIB_TOKEN_ERR_UNAVAILABLE);
        std::printf("      %s is not in this profile: reports unavailable\n", f);
    }
}

TEST("token_api/keygen-issue-accept-round-trip-per-format") {
    for (const char* f : kFormats) {
        if (!available(f)) continue;
        const Keys k = keygen(f);
        if (is_public(f)) {
            CHECK(k.secret.size() == 4096);
            CHECK(k.pub.size() == 1984);
        } else {
            CHECK(k.secret.size() == 32);
            CHECK(k.pub.empty());
        }
        const Bytes& accept_key = is_public(f) ? k.pub : k.secret;
        const Bytes m = bytes_of("{\"sub\":\"alice\",\"exp\":\"2030-01-01T00:00:00Z\"}");
        const Bytes foot = bytes_of("{\"kid\":\"k1\"}"), imp = bytes_of("audience");
        const auto t = issue(f, k.secret, m, foot, imp);
        REQUIRE(t.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(t.token.rfind(std::string(f) + ".", 0) == 0);
        CHECK(t.token.size() == cryptolib_token_issue_len(f, m.size(), foot.size()));
        const auto a = accept(f, t.token, accept_key, foot, imp);
        CHECK(a.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(a.m == m);
        CHECK(accept(f, t.token, accept_key, bytes_of("{\"kid\":\"k2\"}"), imp).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        CHECK(accept(f, t.token, accept_key, foot, bytes_of("other")).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        std::string bad = t.token;
        bad[bad.size() - 1] = bad[bad.size() - 1] == 'A' ? 'B' : 'A';
        CHECK(accept(f, bad, accept_key, foot, imp).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        const Keys other = keygen(f);
        CHECK(accept(f, t.token, is_public(f) ? other.pub : other.secret, foot, imp).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        const auto again = issue(f, k.secret, m, foot, imp);
        CHECK(again.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(again.token != t.token || is_public(f));
        const auto empty = issue(f, k.secret, {}, {}, {});
        CHECK(empty.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(std::count(empty.token.begin(), empty.token.end(), '.') == 2);
        CHECK(accept(f, empty.token, accept_key, {}, {}).rc == CRYPTOLIB_TOKEN_OK);
    }
}

TEST("token_api/the-caller-names-the-format-and-the-header-never-chooses") {
    REQUIRE(available("v4.local"));
    const Keys k = keygen("v4.local");
    const Bytes m = bytes_of("m");
    const auto v4 = issue("v4.local", k.secret, m, {}, {});
    REQUIRE(v4.rc == CRYPTOLIB_TOKEN_OK);
    if (available("cb1.local")) {
        const auto cb1 = issue("cb1.local", k.secret, m, {}, {});
        REQUIRE(cb1.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(accept("v4.local", cb1.token, k.secret, {}, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        CHECK(accept("cb1.local", v4.token, k.secret, {}, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        CHECK(accept("cb1.local", cb1.token, k.secret, {}, {}).rc == CRYPTOLIB_TOKEN_OK);
    }
    std::string relabelled = "cb1.local." + v4.token.substr(9);
    CHECK(accept("v4.local", relabelled, k.secret, {}, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    if (available("cb1.public")) {
        const Keys s = keygen("cb1.public");
        const auto pub = issue("cb1.public", s.secret, m, {}, {});
        REQUIRE(pub.rc == CRYPTOLIB_TOKEN_OK);
        CHECK(accept("cb1.local", pub.token, k.secret, {}, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
        CHECK(accept("cb1.public", v4.token, s.pub, {}, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    }
}

TEST("token_api/argument-errors-are-the-callers-own") {
    REQUIRE(available("v4.local"));
    const Keys k = keygen("v4.local");
    uint8_t out[128];
    size_t n = 1;
    const uint8_t m[] = "m";
    CHECK(cryptolib_token_issue("v4.local", nullptr, 0, &n, k.secret.data(), 32, m, 1, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_issue("v4.local", out, sizeof out, nullptr, k.secret.data(), 32, m, 1, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_issue("v4.local", out, sizeof out, &n, k.secret.data(), 31, m, 1, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(n == 0);
    CHECK(cryptolib_token_issue("v4.local", out, 4, &n, k.secret.data(), 32, m, 1, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_issue("v4.local", out, sizeof out, &n, k.secret.data(), 32, nullptr, 1, nullptr, 0, nullptr, 0) ==
          CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    const auto t = issue("v4.local", k.secret, bytes_of("m"), {}, {});
    REQUIRE(t.rc == CRYPTOLIB_TOKEN_OK);
    const auto* tp = reinterpret_cast<const uint8_t*>(t.token.data());
    CHECK(cryptolib_token_accept("v4.local", out, sizeof out, &n, tp, t.token.size(), k.secret.data(), 16, nullptr, 0,
                                 nullptr, 0) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_accept("v4.local", out, 1, &n, tp, t.token.size(), k.secret.data(), 32, nullptr, 0, nullptr,
                                 0) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_accept("v4.local", out, sizeof out, &n, tp, t.token.size(), k.secret.data(), 32, nullptr, 0,
                                 nullptr, 0) == CRYPTOLIB_TOKEN_OK);
    CHECK(n == 1 && out[0] == 'm');
    size_t a = 0, b = 0;
    uint8_t key[16];
    CHECK(cryptolib_token_keygen("v4.local", key, sizeof key, &a, nullptr, 0, &b) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_keygen("v4.local", nullptr, 32, &a, nullptr, 0, &b) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_keygen("v4.local", out, 32, nullptr, nullptr, 0, &b) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_keygen("v4.local", out, 32, &a, nullptr, 0, nullptr) == CRYPTOLIB_TOKEN_OK);
    CHECK(a == 32);
}

TEST("token_api/peek-reads-header-and-footer-without-verifying") {
    REQUIRE(available("v4.local"));
    const Keys k = keygen("v4.local");
    const Bytes foot = bytes_of("{\"kid\":\"prod-2026\"}");
    const auto t = issue("v4.local", k.secret, bytes_of("m"), foot, {});
    REQUIRE(t.rc == CRYPTOLIB_TOKEN_OK);
    CHECK(peek_format(t.token) == "v4.local");
    const auto pf = peek_footer(t.token);
    CHECK(pf.rc == CRYPTOLIB_TOKEN_OK);
    CHECK(pf.f == foot);
    const auto bare = issue("v4.local", k.secret, bytes_of("m"), {}, {});
    REQUIRE(bare.rc == CRYPTOLIB_TOKEN_OK);
    const auto none = peek_footer(bare.token);
    CHECK(none.rc == CRYPTOLIB_TOKEN_OK && none.f.empty());
    std::string forged = t.token;
    forged[forged.size() - 1] = forged[forged.size() - 1] == 'A' ? 'B' : 'A';
    CHECK(peek_format(forged) == "v4.local");
    CHECK(peek_footer(forged).rc == CRYPTOLIB_TOKEN_OK);
    CHECK(accept("v4.local", forged, k.secret, foot, {}).rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    CHECK(peek_format("v9.public.abc") == "v9.public");
    CHECK(peek_format("cb2.local.x.y") == "cb2.local");
    CHECK(peek_format("v4.secret.abc").empty());
    CHECK(peek_format("v4.local").empty());
    CHECK(peek_format("V4.local.abc").empty());
    CHECK(peek_format("abcdefghi.local.x").empty());
    CHECK(peek_format("").empty());
    CHECK(peek_footer("v4.local.abc.a").rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    CHECK(peek_footer("v4.local.abc.a=b").rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    CHECK(peek_footer("v4.local.abc.a.b").rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    CHECK(peek_footer("v4.local.abc.").rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    CHECK(peek_footer("nonsense").rc == CRYPTOLIB_TOKEN_ERR_INVALID);
    const auto kid = peek_footer("v4.local.abc.a2lk");
    CHECK(kid.rc == CRYPTOLIB_TOKEN_OK && kid.f == bytes_of("kid"));
    uint8_t tiny[2];
    size_t n = 0;
    const std::string with = "v4.local.abc.a2lk";
    CHECK(cryptolib_token_peek_footer(reinterpret_cast<const uint8_t*>(with.data()), with.size(), tiny, sizeof tiny,
                                      &n) == CRYPTOLIB_TOKEN_ERR_ARGUMENT);
    CHECK(cryptolib_token_peek_format(reinterpret_cast<const uint8_t*>(with.data()), with.size(), nullptr, 0) == 8);
}

TEST("token_api/per-format-functions-are-the-generic-calls") {
    REQUIRE(available("v4.local"));
    const Keys k = keygen("v4.local");
    const Bytes m = bytes_of("{\"data\":\"x\"}"), foot = bytes_of("f"), imp = bytes_of("i");
    CHECK(cryptolib_paseto_v4_local_encrypt_len(m.size(), foot.size()) ==
          cryptolib_token_issue_len("v4.local", m.size(), foot.size()));
    std::string t(cryptolib_paseto_v4_local_encrypt_len(m.size(), foot.size()), '\0');
    size_t n = 0;
    REQUIRE(cryptolib_paseto_v4_local_encrypt(reinterpret_cast<uint8_t*>(t.data()), t.size(), &n, k.secret.data(), 32,
                                              m.data(), m.size(), foot.data(), foot.size(), imp.data(),
                                              imp.size()) == CRYPTOLIB_PASETO_OK);
    t.resize(n);
    const auto a = accept("v4.local", t, k.secret, foot, imp);
    CHECK(a.rc == CRYPTOLIB_TOKEN_OK && a.m == m);
    const auto g = issue("v4.local", k.secret, m, foot, imp);
    REQUIRE(g.rc == CRYPTOLIB_TOKEN_OK);
    Bytes out(cryptolib_paseto_v4_local_decrypt_cap(g.token.size()));
    CHECK(out.size() == cryptolib_token_accept_cap("v4.local", g.token.size()));
    CHECK(cryptolib_paseto_v4_local_decrypt(out.data(), out.size(), &n, reinterpret_cast<const uint8_t*>(g.token.data()),
                                            g.token.size(), k.secret.data(), 32, foot.data(), foot.size(), imp.data(),
                                            imp.size()) == CRYPTOLIB_PASETO_OK);
    CHECK(Bytes(out.begin(), out.begin() + static_cast<long>(n)) == m);
    if (available("cb1.local")) {
        const auto c = issue("cb1.local", k.secret, m, foot, imp);
        REQUIRE(c.rc == CRYPTOLIB_TOKEN_OK);
        Bytes o2(cryptolib_cb1_local_decrypt_cap(c.token.size()));
        CHECK(cryptolib_cb1_local_decrypt(o2.data(), o2.size(), &n, reinterpret_cast<const uint8_t*>(c.token.data()),
                                          c.token.size(), k.secret.data(), 32, foot.data(), foot.size(), imp.data(),
                                          imp.size()) == CRYPTOLIB_PASETO_OK);
        CHECK(Bytes(o2.begin(), o2.begin() + static_cast<long>(n)) == m);
    } else {
        CHECK(cryptolib_cb1_local_encrypt_len(1, 0) == 0);
        CHECK(cryptolib_cb1_local_encrypt(out.data(), out.size(), &n, k.secret.data(), 32, m.data(), m.size(), nullptr, 0,
                                          nullptr, 0) == CRYPTOLIB_PASETO_ERR_UNAVAILABLE);
    }
    if (available("cb1.public")) {
        const Keys s = keygen("cb1.public");
        const auto c = issue("cb1.public", s.secret, m, foot, imp);
        REQUIRE(c.rc == CRYPTOLIB_TOKEN_OK);
        Bytes o3(cryptolib_cb1_public_verify_cap(c.token.size()));
        CHECK(cryptolib_cb1_public_verify(o3.data(), o3.size(), &n, reinterpret_cast<const uint8_t*>(c.token.data()),
                                          c.token.size(), s.pub.data(), s.pub.size(), foot.data(), foot.size(),
                                          imp.data(), imp.size()) == CRYPTOLIB_PASETO_OK);
        CHECK(Bytes(o3.begin(), o3.begin() + static_cast<long>(n)) == m);
    } else {
        CHECK(cryptolib_cb1_public_sign_len(1, 0) == 0);
        CHECK(cryptolib_cb1_public_sign(out.data(), out.size(), &n, k.secret.data(), 4096, m.data(), m.size(), nullptr,
                                        0, nullptr, 0) == CRYPTOLIB_PASETO_ERR_UNAVAILABLE);
    }
}

TEST("token_api/common-schema-vectors-accept-through-the-generic-calls") {
    const std::filesystem::path dir = std::filesystem::path(CRYPTOLIB_SOURCE_DIR) / "tests" / "vectors" / "tokens";
    REQUIRE(std::filesystem::is_directory(dir));
    int files = 0;
    for (const auto& e : std::filesystem::directory_iterator(dir)) {
        if (e.path().extension() != ".json") continue;
        std::ifstream in(e.path(), std::ios::binary);
        REQUIRE(static_cast<bool>(in));
        std::stringstream ss;
        ss << in.rdbuf();
        const std::string text = ss.str();
        JsonParser p{text};
        const Json root = p.value();
        REQUIRE(p.ok);
        const std::string format = jstr(root, "format");
        const Json* cases = root.get("cases");
        REQUIRE(!format.empty() && cases && cases->kind == Json::Arr && !cases->arr.empty());
        CHECK(e.path().stem().string() == format);
        ++files;
        if (!available(format.c_str())) {
            std::printf("      %s: not in this profile, skipped\n", format.c_str());
            continue;
        }
        const bool pub = is_public(format.c_str());
        int pass = 0, fail = 0, reissued = 0;
        for (const Json& c : cases->arr) {
            const std::string name = jstr(c, "name"), token = jstr(c, "token");
            const Bytes payload = bytes_of(jstr(c, "payload")), f = bytes_of(jstr(c, "footer"));
            const Bytes i = bytes_of(jstr(c, "implicit-assertion"));
            const Json* ef = c.get("expect-fail");
            const bool expect_fail = ef && ef->kind == Json::Bool && ef->b;
            const Bytes key = unhex(jstr(c, pub ? "public-key" : "key"));
            if (key.empty()) {
                CHECK(expect_fail);
                ++fail;
                continue;
            }
            const auto a = accept(format.c_str(), token, key, f, i);
            if (expect_fail) {
                CHECK(a.rc == CRYPTOLIB_TOKEN_ERR_INVALID);
                CHECK(a.m.empty());
                ++fail;
                continue;
            }
            if (a.rc != CRYPTOLIB_TOKEN_OK) std::printf("      %s %s gave %d\n", format.c_str(), name.c_str(), a.rc);
            CHECK(a.rc == CRYPTOLIB_TOKEN_OK);
            CHECK(a.m == payload);
            CHECK(peek_format(token) == format);
            const auto pf = peek_footer(token);
            CHECK(pf.rc == CRYPTOLIB_TOKEN_OK && pf.f == f);
            ++pass;
            if (pub) {
                const Bytes sk = unhex(jstr(c, "secret-key"));
                const auto again = issue(format.c_str(), sk, payload, f, i);
                CHECK(again.rc == CRYPTOLIB_TOKEN_OK);
                CHECK(accept(format.c_str(), again.token, key, f, i).rc == CRYPTOLIB_TOKEN_OK);
                ++reissued;
            }
#ifdef CRYPTOLIB_PASETO_TEST_NONCE
            if (!pub) {
                const Bytes nonce = unhex(jstr(c, "nonce"));
                REQUIRE(nonce.size() == 32);
                std::string again(cryptolib_token_issue_len(format.c_str(), payload.size(), f.size()), '\0');
                size_t n = 0;
                int rc = -99;
                if (format == "v4.local")
                    rc = cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
                        reinterpret_cast<uint8_t*>(again.data()), again.size(), &n, key.data(), 32, payload.data(),
                        payload.size(), f.data(), f.size(), i.data(), i.size(), nonce.data(), 32);
                if (format == "cb1.local")
                    rc = cryptolib_cb1_local_encrypt_with_nonce_for_testing(
                        reinterpret_cast<uint8_t*>(again.data()), again.size(), &n, key.data(), 32, payload.data(),
                        payload.size(), f.data(), f.size(), i.data(), i.size(), nonce.data(), 32);
                CHECK(rc == CRYPTOLIB_TOKEN_OK);
                again.resize(n);
                CHECK(again == token);
                ++reissued;
            }
#endif
        }
        std::printf("      %s: %d accepted, %d rejected as expected, %d re-issued\n", format.c_str(), pass, fail, reissued);
    }
    CHECK(files >= 3);
}

void run_tests_token_api() {
    ::test::run("token_api/table-lists-every-format-with-its-sizes");
    ::test::run("token_api/unknown-format-and-unavailable-format-are-told-apart");
    ::test::run("token_api/keygen-issue-accept-round-trip-per-format");
    ::test::run("token_api/the-caller-names-the-format-and-the-header-never-chooses");
    ::test::run("token_api/argument-errors-are-the-callers-own");
    ::test::run("token_api/peek-reads-header-and-footer-without-verifying");
    ::test::run("token_api/per-format-functions-are-the-generic-calls");
    ::test::run("token_api/common-schema-vectors-accept-through-the-generic-calls");
}
