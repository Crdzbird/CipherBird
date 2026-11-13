/// P-256 ECDSA with SHA-256 through the C ABI: the NIST CAVP P-256 cases
/// and RFC 6979 A.2.5 (tests/vectors/p256/ecdsa_p256_sha256.json), round
/// trips, the refusal of non-canonical signatures and public keys, and the
/// strict PKCS#8 import against keys the OpenSSL command line wrote.
#include "test_framework.hpp"
#include "json_lite.hpp"
#include "cryptolib_c.h"
#include <cryptolib/cryptolib.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace test;

namespace {

using Bytes = std::vector<uint8_t>;

/// Hex to bytes; an odd number of digits (the CAVP out-of-range coordinates
/// are 65 digits) gains a leading zero, so the value keeps its length.
Bytes unhex(std::string_view text) {
    const std::string h = (text.size() % 2 == 1 ? "0" : "") + std::string(text);
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    }
    return out;
}

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

struct Out { Bytes v; std::string err; bool ok; };

Out take(CryptoBufferResult r) {
    Out o{{}, {}, r.error == nullptr && r.buf.data != nullptr};
    if (r.buf.data) o.v.assign(r.buf.data, r.buf.data + r.buf.len);
    if (r.error) o.err = r.error;
    cryptolib_buffer_free(&r.buf);
    cryptolib_str_free(r.error);
    return o;
}

Out public_of(const Bytes& sk) { return take(cryptolib_p256_public_key(sk.data(), sk.size())); }
Out sign(const Bytes& sk, const Bytes& m) { return take(cryptolib_p256_sign(sk.data(), sk.size(), m.data(), m.size())); }
bool verify(const Bytes& pk, const Bytes& m, const Bytes& sig) {
    return cryptolib_p256_verify(pk.data(), pk.size(), m.data(), m.size(), sig.data(), sig.size()) == 1;
}
Out import_der(const Bytes& der) { return take(cryptolib_p256_import_pkcs8_der(der.data(), der.size())); }
Out import_pem(std::string_view pem) {
    return take(cryptolib_p256_import_pkcs8_pem(reinterpret_cast<const uint8_t*>(pem.data()), pem.size()));
}

Bytes point(std::string_view qx, std::string_view qy) { return cat({{0x04}, unhex(qx), unhex(qy)}); }

const char* const kOrderHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const char* const kGx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const char* const kGy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/// n - v for a 32-byte big-endian v below n.
Bytes order_minus(const Bytes& v) {
    const Bytes n = unhex(kOrderHex);
    Bytes out(32);
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int d = static_cast<int>(n[static_cast<size_t>(i)]) - static_cast<int>(v[static_cast<size_t>(i)]) - borrow;
        borrow = d < 0 ? 1 : 0;
        out[static_cast<size_t>(i)] = static_cast<uint8_t>(d < 0 ? d + 256 : d);
    }
    return out;
}

Bytes der(uint8_t tag, const Bytes& content) {
    Bytes out{tag};
    if (content.size() < 0x80) {
        out.push_back(static_cast<uint8_t>(content.size()));
    } else if (content.size() < 0x100) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(content.size()));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(content.size() >> 8));
        out.push_back(static_cast<uint8_t>(content.size()));
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

const Bytes kOidEc = unhex("2a8648ce3d0201");
const Bytes kOidP256 = unhex("2a8648ce3d030107");
const Bytes kOidP384 = unhex("2b81040022");
const Bytes kOidK256 = unhex("2b8104000a");

struct Shape {
    Bytes version{0x00};
    Bytes algorithm = kOidEc;
    Bytes curve = kOidP256;
    Bytes ec_version{0x01};
    Bytes scalar;
    Bytes inner_curve;
    Bytes pub;
    Bytes attributes;
};

Bytes pkcs8(const Shape& s) {
    Bytes ec = cat({der(0x02, s.ec_version), der(0x04, s.scalar)});
    if (!s.inner_curve.empty()) ec = cat({ec, der(0xA0, der(0x06, s.inner_curve))});
    if (!s.pub.empty()) ec = cat({ec, der(0xA1, der(0x03, cat({{0x00}, s.pub})))});
    Bytes info = cat({der(0x02, s.version), der(0x30, cat({der(0x06, s.algorithm), der(0x06, s.curve)})),
                      der(0x04, der(0x30, ec))});
    if (!s.attributes.empty()) info = cat({info, s.attributes});
    return der(0x30, info);
}

const char* const kFixtureDer =
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042063e0acc0eb9f737b59abc9443e8ea418ee738c"
    "e2f317f92c72e48e36a7751476a14403420004a4726836c202048a75e72da9d3e3c934ef7e244bb52de7e416c6c81760ab9ebe30be4dc0"
    "5f6b517af45089b58ee65ae350e3dbc61ed592a3121110fa385777d8";
const char* const kFixtureSk = "63e0acc0eb9f737b59abc9443e8ea418ee738ce2f317f92c72e48e36a7751476";
const char* const kFixturePk =
    "04a4726836c202048a75e72da9d3e3c934ef7e244bb52de7e416c6c81760ab9ebe30be4dc05f6b517af45089b58ee65ae350e3dbc61ed5"
    "92a3121110fa385777d8";
const char* const kFixturePem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY+CswOufc3tZq8lE\n"
    "Po6kGO5zjOLzF/kscuSONqd1FHahRANCAASkcmg2wgIEinXnLanT48k0734kS7Ut\n"
    "5+QWxsgXYKuevjC+TcBfa1F69FCJtY7mWuNQ49vGHtWSoxIREPo4V3fY\n"
    "-----END PRIVATE KEY-----\n";
const char* const kEd25519Der =
    "302e020100300506032b657004220420967c1cd1cb17a8ddadffcd3a5bd4a5216a1ad8aeddad40554ec40baebf55a396";
const char* const kSec1P384Der =
    "3081a4020101043093329d65df1e4b2e1fb7e2577e14e03eacdf6f033eb794992d909eb973b28a84bb318de3f156cb604c8b4266262699"
    "67a00706052b81040022a16403620004f513aa413e32ce1f8a4263f3b9b77b9326775cf126a335729737f558908978847affc41fba8662"
    "448241252151039acf53a2daee5b3053cd7bafdcbe5c10c48f165bbe87877352f9998338519e63c974d890b1643dd79947e0fbdbbd4e6c"
    "f32e";
const char* const kEncryptedDer =
    "3081f4305f06092a864886f70d01050d3052303106092a864886f70d01050c30240410f03572abd0a59d6ad22522740b9fadcc02020800"
    "300c06082a864886f70d02090500301d060960864801650304012a04100bb671e4ca371be2f1740b3633675c1e048190bf87c68929b527"
    "37837c7344d1677fdb8b41a33397f6698e11654c0cff53a32ecfe341e0066c578fad11d8aecd8f1c155793dfcda97b72eaf7b34ca1885d"
    "b8df3908e986d3b95fa46f3dc93be4359d0b89e4ba9e96d92350697d526704a3d353f8b7aab2bc981f2e8967a70646ec71194fdd1dcc42"
    "8d28bb66eb1b0b4b2f2a6231c6b3adda9023918bd53997f17376a2";
const char* const kEncryptedPem =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDRNFW+JfPh1ABZmjpd\n"
    "G+/xAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQmGYWdWna4kAYmedb\n"
    "1YLdkwSBkJhb5Tq8wmZyXmE03ih7BxsHlhbpI7kqA+GTDmlXWtpaKXmBX7cQT2Mu\n"
    "rBEOqw1fP3kz9vxS3C+1xFsV2ZSCW6P508o3N7342VUIiaBzQCitLSuaUl9JFAF3\n"
    "P9P+MHA8tuZBVA+Ch2opxSGLuR9Uj0QSeMsHg0WOCqXVQCtRxUjgYG5832Rp9e9Z\n"
    "MxN+ITiG1A==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";
const char* const kSec1Pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIGPgrMDrn3N7WavJRD6OpBjuc4zi8xf5LHLkjjandRR2oAoGCCqGSM49\n"
    "AwEHoUQDQgAEpHJoNsICBIp15y2p0+PJNO9+JEu1LefkFsbIF2Crnr4wvk3AX2tR\n"
    "evRQibWO5lrjUOPbxh7VkqMSERD6OFd32A==\n"
    "-----END EC PRIVATE KEY-----\n";

bool has(const std::string& s, std::string_view needle) { return s.find(needle) != std::string::npos; }

const Json& vectors() {
    static const Json root = [] {
        const std::string path = std::string(CRYPTOLIB_SOURCE_DIR) + "/tests/vectors/p256/ecdsa_p256_sha256.json";
        std::ifstream in(path, std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        static std::string text;
        text = ss.str();
        JsonParser p{text};
        Json j = p.value();
        if (!p.ok) j = Json{};
        return j;
    }();
    return root;
}

const std::vector<Json>& section(const char* name) {
    static const std::vector<Json> empty;
    const Json* s = vectors().get(name);
    return s && s->kind == Json::Arr ? s->arr : empty;
}

bool flag(const Json& t, const char* name) {
    const Json* v = t.get(name);
    return v && v->kind == Json::Bool && v->b;
}

}

#ifdef CRYPTOLIB_HAS_P256

TEST("p256/available-sizes-and-the-order-constant") {
    REQUIRE(cryptolib_init() == 0);
    CHECK(cryptolib_p256_available() == (crypto::ec::P256::DETERMINISTIC_NONCES ? 2 : 1));
    CHECK(crypto::ec::P256::SECRET_KEY_BYTES == CRYPTOLIB_P256_SECRET_KEY_BYTES);
    CHECK(crypto::ec::P256::PUBLIC_KEY_BYTES == CRYPTOLIB_P256_PUBLIC_KEY_BYTES);
    CHECK(crypto::ec::P256::SIGNATURE_BYTES == CRYPTOLIB_P256_SIGNATURE_BYTES);
    CHECK(crypto::ec::P256::MAX_PKCS8_BYTES == CRYPTOLIB_P256_MAX_PKCS8_BYTES);
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    REQUIRE(g != nullptr);
    uint8_t n[32];
    CHECK(BN_bn2binpad(EC_GROUP_get0_order(g), n, 32) == 32);
    CHECK(std::memcmp(n, crypto::ec::p256_detail::ORDER, 32) == 0);
    CHECK(Bytes(n, n + 32) == unhex(kOrderHex));
    EC_GROUP_free(g);
    std::printf("      nonces: %s\n", crypto::ec::P256::DETERMINISTIC_NONCES ? "deterministic (RFC 6979)" : "libcrypto hedged random");
}

TEST("p256/keygen-sign-verify-round-trip") {
    CryptoKeyPair kp = cryptolib_p256_keygen();
    REQUIRE(kp.secret_key.data && kp.public_key.data);
    CHECK(kp.secret_key.len == 32);
    CHECK(kp.public_key.len == 65);
    const Bytes sk(kp.secret_key.data, kp.secret_key.data + kp.secret_key.len);
    const Bytes pk(kp.public_key.data, kp.public_key.data + kp.public_key.len);
    cryptolib_keypair_free(&kp);
    CHECK(pk[0] == 0x04);
    const auto derived = public_of(sk);
    CHECK(derived.ok && derived.v == pk);
    CHECK(crypto::ec::P256::valid_public_key(pk));
    const Bytes msgs[] = {{}, bytes_of("m"), bytes_of("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJURUFNIn0"), Bytes(1 << 20, 0x5a)};
    for (const Bytes& m : msgs) {
        const auto s = sign(sk, m);
        REQUIRE(s.ok);
        CHECK(s.v.size() == 64);
        CHECK(verify(pk, m, s.v));
        Bytes other = m;
        other.push_back(0x00);
        CHECK(!verify(pk, other, s.v));
        for (size_t bit : {size_t{0}, size_t{255}, size_t{256}, size_t{511}}) {
            Bytes bad = s.v;
            bad[bit / 8] ^= static_cast<uint8_t>(0x80u >> (bit % 8));
            CHECK(!verify(pk, m, bad));
        }
    }
    CryptoKeyPair second = cryptolib_p256_keygen();
    REQUIRE(second.public_key.data);
    const Bytes pk2(second.public_key.data, second.public_key.data + second.public_key.len);
    const Bytes sk2(second.secret_key.data, second.secret_key.data + second.secret_key.len);
    cryptolib_keypair_free(&second);
    CHECK(sk2 != sk);
    const auto s = sign(sk, bytes_of("m"));
    CHECK(!verify(pk2, bytes_of("m"), s.v));
}

TEST("p256/the-generator-and-the-edges-of-the-scalar-range") {
    Bytes one(32, 0);
    one[31] = 1;
    const auto g = public_of(one);
    REQUIRE(g.ok);
    CHECK(g.v == point(kGx, kGy));
    const Bytes n = unhex(kOrderHex);
    const Bytes top = order_minus(one);
    const auto neg = public_of(top);
    REQUIRE(neg.ok);
    CHECK(Bytes(neg.v.begin() + 1, neg.v.begin() + 33) == unhex(kGx));
    CHECK(Bytes(neg.v.begin() + 33, neg.v.end()) != unhex(kGy));
    CHECK(sign(top, bytes_of("m")).ok);
    for (const Bytes& bad : {Bytes(32, 0), n, Bytes(32, 0xff), Bytes(31, 1), Bytes(33, 1), Bytes{}}) {
        const auto p = public_of(bad);
        CHECK(!p.ok && p.v.empty() && has(p.err, "p256:"));
        const auto s = sign(bad, bytes_of("m"));
        CHECK(!s.ok && s.v.empty());
    }
    CHECK(!take(cryptolib_p256_public_key(nullptr, 32)).ok);
    CHECK(!take(cryptolib_p256_sign(nullptr, 32, one.data(), 1)).ok);
    CHECK(!take(cryptolib_p256_sign(one.data(), 32, nullptr, 1)).ok);
    CHECK(take(cryptolib_p256_sign(one.data(), 32, nullptr, 0)).ok);
}

TEST("p256/rfc6979-a25-deterministic-signatures") {
    const Json* r = vectors().get("rfc6979");
    REQUIRE(r != nullptr);
    const Bytes d = unhex(jstr(*r, "d"));
    const Bytes q = point(jstr(*r, "qx"), jstr(*r, "qy"));
    const auto pub = public_of(d);
    REQUIRE(pub.ok);
    CHECK(pub.v == q);
    const Json* cases = r->get("cases");
    REQUIRE(cases && cases->arr.size() == 2);
    for (const Json& c : cases->arr) {
        const Bytes m = bytes_of(jstr(c, "message"));
        const Bytes expect = cat({unhex(jstr(c, "r")), unhex(jstr(c, "s"))});
        CHECK(verify(q, m, expect));
        const auto s = sign(d, m);
        REQUIRE(s.ok);
        CHECK(verify(q, m, s.v));
        if (crypto::ec::P256::DETERMINISTIC_NONCES) {
            CHECK(s.v == expect);
            CHECK(sign(d, m).v == s.v);
        }
    }
    if (!crypto::ec::P256::DETERMINISTIC_NONCES)
        std::printf("      note: this libcrypto has no RFC 6979 nonces, the exact answers are only verified\n");
}

TEST("p256/cavp-key-pairs") {
    const auto& v = section("keypair");
    REQUIRE(v.size() == 10);
    for (const Json& t : v) {
        const auto p = public_of(unhex(jstr(t, "d")));
        CHECK(p.ok && p.v == point(jstr(t, "qx"), jstr(t, "qy")));
    }
}

TEST("p256/cavp-public-key-validation") {
    const auto& v = section("pkv");
    REQUIRE(v.size() == 12);
    int valid = 0, invalid = 0;
    for (const Json& t : v) {
        const Bytes q = point(jstr(t, "qx"), jstr(t, "qy"));
        const bool expect = flag(t, "valid");
        if (crypto::ec::P256::valid_public_key(q) != expect) std::printf("      pkv mismatch: %s\n", jstr(t, "note").c_str());
        CHECK(crypto::ec::P256::valid_public_key(q) == expect);
        expect ? ++valid : ++invalid;
    }
    CHECK(valid == 4 && invalid == 8);
}

TEST("p256/cavp-signature-verification") {
    const auto& v = section("sigver");
    REQUIRE(v.size() == 15);
    int valid = 0, invalid = 0;
    for (const Json& t : v) {
        const bool got = verify(point(jstr(t, "qx"), jstr(t, "qy")), unhex(jstr(t, "message")),
                                cat({unhex(jstr(t, "r")), unhex(jstr(t, "s"))}));
        const bool expect = flag(t, "valid");
        if (got != expect) std::printf("      sigver mismatch: %s\n", jstr(t, "note").c_str());
        CHECK(got == expect);
        expect ? ++valid : ++invalid;
    }
    CHECK(valid == 3 && invalid == 12);
}

TEST("p256/cavp-signature-generation-cases-verify") {
    const auto& v = section("siggen");
    REQUIRE(v.size() == 15);
    for (const Json& t : v) {
        const Bytes d = unhex(jstr(t, "d")), q = point(jstr(t, "qx"), jstr(t, "qy")), m = unhex(jstr(t, "message"));
        const auto p = public_of(d);
        CHECK(p.ok && p.v == q);
        CHECK(verify(q, m, cat({unhex(jstr(t, "r")), unhex(jstr(t, "s"))})));
        const auto s = sign(d, m);
        CHECK(s.ok && verify(q, m, s.v));
    }
}

TEST("p256/verify-refuses-non-canonical-signatures-and-keys") {
    const Json* r = vectors().get("rfc6979");
    REQUIRE(r != nullptr);
    const Bytes q = point(jstr(*r, "qx"), jstr(*r, "qy"));
    const Json& c = r->get("cases")->arr[0];
    const Bytes m = bytes_of(jstr(c, "message"));
    const Bytes rr = unhex(jstr(c, "r")), ss = unhex(jstr(c, "s"));
    const Bytes sig = cat({rr, ss});
    REQUIRE(verify(q, m, sig));
    const Bytes n = unhex(kOrderHex), zero(32, 0), ones(32, 0xff);
    CHECK(verify(q, m, cat({rr, order_minus(ss)})));
    CHECK(!verify(q, m, cat({order_minus(rr), ss})));
    for (const Bytes& bad : {cat({zero, ss}), cat({rr, zero}), cat({n, ss}), cat({rr, n}), cat({ones, ss}),
                             cat({rr, ones}), cat({zero, zero}), Bytes(sig.begin(), sig.end() - 1),
                             cat({sig, {0x00}}), cat({{0x00}, sig}), Bytes{}, cat({ss, rr})}) {
        CHECK(!verify(q, m, bad));
    }
    const Bytes der_sig = cat({{0x30, 0x46, 0x02, 0x21, 0x00}, rr, {0x02, 0x21, 0x00}, ss});
    CHECK(!verify(q, m, der_sig));
    Bytes compressed = cat({{static_cast<uint8_t>(0x02 | (q[64] & 1))}, Bytes(q.begin() + 1, q.begin() + 33)});
    Bytes off = q;
    off[64] ^= 0x01;
    Bytes hybrid = q;
    hybrid[0] = static_cast<uint8_t>(0x06 | (q[64] & 1));
    Bytes wrong_prefix = q;
    wrong_prefix[0] = 0x05;
    Bytes origin(65, 0);
    origin[0] = 0x04;
    const Bytes p = unhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    Bytes x_is_p = cat({{0x04}, p, Bytes(q.begin() + 33, q.end())});
    for (const Bytes& bad : {compressed, off, hybrid, wrong_prefix, origin, x_is_p, Bytes(q.begin(), q.end() - 1),
                             cat({q, {0x00}}), Bytes{}, Bytes(q.begin() + 1, q.end())}) {
        CHECK(!verify(bad, m, sig));
        CHECK(!crypto::ec::P256::valid_public_key(bad));
    }
    CHECK(cryptolib_p256_verify(nullptr, 65, m.data(), m.size(), sig.data(), 64) == 0);
    CHECK(cryptolib_p256_verify(q.data(), 65, m.data(), m.size(), nullptr, 64) == 0);
    CHECK(cryptolib_p256_verify(q.data(), 65, nullptr, 3, sig.data(), 64) == 0);
}

TEST("p256/pkcs8-import-of-keys-openssl-wrote") {
    const Bytes fixture = unhex(kFixtureDer);
    const Bytes want = cat({unhex(kFixtureSk), unhex(kFixturePk)});
    const auto a = import_der(fixture);
    REQUIRE(a.ok);
    CHECK(a.v.size() == 97);
    CHECK(a.v == want);
    const auto b = import_pem(kFixturePem);
    CHECK(b.ok && b.v == want);
    std::string crlf;
    for (const char c : std::string_view(kFixturePem)) {
        if (c == '\n') crlf += '\r';
        crlf += c;
    }
    CHECK(import_pem(crlf).v == want);
    CHECK(import_pem(std::string("\n \t") + kFixturePem + "\r\n\n").v == want);
    std::string one_line;
    for (const char c : std::string_view(kFixturePem)) {
        if (c != '\n') one_line += c;
    }
    CHECK(import_pem(one_line).v == want);
    const Bytes sk(a.v.begin(), a.v.begin() + 32), pk(a.v.begin() + 32, a.v.end());
    const auto s = sign(sk, bytes_of("apns"));
    CHECK(s.ok && verify(pk, bytes_of("apns"), s.v));
}

TEST("p256/pkcs8-import-accepts-the-optional-fields") {
    const Json* r = vectors().get("rfc6979");
    REQUIRE(r != nullptr);
    const Bytes d = unhex(jstr(*r, "d")), q = point(jstr(*r, "qx"), jstr(*r, "qy"));
    const Bytes want = cat({d, q});
    Shape bare;
    bare.scalar = d;
    CHECK(import_der(pkcs8(bare)).v == want);
    Shape with_pub = bare;
    with_pub.pub = q;
    CHECK(import_der(pkcs8(with_pub)).v == want);
    CHECK(pkcs8(Shape{{0x00}, kOidEc, kOidP256, {0x01}, unhex(kFixtureSk), {}, unhex(kFixturePk), {}}) == unhex(kFixtureDer));
    Shape apple = with_pub;
    apple.inner_curve = kOidP256;
    CHECK(import_der(pkcs8(apple)).v == want);
    Shape params_only = bare;
    params_only.inner_curve = kOidP256;
    const auto got = import_der(pkcs8(params_only));
    REQUIRE(got.ok && got.v == want);
    if (crypto::ec::P256::DETERMINISTIC_NONCES) {
        const Json& c = r->get("cases")->arr[0];
        const auto s = sign(Bytes(got.v.begin(), got.v.begin() + 32), bytes_of(jstr(c, "message")));
        CHECK(s.v == cat({unhex(jstr(c, "r")), unhex(jstr(c, "s"))}));
    }
}

TEST("p256/pkcs8-import-is-strict") {
    const Bytes fixture = unhex(kFixtureDer);
    const Bytes sk = unhex(kFixtureSk), pk = unhex(kFixturePk);
    int flips = 0;
    for (size_t i = 0; i < fixture.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
            Bytes bad = fixture;
            bad[i] ^= static_cast<uint8_t>(1u << bit);
            const auto o = import_der(bad);
            if (o.ok) std::printf("      accepted a flipped bit at byte %zu bit %d\n", i, bit);
            CHECK(!o.ok && o.v.empty());
            ++flips;
        }
    }
    CHECK(flips == 138 * 8);
    for (size_t len = 0; len < fixture.size(); ++len) CHECK(!import_der(Bytes(fixture.begin(), fixture.begin() + static_cast<long>(len))).ok);
    CHECK(!import_der(cat({fixture, {0x00}})).ok);
    CHECK(!import_der(cat({fixture, fixture})).ok);
    Shape good;
    good.scalar = sk;
    good.pub = pk;
    REQUIRE(import_der(pkcs8(good)).ok);
    const Bytes n = unhex(kOrderHex);
    const auto expect = [](const Shape& s, std::string_view why) {
        const auto o = import_der(pkcs8(s));
        if (o.ok || !has(o.err, why)) std::printf("      wanted \"%.*s\", got ok=%d \"%s\"\n", static_cast<int>(why.size()), why.data(), o.ok, o.err.c_str());
        CHECK(!o.ok && o.v.empty() && has(o.err, why));
    };
    Shape s = good;
    s.curve = kOidP384;
    expect(s, "not P-256");
    s = good;
    s.curve = kOidK256;
    expect(s, "not P-256");
    s = good;
    s.curve = kOidP384;
    s.scalar = Bytes(48, 0x11);
    s.pub.clear();
    expect(s, "not P-256");
    s = good;
    s.inner_curve = kOidP384;
    expect(s, "not P-256");
    s = good;
    s.algorithm = unhex("2a8648ce3d0202");
    expect(s, "id-ecPublicKey");
    s = good;
    s.version = {0x01};
    expect(s, "PKCS#8 version");
    s = good;
    s.ec_version = {0x02};
    expect(s, "ECPrivateKey version");
    s = good;
    s.attributes = der(0xA0, der(0x30, {}));
    expect(s, "attributes");
    s = good;
    s.pub.clear();
    s.scalar = Bytes(32, 0);
    expect(s, "out of range");
    s.scalar = n;
    expect(s, "out of range");
    s.scalar = Bytes(32, 0xff);
    expect(s, "out of range");
    s.scalar = Bytes(sk.begin() + 1, sk.end());
    expect(s, "32 bytes");
    s.scalar = cat({{0x00}, sk});
    expect(s, "32 bytes");
    s = good;
    s.pub = point(kGx, kGy);
    expect(s, "does not match");
    s = good;
    s.pub = cat({{static_cast<uint8_t>(0x02 | (pk[64] & 1))}, Bytes(pk.begin() + 1, pk.begin() + 33)});
    expect(s, "uncompressed");
    const auto reject = [](const Bytes& d, std::string_view why) {
        const auto o = import_der(d);
        if (o.ok || !has(o.err, why)) std::printf("      wanted \"%.*s\", got ok=%d \"%s\"\n", static_cast<int>(why.size()), why.data(), o.ok, o.err.c_str());
        CHECK(!o.ok && o.v.empty() && has(o.err, why));
    };
    reject(unhex(kEd25519Der), "id-ecPublicKey");
    reject(unhex(kEncryptedDer), "encrypted");
    reject(unhex(kSec1P384Der), "SEC 1");
    const Bytes spki = der(0x30, cat({der(0x30, cat({der(0x06, kOidEc), der(0x06, kOidP256)})), der(0x03, cat({{0x00}, pk}))}));
    reject(spki, "PrivateKeyInfo");
    Shape v2 = good;
    v2.version = {0x01};
    expect(v2, "PKCS#8 version");
    reject(cat({{0x30, 0x82, 0x00, 0x87}, Bytes(fixture.begin() + 3, fixture.end())}), "PrivateKeyInfo");
    reject(cat({{0x30, 0x80}, Bytes(fixture.begin() + 3, fixture.end()), {0x00, 0x00}}), "PrivateKeyInfo");
    reject(Bytes(4097, 0x30), "size");
    reject(Bytes{}, "size");
    CHECK(!take(cryptolib_p256_import_pkcs8_der(nullptr, 138)).ok);
    CHECK(!take(cryptolib_p256_import_pkcs8_pem(nullptr, 241)).ok);
}

TEST("p256/pem-import-is-strict") {
    const std::string pem = kFixturePem;
    const auto expect = [](const std::string& text, std::string_view why) {
        const auto o = import_pem(text);
        if (o.ok || !has(o.err, why)) std::printf("      wanted \"%.*s\", got ok=%d \"%s\"\n", static_cast<int>(why.size()), why.data(), o.ok, o.err.c_str());
        CHECK(!o.ok && o.v.empty() && has(o.err, why));
    };
    expect(kEncryptedPem, "encrypted");
    expect(kSec1Pem, "SEC 1");
    expect("Bag Attributes\n" + pem, "PRIVATE KEY block");
    expect(pem + pem, "base64");
    expect(pem + "trailing", "PRIVATE KEY block");
    expect(pem.substr(0, pem.size() - 27), "PRIVATE KEY block");
    std::string wrong_label = pem;
    wrong_label.replace(wrong_label.find("PRIVATE"), 7, "PUBLIC ");
    expect(wrong_label, "PRIVATE KEY block");
    std::string bad_char = pem;
    bad_char[40] = '*';
    expect(bad_char, "base64");
    std::string nul = pem;
    nul.insert(40, 1, '\0');
    expect(nul, "base64");
    std::string url_safe = pem;
    url_safe[url_safe.find('+')] = '-';
    expect(url_safe, "base64");
    std::string truncated_body = pem;
    truncated_body.erase(60, 2);
    expect(truncated_body, "p256:");
    std::string flipped = pem;
    flipped[100] = flipped[100] == 'A' ? 'B' : 'A';
    expect(flipped, "p256:");
    expect("-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----", "base64");
    expect(std::string(4097, 'A'), "size");
    expect("", "size");
    const std::string der_text(reinterpret_cast<const char*>(unhex(kFixtureDer).data()), 138);
    expect(der_text, "PRIVATE KEY block");
}

#else

TEST("p256/reports-unavailable-without-libcrypto-ec") {
    CHECK(cryptolib_p256_available() == 0);
    CryptoKeyPair kp = cryptolib_p256_keygen();
    CHECK(kp.secret_key.data == nullptr && kp.public_key.data == nullptr);
    const Bytes sk(32, 1);
    CHECK(has(public_of(sk).err, "not enabled"));
    CHECK(has(sign(sk, sk).err, "not enabled"));
    CHECK(!verify(Bytes(65, 4), sk, Bytes(64, 1)));
    CHECK(has(import_der(unhex(kFixtureDer)).err, "not enabled"));
    CHECK(has(import_pem(kFixturePem).err, "not enabled"));
}

#endif

void run_tests_p256() {
#ifdef CRYPTOLIB_HAS_P256
    RUN("p256/available-sizes-and-the-order-constant");
    RUN("p256/keygen-sign-verify-round-trip");
    RUN("p256/the-generator-and-the-edges-of-the-scalar-range");
    RUN("p256/rfc6979-a25-deterministic-signatures");
    RUN("p256/cavp-key-pairs");
    RUN("p256/cavp-public-key-validation");
    RUN("p256/cavp-signature-verification");
    RUN("p256/cavp-signature-generation-cases-verify");
    RUN("p256/verify-refuses-non-canonical-signatures-and-keys");
    RUN("p256/pkcs8-import-of-keys-openssl-wrote");
    RUN("p256/pkcs8-import-accepts-the-optional-fields");
    RUN("p256/pkcs8-import-is-strict");
    RUN("p256/pem-import-is-strict");
#else
    RUN("p256/reports-unavailable-without-libcrypto-ec");
#endif
}
