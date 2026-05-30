/**
 * test_kat.cpp — Known-Answer Tests against official vectors.
 *
 * Sources (no vectors are invented; each cites its standard):
 *   - X25519   : RFC 7748 §5.2 (first test vector)
 *   - Ed25519  : RFC 8032 §7.1 TEST 1 (empty message)
 *   - ML-KEM   : FIPS 203 parameter sizes
 *   - ML-DSA   : FIPS 204 parameter sizes
 *   - SLH-DSA  : FIPS 205 key sizes (SHA2-128f)
 *
 * Round-trip behaviour is covered elsewhere; these pin exact bytes / sizes so a
 * wrong algorithm binding or parameter set is caught, not just "it decrypts what
 * it encrypted".
 */

#include "test_framework.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace test;

namespace {

std::vector<uint8_t> from_hex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

} // namespace

// ── X25519 — RFC 7748 §5.2 ───────────────────────────────────────────────────
TEST("kat/x25519/rfc7748") {
    auto scalar = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u      = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    const std::string expected =
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

    auto r = crypto::asymmetric::X25519::shared_secret(scalar, u);
    REQUIRE(r.is_ok());
    CHECK(r.value().to_hex() == expected);
}

// ── Ed25519 — RFC 8032 §7.1 TEST 1 (empty message) ───────────────────────────
TEST("kat/ed25519/rfc8032-test1") {
    auto seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const std::string expected_pub =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const std::string expected_sig =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    auto kp = crypto::asymmetric::Ed25519::keypair_from_seed(seed);
    REQUIRE(kp.is_ok());
    CHECK(kp.value().public_key.to_hex() == expected_pub);

    // Empty message.
    auto sig = crypto::asymmetric::Ed25519::sign({}, kp.value().secret_key.span());
    REQUIRE(sig.is_ok());
    CHECK(sig.value().to_hex() == expected_sig);

    // And it verifies.
    CHECK(crypto::asymmetric::Ed25519::verify({}, sig.value().span(),
                                              kp.value().public_key.span()));
}

#ifdef CRYPTOLIB_HAS_PQ
// ── ML-KEM parameter sizes — FIPS 203 ────────────────────────────────────────
TEST("kat/ml-kem/fips203-sizes") {
    using K = crypto::pq::MlKem;
    struct Exp { K::Level lvl; std::size_t pk, sk, ct, ss; };
    const Exp exps[] = {
        { K::Level::KEM_512,   800, 1632,  768, 32 },
        { K::Level::KEM_768,  1184, 2400, 1088, 32 },
        { K::Level::KEM_1024, 1568, 3168, 1568, 32 },
    };
    for (const auto& e : exps) {
        auto s = K::sizes(e.lvl);
        REQUIRE(s.is_ok());
        CHECK(s.value().public_key    == e.pk);
        CHECK(s.value().secret_key    == e.sk);
        CHECK(s.value().ciphertext    == e.ct);
        CHECK(s.value().shared_secret == e.ss);
    }
}

// ── ML-DSA parameter sizes — FIPS 204 ────────────────────────────────────────
TEST("kat/ml-dsa/fips204-sizes") {
    using D = crypto::pq::MlDsa;
    struct Exp { D::Level lvl; std::size_t pk, sk, sig; };
    const Exp exps[] = {
        { D::Level::DSA_44, 1312, 2560, 2420 },
        { D::Level::DSA_65, 1952, 4032, 3309 },
        { D::Level::DSA_87, 2592, 4896, 4627 },
    };
    for (const auto& e : exps) {
        auto s = D::sizes(e.lvl);
        REQUIRE(s.is_ok());
        CHECK(s.value().public_key == e.pk);
        CHECK(s.value().secret_key == e.sk);
        CHECK(s.value().signature  == e.sig);
    }
}

// ── SLH-DSA key sizes — FIPS 205 (SHA2-128f) ─────────────────────────────────
TEST("kat/slh-dsa/fips205-sizes-128f") {
    using S = crypto::pq::SlhDsa;
    auto s = S::sizes(S::Level::L128f, S::HashFamily::SHA2);
    REQUIRE(s.is_ok());
    CHECK(s.value().public_key == 32);   // 2n, n=16
    CHECK(s.value().secret_key == 64);   // 4n
    CHECK(s.value().signature  == 17088);
}
#endif // CRYPTOLIB_HAS_PQ

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_kat() {
    RUN("kat/x25519/rfc7748");
    RUN("kat/ed25519/rfc8032-test1");
#ifdef CRYPTOLIB_HAS_PQ
    RUN("kat/ml-kem/fips203-sizes");
    RUN("kat/ml-dsa/fips204-sizes");
    RUN("kat/slh-dsa/fips205-sizes-128f");
#endif
}
