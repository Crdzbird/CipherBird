// crypto::Ecvrf — ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381), validated against
// the RFC's Appendix B.3 test vectors + end-to-end prove/verify properties.
#include "test_framework.hpp"

#include <cryptolib/ecvrf.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Ecvrf;

namespace {
std::vector<uint8_t> unhex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> o;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) o.push_back((nib(h[i]) << 4) | nib(h[i + 1]));
    return o;
}
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }

struct Vector { const char* sk; const char* pk; const char* alpha; const char* pi; const char* beta; };

// RFC 9381 Appendix B.3 — ECVRF-EDWARDS25519-SHA512-TAI.
const Vector VECTORS[] = {
    { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
      "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae" },
    { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
      "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031" },
    { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
      "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
      "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f" },
};
} // namespace

TEST("ecvrf/kat/rfc9381-tai") {
    for (const auto& v : VECTORS) {
        auto sk = unhex(v.sk), pk = unhex(v.pk), alpha = unhex(v.alpha);
        // Public key derives from the secret seed.
        CHECK(vec(Ecvrf::derive_public_key(sp(sk))) == pk);
        // prove reproduces the exact proof.
        auto pi = Ecvrf::prove(sp(sk), sp(alpha));
        REQUIRE(pi.is_ok());
        CHECK(vec(pi.value()) == unhex(v.pi));
        // proof_to_hash reproduces beta.
        auto beta = Ecvrf::proof_to_hash(pi.value().span());
        REQUIRE(beta.is_ok());
        CHECK(vec(beta.value()) == unhex(v.beta));
        // verify accepts and returns the same beta.
        auto vr = Ecvrf::verify(sp(pk), sp(alpha), pi.value().span());
        REQUIRE(vr.is_ok());
        CHECK(vec(vr.value()) == unhex(v.beta));
    }
}

TEST("ecvrf/e2e/prove-verify") {
    auto kp = Ecvrf::generate_keypair();
    auto alpha = unhex("deadbeefcafe");
    auto pi = Ecvrf::prove(kp.secret_key.span(), sp(alpha));
    REQUIRE(pi.is_ok());
    CHECK(pi.value().size() == Ecvrf::PROOF_BYTES);

    auto beta = Ecvrf::verify(kp.public_key.span(), sp(alpha), pi.value().span());
    REQUIRE(beta.is_ok());
    CHECK(beta.value().size() == Ecvrf::HASH_BYTES);
    // proof_to_hash matches the verify output.
    auto direct = Ecvrf::proof_to_hash(pi.value().span());
    REQUIRE(direct.is_ok());
    CHECK(vec(direct.value()) == vec(beta.value()));
}

TEST("ecvrf/e2e/unique-and-deterministic") {
    auto kp = Ecvrf::generate_keypair();
    auto a1 = unhex("01"), a2 = unhex("02");
    // Same input → identical proof (deterministic).
    auto p1 = Ecvrf::prove(kp.secret_key.span(), sp(a1));
    auto p1b = Ecvrf::prove(kp.secret_key.span(), sp(a1));
    REQUIRE(p1.is_ok()); REQUIRE(p1b.is_ok());
    CHECK(vec(p1.value()) == vec(p1b.value()));
    // Different input → different output.
    auto p2 = Ecvrf::prove(kp.secret_key.span(), sp(a2));
    REQUIRE(p2.is_ok());
    auto b1 = Ecvrf::proof_to_hash(p1.value().span());
    auto b2 = Ecvrf::proof_to_hash(p2.value().span());
    CHECK(vec(b1.value()) != vec(b2.value()));
}

TEST("ecvrf/e2e/rejects-tampering") {
    auto kp = Ecvrf::generate_keypair();
    auto alpha = unhex("aabbcc");
    auto pi = Ecvrf::prove(kp.secret_key.span(), sp(alpha));
    REQUIRE(pi.is_ok());

    // Tampered proof is rejected.
    auto bad = vec(pi.value());
    bad[70] ^= 0x01;
    CHECK(Ecvrf::verify(kp.public_key.span(), sp(alpha), sp(bad)).is_err());
    // Wrong message is rejected.
    CHECK(Ecvrf::verify(kp.public_key.span(), sp(unhex("aabbcd")), pi.value().span()).is_err());
    // Wrong public key is rejected.
    auto other = Ecvrf::generate_keypair();
    CHECK(Ecvrf::verify(other.public_key.span(), sp(alpha), pi.value().span()).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_ecvrf() {
    RUN("ecvrf/kat/rfc9381-tai");
    RUN("ecvrf/e2e/prove-verify");
    RUN("ecvrf/e2e/unique-and-deterministic");
    RUN("ecvrf/e2e/rejects-tampering");
}
