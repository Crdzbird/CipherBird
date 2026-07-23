// crypto::Oprf — OPRF(ristretto255, SHA-512) base mode (RFC 9497), validated
// against the RFC's Appendix A.1.1 test vectors + end-to-end oblivious flow.
#include "test_framework.hpp"

#include <cryptolib/oprf.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Oprf;

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

struct Vector { const char* input; const char* blind; const char* blinded; const char* eval; const char* output; };
} // namespace

TEST("oprf/kat/rfc9497-ristretto255") {
    auto seed = unhex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    auto info = unhex("74657374206b6579");
    auto sk_want = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";

    auto kp = Oprf::derive_keypair(sp(seed), sp(info));
    REQUIRE(kp.is_ok());
    CHECK(vec(kp.value().secret_key) == unhex(sk_want));

    const Vector vectors[] = {
        { "00",
          "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
          "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
          "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
          "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3"
          "ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6" },
        { "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
          "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
          "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
          "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
          "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4"
          "f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73" },
    };

    for (const auto& v : vectors) {
        auto input = unhex(v.input), blind = unhex(v.blind);
        // Client blinds (deterministic) → matches the vector blinded element.
        auto b = Oprf::blind_with_scalar(sp(input), sp(blind));
        REQUIRE(b.is_ok());
        CHECK(vec(b.value().blinded_element) == unhex(v.blinded));
        // Server blind-evaluates → matches the vector evaluation element.
        auto ev = Oprf::blind_evaluate(kp.value().secret_key.span(), b.value().blinded_element.span());
        REQUIRE(ev.is_ok());
        CHECK(vec(ev.value()) == unhex(v.eval));
        // Client finalizes → matches the vector output.
        auto out = Oprf::finalize(sp(input), sp(blind), ev.value().span());
        REQUIRE(out.is_ok());
        CHECK(vec(out.value()) == unhex(v.output));
        // Server one-shot Evaluate matches the same output.
        auto server = Oprf::evaluate(kp.value().secret_key.span(), sp(input));
        REQUIRE(server.is_ok());
        CHECK(vec(server.value()) == unhex(v.output));
    }
}

TEST("oprf/e2e/oblivious-flow") {
    auto seed = unhex("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2");
    auto kp = Oprf::derive_keypair(sp(seed));
    REQUIRE(kp.is_ok());
    auto input = unhex("70617373776f7264"); // "password"

    // Full oblivious round trip: blind → blind_evaluate → finalize.
    auto b = Oprf::blind(sp(input));
    REQUIRE(b.is_ok());
    auto ev = Oprf::blind_evaluate(kp.value().secret_key.span(), b.value().blinded_element.span());
    REQUIRE(ev.is_ok());
    auto out = Oprf::finalize(sp(input), b.value().blind.span(), ev.value().span());
    REQUIRE(out.is_ok());
    CHECK(out.value().size() == Oprf::OUTPUT_BYTES);

    // The oblivious output equals the server's direct evaluation (correctness).
    auto server = Oprf::evaluate(kp.value().secret_key.span(), sp(input));
    REQUIRE(server.is_ok());
    CHECK(vec(out.value()) == vec(server.value()));

    // A fresh blind of the same input yields the SAME final output (determinism)
    // but a DIFFERENT blinded element (obliviousness).
    auto b2 = Oprf::blind(sp(input));
    REQUIRE(b2.is_ok());
    CHECK(vec(b2.value().blinded_element) != vec(b.value().blinded_element));
    auto ev2 = Oprf::blind_evaluate(kp.value().secret_key.span(), b2.value().blinded_element.span());
    auto out2 = Oprf::finalize(sp(input), b2.value().blind.span(), ev2.value().span());
    REQUIRE(out2.is_ok());
    CHECK(vec(out2.value()) == vec(out.value()));

    // A different input yields a different output.
    auto other = Oprf::evaluate(kp.value().secret_key.span(), sp(unhex("70617373776f7265")));
    REQUIRE(other.is_ok());
    CHECK(vec(other.value()) != vec(server.value()));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_oprf() {
    RUN("oprf/kat/rfc9497-ristretto255");
    RUN("oprf/e2e/oblivious-flow");
}
