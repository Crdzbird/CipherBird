// crypto::Frost — FROST(Ed25519, SHA-512) threshold signatures (RFC 9591).
// Validated against the RFC's official test vectors + end-to-end threshold props.
#include "test_framework.hpp"

#include <cryptolib/frost.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Frost;

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
crypto::SecureBuffer sb(std::string_view hex) { auto v = unhex(hex); return crypto::SecureBuffer(v.data(), v.size()); }
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }

// RFC 9591 §C.1 — FROST(Ed25519, SHA-512) test vectors.
namespace rfc {
const auto GROUP_PK = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const auto MSG      = "74657374";
const auto S1       = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
const auto S3       = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02";
const auto H1       = "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407";
const auto B1       = "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301";
const auto HC1      = "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3";
const auto BC1      = "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932";
const auto H3       = "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e";
const auto B3       = "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d";
const auto HC3      = "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91";
const auto BC3      = "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552";
const auto SS1      = "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603";
const auto SS3      = "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007";
const auto SIG      = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
                      "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";
}

std::vector<Frost::Commitment> rfc_commitments() {
    std::vector<Frost::Commitment> cs;
    cs.push_back(Frost::Commitment{ 1, sb(rfc::HC1), sb(rfc::BC1) });
    cs.push_back(Frost::Commitment{ 3, sb(rfc::HC3), sb(rfc::BC3) });
    return cs;
}
} // namespace

// The commitments derived from the vector nonces must match the vector commitments.
TEST("frost/kat/commitments") {
    auto c1 = Frost::commit_with_nonces(1, sb(rfc::H1), sb(rfc::B1));
    REQUIRE(c1.is_ok());
    CHECK(vec(c1.value().second.hiding) == unhex(rfc::HC1));
    CHECK(vec(c1.value().second.binding) == unhex(rfc::BC1));
    auto c3 = Frost::commit_with_nonces(3, sb(rfc::H3), sb(rfc::B3));
    REQUIRE(c3.is_ok());
    CHECK(vec(c3.value().second.hiding) == unhex(rfc::HC3));
    CHECK(vec(c3.value().second.binding) == unhex(rfc::BC3));
}

// Each participant's signature share must match the RFC vector exactly.
TEST("frost/kat/signature-shares") {
    auto cs = rfc_commitments();
    auto msg = unhex(rfc::MSG);
    Frost::SignerShare share1{ 1, sb(rfc::S1) };
    Frost::Nonces n1{ sb(rfc::H1), sb(rfc::B1) };
    auto ss1 = Frost::sign(share1, sb(rfc::GROUP_PK).span(), n1, msg, cs);
    REQUIRE(ss1.is_ok());
    CHECK(vec(ss1.value()) == unhex(rfc::SS1));

    Frost::SignerShare share3{ 3, sb(rfc::S3) };
    Frost::Nonces n3{ sb(rfc::H3), sb(rfc::B3) };
    auto ss3 = Frost::sign(share3, sb(rfc::GROUP_PK).span(), n3, msg, cs);
    REQUIRE(ss3.is_ok());
    CHECK(vec(ss3.value()) == unhex(rfc::SS3));
}

// Aggregation must reproduce the RFC's final signature, and it must verify as a
// standard Ed25519 signature under the group public key.
TEST("frost/kat/aggregate-and-verify") {
    auto cs = rfc_commitments();
    auto msg = unhex(rfc::MSG);
    std::vector<crypto::SecureBuffer> shares;
    shares.push_back(sb(rfc::SS1));
    shares.push_back(sb(rfc::SS3));
    auto sig = Frost::aggregate(sb(rfc::GROUP_PK).span(), msg, cs, shares);
    REQUIRE(sig.is_ok());
    CHECK(vec(sig.value()) == unhex(rfc::SIG));
    CHECK(Frost::verify(msg, sig.value().span(), sb(rfc::GROUP_PK).span()));
    // Standard Ed25519 verification rejects a different message.
    auto other = unhex("74657375");
    CHECK(!Frost::verify(other, sig.value().span(), sb(rfc::GROUP_PK).span()));
}

// ── End-to-end with freshly generated keys ──────────────────────────────────
namespace {
crypto::SecureBuffer round_trip_sign(const crypto::Frost::KeyGen& kg,
                                     const std::vector<int>& signer_indices,
                                     std::span<const uint8_t> msg) {
    std::vector<Frost::Nonces> nonces;
    std::vector<Frost::Commitment> commitments;
    for (int idx : signer_indices) {
        auto c = Frost::commit(kg.shares[idx]);
        nonces.push_back(std::move(c.value().first));
        commitments.push_back(std::move(c.value().second));
    }
    std::vector<crypto::SecureBuffer> shares;
    for (std::size_t k = 0; k < signer_indices.size(); ++k) {
        auto ss = Frost::sign(kg.shares[signer_indices[k]], kg.group_public_key.span(),
                              nonces[k], msg, commitments);
        shares.push_back(std::move(ss.value()));
    }
    return std::move(Frost::aggregate(kg.group_public_key.span(), msg, commitments, shares).value());
}
}

TEST("frost/e2e/any-threshold-subset-signs") {
    auto kg = Frost::keygen(5, 3);
    REQUIRE(kg.is_ok());
    auto msg = unhex("deadbeefcafe");
    // Two different 3-of-5 subsets both produce valid signatures.
    auto sig1 = round_trip_sign(kg.value(), {0, 1, 2}, msg);
    CHECK(Frost::verify(msg, sig1.span(), kg.value().group_public_key.span()));
    auto sig2 = round_trip_sign(kg.value(), {1, 3, 4}, msg);
    CHECK(Frost::verify(msg, sig2.span(), kg.value().group_public_key.span()));
}

TEST("frost/e2e/below-threshold-fails") {
    auto kg = Frost::keygen(5, 3);
    REQUIRE(kg.is_ok());
    auto msg = unhex("00112233");
    // Only 2 signers for a 3-of-5 key → Lagrange over the wrong set → invalid sig.
    auto sig = round_trip_sign(kg.value(), {0, 1}, msg);
    CHECK(!Frost::verify(msg, sig.span(), kg.value().group_public_key.span()));
}

TEST("frost/e2e/verify-share") {
    auto kg = Frost::keygen(3, 2);
    REQUIRE(kg.is_ok());
    auto msg = unhex("abcdef");
    std::vector<int> idx{0, 2};
    std::vector<Frost::Nonces> nonces;
    std::vector<Frost::Commitment> commitments;
    for (int i : idx) {
        auto c = Frost::commit(kg.value().shares[i]);
        nonces.push_back(std::move(c.value().first));
        commitments.push_back(std::move(c.value().second));
    }
    for (std::size_t k = 0; k < idx.size(); ++k) {
        auto ss = Frost::sign(kg.value().shares[idx[k]], kg.value().group_public_key.span(),
                              nonces[k], msg, commitments);
        auto ok = Frost::verify_share(kg.value().shares[idx[k]].identifier,
                                      kg.value().public_shares[idx[k]].span(), ss.value().span(),
                                      commitments[k], kg.value().group_public_key.span(), msg, commitments);
        REQUIRE(ok.is_ok());
        CHECK(ok.value());
    }
    // A share from the wrong participant's key must fail verification.
    auto ss0 = Frost::sign(kg.value().shares[idx[0]], kg.value().group_public_key.span(),
                           nonces[0], msg, commitments);
    auto bad = Frost::verify_share(kg.value().shares[idx[0]].identifier,
                                   kg.value().public_shares[idx[1]].span(), ss0.value().span(),
                                   commitments[0], kg.value().group_public_key.span(), msg, commitments);
    REQUIRE(bad.is_ok());
    CHECK(!bad.value());
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_frost() {
    RUN("frost/kat/commitments");
    RUN("frost/kat/signature-shares");
    RUN("frost/kat/aggregate-and-verify");
    RUN("frost/e2e/any-threshold-subset-signs");
    RUN("frost/e2e/below-threshold-fails");
    RUN("frost/e2e/verify-share");
}
