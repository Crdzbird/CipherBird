#include "test_framework.hpp"
#include <algorithm>
using namespace test;

using crypto::Shamir;

static bool eq(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

TEST("shamir/k-of-n-reconstruct") {
    auto secret = crypto::random_bytes(32);
    auto shares = Shamir::split(secret.span(), 5, 3);
    REQUIRE(shares.is_ok());
    CHECK(shares.value().size() == 5);

    // Any 3 shares reconstruct.
    std::vector<Shamir::Share> subset;
    subset.push_back(std::move(shares.value()[0]));
    subset.push_back(std::move(shares.value()[2]));
    subset.push_back(std::move(shares.value()[4]));
    auto rec = Shamir::combine(subset);
    REQUIRE(rec.is_ok());
    CHECK(eq(rec.value().span(), secret.span()));
}

TEST("shamir/all-shares-reconstruct") {
    auto secret = crypto::random_bytes(48);
    auto shares = Shamir::split(secret.span(), 4, 2);
    REQUIRE(shares.is_ok());
    auto rec = Shamir::combine(shares.value());
    REQUIRE(rec.is_ok());
    CHECK(eq(rec.value().span(), secret.span()));
}

TEST("shamir/fewer-than-k-does-not-reveal") {
    auto secret = crypto::random_bytes(32);
    auto shares = Shamir::split(secret.span(), 5, 3);
    REQUIRE(shares.is_ok());
    // Only 2 of 3 → reconstruction must NOT equal the secret.
    std::vector<Shamir::Share> two;
    two.push_back(std::move(shares.value()[0]));
    two.push_back(std::move(shares.value()[1]));
    auto rec = Shamir::combine(two);
    REQUIRE(rec.is_ok());           // no error — that's the point
    CHECK(!eq(rec.value().span(), secret.span()));
}

TEST("shamir/tampered-share-corrupts") {
    auto secret = crypto::random_bytes(32);
    auto shares = Shamir::split(secret.span(), 3, 3);
    REQUIRE(shares.is_ok());
    shares.value()[1].y.data()[0] ^= 0x01;  // flip a byte
    auto rec = Shamir::combine(shares.value());
    REQUIRE(rec.is_ok());
    CHECK(!eq(rec.value().span(), secret.span()));
}

TEST("shamir/distinct-indices-and-lengths") {
    auto secret = crypto::random_bytes(16);
    auto shares = Shamir::split(secret.span(), 3, 2);
    REQUIRE(shares.is_ok());
    // duplicate index rejected
    std::vector<Shamir::Share> dup;
    dup.push_back(Shamir::Share{1, crypto::SecureBuffer(16)});
    dup.push_back(Shamir::Share{1, crypto::SecureBuffer(16)});
    CHECK(Shamir::combine(dup).is_err());
    // index 0 rejected
    std::vector<Shamir::Share> zero;
    zero.push_back(Shamir::Share{0, crypto::SecureBuffer(16)});
    CHECK(Shamir::combine(zero).is_err());
}

TEST("shamir/bad-params-rejected") {
    auto secret = crypto::random_bytes(16);
    CHECK(Shamir::split(secret.span(), 3, 0).is_err());   // k=0
    CHECK(Shamir::split(secret.span(), 2, 3).is_err());   // k>n
    std::vector<uint8_t> empty;
    CHECK(Shamir::split(empty, 3, 2).is_err());           // empty secret
}

TEST("shamir/single-byte-secret") {
    std::vector<uint8_t> s{0x42};
    auto shares = Shamir::split(s, 5, 3);
    REQUIRE(shares.is_ok());
    std::vector<Shamir::Share> subset;
    subset.push_back(std::move(shares.value()[1]));
    subset.push_back(std::move(shares.value()[3]));
    subset.push_back(std::move(shares.value()[4]));
    auto rec = Shamir::combine(subset);
    REQUIRE(rec.is_ok());
    CHECK(rec.value().size() == 1 && rec.value().data()[0] == 0x42);
}

void run_tests_shamir() {
    RUN("shamir/k-of-n-reconstruct");
    RUN("shamir/all-shares-reconstruct");
    RUN("shamir/fewer-than-k-does-not-reveal");
    RUN("shamir/tampered-share-corrupts");
    RUN("shamir/distinct-indices-and-lengths");
    RUN("shamir/bad-params-rejected");
    RUN("shamir/single-byte-secret");
}
