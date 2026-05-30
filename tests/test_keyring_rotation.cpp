#include "test_framework.hpp"
#include <vector>
using namespace test;

using crypto::Keyring;
using crypto::KdfParams;

static bool eq(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    return crypto::secure_equal(a, b);
}

TEST("keyring/rewrap-keeps-master-changes-factors") {
    auto f1 = crypto::random_bytes(32);
    auto kr = Keyring::create();
    REQUIRE(kr.add_device_slot(f1.span()).is_ok());
    REQUIRE(kr.add_passphrase_slot("old-pass", KdfParams::interactive()).is_ok());
    auto master0 = kr.unlock_with_device(f1.span());
    REQUIRE(master0.is_ok());

    // Change credentials: new device factor + new passphrase, SAME master.
    auto f2 = crypto::random_bytes(32);
    std::vector<std::span<const uint8_t>> dfs{f2.span()};
    std::vector<std::string_view> pps{"new-pass"};
    REQUIRE(kr.rewrap(dfs, pps, KdfParams::interactive()).is_ok());

    // New factors unlock to the SAME master (existing data still decryptable).
    auto viaF2 = kr.unlock_with_device(f2.span());
    REQUIRE(viaF2.is_ok());
    CHECK(eq(viaF2.value().span(), master0.value().span()));
    auto viaP2 = kr.unlock_with_passphrase("new-pass");
    REQUIRE(viaP2.is_ok());
    CHECK(eq(viaP2.value().span(), master0.value().span()));

    // Old factors no longer work.
    CHECK(kr.unlock_with_device(f1.span()).is_err());
    CHECK(kr.unlock_with_passphrase("old-pass").is_err());
}

TEST("keyring/rekey-changes-master-returns-old") {
    auto f1 = crypto::random_bytes(32);
    auto kr = Keyring::create();
    REQUIRE(kr.add_device_slot(f1.span()).is_ok());
    auto master0 = kr.unlock_with_device(f1.span());
    REQUIRE(master0.is_ok());

    auto f2 = crypto::random_bytes(32);
    std::vector<std::span<const uint8_t>> dfs{f2.span()};
    std::vector<std::string_view> pps{};
    auto old = kr.rekey(dfs, pps);
    REQUIRE(old.is_ok());
    // rekey returns the OLD master (for re-encrypting existing data).
    CHECK(eq(old.value().span(), master0.value().span()));

    // The keyring now holds a NEW master, openable with f2, != old.
    auto master1 = kr.unlock_with_device(f2.span());
    REQUIRE(master1.is_ok());
    CHECK(!eq(master1.value().span(), master0.value().span()));
    CHECK(kr.unlock_with_device(f1.span()).is_err());
}

TEST("keyring/rotation-requires-unlock") {
    auto f1 = crypto::random_bytes(32);
    auto kr = Keyring::create();
    REQUIRE(kr.add_device_slot(f1.span()).is_ok());
    auto blob = kr.serialise();
    auto locked = Keyring::deserialise(blob.span());  // fresh: no master in memory
    REQUIRE(locked.is_ok());
    auto f2 = crypto::random_bytes(32);
    std::vector<std::span<const uint8_t>> dfs{f2.span()};
    std::vector<std::string_view> pps{};
    CHECK(locked.value().rewrap(dfs, pps).is_err());
    CHECK(locked.value().rekey(dfs, pps).is_err());
}

TEST("keyring/rewrap-no-factors-rolls-back") {
    auto f1 = crypto::random_bytes(32);
    auto kr = Keyring::create();
    REQUIRE(kr.add_device_slot(f1.span()).is_ok());
    std::vector<std::span<const uint8_t>> none;
    std::vector<std::string_view> nopw;
    CHECK(kr.rewrap(none, nopw).is_err());
    // Unchanged: original factor still unlocks.
    CHECK(kr.unlock_with_device(f1.span()).is_ok());
}

void run_tests_keyring_rotation() {
    RUN("keyring/rewrap-keeps-master-changes-factors");
    RUN("keyring/rekey-changes-master-returns-old");
    RUN("keyring/rotation-requires-unlock");
    RUN("keyring/rewrap-no-factors-rolls-back");
}
