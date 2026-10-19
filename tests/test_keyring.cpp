/**
 * test_keyring.cpp — envelope/key-slot keyring.
 *
 * Verifies: single-device (device factor) and cross-device (passphrase) unlock
 * recover the SAME master key; wrong factors are rejected; revocation works;
 * tampering / Argon2id-param downgrade fails authentication; malformed envelopes
 * are rejected without out-of-bounds access (run under ASan).
 *
 * Passphrase slots use INTERACTIVE Argon2id params here to keep tests fast.
 */

#include "test_framework.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace test;

namespace {
std::vector<uint8_t> bytes(const crypto::SecureBuffer& b) {
    return std::vector<uint8_t>(b.span().begin(), b.span().end());
}
}

// A passphrase slot's Argon2id cost travels in the envelope. A forged envelope
// must be refused before any derivation, not after gigabytes are requested.
TEST("keyring/deserialise/kdf-params-outside-policy-rejected") {
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_passphrase_slot("pw", crypto::KdfParams::interactive()).is_ok());
    auto blob = bytes(kr.serialise());
    std::vector<uint8_t> marker;
    for (int i = 0; i < 8; ++i) marker.push_back(uint8_t(uint64_t(crypto_pwhash_OPSLIMIT_INTERACTIVE) >> (8 * i)));
    for (int i = 0; i < 8; ++i) marker.push_back(uint8_t(uint64_t(crypto_pwhash_MEMLIMIT_INTERACTIVE) >> (8 * i)));
    auto at = std::search(blob.begin(), blob.end(), marker.begin(), marker.end());
    REQUIRE(at != blob.end());
    const std::size_t ops_off = static_cast<std::size_t>(at - blob.begin());
    auto forged = blob;
    forged[ops_off + 5] = 1; // ops = 2^40 + 2
    auto r = crypto::Keyring::deserialise(forged);
    CHECK_ERR(r);
    CHECK(r.error().message.find("outside policy") != std::string::npos);
    forged = blob;
    forged[ops_off + 8 + 5] = 1; // mem = 2^40 + 64 MiB
    r = crypto::Keyring::deserialise(forged);
    CHECK_ERR(r);
    CHECK(crypto::Keyring::deserialise(blob).is_ok());
}

// A stand-in for the platform key module: wraps and unwraps a factor under a
// key the keyring never sees. Real modules are the Secure Enclave and the
// Android Keystore, driven by the bindings.
namespace {
struct FakeModule {
    crypto::SecureBuffer key = crypto::random_bytes(32);
    std::vector<uint8_t> wrap(std::span<const uint8_t> factor) const {
        auto ct = crypto::symmetric::XChaCha20Poly1305::encrypt(factor, key.span(), {});
        return bytes_of(ct.value());
    }
    crypto::Result<crypto::SecureBuffer> unwrap(std::span<const uint8_t> blob) const {
        return crypto::symmetric::XChaCha20Poly1305::decrypt(blob, key.span(), {});
    }
    template <class B> static std::vector<uint8_t> bytes_of(const B& b) {
        return std::vector<uint8_t>(b.span().begin(), b.span().end());
    }
};
}

TEST("keyring/hardware/round-trip-through-a-module") {
    FakeModule module;
    const std::vector<uint8_t> key_id = {'s', 'e', ':', 'b', 'a', 'n', 'k', '1'};

    auto kr = crypto::Keyring::create();
    auto factor = kr.add_hardware_slot(key_id);
    REQUIRE(factor.is_ok());
    CHECK(factor.value().size() == 32);
    CHECK(kr.slot_count() == 1);
    CHECK(kr.slot_type(0).value() == crypto::Keyring::SlotType::HardwareWrapped);
    REQUIRE(kr.set_hardware_blob(0, module.wrap(factor.value().span())).is_ok());
    REQUIRE(kr.add_passphrase_slot("pw", crypto::KdfParams::interactive()).is_ok());

    auto blob = kr.serialise();
    CHECK(blob.span()[4] == crypto::Keyring::VERSION_HARDWARE);
    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    auto slot = loaded.value().hardware_slot(0);
    REQUIRE(slot.is_ok());
    CHECK(FakeModule::bytes_of(slot.value().first) == key_id);
    auto unwrapped = module.unwrap(slot.value().second.span());
    REQUIRE(unwrapped.is_ok());
    auto master = loaded.value().unlock_with_hardware(0, unwrapped.value().span());
    REQUIRE(master.is_ok());
    auto by_pass = crypto::Keyring::deserialise(blob.span()).value().unlock_with_passphrase("pw");
    REQUIRE(by_pass.is_ok());
    CHECK(bytes(master.value()) == bytes(by_pass.value()));

    auto wrong = crypto::random_bytes(32);
    CHECK(loaded.value().unlock_with_hardware(0, wrong.span()).is_err());
    CHECK(loaded.value().unlock_with_hardware(1, unwrapped.value().span()).is_err());
    CHECK(loaded.value().hardware_slot(1).is_err());
    CHECK(loaded.value().set_hardware_blob(1, key_id).is_err());
    REQUIRE(loaded.value().remove_slot(0).is_ok());
    CHECK(loaded.value().serialise().span()[4] == crypto::Keyring::VERSION);
}

TEST("keyring/hardware/envelope-version-and-tamper") {
    auto plain = crypto::Keyring::create();
    REQUIRE(plain.add_device_slot(crypto::random_bytes(32).span()).is_ok());
    CHECK(plain.serialise().span()[4] == crypto::Keyring::VERSION);

    auto kr = crypto::Keyring::create();
    auto factor = kr.add_hardware_slot(std::vector<uint8_t>{1, 2, 3});
    REQUIRE(factor.is_ok());
    REQUIRE(kr.set_hardware_blob(0, std::vector<uint8_t>(40, 0xab)).is_ok());
    auto blob = bytes(kr.serialise());

    auto downgraded = blob;
    downgraded[4] = crypto::Keyring::VERSION;
    CHECK(crypto::Keyring::deserialise(downgraded).is_err());

    auto renamed = blob;
    const std::vector<uint8_t> id = {1, 2, 3};
    auto at = std::search(renamed.begin() + 5, renamed.end(), id.begin(), id.end());
    REQUIRE(at != renamed.end());
    *at = 9;
    auto loaded = crypto::Keyring::deserialise(renamed);
    REQUIRE(loaded.is_ok());
    CHECK(loaded.value().unlock_with_hardware(0, factor.value().span()).is_err());

    auto truncated = std::vector<uint8_t>(blob.begin(), blob.end() - 1);
    CHECK(crypto::Keyring::deserialise(truncated).is_err());
    CHECK(kr.set_hardware_blob(0, std::vector<uint8_t>(crypto::Keyring::MAX_HW_BLOB_BYTES + 1, 1)).is_err());
    CHECK(kr.add_hardware_slot({}).is_err());
}

// ── Single-device: device factor wraps + recovers the master key ─────────────
TEST("keyring/device/round-trip") {
    auto factor = crypto::random_bytes(32);

    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());
    CHECK(kr.slot_count() == 1);

    auto blob = kr.serialise();
    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());

    auto master = loaded.value().unlock_with_device(factor.span());
    REQUIRE(master.is_ok());
    CHECK(master.value().size() == 32);

    // The recovered master must equal the original (compare via a 2nd unlock).
    auto kr2 = crypto::Keyring::deserialise(blob.span());
    REQUIRE(kr2.is_ok());
    auto m2 = kr2.value().unlock_with_device(factor.span());
    REQUIRE(m2.is_ok());
    CHECK(master.value().to_hex() == m2.value().to_hex());
}

// ── Wrong device factor is rejected ──────────────────────────────────────────
TEST("keyring/device/wrong-factor-rejected") {
    auto factor = crypto::random_bytes(32);
    auto wrong  = crypto::random_bytes(32);

    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());
    auto blob = kr.serialise();

    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    CHECK(loaded.value().unlock_with_device(wrong.span()).is_err());
}

// ── Cross-device: passphrase + device slots open the SAME master key ─────────
TEST("keyring/cross-device/same-master") {
    auto factor = crypto::random_bytes(32);

    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());
    REQUIRE(kr.add_passphrase_slot("correct horse battery staple",
                                   crypto::KdfParams::interactive()).is_ok());
    CHECK(kr.slot_count() == 2);

    auto blob = kr.serialise();

    auto a = crypto::Keyring::deserialise(blob.span());
    auto b = crypto::Keyring::deserialise(blob.span());
    REQUIRE(a.is_ok()); REQUIRE(b.is_ok());

    auto viaDevice = a.value().unlock_with_device(factor.span());
    auto viaPass   = b.value().unlock_with_passphrase("correct horse battery staple");
    REQUIRE(viaDevice.is_ok()); REQUIRE(viaPass.is_ok());
    CHECK(viaDevice.value().to_hex() == viaPass.value().to_hex());
}

// ── Wrong passphrase is rejected ─────────────────────────────────────────────
TEST("keyring/passphrase/wrong-rejected") {
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_passphrase_slot("s3cret", crypto::KdfParams::interactive()).is_ok());
    auto blob = kr.serialise();
    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    CHECK(loaded.value().unlock_with_passphrase("wrong").is_err());
}

// ── The recovered master key actually drives a SecureVault round-trip ────────
TEST("keyring/master-drives-vault") {
    auto factor = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());
    auto blob = kr.serialise();

    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    auto master = loaded.value().unlock_with_device(factor.span());
    REQUIRE(master.is_ok());

    auto kp = crypto::SecureVault::generate_keypair();
    crypto::SecureVault vault(master.value().span(), std::move(kp));
    auto sealed = vault.seal(std::string_view("top secret"), std::string_view("ctx"));
    REQUIRE(sealed.is_ok());
    auto opened = vault.open(sealed.value(), std::string_view("ctx"));
    REQUIRE(opened.is_ok());
    CHECK(opened.value().to_string() == "top secret");
}

// ── Revocation: removing a slot prevents that factor from unlocking ──────────
TEST("keyring/revocation") {
    auto factor = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());                 // slot 0
    REQUIRE(kr.add_passphrase_slot("pw", crypto::KdfParams::interactive()).is_ok()); // slot 1

    REQUIRE(kr.remove_slot(0).is_ok());   // revoke the device slot
    CHECK(kr.slot_count() == 1);

    auto blob = kr.serialise();
    auto loaded = crypto::Keyring::deserialise(blob.span());
    REQUIRE(loaded.is_ok());
    // Device factor no longer works; passphrase still does.
    CHECK(loaded.value().unlock_with_device(factor.span()).is_err());
    auto kr2 = crypto::Keyring::deserialise(blob.span());
    REQUIRE(kr2.is_ok());
    CHECK(kr2.value().unlock_with_passphrase("pw").is_ok());
}

// ── Tampering the wrapped ciphertext fails authentication ────────────────────
TEST("keyring/tamper-ciphertext-rejected") {
    auto factor = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_device_slot(factor.span()).is_ok());
    auto blob = bytes(kr.serialise());

    blob[blob.size() - 1] ^= 0x01;  // flip last byte (inside wrapped ct/tag)
    auto loaded = crypto::Keyring::deserialise(blob);
    if (loaded.is_ok())
        CHECK(loaded.value().unlock_with_device(factor.span()).is_err());
}

// ── Argon2id-param downgrade is bound into the AAD → rejected ─────────────────
TEST("keyring/param-downgrade-rejected") {
    auto kr = crypto::Keyring::create();
    REQUIRE(kr.add_passphrase_slot("pw", crypto::KdfParams::interactive()).is_ok());
    auto blob = bytes(kr.serialise());

    // The ops field (8 bytes) sits right after type(1)+salt_len(1)+salt(16),
    // i.e. at header(4+1+16+1)=22, then type(1)+saltlen(1)+salt(16)=18 → ops at 40.
    // Rather than rely on exact offset, flip a byte in the kdf-params region by
    // scanning: the ops/mem bytes are the only 16 bytes before the 2-byte wlen.
    // Flip a byte ~ in that region; AAD binding must make unlock fail.
    const std::size_t hdr = 4 + 1 + 16 + 1;          // magic+ver+id+count
    const std::size_t ops_off = hdr + 1 + 1 + 16;    // type+saltlen+salt
    blob[ops_off] ^= 0x01;                           // perturb opslimit
    auto loaded = crypto::Keyring::deserialise(blob);
    if (loaded.is_ok())
        CHECK(loaded.value().unlock_with_passphrase("pw").is_err());
}

// ── Malformed / truncated envelopes are rejected without OOB access ───────────
TEST("keyring/malformed-rejected") {
    CHECK(crypto::Keyring::deserialise({}).is_err());

    std::vector<uint8_t> badmagic = {'X','X','X','X', 1};
    CHECK(crypto::Keyring::deserialise(badmagic).is_err());

    // Valid header claiming 5 slots but no slot data follows.
    std::vector<uint8_t> trunc = {'C','K','R','1', 1};
    for (int i = 0; i < 16; ++i) trunc.push_back(0);  // envelope id
    trunc.push_back(5);                                // slot_count = 5, nothing else
    CHECK(crypto::Keyring::deserialise(trunc).is_err());

    // Slot claims a huge salt length.
    std::vector<uint8_t> badsalt = {'C','K','R','1', 1};
    for (int i = 0; i < 16; ++i) badsalt.push_back(0);
    badsalt.push_back(1);          // 1 slot
    badsalt.push_back(0);          // type
    badsalt.push_back(200);        // salt_len = 200, but no bytes follow
    CHECK(crypto::Keyring::deserialise(badsalt).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_keyring() {
    RUN("keyring/deserialise/kdf-params-outside-policy-rejected");
    RUN("keyring/hardware/round-trip-through-a-module");
    RUN("keyring/hardware/envelope-version-and-tamper");
    RUN("keyring/device/round-trip");
    RUN("keyring/device/wrong-factor-rejected");
    RUN("keyring/cross-device/same-master");
    RUN("keyring/passphrase/wrong-rejected");
    RUN("keyring/master-drives-vault");
    RUN("keyring/revocation");
    RUN("keyring/tamper-ciphertext-rejected");
    RUN("keyring/param-downgrade-rejected");
    RUN("keyring/malformed-rejected");
}
