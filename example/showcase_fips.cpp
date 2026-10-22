/**
 * FIPS profile showcase: builds only with CRYPTOLIB_PROFILE=fips and runs
 * every approved operation the profile offers through the OpenSSL FIPS
 * Provider (certificate #4985). Point CRYPTOLIB_FIPS_MODULE_DIR at the
 * directory holding fips.dylib or fips.so and CRYPTOLIB_FIPS_CONFIG at the
 * OpenSSL config that includes fipsmodule.cnf, then run it. Exit status is
 * non-zero if the provider does not load or any check fails.
 */
#include <cryptolib/cryptolib.hpp>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
int g_pass = 0, g_fail = 0;
void check(bool ok, const std::string& label) {
    std::cout << (ok ? "  [OK]   " : "  [FAIL] ") << label << "\n";
    (ok ? g_pass : g_fail)++;
}
std::vector<uint8_t> text(std::string_view s) { return { s.begin(), s.end() }; }
std::vector<uint8_t> copy(std::span<const uint8_t> s) { return { s.begin(), s.end() }; }
std::string hex(std::span<const uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string out;
    for (auto x : b) { out += d[x >> 4]; out += d[x & 15]; }
    return out;
}
}

int main() {
    using namespace crypto::fips;
    std::cout << "CipherBird fips profile showcase\n\n";
    auto init = Provider::init(Provider::Location{});
    if (init.is_err()) {
        std::cout << "  provider did not load: " << init.error().message << "\n";
        return EXIT_FAILURE;
    }
    auto st = Provider::status();
    std::cout << "  provider: " << st.provider_name << " " << st.provider_version
              << " from " << st.module_directory << "\n"
              << "  self tests passed: " << (st.self_tests_passed ? "yes" : "no")
              << ", approved mode: " << (st.approved_mode ? "yes" : "no") << "\n\n";
    check(st.loaded && st.self_tests_passed && st.approved_mode, "module loaded, self-tested, approved mode on");

    auto d = Digest::compute(Hash::Sha256, text("abc"));
    check(d.is_ok() && hex(d.value().span()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 known answer");
    std::vector<uint8_t> key(20, 0x0b);
    auto mac = Hmac::compute(Hash::Sha256, key, text("Hi There"));
    check(mac.is_ok() && hex(mac.value().span()) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "HMAC-SHA256 RFC 4231 case 1");
    check(mac.is_ok() && Hmac::verify(Hash::Sha256, key, text("Hi There"), mac.value().span()), "HMAC verification");
    std::vector<uint8_t> ikm(22, 0x0b), salt = {0,1,2,3,4,5,6,7,8,9,10,11,12}, info = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    auto okm = Hkdf::derive(Hash::Sha256, ikm, salt, info, 42);
    check(okm.is_ok() && hex(okm.value().span()) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "HKDF-SHA256 RFC 5869 case 1");
    auto dk = Pbkdf2::derive(Hash::Sha256, text("passwordPASSWORDpassword"), text("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 40);
    check(dk.is_ok() && hex(dk.value().span()) == "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9", "PBKDF2-HMAC-SHA256 known answer");
    auto rnd = Random::bytes(32);
    check(rnd.is_ok() && rnd.value().size() == 32, "32 bytes from the module DRBG");

    auto k = std::move(Random::bytes(32).value());
    auto wire = Aes256Gcm::encrypt(k.span(), text("cardholder data"), text("ctx"));
    auto back = Aes256Gcm::decrypt(k.span(), wire.value().span(), text("ctx"));
    check(back.is_ok() && copy(back.value().span()) == text("cardholder data"), "AES-256-GCM round trip with a module-built IV");
    auto forged = copy(wire.value().span()); forged[20] ^= 1;
    check(Aes256Gcm::decrypt(k.span(), forged, text("ctx")).is_err(), "a tampered AES-256-GCM message is rejected");

    auto a = std::move(P256::generate_keypair().value());
    auto b = std::move(P256::generate_keypair().value());
    auto s1 = P256::ecdh(a.private_key.span(), b.public_key.span());
    auto s2 = P256::ecdh(b.private_key.span(), a.public_key.span());
    check(s1.is_ok() && s2.is_ok() && copy(s1.value().span()) == copy(s2.value().span()), "P-256 ECDH agrees on both sides");
    auto sig = P256::sign(a.private_key.span(), text("transaction 42"));
    check(sig.is_ok() && P256::verify(a.public_key.span(), text("transaction 42"), sig.value().span()), "ECDSA P-256 with SHA-256 verifies");
    check(sig.is_ok() && !P256::verify(a.public_key.span(), text("transaction 43"), sig.value().span()), "ECDSA rejects a changed message");

    auto env = std::move(Envelope::create().value());
    check(env.add_passphrase_slot(text("correct horse battery staple"), 1000).is_ok(), "key envelope: passphrase slot added");
    auto blob = env.serialise();
    auto loaded = Envelope::deserialise(blob.span());
    auto master = loaded.value().unlock_with_passphrase(text("correct horse battery staple"));
    check(master.is_ok() && master.value().size() == 32, "key envelope: stored blob unlocks the 32-byte master");
    check(loaded.value().unlock_with_passphrase(text("wrong")).is_err(), "key envelope: wrong passphrase rejected");

    auto r = std::move(P256::generate_keypair().value());
    auto sealed = HpkeP256::seal(r.public_key.span(), text("app info"), text("aad"), text("secret payload"));
    auto opened = HpkeP256::open(sealed.value().enc.span(), r.private_key.span(), r.public_key.span(), text("app info"), text("aad"), sealed.value().ct.span());
    check(opened.is_ok() && copy(opened.value().span()) == text("secret payload"), "HPKE DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM round trip");

    std::cout << "\n  Passed: " << g_pass << "  Failed: " << g_fail << "\n";
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
